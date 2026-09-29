"""Write-ahead mutation journal with automated LIFO rollback.

Every domain mutation is journaled BEFORE execution (WAL semantics) as an
append-only fsync'd JSONL record. Lifecycle:
  PENDING -> APPLIED -> REVERTED / REVERT_FAILED / (inline REVERTED)
  PENDING -> FAILED / SKIPPED
The journal stores NO secrets — revert templates are rendered at rollback time
with credentials injected from state.json.
"""
import json
import os
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from loguru import logger


@dataclass
class Entry:
    entry_id: str
    ts: str
    attack: str
    kind: str                  # PASSWORD_RESET | GROUP_MEMBER_ADD | DACL_ADD_ACE | ...
    target: str
    principal: str
    revert_level: str          # AUTO | ADMIN_REQUIRED
    revert_template: str = ""  # rendered at rollback time
    pre_state: dict = field(default_factory=dict)
    detail: str = ""
    status: str = "PENDING"    # PENDING|APPLIED|REVERTED|REVERT_FAILED|FAILED|SKIPPED
    note: str = ""


class Handle:
    def __init__(self, entry_id: str):
        self.entry_id = entry_id
        self.ok = False
        self.error = ""
        self.inline = None             # stash (e.g. pywhisker device-id)


def rollback_cred(state):
    """Best credential for undo: validated plaintext > validated hash > any."""
    creds = state.creds
    for pred in (lambda c: c.validated and c.secret_type == "password",
                 lambda c: c.validated,
                 lambda c: c.secret_type == "password"):
        for c in creds:
            if pred(c):
                return c
    return creds[0] if creds else None


class Journal:

    def __init__(self, output_dir: str):
        self.path = Path(output_dir) / "journal.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._order: list = []         # entry_ids in creation order (LIFO basis)
        self._entries: dict = {}
        self._load()

    # ------------------------------------------------------------ persistence

    def _load(self):
        if not self.path.exists():
            return
        for line in self.path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            eid = rec["entry_id"]
            if rec["event"] == "PENDING":
                rec.pop("event")
                self._entries[eid] = Entry(**rec)
                self._order.append(eid)
            elif eid in self._entries:
                self._entries[eid].status = rec["event"]
                self._entries[eid].note = rec.get("note", "")

    def _write(self, record: dict):
        """Append + fsync: the write-ahead guarantee."""
        with open(self.path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _mark(self, event: str, eid: str, note: str = ""):
        self._write({"event": event, "entry_id": eid, "note": note})
        if eid in self._entries:
            self._entries[eid].status = event
            self._entries[eid].note = note

    # ------------------------------------------------------------ write API

    def pending(self, *, attack, kind, target, principal, revert_level,
                revert_template="", pre_state=None, detail="") -> str:
        eid = uuid4().hex[:12]
        e = Entry(eid, datetime.now().isoformat(timespec="seconds"), attack, kind,
                  target, principal, revert_level, revert_template,
                  pre_state or {}, detail)
        self._entries[eid] = e
        self._order.append(eid)
        self._write({"event": "PENDING", **asdict(e)})
        return eid

    @contextmanager
    def mutate(self, **kw):
        """with ctx.journal.mutate(kind=..., revert_template=...) as m:
                r = run_mutation()
                m.ok = r.ok"""
        h = Handle(self.pending(**kw))
        try:
            yield h
        except Exception as ex:
            h.ok, h.error = False, f"exception: {ex}"
        if h.ok:
            self._mark("APPLIED", h.entry_id)
        else:
            self._mark("FAILED", h.entry_id, h.error or "attack reported failure")

    # ------------------------------------------------------------ rollback

    def _render(self, e: Entry, cred, cfg) -> str:
        t = cfg.target
        vals = {"dc_ip": t.dc_ip, "domain": t.domain,
                "target": e.target, "principal": e.principal, **(e.pre_state or {})}
        if cred:
            vals["bl_auth"] = (f"-u '{cred.username}' -p '{cred.secret}'"
                               if cred.secret_type == "password" else
                               f"-u '{cred.username}' -p ':{cred.secret}'")
            vals["imp_auth"] = (f"'{t.domain}\\{cred.username}:{cred.secret}@{t.dc_ip}'"
                                if cred.secret_type == "password" else
                                f"'{t.domain}\\{cred.username}@{t.dc_ip}' -hashes :{cred.secret}")
        else:
            vals["bl_auth"] = vals["imp_auth"] = "<NO_CREDS_IN_STATE — run manually>"
        return e.revert_template.format(**vals)

    def rollback(self, ex, cfg, state, dry_run=False):
        """Undo APPLIED+AUTO entries LIFO. Returns (reverted, failed, manual, unknown)."""
        cred = rollback_cred(state)
        logger.info(f"rollback auth as: {cred.username if cred else 'NONE — manual only'}")
        reverted, failed, manual, unknown = [], [], [], []

        for eid in reversed(self._order):                    # LIFO
            e = self._entries[eid]
            tag = f"{e.kind} {e.principal} → {e.target}"
            if e.status in ("REVERTED", "FAILED", "SKIPPED"):
                continue
            if e.status == "PENDING":
                logger.warning(f"⚠ UNKNOWN STATE (interrupted run?): {tag} — verify manually")
                unknown.append(e)
                continue
            if e.revert_level == "ADMIN_REQUIRED":
                logger.warning(f"✋ manual action required: {tag} — {e.detail}")
                manual.append(e)
                continue
            cmd = self._render(e, cred, cfg)
            if dry_run:
                logger.info(f"[dry] would revert {tag}: {cmd}")
                continue
            r = ex.run(cmd, name=f"revert_{e.kind}_{e.target[:20]}")
            if r.ok:
                self._mark("REVERTED", eid, f"auto-revert: {cmd[:80]}")
                logger.success(f"↩️  reverted {tag}")
                reverted.append(e)
            else:
                self._mark("REVERT_FAILED", eid, r.stderr[:200])
                logger.error(f"✗ revert FAILED: {tag} — manual fix needed")
                failed.append(e)
        return reverted, failed, manual, unknown

    # ------------------------------------------------------------ artifacts & summary

    def write_revert_script(self, path, cfg, state):
        cred, lines = rollback_cred(state), [
            "#!/bin/bash",
            f"# Forge rollback script — {datetime.now():%Y-%m-%d %H:%M}",
            f"# domain: {cfg.target.domain}  dc: {cfg.target.dc_ip}",
            "# Review before executing. Undo commands are idempotent.",
            ""]
        for eid in reversed(self._order):
            e = self._entries[eid]
            tag = f"[{e.status}] {e.kind}: {e.principal} → {e.target}"
            if e.status == "PENDING":
                lines += [f"# !! UNKNOWN STATE — run interrupted: {tag}",
                          f"#    verify manually: {e.detail}", ""]
            elif e.status in ("REVERTED", "FAILED", "SKIPPED"):
                lines.append(f"# {tag} — nothing to do")
            elif e.revert_level == "ADMIN_REQUIRED":
                lines += [f"# MANUAL REQUIRED: {tag}", f"#   {e.detail}", ""]
            else:
                lines += [f"# {tag}", self._render(e, cred, cfg), ""]
        Path(path).write_text("\n".join(lines))
        logger.info(f"revert script → {path}")

    def summary(self):
        rows = [{"kind": e.kind, "target": e.target, "principal": e.principal,
                 "status": e.status, "level": e.revert_level, "detail": e.detail}
                for e in (self._entries[i] for i in self._order)]
        n = lambda s: sum(1 for r in rows if r["status"] == s)
        return rows, n
