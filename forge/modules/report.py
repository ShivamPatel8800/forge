"""Professional pentest report generator."""
import json
import re
from datetime import datetime
from pathlib import Path

from loguru import logger

from ..core.engine import register

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}

SHORT = {
    "ASREP_ROAST": "AS-REP Roasting", "KERBEROAST": "Kerberoasting",
    "DCSYNC_DUMP": "DCSync", "ESC1": "AD CS ESC1",
    "ACL_RESET_PWD": "Forced Password Reset", "ACL_SHADOW_CREDS": "Shadow Credentials",
    "ACL_TARGETED_KERB": "Targeted Kerberoast", "ACL_TARGETED_ASREP": "Targeted AS-REP",
    "ACL_GROUP_ADD": "Group Membership Abuse", "ACL_RBCD": "RBCD",
    "ACL_WRITE_DACL": "WriteDACL Bootstrap", "ACL_WRITE_OWNER": "WriteOwner Bootstrap",
    "GPP_CREDS": "GPP Passwords", "NTLM_RELAY": "NTLM Relay", "LAPS_DUMP": "LAPS Abuse",
}

MILESTONES = [
    ("⚔", lambda m: ("rule", re.search(r"⚔\S*\s+(\S+)\s+→\s+(\S+)", m)),
     "executed **{0}** ({1})"),
    ("💰 cracked:", lambda m: ("crack", re.search(r"cracked:\s+(\S+)\s+:\s+(\S+)", m)),
     "cracked password of **{0}**"),
    ("💰 DCSync:", lambda m: ("cred", re.search(r"DCSync:\s+(\S+)", m)),
     "dumped NT hash of **{0}** via DCSync"),
    ("💰 new validated cred:", lambda m: ("cred", re.search(r"cred:\s+(\S+)\s+\((.+)\)", m)),
     "obtained **{0}** via {1}"),
    ("💰 RBCD dump:", lambda m: ("cred", re.search(r"RBCD dump:\s+(\S+)", m)),
     "dumped **{0}**'s hash via RBCD + secretsdump"),
    ("💰 administrator NT hash", lambda m: ("cred", None),
     "obtained **administrator** NT hash via AD CS ESC1"),
    ("💰 GPP password:", lambda m: ("cred", re.search(r"GPP password:\s+(\S+)", m)),
     "recovered GPP password `{0}`"),
    ("➕", lambda m: ("mutation", re.search(r"➕\S*\s+(\S+) added to (\S+)", m)),
     "added **{0}** to group **{1}** — inherited its rights"),
    ("✍", lambda m: ("mutation", re.search(r"✍\S*\s+GenericAll granted:\s+(\S+) → (\S+)", m)),
     "granted **{0}** GenericAll on **{1}** (WriteDACL bootstrap)"),
    ("👑", lambda m: ("mutation", re.search(r"👑\s+ownership:\s+(\S+) → (\S+)", m)),
     "seized ownership of **{1}** as **{0}**"),
]

PLAN_RULE = {
    "acl_plan_reset_pwd": "ACL_RESET_PWD", "acl_plan_shadow_creds": "ACL_SHADOW_CREDS",
    "acl_plan_targeted_kerberoast": "ACL_TARGETED_KERB",
    "acl_plan_targeted_asrep": "ACL_TARGETED_ASREP",
    "acl_plan_group_add": "ACL_GROUP_ADD", "acl_plan_rbcd": "ACL_RBCD",
    "acl_plan_write_dacl": "ACL_WRITE_DACL", "acl_plan_write_owner": "ACL_WRITE_OWNER",
    "acl_plan_dcsync": "DCSYNC_DUMP", "acl_plan_gpo_modify": "GPO_CONTENT_CONTROL",
    "acl_plan_gplink_abuse": "GPLINK_CONTROL",
}


@register("report")
class ReportPhase:

    def __init__(self, ctx):
        self.ctx = ctx
        self.out = Path(ctx.cfg.output_dir)
        self.md = []

    # ------------------------------------------------------------ main

    def run(self):
        self.md += self._header()
        self.md += self._exec_summary()
        self.md += self._risk_posture()
        self.md += self._chain_narrative()
        self.md += self._findings()
        self.md += self._credentials()
        self.md += self._enum_summary()
        self.md += self._residual_plan()
        self.md += self._restoration()
        self.md += self._appendix()
        (self.out / "report.md").write_text("\n".join(self.md))
        self._dump_json()
        logger.success(f"report written → {self.out / 'report.md'}")

    # ------------------------------------------------------------ helpers

    @property
    def executed_rules(self):
        return {e.split(":")[0] for e in self.ctx.state.executed}

    def _fmt_secret(self, c):
        if not getattr(self.ctx.cfg, "redact_secrets", True):
            return f"`{c.secret}`"
        return "••••••••" if c.secret_type == "password" else f"{c.secret[:12]}…"

    def _da_achieved(self):
        if any(e == "DCSYNC_DUMP" or e.startswith("DCSYNC_DUMP:")
               for e in self.ctx.state.executed):
            return True
        for c in self.ctx.state.creds:
            u = c.username.lower()
            if u == "krbtgt":
                return True
            if u == "administrator" and c.secret_type == "nthash" \
                    and not c.source.startswith("RBCD"):
                return True   # RBCD yields LOCAL admin — excluded, never overclaim
        return False

    def _parse_log(self):
        path = self.out / "logs" / "forge.log"
        events, iteration, first_ts, last_ts, n_cmds = [], 0, None, None, 0
        if not path.exists():
            return events, n_cmds, None
        for line in path.read_text(errors="ignore").splitlines():
            m = re.match(r"^(\S+ \S+) \| (\w+) \| (.*)$", line)
            if not m:
                continue
            ts, _lvl, msg = m.groups()
            first_ts = first_ts or ts
            last_ts = ts
            if "▶ " in msg:
                n_cmds += 1
            it = re.search(r"--- attack iteration (\d+)", msg)
            if it:
                iteration = int(it.group(1))
                events.append((iteration, ts, "iter", f"**— iteration {iteration} —**"))
                continue
            if "chain exhausted" in msg:
                events.append((iteration, ts, "iter", "**chain exhausted — no further progress**"))
                continue
            for marker, (kind, rx, tmpl) in MILESTONES:
                if marker not in msg:
                    continue
                g = rx(msg).groups() if rx and rx.search(msg) else ()
                text = tmpl.format(*g) if g else tmpl.format(msg.split("|")[-1].strip())
                events.append((iteration, ts, kind, text))
                break
        return events, n_cmds, (first_ts, last_ts)

    # ------------------------------------------------------------ sections

    def _header(self):
        t = self.ctx.cfg.target
        eng = getattr(self.ctx.cfg, "engagement", {}) or {}
        return [
            f"# 🔐 Active Directory Penetration Test Report — {t.domain}",
            "", "| | |", "|---|---|",
            f"| **Domain** | {t.domain} |",
            f"| **Domain Controller** | {t.dc_ip}{f' ({t.dc_hostname})' if t.dc_hostname else ''} |",
            f"| **Scope** | {t.range or t.dc_ip} |",
            f"| **Client / Tester** | {eng.get('client', '—')} / {eng.get('tester', '—')} |",
            f"| **Generated** | {datetime.now():%Y-%m-%d %H:%M} |",
            f"| **Mode** | {'SAFE (disruptive attacks skipped)' if self.ctx.cfg.safe_mode else 'UNSAFE (full attack surface)'} |",
            "",
            "> Automated assessment by **Forge** — deterministic attack-chain orchestration",
            "> over nmap, NetExec, BloodHound, Certipy, Impacket, bloodyAD & pywhisker. No AI.",
            "",
        ]

    def _exec_summary(self):
        st = self.ctx.state
        da = self._da_achieved()
        sev = {s: sum(1 for f in st.findings if f.severity == s) for s in SEV_ORDER}
        events, n_cmds, _ = self._parse_log()

        rules = []
        for e in events:
            if e[2] == "rule":
                m = re.match(r"executed \*\*(\S+?)\*\*", e[3])
                if m:
                    rules.append(SHORT.get(m.group(1), m.group(1)))
        techs = list(dict.fromkeys(rules)) or ["enumeration only"]

        seeds = [c for c in st.creds if c.source == "config"]
        story = (f"Starting from **{len(seeds)} seed credential(s)** "
                 f"({', '.join(c.username for c in seeds) or 'none — unauthenticated'}), "
                 f"the engine executed **{len(rules)} attack steps** via {n_cmds} tool invocations")
        story += (f" and achieved **full domain compromise (Domain Admin / krbtgt)**:\n\n"
                  f"`{' → '.join(techs)}`\n") if da else \
                 (f", progressing through: {' → '.join(techs)}.\n")
        return [
            "## 1. Executive Summary", "", story,
            f"The assessment produced **{len(st.findings)} findings** "
            f"({sev['critical']} critical, {sev['high']} high) and harvested "
            f"**{len(st.creds)} credentials**. "
            + ("**Remediation of the critical-path issues is urgent.**" if da else
               "Findings below still warrant remediation — see the residual attack plan (§7)."),
            "",
            f"**Domain Admin equivalent achieved: {'✅ YES' if da else '❌ no'}**",
            "",
        ]

    def _risk_posture(self):
        st = self.ctx.state
        sev = {s: sum(1 for f in st.findings if f.severity == s) for s in SEV_ORDER}
        rows = [f"| {BADGE[s]} {s.upper()} | {n} |" for s, n in sev.items() if n]
        return ["## 2. Risk Posture", "", "| Severity | Count |", "|---|---|", *rows, ""]

    def _chain_narrative(self):
        events, _, span = self._parse_log()
        steps = [e for e in events if e[3]]
        if not steps:
            return ["## 3. Attack Chain Narrative", "",
                    "_No exploitation milestones recorded (enumeration-only run)._", ""]
        dur = ""
        if span and span[0]:
            dur = f" _({span[0].split(' ')[1]} → {span[1].split(' ')[1]})_"
        out = ["## 3. Attack Chain Narrative", "",
               f"How the compromise unfolded{dur}:", "",
               "| # | Time | Event |", "|---|---|---|"]
        n = 0
        for it, ts, _kind, text in steps:
            if text.startswith("**—"):
                out += ["", f"**{text.strip('*')}**", ""]
                continue
            n += 1
            out.append(f"| {n} | {ts.split(' ')[1][:8]} | {text} |")
        out.append("")
        return out

    def _findings(self):
        st = self.ctx.state
        if not st.findings:
            return ["## 4. Findings", "", "_None recorded._", ""]
        out = ["## 4. Findings", ""]
        done = self.executed_rules
        for f in sorted(st.findings, key=lambda x: SEV_ORDER.get(x.severity, 9)):
            exploited = f.vuln_id in done
            out += [
                f"### {BADGE.get(f.severity, '⚪')} [{f.severity.upper()}] {f.title}",
                "",
                f"**ID:** `{f.vuln_id}`  |  **Exploited:** "
                f"{'✅ yes — PoC in evidence' if exploited else '⚪ confirmed, not exercised'}",
                "",
            ]
            if f.description:
                out += [f.description, ""]
            out += ["**Remediation:**", "", f"> {f.remediation}", "", "---", ""]
        return out

    def _credentials(self):
        st = self.ctx.state
        if not st.creds:
            return ["## 5. Credential Lineage", "", "_No credentials obtained._", ""]
        out = ["## 5. Credential Lineage", "",
               "Credentials in acquisition order — each row enabled the steps after it:", "",
               "| # | Account | Type | Obtained via | Valid | Secret |",
               "|---|---|---|---|---|---|"]
        for i, c in enumerate(st.creds, 1):
            out.append(f"| {i} | `{c.username}` | {c.secret_type} | {c.source} "
                       f"| {'✅' if c.validated else '—'} | `{self._fmt_secret(c)}` |")
        out.append("")
        return out

    def _enum_summary(self):
        f, st = self.ctx.state.facts, self.ctx.state
        out = ["## 6. Enumeration Summary", ""]
        if st.hosts:
            out += ["### Hosts", "", "| IP | Roles | Open Ports |", "|---|---|---|"]
            for h in st.hosts:
                out.append(f"| {h.ip} | {', '.join(h.roles) or 'host'} | {len(h.ports)} |")
            out.append("")
        lists = [
            ("Domain Controllers", f.get("domain_controllers")),
            ("Kerberoastable accounts", f.get("kerberoastable_users")),
            ("AS-REP roastable accounts", f.get("asrep_users")),
            ("Unconstrained delegation", f.get("unconstrained_delegation")),
            ("High-value groups identified", f.get("high_value_groups")),
            ("Creds exposed in object descriptions", f.get("password_in_description")),
            ("SMB signing not required (relay targets)", f.get("no_signing_hosts")),
        ]
        for title, val in lists:
            if val:
                shown = ", ".join(f"`{v}`" if isinstance(v, str) else f"`{v[0]}`"
                                  for v in val[:15])
                extra = f" _(+{len(val) - 15} more)_" if len(val) > 15 else ""
                out += [f"- **{title}:** {shown}{extra}"]
        if f.get("machine_account_quota"):
            out += [f"- **MachineAccountQuota:** {f['machine_account_quota']} "
                    "(users can join machines — enables RBCD chains)"]
        out.append("")
        return out

    def _residual_plan(self):
        f, done = self.ctx.state.facts, self.executed_rules
        rows = []
        for key, rid in PLAN_RULE.items():
            items = f.get(key) or []
            if not items:
                continue
            status = "exploited" if rid in done else "**NOT exercised**"
            rows.append(f"| `{rid}` | {len(items)} | {status} |")
        if not rows:
            return ""
        return ["## 7. Residual Attack Plan", "",
                "Escalation opportunities identified from BloodHound analysis. "
                "Unexploited rows are verified, viable paths for follow-up:", "",
                "| Technique | Paths | Status |", "|---|---|---|", *rows, ""]

    def _restoration(self):
        rows, n = self.ctx.journal.summary()
        if not rows:
            return ["## 8. Restoration Report", "",
                    "_No domain mutations were performed during this engagement._", ""]
        counts = {s: n(s) for s in ("REVERTED", "APPLIED", "REVERT_FAILED", "PENDING", "FAILED")}
        out = ["## 8. Restoration Report", "",
               "All domain modifications are tracked in a write-ahead journal. "
               "Automated cleanup: `forge -c config.yaml --rollback "
               f"{self.out}` (LIFO order, idempotent). A reviewable "
               "`revert.sh` is also generated.", "",
               "| State | Count |", "|---|---|",
               f"| ✅ Reverted | {counts['REVERTED']} |",
               f"| ⚠ Open (rollback pending) | {counts['APPLIED']} |",
               f"| ✗ Revert failed — manual fix | {counts['REVERT_FAILED']} |",
               f"| ? Interrupted — verify manually | {counts['PENDING']} |",
               f"| — Never applied | {counts['FAILED']} |", "",
               "| Mutation | Principal → Target | Status | Recovery |",
               "|---|---|---|---|"]
        for r in rows:
            rec = {"AUTO": "🔧 automatic", "ADMIN_REQUIRED": "✋ **manual**"}.get(r["level"], "—")
            out.append(f"| {r['kind']} | `{r['principal']}` → `{r['target']}` "
                       f"| {r['status']} | {rec} |")
        out.append("")
        return out

    def _appendix(self):
        raw, logs = self.out / "raw", self.out / "logs"
        events, n_cmds, _ = self._parse_log()
        out = ["## Appendix A — Methodology", "",
               "Phases: recon (nmap) → enum (NetExec, kerbrute, BloodHound, Certipy) → "
               "iterative analysis/attack loop (deterministic rule engine over parsed facts) "
               "→ report. Every external tool invocation is logged verbatim in `logs/`.", "",
               "## Appendix B — Evidence Index", "",
               f"- Tool invocations: **{n_cmds}**  |  attack iterations: "
               f"**{max((e[0] for e in events), default=0)}**", ""]
        for d, label in ((raw, "Raw outputs"), (logs, "Command logs")):
            if d.exists():
                out.append(f"### {label} (`{d.name}/`)")
                out += ["", "| File | Size |", "|---|---|"]
                for p in sorted(d.rglob("*")):
                    if p.is_file():
                        out.append(f"| `{p.name}` | {p.stat().st_size / 1024:.1f} KB |")
                out.append("")
        return out

    def _dump_json(self):
        st = self.ctx.state
        (self.out / "report.json").write_text(json.dumps({
            "domain": self.ctx.cfg.target.domain,
            "generated": datetime.now().isoformat(),
            "da_achieved": self._da_achieved(),
            "findings": [f.__dict__ for f in st.findings],
            "credentials": [{"username": c.username, "type": c.secret_type,
                             "source": c.source, "valid": c.validated} for c in st.creds],
            "residual_plan": {k: len(v or []) for k, v in self.ctx.state.facts.items()
                              if k.startswith("acl_plan_")},
        }, indent=2))
