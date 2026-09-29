"""BloodHound classic JSON -> identity map + classified ACL attack plan."""
import json
import re
from collections import defaultdict
from pathlib import Path

CONTROL = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "AllExtendedRights"}
LINK_RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "GPLink", "AllExtendedRights"}
KINDS = ("users", "groups", "computers", "domains", "gpos", "ous", "containers")
USER_TECHS = ("reset_pwd", "shadow_creds", "targeted_asrep", "targeted_kerberoast")


class BloodHoundParser:

    def __init__(self, bh_dir, synthetic_edges=None, extra_parents=None):
        self.dir = Path(bh_dir)
        self.raw = defaultdict(list)
        self.synthetic = synthetic_edges or []
        self.extra_parents = extra_parents or {}
        self._smap = None

    # ---------------------------------------------------------- loading

    def load(self):
        for kind in KINDS:
            for path in sorted(self.dir.glob(f"*{kind}.json")):
                try:
                    blob = json.loads(path.read_text(errors="ignore"))
                except Exception:
                    continue
                data = blob.get("data", []) if isinstance(blob, dict) else blob
                for obj in data:
                    if isinstance(obj, dict) and obj.get("ObjectIdentifier"):
                        self.raw[kind].append(obj)
        return self

    # ---------------------------------------------------------- identity

    @property
    def smap(self):
        if self._smap is None:
            self._smap = {}
            for kind in KINDS:
                for o in self.raw[kind]:
                    p = o.get("Properties", {})
                    self._smap[o["ObjectIdentifier"]] = {
                        "sid": o["ObjectIdentifier"],
                        "sam": (p.get("samaccountname") or "").lower(),
                        "name": p.get("name", ""),
                        "type": kind[:-1],
                        "enabled": p.get("enabled", True),
                        "admincount": p.get("admincount", False),
                        "highvalue": p.get("highvalue", False),
                        "spns": p.get("serviceprincipalnames") or [],
                        "dontreqpreauth": p.get("dontreqpreauth", False),
                        "unconstrained": p.get("unconstraineddelegation", False),
                        "description": p.get("description", ""),
                        "owner_sid": p.get("ownersid") or p.get("owner_sid") or "",
                    }
        return self._smap

    def expand_owned(self, owned_sams) -> set:
        """Owned user SIDs + every ancestor group SID (recursive, incl. runtime adds)."""
        sam2sid = {v["sam"]: v["sid"] for v in self.smap.values() if v["sam"]}
        seed = {sam2sid[s] for s in owned_sams if s in sam2sid}
        parent_of = defaultdict(set)
        for g in self.raw["groups"]:
            for m in g.get("Members", []):
                parent_of[m.get("ObjectIdentifier")].add(g["ObjectIdentifier"])
        for gsid, members in self.extra_parents.items():
            for m in members:
                parent_of[m].add(gsid)
        seen, stack = set(seed), list(seed)
        while stack:
            cur = stack.pop()
            for parent in parent_of.get(cur, ()):
                if parent not in seen:
                    seen.add(parent)
                    stack.append(parent)
        return seen

    # ---------------------------------------------------------- classification

    def _prio(self, tgt):
        v = 10
        if tgt.get("highvalue") or tgt.get("admincount"):
            v += 100
        return v + {"group": 50, "computer": 40}.get(tgt["type"], 0)

    def _classify(self, kind, rights, tgt, has_plaintext):
        r = rights
        if kind == "users":
            if not tgt["enabled"] or tgt["sam"] == "krbtgt":
                return None
            if r & {"GenericAll", "ForceChangePassword", "AllExtendedRights"}:
                return "reset_pwd"
            if r & {"AddKeyCredentialLink", "GenericWrite"}:
                return "shadow_creds" if has_plaintext else "targeted_asrep"
            if "WriteSPN" in r:
                return "targeted_kerberoast"
            if "WriteDacl" in r:
                return "write_dacl"
            if r & {"WriteOwner", "Owns"}:
                return "write_owner"
        elif kind == "groups":
            if r & {"AddMember", "GenericAll", "GenericWrite"}:
                return "group_add"
            if "WriteDacl" in r:
                return "write_dacl"
            if r & {"WriteOwner", "Owns"}:
                return "write_owner"
        elif kind == "computers":
            if r & {"GenericAll", "GenericWrite", "AllExtendedRights"}:
                return "rbcd"
            if "WriteDacl" in r:
                return "write_dacl"
            if r & {"WriteOwner", "Owns"}:
                return "write_owner"
        elif kind == "domains":
            if "GetChanges" in r and "GetChangesAll" in r:
                return "dcsync"
        elif kind == "gpos" and r & CONTROL:
            return "gpo_modify"
        elif kind == "ous" and r & LINK_RIGHTS:
            return "gplink_abuse"
        return None

    def build_plan(self, owned_sams, plaintext_sams):
        effective = self.expand_owned(owned_sams)
        smap, by_tech, seen = self.smap, defaultdict(list), set()

        def add_edge(e):
            key = (e["target_sid"], e["right"], e["principal_sid"], e["technique"])
            if key not in seen:
                seen.add(key)
                by_tech[e["technique"]].append(e)

        def edge_for(tech, tgt_id, tgt, ace, prio):
            return {"technique": tech, "priority": prio,
                    "target_sid": tgt_id,
                    "target_sam": tgt.get("sam") or tgt.get("name", "").lower(),
                    "target_name": tgt.get("name"),
                    "target_type": tgt.get("type"),
                    "owner_sid": tgt.get("owner_sid", ""),
                    "right": ace.get("RightName"),
                    "principal_sid": ace["PrincipalSID"],
                    "principal_sam": smap.get(ace["PrincipalSID"], {}).get("sam") or
                                     smap.get(ace["PrincipalSID"], {}).get("name", "").lower()}

        for kind in ("users", "groups", "computers", "domains", "gpos", "ous"):
            for o in self.raw[kind]:
                tgt = smap.get(o["ObjectIdentifier"], {})
                rights = {a.get("RightName") for a in o.get("Aces", [])
                          if a.get("PrincipalSID") in effective}
                if not rights:
                    continue
                tech = self._classify(kind, rights, tgt, bool(plaintext_sams))
                if not tech:
                    continue
                if tech in USER_TECHS and tgt.get("sam") in owned_sams:
                    continue
                if tech == "group_add" and effective & {m.get("ObjectIdentifier")
                                                        for m in o.get("Members", [])}:
                    continue
                prio = 1000 if tech == "dcsync" else self._prio(tgt)
                for a in o.get("Aces", []):
                    if a.get("PrincipalSID") in effective:
                        add_edge(edge_for(tech, o["ObjectIdentifier"], tgt, a, prio))

        # synthetic edges — GenericAll granted by us in earlier iterations
        for e in self.synthetic:
            tgt = smap.get(e["target_sid"], {})
            tech = {"group": "group_add", "computer": "rbcd"}.get(tgt.get("type"), "reset_pwd")
            if tech in USER_TECHS and tgt.get("sam") in owned_sams:
                continue
            add_edge({"technique": tech, "priority": self._prio(tgt) + 5,
                      "target_sid": e["target_sid"],
                      "target_sam": tgt.get("sam") or tgt.get("name", "").lower(),
                      "target_name": tgt.get("name"), "target_type": tgt.get("type"),
                      "owner_sid": tgt.get("owner_sid", ""),
                      "right": e["right"], "principal_sid": e["principal_sid"],
                      "principal_sam": smap.get(e["principal_sid"], {}).get("sam", "")})

        for tech in by_tech:
            by_tech[tech].sort(key=lambda x: -x["priority"])
        return by_tech

    # ---------------------------------------------------------- GPO

    def gpo_control(self, effective):
        owned_gpos, linkable = [], []
        for g in self.raw["gpos"]:
            p = g.get("Properties", {})
            rights = {a.get("RightName") for a in g.get("Aces", [])
                      if a.get("PrincipalSID") in effective}
            if rights & CONTROL:
                owned_gpos.append({"gpo": p.get("name"),
                                   "guid": g.get("ObjectIdentifier"),
                                   "rights": sorted(rights & CONTROL)})
        for kind in ("ous", "domains"):
            for o in self.raw[kind]:
                p = o.get("Properties", {})
                rights = {a.get("RightName") for a in o.get("Aces", [])
                          if a.get("PrincipalSID") in effective}
                if rights & LINK_RIGHTS:
                    linkable.append({
                        "container": p.get("name"), "type": kind[:-1],
                        "linked_gpos": re.findall(r"LDAP://([^;\]]+)", p.get("gplink") or ""),
                        "rights": sorted(rights & LINK_RIGHTS)})
        return owned_gpos, linkable

    # ---------------------------------------------------------- facts

    def facts(self, owned_sams, plaintext_sams):
        f, smap = {}, self.smap
        effective = self.expand_owned(owned_sams)

        plan = self.build_plan(owned_sams, plaintext_sams)
        for tech, items in plan.items():
            f[f"acl_plan_{tech}"] = items
        f["dcsync_rights"] = bool(plan.get("dcsync"))

        f["owned_effective_sids"] = sorted(effective)
        f["high_value_sids"] = [sid for sid, v in smap.items()
                                if v["highvalue"] or
                                (v["admincount"] and v["type"] in ("user", "group"))]
        f["high_value_groups"] = [v["name"] for v in smap.values()
                                  if v["type"] == "group" and v["admincount"]]
        f["computer_fqdn_map"] = {v["sam"]: v["name"] for v in smap.values()
                                  if v["type"] == "computer" and v["sam"]}

        for d in self.raw["domains"]:
            p = d.get("Properties", {})
            f["machine_account_quota"] = p.get("machineaccountquota", 10)
            f["domain_sid"] = d.get("ObjectIdentifier")

        f["gpo_owned_control"], f["gplink_control"] = self.gpo_control(effective)

        f["kerberoastable_users"] = [v["sam"] for v in smap.values()
            if v["type"] == "user" and v["spns"] and v["enabled"] and v["sam"] != "krbtgt"]
        f["asrep_users"] = [v["sam"] for v in smap.values()
            if v["type"] == "user" and v["dontreqpreauth"] and v["enabled"]]
        f["unconstrained_delegation"] = [v["name"] for v in smap.values() if v["unconstrained"]]
        f["password_in_description"] = [(v["sam"], v["description"]) for v in smap.values()
            if v["type"] == "user" and v["description"]
            and re.search(r"(passw(or)?d|pwd|secret|creds?)", v["description"], re.I)]
        return f
