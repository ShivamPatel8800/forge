import glob
import json

from loguru import logger

from ..core.engine import register
from .bhparser import BloodHoundParser


@register("analyze")
class AnalysisPhase:
    """Rebuilds all facts each iteration from (stale) BH data + runtime overrides."""

    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        f, st = self.ctx.state.facts, self.ctx.state
        if not f.get("bh_dir"):
            logger.warning("no BloodHound data — skipping analysis")
            return
        owned = {c.username.lower() for c in st.creds}
        plaintext = {c.username.lower() for c in st.creds
                     if c.secret_type == "password" and c.validated}
        parsed = BloodHoundParser(
            f["bh_dir"],
            synthetic_edges=f.get("synthetic_acl_edges", []),
            extra_parents=f.get("added_group_memberships", {}),
        ).load().facts(owned, plaintext)
        f.update(parsed)
        f["have_valid_cred"] = any(c.validated for c in st.creds)
        f["have_plaintext_cred"] = bool(plaintext)
        self._parse_certipy(f)
        sizes = ", ".join(f"{k.replace('acl_plan_', '')}={len(v)}"
                          for k, v in parsed.items() if k.startswith("acl_plan_"))
        logger.info(f"ACL plan: {sizes or 'empty'} | esc1={len(f.get('esc1_templates', []))}")

    def _parse_certipy(self, f):
        """Certipy -json output -> ESC1 template list."""
        f.setdefault("esc1_templates", [])
        prefix = f.get("certipy_json")
        if not prefix:
            return
        for path in glob.glob(f"{prefix}*.json"):
            try:
                data = json.load(open(path, errors="ignore"))
            except Exception:
                continue
            tpls = data.get("Certificate Templates", {})
            tpls = tpls.values() if isinstance(tpls, dict) else tpls
            for tpl in tpls:
                if not isinstance(tpl, dict):
                    continue
                esc1 = tpl.get("ESC1", False) or (
                    "EnrolleeSuppliesSubject" in (tpl.get("Certificate Name Flag") or "")
                    and tpl.get("Enabled", True))
                if esc1 and tpl.get("Template Name"):
                    f["esc1_templates"].append({"template": tpl["Template Name"],
                                                "ca": tpl.get("CA Name", "")})
