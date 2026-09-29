import hashlib
import json
from pathlib import Path

import yaml
from loguru import logger


def rules_path() -> str:
    return str(Path(__file__).resolve().parent.parent / "rules.yaml")


def load_rules(path=None) -> list:
    return yaml.safe_load(open(path or rules_path()))["rules"]


def rule_signature(rule, facts) -> str:
    """Hash of the fact values a rule depends on — plan changes => rule can re-fire."""
    blob = json.dumps({k: facts.get(k) for k in rule.get("requires", {})},
                      sort_keys=True, default=str)
    return hashlib.md5(blob.encode()).hexdigest()[:10]


def check(cond, val) -> bool:
    if cond == "nonempty":
        return bool(val)
    if cond == "exists":
        return val is not None
    if isinstance(cond, bool):
        return bool(val) == cond
    return val == cond


class RuleEngine:
    """Deterministic fact→attack matching. No AI — auditable YAML rules."""

    def __init__(self, rules: list):
        self.rules = rules

    def applicable(self, state, cfg):
        for r in self.rules:
            sig = f"{r['id']}:{rule_signature(r, state.facts)}"
            if r["id"] in state.executed or sig in state.executed:
                continue
            if r.get("disruptive") and cfg.safe_mode:
                logger.debug(f"[skip-safe] {r['id']}")
                continue
            if all(check(c, state.facts.get(f)) for f, c in r.get("requires", {}).items()):
                yield r
