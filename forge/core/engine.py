from pathlib import Path

from loguru import logger

from .executor import Executor
from .journal import Journal
from .rules import load_rules
from .state import State
from ..config import Config

REGISTRY = {}


def register(phase):
    def deco(cls):
        REGISTRY[phase] = cls
        return cls
    return deco


ATTACKS = {}   # populated by @register_attack in modules (imported lazily in run())


class Context:
    def __init__(self, cfg, state, ex, rules, attacks, journal):
        self.cfg, self.state, self.ex = cfg, state, ex
        self.rules, self.attacks, self.journal = rules, attacks, journal


class Engine:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = State(cfg.output_dir)
        self.ex = Executor(cfg.output_dir, cfg.dry_run, tool_paths=cfg.tool_paths)
        logger.add(f"{cfg.output_dir}/logs/forge.log",
                   format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {message}",
                   enqueue=True, level="INFO")
        self.journal = Journal(cfg.output_dir)
        self.rules = load_rules()
        self.ctx = Context(cfg, self.state, self.ex, self.rules, ATTACKS, self.journal)

    def run(self):
        # lazy import: these modules import ATTACKS/REGISTRY from here — circular otherwise
        from ..modules import recon, enum, analysis, attacks, aclattacks, report  # noqa: F401
        for phase in ("recon", "enum", "attack_loop", "report"):
            logger.info(f"{'=' * 20} PHASE: {phase.upper()} {'=' * 20}")
            if phase == "attack_loop":
                self._attack_loop()
            else:
                REGISTRY[phase](self.ctx).run()
            self.state.save()

    def _attack_loop(self):
        for i in range(1, self.cfg.max_iterations + 1):
            logger.info(f"--- attack iteration {i} ---")
            REGISTRY["analyze"](self.ctx).run()
            new_creds = REGISTRY["attack"](self.ctx).run()
            progressed = new_creds > 0 or self.state.facts.pop("chain_progressed", False)
            logger.info(f"iteration {i}: +{new_creds} creds | progressed={progressed}")
            if not progressed:
                logger.success("chain exhausted — no new credentials or graph mutations. Done.")
                break

    def rollback(self):
        rev, fail, manual, unknown = self.journal.rollback(
            self.ex, self.cfg, self.state, dry_run=self.cfg.dry_run)
        self.journal.write_revert_script(str(Path(self.cfg.output_dir) / "revert.sh"),
                                         self.cfg, self.state)
        logger.success(f"rollback done: {len(rev)} reverted, {len(fail)} failed, "
                       f"{len(manual)} manual, {len(unknown)} unknown")
