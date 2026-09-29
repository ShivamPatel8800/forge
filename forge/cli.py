import argparse

from .config import load_config
from .core.engine import Engine


def main():
    p = argparse.ArgumentParser(prog="forge", description="AD attack-chain orchestrator")
    p.add_argument("-c", "--config", required=True)
    p.add_argument("--dry-run", action="store_true", help="print commands, execute nothing")
    p.add_argument("--unsafe", action="store_true", help="enable disruptive attacks (relay, GPO)")
    p.add_argument("--rollback", metavar="RUN_DIR",
                   help="undo all journaled mutations from a previous run, then exit")
    args = p.parse_args()

    cfg = load_config(args.config)
    if args.dry_run:
        cfg.dry_run = True
    if args.unsafe:
        cfg.safe_mode = False
    if args.rollback:
        cfg.output_dir = args.rollback
        Engine(cfg).rollback()
        return
    Engine(cfg).run()


if __name__ == "__main__":
    main()
