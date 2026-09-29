import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class CmdResult:
    name: str
    cmd: str
    rc: int
    stdout: str = ""
    stderr: str = ""
    output_file: Path = None

    @property
    def ok(self):
        return self.rc == 0


class Executor:
    """All external tools run through here: logging, evidence capture, dry-run,
    and binary remapping via config `tools:` overrides."""

    def __init__(self, output_dir: str, dry_run=False, timeout=1200, tool_paths=None):
        out = Path(output_dir)
        self.rawdir = out / "raw"
        self.logdir = out / "logs"
        self.rawdir.mkdir(parents=True, exist_ok=True)
        self.logdir.mkdir(parents=True, exist_ok=True)
        self.dry_run, self.timeout = dry_run, timeout
        self.tool_paths = tool_paths or {}

    def _resolve(self, cmd: str) -> str:
        head, sep, rest = cmd.partition(" ")
        override = self.tool_paths.get(head)
        return f"{override}{sep}{rest}" if override else cmd

    def run(self, cmd: str, name="cmd", output_file=None, timeout=None, env=None) -> CmdResult:
        cmd = self._resolve(cmd)
        logger.info(f"▶ {name} :: {cmd}")
        if self.dry_run:
            return CmdResult(name, cmd, 0)
        try:
            p = subprocess.run(shlex.split(cmd), capture_output=True, text=True,
                               timeout=timeout or self.timeout,
                               env={**os.environ, **(env or {})})
        except subprocess.TimeoutExpired:
            logger.error(f"⏱ TIMEOUT: {name}")
            return CmdResult(name, cmd, 124, stderr="timeout")
        except FileNotFoundError:
            logger.error(f"✗ binary not found: {name} (install it or remap via tools:)")
            return CmdResult(name, cmd, 127, stderr="binary not found")
        (self.logdir / f"{name}.log").write_text(f"$ {cmd}\n\n{p.stdout}\n\n{p.stderr}")
        out_file = None
        if output_file and p.stdout.strip():
            out_file = self.rawdir / output_file
            out_file.write_text(p.stdout)
        if p.returncode != 0:
            logger.warning(f"✗ {name} rc={p.returncode}: {p.stderr[:200]}")
        return CmdResult(name, cmd, p.returncode, p.stdout, p.stderr, out_file)
