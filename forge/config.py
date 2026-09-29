from dataclasses import dataclass, field

import yaml


@dataclass
class Target:
    domain: str
    dc_ip: str
    dc_hostname: str = None
    range: str = None


@dataclass
class Config:
    target: Target = None
    credentials: list = field(default_factory=list)
    output_dir: str = "./output"
    safe_mode: bool = True
    dry_run: bool = False
    max_iterations: int = 8
    wordlists: dict = field(default_factory=dict)
    iface: str = "eth0"
    engagement: dict = field(default_factory=dict)
    redact_secrets: bool = True
    tool_paths: dict = field(default_factory=dict)


def load_config(path: str) -> Config:
    raw = yaml.safe_load(open(path))
    t = Target(**raw.pop("target"))
    return Config(target=t, **raw)
