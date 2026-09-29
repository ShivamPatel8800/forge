import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class Host:
    ip: str
    hostname: str = None
    roles: list = field(default_factory=list)     # ["dc", ...]
    os: str = None
    ports: dict = field(default_factory=dict)
    smb_signing_required: bool = None


@dataclass
class Cred:
    username: str
    secret: str
    secret_type: str            # password | nthash
    source: str = ""
    validated: bool = False


@dataclass
class Finding:
    vuln_id: str
    severity: str               # critical|high|medium|low|info
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""


class State:
    def __init__(self, output_dir: str):
        self.path = Path(output_dir) / "state.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.hosts, self.creds, self.findings = [], [], []
        self.facts = {}
        self.executed = set()
        self._cred_keys = set()
        if self.path.exists():
            self.load()

    def save(self):
        self.path.write_text(json.dumps({
            "hosts": [asdict(h) for h in self.hosts],
            "creds": [asdict(c) for c in self.creds],
            "findings": [asdict(f) for f in self.findings],
            "facts": self.facts,
            "executed": sorted(self.executed),
        }, indent=2, default=str))

    def load(self):
        d = json.loads(self.path.read_text())
        self.hosts = [Host(**h) for h in d["hosts"]]
        self.creds = [Cred(**c) for c in d["creds"]]
        self.findings = [Finding(**f) for f in d["findings"]]
        self.facts = d["facts"]
        self.executed = set(d["executed"])
        self._cred_keys = {(c.username.lower(), c.secret, c.secret_type) for c in self.creds}

    def add_cred(self, cred: Cred) -> bool:
        """Dedupe. True only if genuinely new -> drives the attack loop."""
        key = (cred.username.lower(), cred.secret, cred.secret_type)
        if key not in self._cred_keys:
            self.creds.append(cred)
            self._cred_keys.add(key)
            return True
        return False

    def add_finding(self, f: Finding):
        if not any(x.vuln_id == f.vuln_id for x in self.findings):
            self.findings.append(f)
