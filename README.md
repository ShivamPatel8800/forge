<div align="center">

# 🔨 Forge — AD Attack-Chain Orchestrator

**Automated Active Directory penetration testing — from one credential to Domain Admin, autonomously.**

Python 3.10+ • MIT License • Kali/Linux • No AI — deterministic rules • Active development • PRs welcome

[Overview](#overview) •
[Why Forge](#why-forge-exists) •
[Architecture](#architecture) •
[Install](#installation) •
[Quick Start](#quick-start) •
[Safety Model](#safety--opsec-model) •
[Docs](#report-output)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Why Forge Exists](#why-forge-exists)
- [Architecture](#architecture)
- [Attack Coverage](#attack-coverage)
- [The Credential-Harvesting Loop](#the-credential-harvesting-loop)
- [Safety & OpSec Model](#safety--opsec-model)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [CLI Reference](#cli-reference)
- [Report Output](#report-output)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [How Forge Compares](#how-forge-compares)
- [Validated On](#validated-on)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

**Forge** is an open-source attack-chain orchestration framework for Active Directory.
It chains the industry-standard offensive toolset — **NetExec, Impacket, BloodHound,
Certipy, bloodyAD, pywhisker, John the Ripper** — through a deterministic YAML rule
engine that:

1. **Enumerates** the domain (hosts, users, ACLs, certificates, delegation, shares)
2. **Converts** BloodHound and Certipy output into structured attack *facts*
3. **Matches** facts against 17 orchestrated attack rules
4. **Executes** the winning exploitation primitives
5. **Harvests** every credential it cracks — and feeds them back into step 2
6. **Loops** until the domain falls or the chain is exhausted
7. **Rolls back** every domain mutation with a single command when the engagement ends

Every decision the engine makes is traceable to an auditable YAML rule — **no AI,
no LLM, no black box.**

> ⚠️ **Legal notice:** Forge performs *real* attacks (password resets, ACL
> modifications, machine account creation, credential dumping). Use it **only**
> against labs you own (GOAD, HackTheBox Pro Labs) or client environments with
> **written, signed authorization**. You are solely responsible for how you use
> this tool. See [Legal & Ethical Use](#legal--ethical-use) below.

---

## Why Forge Exists

Individual tools are excellent — chaining them is the hard part:

- **BloodHound** *shows* the attack path. Someone still has to walk it.
- **NetExec** executes atomic attacks. It doesn't chain AS-REP → ACL → RBCD → DCSync.
- **Certipy** exploits ESC1. It doesn't pivot the result into the next technique.
- Manual chaining is slow, unreproducible, and leaves the domain dirty afterwards.

Forge closes the loop: it *walks* the path automatically, records every step, and
**restores the domain** when the engagement is over.

---

## Architecture

```text
                       ┌─────────────────────────────────────────────┐
                       │                FORGE ENGINE                  │
                       └─────────────────────────────────────────────┘
   RECON ───► ENUM ───► ┌──────── ATTACK LOOP (× N) ────────┐ ───► REPORT
   nmap       kerbrute  │  analyze  → facts (BH/Certipy)     │     report.md
              nxc       │  match    → YAML rule engine       │     report.json
              BloodHound│  execute  → attack modules         │     evidence/
              Certipy   │  harvest  → new credentials ────────┘──► back to analyze
                       └────────────────────────────────────┘
```

| Phase | What happens |
|---|---|
| **recon** | nmap service sweep; DC identification via port 88/389 |
| **enum** | kerbrute user enum, unauthenticated AS-REP check, SMB signing sweep, password policy, shares, GPP/LAPS checks, BloodHound + Certipy collection |
| **attack loop** | BloodHound JSON → SID map → group-expansion → ACL classification → rule match → exploit → harvest → repeat |
| **report** | Full pentest report from run logs + state: narrative, findings, lineage, restoration |

---

## Attack Coverage

| Category | Technique | Executed with | MITRE ATT&CK |
|---|---|---|---|
| Credentials | GPP (cpassword) decrypt | native AES (no external tool) | T1552.006 |
| Credentials | AS-REP Roasting | impacket-GetNPUsers + John | T1558.004 |
| Credentials | Kerberoasting | impacket-GetUserSPNs + John | T1558.003 |
| Credentials | LAPS password read | NetExec | T1552 |
| Kerberos | Targeted AS-REP (GenericWrite) | bloodyAD + GetNPUsers | T1558.004 |
| Kerberos | Targeted Kerberoast (WriteSPN) | bloodyAD + GetUserSPNs | T1558.003 |
| ACL | Forced password reset (GenericAll / ForceChangePassword / AllExtendedRights) | bloodyAD | T1098 |
| ACL | Shadow Credentials (GenericWrite / AddKeyCredentialLink) | pywhisker + Certipy | T1098 |
| ACL | Group self-membership (AddMember) | bloodyAD | T1098 |
| ACL | WriteDACL → FullControl bootstrap | impacket-dacledit | — |
| ACL | WriteOwner → seize → DACL | impacket-owneredit | — |
| Delegation | RBCD (GenericAll on computer) | addcomputer + rbcd + getST + secretsdump | T1134 |
| AD CS | ESC1 (SAN injection) | Certipy | T1649 |
| Domain | DCSync (GetChanges + GetChangesAll) | impacket-secretsdump | T1003.006 |
| Relay | NTLM relay staging (SMB signing audit) | Responder + ntlmrelayx runbook | T1557 |
| GPO | GPO content & gPLink control | staged runbook (pyGPOAbuse) | T1484.001 |

*Detection-only checks (delegation misconfig, description-password leaks,
MachineAccountQuota, SMB signing) feed the report's enumeration summary.*

---

## The Credential-Harvesting Loop

The engine's core behavior: **every new credential re-triggers analysis**, because a
fresh credential changes what BloodHound data means (new "owned" principal → new
inherited group rights → new attack paths).

```text
samwell.tarly  (seed credential)
   │
   ├─ BloodHound: samwell.tarly has AddMember on SRV-ADMINS
   ▼
ACL_GROUP_ADD ──► samwell.tarly ∈ SRV-ADMINS          (mutation, journaled)
   │
   ├─ re-analysis: SRV-ADMINS has GenericAll on WEB01$    ▼
ACL_RBCD ──► machine AF3C21$ created ──► RBCD write ──► S4U ticket ──► secretsdump
   │        (+ local admin hash of WEB01)
   ▼
DCSYNC_DUMP ──► every NT hash in the domain ──► 🔴 DOMAIN COMPROMISED
```

Rules **re-fire when their fact set changes** — each rule's trigger conditions are
hashed into a signature, so an ACL chain discovered *after* a group-add runs even if
the same rule already executed earlier in the run. Graph mutations that yield no
credentials (group adds, DACL grants) set a `chain_progressed` flag so the loop knows
to keep going.

Because BloodHound data is a *snapshot*, Forge handles staleness deterministically:
mutations the engine made itself (synthetic ACL edges, runtime group membership) are
recorded in state and merged into every re-analysis — zero re-collection, full
reproducibility.

---

## Safety & OpSec Model

### Write-ahead mutation journal (WAL)

Every domain mutation is journaled to an fsync'd JSONL file **before** execution —
the same guarantee a database gives its undo log. A crashed run can't lose knowledge
of what it was doing.

```text
PENDING ──► APPLIED ──► REVERTED          (undone inline or by --rollback)
   │            └─────► REVERT_FAILED     (undo attempted, failed → flagged manual)
   ├──► FAILED                            (mutation never executed)
   └──► SKIPPED
```

### Mutation → recovery mapping

| Mutation | Recovery | Notes |
|---|---|---|
| Group member added | 🔧 automatic | `remove groupMember` |
| DACL ACE added | 🔧 automatic | `dacledit -action remove` |
| Owner changed | 🔧 automatic* | *when original owner exists in BloodHound data |
| KeyCredential planted | 🔧 automatic | `pywhisker --action remove` by device-id (removed inline on success; `--rollback` retries if inline cleanup failed) |
| Temporary SPN added | 🔧 automatic | deleted inline; rollback retries on failure |
| `dontReqPreauth` toggled | 🔧 automatic | reverted inline; rollback retries on failure |
| Machine account created | 🔧 automatic | `addcomputer -delete` |
| RBCD delegation written | 🔧 automatic | `rbcd -action remove` strips **only our ACE** — pre-existing delegation preserved |
| **Password reset** | ✋ **manual** | original plaintext is destroyed *by design* — flagged `ADMIN_REQUIRED` with concrete remediation steps, never fake-undone |

### Additional safety layers

- **`--dry-run`** — prints the entire attack chain without executing anything
- **`safe_mode`** (default) — skips disruptive rules (relay, GPO); enable with `--unsafe`
- **LIFO rollback** — undo happens in reverse creation order, so composite chains
  (owner-seize → DACL-grant) unwind correctly
- **Idempotent rollback** — re-running `--rollback` skips already-reverted entries
- **No secrets in the journal** — revert commands are rendered at rollback time from
  `state.json`; `journal.jsonl` and `revert.sh` are safe to attach to a deliverable

### Legal & Ethical Use

Forge is built for **authorized security assessments and lab research only**:

- Get **written, signed scope authorization** before running against any environment you don't personally own.
- Prefer labs (GOAD, HTB Pro Labs, your own test domain) for learning and tool development.
- `safe_mode` is on by default specifically to reduce blast radius (no relay staging, no GPO edits) until you've confirmed scope.
- Always run `--dry-run` first against a new target so you know exactly what will execute.
- Keep `output/` (journal, logs, evidence) confidential — it contains a full record of every action taken and often cracked credentials.

---

## Installation

Tested on **Kali Linux**. Any Debian-based distro works.

```bash
# system + attack tools
sudo apt update
sudo apt install -y nmap john kerbrute netexec python3-venv pipx git
pipx ensurepath && source ~/.bashrc
pipx install impacket certipy-ad bloodhound-python bloodyad pywhisker

# forge
git clone https://github.com/ShivamPatel8800/forge.git
cd forge
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -c "from forge.core.engine import Engine; print('✔ imports OK')"
```

**Verify tool availability** (all 13 binaries must resolve):

```bash
which nmap john kerbrute nxc impacket-secretsdump impacket-dacledit impacket-rbcd \
      impacket-addcomputer impacket-getST certipy bloodhound-python bloodyAD pywhisker
```

---

## Quick Start

```bash
cp config.example.yaml config.yaml
nano config.yaml          # set your lab's domain, DC IP, seed credential

# 1. preview the full attack chain — executes nothing
python -m forge -c config.yaml --dry-run

# 2. live run (safe mode: disruptive rules skipped)
python -m forge -c config.yaml

# 3. live run with disruptive rules enabled (relay staging, GPO runbooks)
python -m forge -c config.yaml --unsafe

# 4. when the engagement is done — restore the domain
python -m forge -c config.yaml --rollback output/

# 5. review everything
less output/report.md        # the pentest report
less output/revert.sh        # human-auditable undo script
```

**Example GOAD config:**

```yaml
target:
  domain: "sevenkingdoms.local"
  dc_ip: "10.0.10.10"
  dc_hostname: "kingslanding.sevenkingdoms.local"
  range: "10.0.10.0/24"

credentials:
  - username: "samwell.tarly"
    password: "<seed credential>"

output_dir: "./output"
safe_mode: true
max_iterations: 8
wordlists:
  users: "./wordlists/users.txt"
  passwords: "/usr/share/wordlists/rockyou.txt"
```

> **Kerberos prerequisites:** clock skew to the DC must be < 5 min
> (`sudo ntpdate <dc_ip>`) and the DC must be reachable on 88/389/445.

---

## Configuration Reference

| Key | Required | Description |
|---|---|---|
| `target.domain` | ✅ | AD domain FQDN (Kerberos realm) |
| `target.dc_ip` | ✅ | Domain controller IP |
| `target.dc_hostname` | recommended | DC FQDN — best BloodHound results |
| `target.range` | optional | CIDR — enables SMB sweeps, GPP/LAPS across hosts |
| `credentials[]` | optional | `username` + `password`, or `username` + `nthash`; the tool also runs fully unauthenticated |
| `output_dir` | — | where state, logs, evidence, reports go (default `./output`) |
| `safe_mode` | — | skip disruptive rules (default `true`) |
| `max_iterations` | — | attack-loop depth (default 8; ACL chains need more) |
| `redact_secrets` | — | mask secrets in the generated report (default `true`) |
| `wordlists.users` | — | kerbrute user list |
| `wordlists.passwords` | — | John wordlist for AS-REP / Kerberoast cracking |
| `tool_paths` | — | remap any binary (e.g. run a tool in Docker) |

## CLI Reference

| Command | Effect |
|---|---|
| `--dry-run` | print every command, execute nothing |
| `--unsafe` | enable disruptive rules (relay staging, GPO) |
| `--rollback <RUN_DIR>` | LIFO-undo all journaled mutations from that run, write `revert.sh`, exit |
| `-c <config.yaml>` | config file (required) |

---

## Report Output

Each run produces a client-grade report (`report.md` + machine-readable `report.json`):

1. **Header** — scope, mode, engagement metadata
2. **Executive Summary** — seed credentials → techniques executed → **explicit Domain-Admin verdict** (honest: RBCD local-admin is *not* counted as DA)
3. **Risk Posture** — severity counts
4. **Attack Chain Narrative** — timestamped, per-iteration table of every milestone
5. **Findings** — severity, exploited/confirmed status, remediation guidance
6. **Credential Lineage** — acquisition order: each row *enabled* the steps after it
7. **Enumeration Summary** — hosts, roastable accounts, delegation, relay targets, MAQ
8. **Residual Attack Plan** — verified-but-unexercised escalation paths (follow-up value)
9. **Restoration Report** — journal states, auto vs manual recovery
10. **Appendix** — methodology + full evidence index (every tool invocation logged)

Every external command is captured verbatim in `output/logs/` — full PoC chain,
reproducible by hand.

## Project Structure

```text
forge/
├── core/
│   ├── engine.py       # orchestrator: phases + credential-harvesting loop
│   ├── executor.py     # subprocess wrapper: logging, evidence, dry-run, tool remap
│   ├── rules.py        # YAML rule engine w/ signature-based re-firing
│   ├── journal.py      # write-ahead mutation journal + LIFO rollback
│   └── state.py        # hosts, credentials, findings, facts (JSON persistence)
├── modules/
│   ├── recon.py        # nmap → hosts/DC facts
│   ├── enum.py         # kerbrute, nxc, BloodHound, Certipy collection
│   ├── bhparser.py     # BH JSON → SID map → group expansion → ACL attack plan
│   ├── analysis.py     # facts pipeline (+ Certipy ESC parsing)
│   ├── attacks.py      # AS-REP, Kerberoast, DCSync, ESC1, GPP, LAPS, relay
│   ├── aclattacks.py   # the full journaled ACL chain (8 primitives + GPO)
│   └── report.py       # report.md / report.json generation
└── rules.yaml           # the attack logic — data, not code
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `KRB_AP_ERR_SKEW` | Clock skew with DC | `sudo ntpdate <dc_ip>` before every run |
| BloodHound collection returns empty | LDAP/389 blocked or wrong `dc_hostname` | Confirm `target.dc_hostname` resolves and 389/636 are reachable |
| `which` check fails for a binary | Tool installed via `pipx` but not on `PATH` | Re-run `pipx ensurepath && source ~/.bashrc`, or set `tool_paths` in config |
| Rule never fires despite valid ACL | Fact signature already matched earlier iteration | Check `output/logs/rules.log` for the signature dedup entry |
| `--rollback` reports `REVERT_FAILED` | Target object changed out-of-band since the run | Apply the manual steps printed for that entry; check `revert.sh` |
| Password-reset findings marked `ADMIN_REQUIRED` | Expected — original plaintext is destroyed by design | Hand the printed remediation steps to the client/lab owner |

## How Forge Compares

| Tool | Strength | Gap Forge fills |
|---|---|---|
| **BloodHound** | maps attack paths | doesn't execute them — Forge parses its data and walks the path |
| **NetExec** | enumeration + atomic attacks | no chaining, no rollback — Forge drives it as a component |
| **Certipy** | ADCS enum + ESC exploitation | one ESC at a time — Forge chains ESC1 results into broader compromise |
| **Impacket** | protocol-level primitives | manual invocation — Forge selects, sequences, journals and reverts them |

## Validated On

- **GOAD (Game of Active Directory)** — multi-domain lab covering ACL chains,
  ADCS ESC1, RBCD, GPP, relay targets *(demo report + logs to be added)*
- HackTheBox Pro Labs AD ranges

## Roadmap

- [ ] ESC2–ESC8 coverage (Certipy-driven)
- [ ] Constrained delegation abuse (`AllowedToDelegate`)
- [ ] gMSA password dumping (`ReadGMSAPassword` edges)
- [ ] Path-to-DA graph rendering (Graphviz → embedded in report)
- [ ] Shortest-path planner (networkx) over full BH graph
- [ ] Lockout-aware password spraying (policy-parsed, jittered)
- [ ] Multi-domain / trust-walking (ExtraSids, trust keys)
- [ ] Retest/diff mode — compare two runs, report fixed/regressed
- [ ] HTML report with severity charts

## Contributing

Contributions are welcome — especially new rules in `rules.yaml`, additional
recovery mappings in `journal.py`, and lab writeups under `Validated On`.

1. Fork the repo and create a feature branch
2. Add/adjust rules or modules with corresponding tests where applicable
3. Run against a lab (GOAD recommended) with `--dry-run` first
4. Open a PR describing the technique, the rule signature, and rollback behavior

Please don't submit attack primitives without a matching entry in the
**Mutation → recovery mapping** table — every mutation Forge makes must be
undoable or explicitly flagged manual.

## License

[MIT](LICENSE) — © 2025 Shivam

---

<div align="center">

**Built for defenders to understand attackers — responsibly.**

</div>
