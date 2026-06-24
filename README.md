# ShadowInject

**Automated Exploit Generation Framework** powered by AI.

ShadowInject is a modular Python framework that automates vulnerability discovery and Proof-of-Concept generation. It combines network reconnaissance, AI-driven analysis (GPT-4o), and sandboxed execution to streamline penetration testing workflows.

Built for security professionals, CTF players, and pentesters who want to move from scan to PoC in seconds.

---

## Features

- **AI-Powered Analysis** — Uses GPT-4o to analyze scan results and detect SQLi, LFI, RCE, XSS, SSRF, and more
- **Automated PoC Generation** — Generates ready-to-run Python exploit scripts from vulnerability descriptions
- **PayloadsAllTheThings Integration** — References real payloads from 60+ attack categories as inspiration for PoC generation
- **Safety Switch** — CIDR-based IP restriction prevents accidental targeting outside authorized ranges
- **Docker Sandbox** — Executes generated exploits in isolated containers for safe validation (optional)
- **Interactive Dashboard** — Rich terminal UI with phases, tables, and human-in-the-loop confirmation
- **Markdown Reports** — Automatic report generation with scan results, vulnerabilities, and exploit output
- **Zero External Dependencies for Scanning** — Multi-threaded TCP scanner works without nmap

---

## Architecture

```
main.py
  |
  +-- Safety Switch          CIDR validation before any action
  |
  +-- Port Scanner           Multi-threaded TCP connect scanner
  |
  +-- HTTP Prober            Discovers endpoints and collects responses
  |
  +-- Analyzer Agent (AI)    GPT-4o analyzes responses for vulnerabilities
  |     +-- PayloadsAllTheThings  References real techniques
  |
  +-- Human Verification      "Generate and execute?" prompt
  |
  +-- Exploit Generator (AI) GPT-4o generates Python PoC script
  |     +-- PayloadsAllTheThings  Injects real payload examples
  |
  +-- Docker Sandbox         Executes PoC in isolated container
  |
  +-- Log Manager            Saves Markdown report
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/CarlosConcepcion/shadowinject.git
cd shadowinject

# Clone payload references
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git payloads_reference

# Install dependencies
pip install -r requirements.txt

# Set your OpenAI API key
echo 'OPENAI_API_KEY=sk-your-key-here' > .env
```

### Requirements

- Python 3.10+
- OpenAI API key (GPT-4o recommended)
- Docker (optional, for sandbox execution)

---

## Usage

```bash
# Show available payload categories
python main.py --list-payloads

# Run against a target
python main.py --target 192.168.1.101

# Custom config file
python main.py --target 10.0.0.5 --config config/custom.yaml

# Verbose debug output
python main.py --target 192.168.1.101 --verbose

# Show help
python main.py --help
```

### Example Workflow

```
$ python main.py --target 192.168.1.101

┌──────────────────────────────────┐
│         SHADOWINJECT             │
│   Exploit Generation Framework   │
│   Target: 192.168.1.101          │
└──────────────────────────────────┘

── Phase 1/6: SAFETY CHECK ──
  [OK] Target 192.168.1.101 is in allowed range

── Phase 2/6: RECONNAISSANCE ──
  [*] Scanning ports...
  Port    State    Service
  ─────────────────────────
  21/tcp  open     ftp
  80/tcp  open     http
  3306/tcp open     mysql

  [*] Probing HTTP endpoints...
  Method  Path               Status
  ──────────────────────────────────
  GET     /                  200
  GET     /api/v1/users      200
  POST    /api/v1/login      401

── Phase 3/6: VULNERABILITY ANALYSIS ──
  [!] SQL Injection in GET /api/v1/users?id=
      Confidence: 85%
      Evidence: Parameter reflection in error response

── Phase 4/6: HUMAN VERIFICATION ──
  → Generate and execute payload in sandbox? (y/n): y

── Phase 5/6: EXPLOIT GENERATION ──
  [*] PoC generated: exploits/poc_sql_injection_12345.py

── Phase 6/6: SANDBOX EXECUTION ──
  [SUCCESS] Payload executed successfully
  Root access detected on target

  Report saved to: logs/report_192_168_1_101.md
```

---

## Configuration

Edit `config/config.yaml` to customize behavior:

```yaml
target:
  allowed_cidrs:          # IP ranges the safety switch allows
    - "192.168.0.0/16"
    - "10.0.0.0/8"

scan:
  ports_common: [...]     # Ports to scan
  http_paths: [...]       # HTTP endpoints to probe

llm:
  model: "gpt-4o"         # OpenAI model
  temperature: 0.1        # Lower = more deterministic

sandbox:
  enabled: true           # Set false if Docker is unavailable
  docker_image: "python:3.11-slim"
```

---

## Safety

ShadowInject includes multiple safety layers:

1. **Safety Switch** — All operations are blocked unless the target IP falls within a configured CIDR range
2. **Human Verification** — Every exploit generation requires explicit user confirmation
3. **Docker Sandbox** — Exploits execute in network-disabled containers with limited resources
4. **Network Isolation** — Sandbox containers run with `--network-disabled` by default

---

## Project Structure

```
shadowinject/
├── main.py                          # CLI entry point
├── config/
│   ├── config.yaml                  # Main configuration
│   └── agents.yaml                  # Agent role definitions
├── framework/
│   ├── safety/ip_restrictor.py      # CIDR validation
│   ├── tools/
│   │   ├── nmap_wrapper.py          # TCP port scanner
│   │   ├── http_client.py           # HTTP endpoint prober
│   │   ├── llm_client.py            # OpenAI API wrapper
│   │   ├── docker_client.py         # Docker sandbox controller
│   │   └── payload_reference.py     # PayloadsAllTheThings indexer
│   ├── agents/
│   │   ├── analyzer_agent.py        # AI vulnerability analysis
│   │   ├── exploit_generator_agent.py  # AI PoC generation
│   │   └── orchestrator.py          # Pipeline coordinator
│   ├── dashboard/terminal_ui.py     # Rich terminal interface
│   └── reporting/log_manager.py     # Markdown report generator
├── exploits/                        # Generated PoC scripts
├── logs/                            # Assessment reports
├── payloads_reference/              # PayloadsAllTheThings (clone)
└── requirements.txt
```

---

## License

MIT
