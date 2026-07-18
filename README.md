
# Ctrl+Alt+Delulu

> **AI-powered security scanner for developers — built by three women at Hackathon 2026**

Most security tools speak to security engineers. This one speaks to developers.

Ctrl+Alt+Delulu builds an AI-powered security layer on top of Semgrep Open Source to make security findings understandable for every developer. Instead of overwhelming users with raw scanner output, the platform explains every vulnerability in plain English, highlights issues directly inside VS Code, detects dangerous package names, prevents accidental secret leaks while coding, and generates a complete project security report when development is finished.

**No jargon. No wall of errors. Just answers.**

---

# The Team

| | Name | Parts |
|---|---|---|
| 🟣 | **Rabia** | VS Code Extension (Part 03) • Paste Guard (Part 05) |
| 🩷 | **Sumaira** | Core Scanner (Part 01) • AI Explanation Layer (Part 02) |
| 🩵 | **Tasneem** | Package Name Checker (Part 04) • Summary Card Generator (Part 06) |

---

# Features

| Part | Feature | Status |
|------|---------|--------|
| 01 | **Core Scanner** — Scans your codebase using Semgrep and stores findings | ✅ Complete |
| 02 | **AI Explanation Layer** — Converts technical findings into beginner-friendly explanations | ✅ Complete |
| 03 | **VS Code Extension** — Live scanning with inline diagnostics and AI explanations | ✅ Complete |
| 04 | **Package Name Checker** — Detects typosquatting and malicious package names | ✅ Complete |
| 05 | **Paste Guard** — Detects API keys, secrets and credentials before they're exposed | ✅ Complete |
| 06 | **Summary Card Generator** — Generates a complete project security report | ✅ Complete |

---

# Setup

Create a virtual environment.

```bash
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create an NVIDIA NIM API key from **https://build.nvidia.com**

Copy the example environment file.

```bash
cp .env.example .env
```

Then add your API key.

```
NVIDIA_API_KEY=nvapi-xxxxxxxxxxxxxxxx
```

---

# First Run

Before using any component, initialise the shared project state.

```bash
python init_scan_state.py --name "your-project-name"
```

This creates:

```
scan-state.json
```

Every part of the project communicates through this file.

---

# Running the Project

## Scan an entire project

```bash
python main.py test_project/
```

---

## VS Code Extension

Open the project inside VS Code.

Open the **vscode-ext** folder.

Press

```
F5
```

to launch the Extension Development Host.

The extension will:

- Scan automatically when files are saved
- Highlight vulnerabilities inline
- Show AI explanations
- Read live findings from `scan-state.json`

---

## Package Checker

Check an entire dependency file.

```bash
python pkg-checker/checker.py --file requirements.txt
```

Check a single package.

```bash
python pkg-checker/checker.py --package requets --ecosystem pypi
```

Watch dependency files continuously.

```bash
python pkg-checker/checker.py --watch requirements.txt,package.json
```

---

## Paste Guard

Paste Guard runs automatically inside the VS Code Extension.

Whenever pasted text contains:

- API Keys
- AWS Keys
- GitHub Tokens
- JWT Tokens
- Passwords
- Private Keys
- Generic Secrets

it will

- show a warning popup
- stop accidental exposure
- save the finding into `scan-state.json`

---

## Generate the Security Report

```bash
python summary/generator.py
```

Outputs

```
project-summary.html
project-summary.pdf
project-summary.json
project-summary.txt
```

Open

```
project-summary.html
```

to view the interactive report.

---

# Additional Options

Skip AI explanations.

```bash
python main.py path/to/project --skip-ai
```

Use the complete Semgrep registry.

```bash
python main.py path/to/project --config auto
```

---

# Switching AI Providers

By default the project uses **NVIDIA NIM**.

To switch to Anthropic Claude:

```
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-key
```

---

# Test Project

A deliberately vulnerable Flask application is included.

```
test_project/
```

It contains examples of:

- SQL Injection
- Cross-Site Scripting (XSS)
- eval() Injection
- Shell Injection
- Weak MD5 Hashing
- Insecure Pickle Usage
- Hardcoded AWS Keys
- Command Injection

Run

```bash
python main.py test_project/
```

to verify the entire pipeline.

---

# Repository Structure

```
ctrl-alt-delulu/

├── core/
│   ├── scanner.py
│   ├── state.py
│   └── rules/

├── ai-layer/
│   └── explain.py

├── vscode-ext/

├── pkg-checker/
│   └── checker.py

├── paste-guard/

├── summary/
│   └── generator.py

├── test_project/

├── init_scan_state.py

├── main.py

├── .env.example

└── requirements.txt
```

---

# How Everything Connects

Every component communicates through one shared file.

```
scan-state.json
```

| Component | Reads | Writes |
|-----------|:----:|:------:|
| Core Scanner | ❌ | ✅ |
| AI Layer | ✅ | ✅ |
| VS Code Extension | ✅ | ❌ |
| Package Checker | ❌ | ✅ |
| Paste Guard | ❌ | ✅ |
| Summary Generator | ✅ | ❌ |

### Data Flow

```
Core Scanner ───────┐
                    │
Package Checker ────├────► scan-state.json ◄──── AI Layer
                    │               │
Paste Guard ────────┘               │
                                    │
                           VS Code Extension
                                    │
                                    ▼
                          Summary Card Generator
```

`scan-state.json` is generated locally by:

```bash
python init_scan_state.py
```

It should **never** be committed to GitHub.

---

# PDF Export

PDF generation uses **WeasyPrint**.

If PDF export is unavailable, install:

```bash
sudo apt-get update

sudo apt-get install -y \
libpango-1.0-0 \
libpangocairo-1.0-0 \
libcairo2 \
libgdk-pixbuf-2.0-0 \
libffi-dev
```

---

# Files Never Committed

```
.env

scan-state.json

project-summary.json

project-summary.txt

project-summary.html

project-summary.pdf
```

These are already included in `.gitignore`.

---

# Built With

- Semgrep Open Source
- NVIDIA NIM
- Anthropic Claude (optional)
- Python
- VS Code Extension API
- WeasyPrint

---

## ctrl+alt+delulu

**Three women.**

**One scanner.**

**Zero jargon.**
