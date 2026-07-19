# Ctrl+Alt+Delulu

**AI-powered security scanner for developers**
*Hackathon 2026 Submission — built by three women*

Most security tools speak to security engineers. This one speaks to developers.

Ctrl+Alt+Delulu adds an AI explanation layer on top of **Semgrep** (open source) so security findings are actually understandable. Instead of raw scanner output, every issue is explained in plain English — what's wrong, why it matters, and exactly how to fix it — shown live inside VS Code, alongside typosquat detection, a paste-time secret guard, and a full project security report.

**No jargon. No wall of errors. Just answers.**

---

## Overview

| | |
|---|---|
| **Project** | Ctrl+Alt+Delulu |
| **Team** | 3 members |
| **Category** | AI-powered developer security tooling |
| **Base** | Semgrep OSS (extended, not rebuilt) |
| **AI Provider** | NVIDIA NIM (free tier), Anthropic Claude supported as alternate |
| **Repository** | `github.com/Sumera01/ctrl-alt-delulu` |

---

## The Problem

Developers can't act on security scanner output. Raw findings are written for security engineers — dense, jargon-heavy, and disconnected from "what do I actually change." Most vulnerabilities ship anyway, not from carelessness, but because the report itself is a barrier.

## The Solution

Ctrl+Alt+Delulu keeps Semgrep's detection engine but replaces its output with an AI-generated explanation for every finding: what's wrong, why it's dangerous, and the exact fix — delivered inline in the editor, checked automatically on paste and on save, and rolled into one summary report at the end of a project.

---

## Features

| # | Feature | What it does |
|---|---|---|
| 01 | **Core Scanner** | Wraps Semgrep OSS, scans any codebase, produces structured findings |
| 02 | **AI Explanation Layer** | Converts each finding into a plain-language explanation via AI |
| 03 | **VS Code Extension** | Scans on save, shows inline diagnostics and AI explanations live |
| 04 | **Package Name Checker** | Detects typosquatted or malicious dependency names |
| 05 | **Paste Guard** | Blocks accidental secret/API key pastes before they land in code |
| 06 | **Summary Card Generator** | Full project security report — JSON, TXT, HTML, PDF |

All six features are implemented and integrated.

---

## Architecture

Every part reads and writes a single shared file, **`scan-state.json`** — one source of truth, no duplicated logic between parts.

```
Core Scanner ───────┐
Package Checker ────├────► scan-state.json ◄──── AI Layer
Paste Guard ────────┘               │
                            VS Code Extension
                                     │
                                     ▼
                           Summary Card Generator
```

| Component | Reads | Writes |
|---|:---:|:---:|
| Core Scanner | ❌ | ✅ |
| AI Layer | ✅ | ✅ |
| VS Code Extension | ✅ | ❌ |
| Package Checker | ❌ | ✅ |
| Paste Guard | ❌ | ✅ |
| Summary Generator | ✅ | ❌ |

`scan-state.json` is generated locally per run and is never committed to version control.

---

## Verification

Tested end-to-end against a deliberately vulnerable sample application (`test_project/` — 2 files, 8 vulnerability classes: SQL injection, reflected XSS, `eval()` code injection, shell command injection, weak MD5 hashing, insecure pickle deserialization, hardcoded AWS credentials).

**Result, using Semgrep's full rule registry:**

| Metric | Result |
|---|---|
| Findings detected | 16 |
| Findings explained by AI | 16 / 16 |
| Severity breakdown | 7 Critical · 4 High · 5 Medium |
| Security score | 0 / 100 (correctly flagged "At Risk") |
| Package check | 7 dependencies checked, 0 typosquats (correct) |
| Summary formats generated | JSON, TXT, HTML, PDF |

The pipeline is idempotent — re-running a scan on unchanged code does not create duplicate findings or re-trigger AI calls.

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Get a free NVIDIA NIM API key at **build.nvidia.com** (sign up → any model → "Get API Key", starts with `nvapi-`):

```bash
cp .env.example .env
# open .env and paste your key into NVIDIA_API_KEY=...
```

To use Anthropic Claude instead, set in `.env`:
```
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-key-here
```

---

## First-time setup (once per clone)

```bash
python init_scan_state.py --name "your-project-name"
```
Creates `scan-state.json` — required before running any other part.

---

## Running it

**Full pipeline — scan + AI explanations**
```bash
python main.py test_project/ --config auto
```
`--config auto` uses Semgrep's full rule registry (needs internet). `--skip-ai` scans only.

**Package checker**
```bash
python pkg-checker/checker.py --file requirements.txt
```

**Summary report**
```bash
python summary/generator.py
```
Outputs `project-summary.json` / `.txt` / `.html` / `.pdf`. Open the HTML version — click any row under **All Findings** to expand the full explanation.

**VS Code Extension**
```bash
cd vscode-ext
npm install
npm run compile
```
In VS Code: **Run and Debug** → **"Run Ctrl+Alt+Delulu Extension"** → `F5`. In the Extension Development Host window, open the repo root as the workspace folder, then save any file in `test_project/` to trigger a scan. Paste Guard runs automatically inside the extension.

---

## Repository structure

```
ctrl-alt-delulu/
├── core/                 Part 01 — scanner.py, state.py, rules/
├── ai-layer/             Part 02 — explain.py
├── vscode-ext/           Part 03 — VS Code extension (TypeScript)
├── pkg-checker/          Part 04 — checker.py
├── paste-guard/          Part 05 — guard.py
├── summary/              Part 06 — generator.py
├── test_project/         vulnerable sample app used for verification
├── init_scan_state.py    run once — creates scan-state.json
├── main.py               runs Part 01 + Part 02 together
├── requirements.txt
└── .env.example
```

---

## Environment notes

- **PDF export** requires system libraries beyond the Python package (WeasyPrint):
  ```bash
  sudo apt-get update
  sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev
  ```
- **Never committed** (already gitignored): `.env`, `scan-state.json`, `findings.json`, `explanations.json`, `project-summary.*`, `node_modules/`, `vscode-ext/out/`.

---

## Built With

Semgrep (open source) · NVIDIA NIM · Anthropic Claude (optional) · Python · VS Code Extension API · TypeScript · WeasyPrint

---

## Team Contributions

| Member | Parts Owned | Delivered |
|---|---|---|
| **Sumaira** | Part 01 — Core Scanner<br>Part 02 — AI Explanation Layer | Semgrep wrapper with structured findings and shared-state integration; AI explanation pipeline (NVIDIA NIM, Claude-compatible) with parallel processing, automatic retry/repair on malformed responses, and duplicate-safe re-scanning. Also led integration testing, repository hygiene, and end-to-end verification across all six parts. |
| **Rabia** | Part 03 — VS Code Extension<br>Part 05 — Paste Guard | Live scan-on-save with inline diagnostics inside VS Code, reading shared state and rendering AI explanations in the editor; standalone Paste Guard that intercepts clipboard content for secrets before it reaches the codebase. |
| **Tasneem** | Part 04 — Package Name Checker<br>Part 06 — Summary Card Generator | Typosquat/malicious package detection across PyPI and npm manifests using edit-distance matching; end-of-project summary report generator producing JSON, TXT, HTML, and PDF outputs with full security scoring. Also authored the `scan-state.json` initializer used by the whole team. |

---

## ctrl+alt+delulu

**Three women. One scanner. Zero jargon.**
