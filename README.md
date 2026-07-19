# Ctrl+Alt+Delulu

> **AI-powered security scanner for developers — built by three women at Hackathon 2026**

Most security tools speak to security engineers. This one speaks to developers.

Ctrl+Alt+Delulu builds an AI-powered explanation layer on top of **Semgrep** (open source) so security findings are actually understandable. Instead of raw scanner output, every issue is explained in plain English — what's wrong, why it matters, and exactly how to fix it — shown live inside VS Code, alongside typosquat detection, a paste-time secret guard, and a full project security report.

**No jargon. No wall of errors. Just answers.**

---

## The Team

| | Name | Parts |
|---|---|---|
| 🩷 | **Sumaira** | Core Scanner (01) · AI Explanation Layer (02) |
| 🟣 | **Rabia** | VS Code Extension (03) · Paste Guard (05) |
| 🩵 | **Tasneem** | Package Name Checker (04) · Summary Card Generator (06) |

---

## Features

| Part | Feature | Status |
|---|---|---|
| 01 | **Core Scanner** — wraps Semgrep OSS, scans a codebase, writes structured findings | ✅ Built & tested |
| 02 | **AI Explanation Layer** — turns raw findings into plain-language explanations via NVIDIA NIM (or Claude) | ✅ Built & tested |
| 03 | **VS Code Extension** — scans on save, shows inline diagnostics, surfaces AI explanations | ✅ Built, compiles clean |
| 04 | **Package Name Checker** — detects typosquatted/malicious package names | ✅ Built & tested |
| 05 | **Paste Guard** — blocks accidental secret/API key pastes before they land in code | ✅ Built |
| 06 | **Summary Card Generator** — full project security report (JSON/TXT/HTML/PDF) | ✅ Built & tested |

**Verified end-to-end:** scanned a deliberately vulnerable 2-file Flask app (`test_project/`, 8 vulnerability types) with Semgrep's full rule registry — caught **16 real findings**, all 16 explained by AI with zero failures, correctly aggregated into a summary card (7 Critical / 4 High / 5 Medium, Security Score 0/100).

---

## How it all connects

Every part reads and writes one shared file: **`scan-state.json`**. Nobody re-implements scanning or explaining — everyone just reads what's already there.

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

`scan-state.json` is generated locally per-run and is **never committed** — see `.gitignore`.

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

To use Anthropic/Claude instead, set in `.env`:
```
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-key-here
```

---

## First-time setup (once per clone)

```bash
python init_scan_state.py --name "your-project-name"
```
Creates `scan-state.json` — required before running any part.

---

## Running it

### Full pipeline (scan + AI explanations)
```bash
python main.py test_project/ --config auto
```
- `--config auto` uses Semgrep's full rule registry (needs internet)
- `--skip-ai` scans only, skips AI calls
- Safe to re-run: duplicate findings are deduped, already-explained findings are skipped

### Package checker
```bash
python pkg-checker/checker.py --file requirements.txt
python pkg-checker/checker.py --package requets --ecosystem pypi
python pkg-checker/checker.py --watch requirements.txt,package.json
```

### Summary report
```bash
python summary/generator.py
```
Outputs `project-summary.json` / `.txt` / `.html` / `.pdf`. Open the HTML — click any row in **ALL FINDINGS** to expand the full explanation.

### VS Code Extension
```bash
cd vscode-ext
npm install
npm run compile
```
Then in VS Code: **Run and Debug** panel → **"Run Ctrl+Alt+Delulu Extension"** → `F5`. In the Extension Development Host window that opens, open the repo root as your workspace folder, then save any file in `test_project/` to trigger a scan. Paste Guard runs automatically inside the extension.

---

## Test target

`test_project/` — a deliberately vulnerable Flask app covering 8 vulnerability types: SQL injection, reflected XSS, `eval()` code injection, shell command injection, weak MD5 hashing, insecure pickle deserialization, and a hardcoded AWS key. Catches 16 real findings with `--config auto`.

`core/rules/basic-security.yaml` — a small offline ruleset (3 rules) for testing without registry access.

---

## Repository structure

```
ctrl-alt-delulu/
├── core/                 # Part 01 — scanner.py, state.py, rules/
├── ai-layer/             # Part 02 — explain.py
├── vscode-ext/           # Part 03 — VS Code extension (TypeScript)
├── pkg-checker/          # Part 04 — checker.py
├── paste-guard/          # Part 05 — guard.py
├── summary/              # Part 06 — generator.py
├── test_project/         # vulnerable sample app for testing
├── init_scan_state.py    # run once — creates scan-state.json
├── main.py               # runs Part 01 + Part 02 together
├── requirements.txt
└── .env.example
```

---

## Known environment notes

- **PDF export** needs system libraries beyond the Python package (WeasyPrint). If you see "PDF skipped":
  ```bash
  sudo apt-get update
  sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev
  ```
  Not persistent across fresh Codespace rebuilds — re-run if needed.
- **Files never committed** (already gitignored): `.env`, `scan-state.json`, `findings.json`, `explanations.json`, `project-summary.*`, `node_modules/`, `vscode-ext/out/`.

---

## Built with

Semgrep (open source) · NVIDIA NIM · Anthropic Claude (optional) · Python · VS Code Extension API · TypeScript · WeasyPrint

---

## ctrl+alt+delulu

**Three women. One scanner. Zero jargon.**


git status
git log --oneline -5
```
