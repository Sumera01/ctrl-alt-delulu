"""
Ctrl+Alt+Delulu — scan-state.json Initialiser
==============================================
Run this ONCE when setting up the repo.
It creates the shared scan-state.json file that all 6 parts read and write to.

Usage:
    python init_scan_state.py
    python init_scan_state.py --path /path/to/your/project

"""

import json
import os
import argparse
from datetime import datetime, timezone

# ── Colours for terminal output ──────────────────────────────────────────────
PINK   = "\033[38;5;198m"
PURPLE = "\033[38;5;135m"
CYAN   = "\033[38;5;51m"
YELLOW = "\033[38;5;226m"
GREEN  = "\033[38;5;46m"
MUTED  = "\033[38;5;245m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def print_banner():
    print(f"""
{PURPLE}  ██████╗{PINK} ████████╗{CYAN} ██████╗ {RESET}
{PURPLE}  ██╔══██╗{PINK}╚══██╔══╝{CYAN}██╔════╝ {RESET}
{PURPLE}  ██║  ██║{PINK}   ██║   {CYAN}██║  ███╗{RESET}
{PURPLE}  ██║  ██║{PINK}   ██║   {CYAN}██║   ██║{RESET}
{PURPLE}  ██████╔╝{PINK}   ██║   {CYAN}╚██████╔╝{RESET}
{PURPLE}  ╚═════╝ {PINK}   ╚═╝   {CYAN} ╚═════╝ {RESET}

{BOLD}  Ctrl+Alt+Delulu — scan-state.json Initialiser{RESET}
{MUTED}  Run once. Sets up the shared file for all 6 parts.{RESET}
""")

def build_initial_state(project_name, project_path):
    """
    Builds the starting scan-state.json structure.
    All values are empty or zero — parts fill them in as they run.
    """
    return {
        "meta": {
            "version": "1.0.0",
            "created_by": "init_scan_state.py",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "description": "Shared state file for Ctrl+Alt+Delulu vulnerability scanner. All 6 parts read and write to this file. Do not edit manually."
        },
        "project": {
            "name": project_name,
            "path": project_path,
            "started": "",
            "ended": "",
            "languages": [],
            "packages": {}
        },
        "findings": [],
        "stats": {
            "total": 0,
            "fixed": 0,
            "open": 0,
            "by_type": {
                "vulnerability": 0,
                "typosquatting": 0,
                "secret": 0
            },
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
    }

def validate_output_path(output_path):
    """
    Makes sure the folder exists before trying to write the file.
    """
    directory = os.path.dirname(output_path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory)
        print(f"  {YELLOW}Created folder:{RESET} {directory}")

def write_state_file(state, output_path):
    """
    Writes the state to disk as formatted JSON.
    """
    with open(output_path, "w") as f:
        json.dump(state, f, indent=2)

def verify_file(output_path):
    """
    Reads the file back and confirms it is valid JSON with the right structure.
    """
    with open(output_path, "r") as f:
        loaded = json.load(f)

    required_keys = ["meta", "project", "findings", "stats"]
    for key in required_keys:
        if key not in loaded:
            raise ValueError(f"Missing required key: {key}")

    return loaded

def main():
    print_banner()

    # ── Argument parsing ──────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Initialise scan-state.json for the Ctrl+Alt+Delulu scanner"
    )
    parser.add_argument(
        "--path",
        default=".",
        help="Path to the project you will be scanning (default: current directory)"
    )
    parser.add_argument(
        "--output",
        default="scan-state.json",
        help="Where to write the file (default: scan-state.json in current directory)"
    )
    parser.add_argument(
        "--name",
        default="",
        help="Name of the project being scanned (optional)"
    )
    args = parser.parse_args()

    # ── Resolve paths ─────────────────────────────────────────────────────────
    project_path = os.path.abspath(args.path)
    output_path  = os.path.abspath(args.output)

    # ── Project name ──────────────────────────────────────────────────────────
    project_name = args.name if args.name else os.path.basename(project_path)

    # ── Check if file already exists ──────────────────────────────────────────
    if os.path.exists(output_path):
        print(f"  {YELLOW}⚠  File already exists:{RESET} {output_path}")
        answer = input(f"  {YELLOW}Overwrite it? This will delete all existing findings. (yes/no):{RESET} ").strip().lower()
        if answer != "yes":
            print(f"\n  {MUTED}Cancelled. Existing file was not changed.{RESET}\n")
            return
        print()

    # ── Build and write ───────────────────────────────────────────────────────
    print(f"  {CYAN}Project name :{RESET} {project_name}")
    print(f"  {CYAN}Project path :{RESET} {project_path}")
    print(f"  {CYAN}Output file  :{RESET} {output_path}")
    print()

    print(f"  {MUTED}Building initial state...{RESET}")
    state = build_initial_state(project_name, project_path)

    print(f"  {MUTED}Validating output path...{RESET}")
    validate_output_path(output_path)

    print(f"  {MUTED}Writing scan-state.json...{RESET}")
    write_state_file(state, output_path)

    print(f"  {MUTED}Verifying file...{RESET}")
    verify_file(output_path)

    # ── Success ───────────────────────────────────────────────────────────────
    print(f"""
  {GREEN}✓  scan-state.json created successfully{RESET}

  {BOLD}What each part does with this file:{RESET}

  {YELLOW}WRITES findings{RESET}  →  Part 1 (Core Scanner)
                   Part 4 (Package Checker)
                   Part 5 (Paste Guard)

  {CYAN}READS findings{RESET}   →  Part 2 (AI Explanation Layer)
                   Part 3 (VS Code Extension)

  {GREEN}READS all + writes summary{RESET}  →  Part 6 (Summary Card Generator)

  {MUTED}────────────────────────────────────────────{RESET}
  {PINK}ctrl{RESET}+{YELLOW}alt{RESET}+{CYAN}delulu{RESET}  {MUTED}one file. six parts. zero surprises.{RESET}
""")

if __name__ == "__main__":
    main()
