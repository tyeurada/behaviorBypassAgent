"""Fetch Elastic behavior detection rules (TOML) for the local rule analyzer.

Downloads the Windows behavior rules from elastic/protections-artifacts
(`behavior/rules/windows/*.toml`) into ./windowsBehaviorRules/ so that
lib/rule_analyzer.py can match live Elastic Defend alerts to their rule
definitions (query logic, exclusions, detection patterns).

Usage:
    python tools/fetch_elastic_rules.py [--dest DIR] [--branch BRANCH]

Requires git. The rules directory is gitignored; re-run this script to update.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_URL = "https://github.com/elastic/protections-artifacts.git"
RULES_SUBDIR = "behavior/rules/windows"
DEFAULT_DEST = Path(__file__).resolve().parent.parent / "windowsBehaviorRules"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr.strip()}")


def fetch_rules(dest: Path, branch: str) -> int:
    """Sparse-clone the rules subtree and copy TOML files into dest."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                "--branch",
                branch,
                REPO_URL,
                str(repo),
            ]
        )
        run(["git", "sparse-checkout", "set", RULES_SUBDIR], cwd=repo)

        src = repo / RULES_SUBDIR
        tomls = sorted(src.glob("*.toml"))
        if not tomls:
            raise RuntimeError(f"No TOML files found under {RULES_SUBDIR} in cloned repo")

        dest.mkdir(parents=True, exist_ok=True)
        for toml in tomls:
            shutil.copy2(toml, dest / toml.name)
        return len(tomls)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch Elastic Windows behavior rules (TOML)")
    parser.add_argument("--dest", default=str(DEFAULT_DEST), help="Destination directory for TOML rules")
    parser.add_argument("--branch", default="main", help="Branch of elastic/protections-artifacts")
    args = parser.parse_args()

    dest = Path(args.dest).resolve()
    print(f"Fetching Windows behavior rules from {REPO_URL} ({args.branch}) -> {dest}")
    try:
        count = fetch_rules(dest, args.branch)
    except Exception as e:
        print(f"Error: {e}")
        return 1

    print(f"Done. {count} rule files written to {dest}")
    print("Note: this directory is gitignored; re-run this script to refresh the rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
