from __future__ import annotations
import argparse, subprocess, sys, pathlib, re, requests

SCRIPTS = (
    "match-stack.py",
    "match-tuple.py",
    "match-contops.py",
    "match-compare.py",
    "match-compare-other.py",
    "match-arithops.py",
    "match-cell.py",
    "match-apps.py",
    "match-codepage.py",
    "match-debug.py",
    "match-dict.py",
    "match-exceptions.py",
)

_GITHUB_COMMITS_API = "https://api.github.com/repos/ton-blockchain/ton/commits/"
_HEX40_RX = re.compile(r"^[0-9a-fA-F]{40}$")

def _resolve_rev(rev: str, *, verbose: bool=False) -> str:
    """Return a 40-char commit SHA for a ref or SHA.

    If `rev` is already a 40-hex SHA, return as-is. Otherwise query GitHub API
    for the ref (branch or tag) and return the resolved commit SHA.
    """
    if _HEX40_RX.fullmatch(rev):
        return rev.lower()
    url = _GITHUB_COMMITS_API + rev
    if verbose:
        print(f"→ Resolving rev '{rev}' via {url}")
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        # GitHub returns either a commit object with 'sha' or a list (for ambiguous)
        if isinstance(data, list):
            if not data:
                raise ValueError("Empty commit list from GitHub API")
            sha = data[0].get("sha")
        else:
            sha = data.get("sha")
        if not sha or not _HEX40_RX.fullmatch(sha):
            raise ValueError("Could not resolve SHA from GitHub response")
        print(f"  ✓ Resolved '{rev}' → {sha}")
        return sha.lower()
    except Exception as e:
        print(f"⚠ Failed to resolve rev '{rev}': {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json", help="cp0 JSON to feed both matchers")
    ap.add_argument("--out", default="match_report.json",
                    help="output JSON (both scripts write here)")
    ap.add_argument("-v", "--verbose", action="store_true", help="echo the commands")
    ap.add_argument("--rev", default="cee4c674ea999fecc072968677a34a7545ac9c4d",
                    help="TON repo revision (commit/tag) to forward to all matchers")
    args = ap.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent

    resolved_rev = _resolve_rev(args.rev, verbose=args.verbose)

    for idx, script in enumerate(SCRIPTS):
        script_path = str(script_dir / script)
        cmd = [
            sys.executable,
            script_path,
            "--cp0", args.cp0,
            "--out", args.out,
            "--rev", resolved_rev,
        ]
        if idx:                       # second script: merge instead of clobber
            cmd.append("--append")

        if args.verbose:
            print("→", " ".join(cmd))
        subprocess.run(cmd, check=True)

if __name__ == "__main__":
    main()
