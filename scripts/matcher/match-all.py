from __future__ import annotations
import argparse, subprocess, sys, pathlib, re, requests

SCRIPTS = (
    "match-stack",
    "match-tuple",
    "match-contops",
    "match-compare",
    "match-compare-other",
    "match-arithops",
    "match-cell",
    "match-apps",
    "match-codepage",
    "match-debug",
    "match-dict",
    "match-exceptions",
)

_GITHUB_COMMITS_API = "https://api.github.com/repos/ton-blockchain/ton/commits/"
_HEX40_RX = re.compile(r"^[0-9a-fA-F]{40}$")


def _resolve_rev(rev: str) -> str:
    """
    Return a commit SHA for a ref or SHA.
    If `rev` is already SHA, return as-is. Otherwise query GitHub and resolve ref to SHA
    """
    if _HEX40_RX.fullmatch(rev):
        return rev.lower()
    url = _GITHUB_COMMITS_API + rev
    print(f"→ Resolving rev '{rev}' via {url}")
    try:
        resp = requests.get(url, timeout=5, headers={'Accept': 'application/vnd.github.sha'})
        resp.raise_for_status()
        sha = resp.text
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
    ap.add_argument("--rev", default="master",
                    help="ton-blockchain/ton revision (commit/tag) to use for source code parsing")
    args = ap.parse_args()

    resolved_rev = _resolve_rev(args.rev)

    for idx, script in enumerate(SCRIPTS):
        cmd = [
            sys.executable,
            "-m",
            f"matcher.{script}",
            "--cp0", args.cp0,
            "--out", args.out,
            "--rev", resolved_rev,
        ]
        if idx:  # second script: merge instead of clobber
            cmd.append("--append")

        if args.verbose:
            print("→", " ".join(cmd))
        subprocess.run(cmd, check=True)


if __name__ == "__main__":
    main()
