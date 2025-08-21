from __future__ import annotations
import argparse, subprocess, sys, pathlib

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

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json", help="cp0 JSON to feed both matchers")
    ap.add_argument("--out", default="match_report.json",
                    help="output JSON (both scripts write here)")
    ap.add_argument("-v", "--verbose", action="store_true", help="echo the commands")
    args = ap.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent

    for idx, script in enumerate(SCRIPTS):
        script_path = str(script_dir / script)
        cmd = [
            sys.executable,
            script_path,
            "--cp0", args.cp0,
            "--out", args.out,
        ]
        if idx:                       # second script: merge instead of clobber
            cmd.append("--append")

        if args.verbose:
            print("→", " ".join(cmd))
        subprocess.run(cmd, check=True)

if __name__ == "__main__":
    main()
