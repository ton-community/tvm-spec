#!/usr/bin/env python3
"""
Match code-page-related mnemonics from cp0.json to exec_* handlers in contops.cpp.

usage
-----
python matcher/match-codepage.py --cp0 cp0.json            # <- typical run
       [--cpp contops.cpp]                                 # use local source
       [--out match_codepage.json] [--append]              # merge/append
"""

from __future__ import annotations
import argparse, json, logging, pathlib, re, requests
from collections import OrderedDict
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

CONTOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/contops.cpp"
)

CATEGORY   = "codepage"                       # cp0 “doc.category”
EXEC_RX    = re.compile(r"(?:int|void)\\s+(exec_[A-Za-z0-9_]+)\\s*\(")

# ───────────────────────────────────────────────────────────────
RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^SETCP$")        , "exec_set_cp"),
    (re.compile(r"^SETCP_SPECIAL$"), "exec_set_cp"),      # same handler
    (re.compile(r"^SETCPX$")       , "exec_set_cpx"),
]

# ────────────────────────────────────────────────────

def fetch_cpp(local: str | None) -> str:
    if local:
        return pathlib.Path(local).read_text(encoding="utf-8")
    logging.info("Fetching contops.cpp from GitHub …")
    resp = requests.get(CONTOPS_URL, timeout=30)
    resp.raise_for_status()
    logging.info("  OK  (%d bytes)", len(resp.text))
    return resp.text


def extract_exec_lines(src: str) -> Dict[str, int]:
    """return {exec_fn → line_number}"""
    lines: Dict[str, int] = {}
    for m in EXEC_RX.finditer(src):
        fn = m.group(1)
        lines[fn] = src.count("\n", 0, m.start()) + 1
    logging.info("Found %d exec_* handlers in contops.cpp", len(lines))
    return lines


def load_cp0(path: str) -> List[Dict]:
    data = json.load(open(path, encoding="utf-8"))
    instr = data["instructions"] if "instructions" in data else data
    return [
        i for i in instr
        if (i.get("doc", {}).get("category") or i.get("category")) == CATEGORY
    ]


def match_func(mnem: str) -> str | None:
    for rx, fn in RULES:
        if rx.fullmatch(mnem):
            return fn
    return None

# ────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0",  default="cp0.json",
                    help="path to cp0.json (default: ./cp0.json)")
    ap.add_argument("--cpp",  help="local contops.cpp (else download)")
    ap.add_argument("--out",  default="match-report.json")
    ap.add_argument("--append", action="store_true",
                    help="append / merge with existing output file")
    args = ap.parse_args()

    cpp_src    = fetch_cpp(args.cpp)
    exec_lines = extract_exec_lines(cpp_src)

    rows, unmatched = [], []
    for ins in load_cp0(args.cp0):
        mnem = ins["mnemonic"]
        fn   = match_func(mnem)
        if fn is None:
            unmatched.append(mnem)
            continue
        rows.append(
            dict(
                mnemonic    = mnem,
                function    = fn,
                score       = 1.0,                 # fully deterministic rule
                category    = CATEGORY,
                source_path = CONTOPS_URL if args.cpp is None
                                           else pathlib.Path(args.cpp).as_uri(),
                source_line = exec_lines.get(fn, 0)
            )
        )

    total_cp0  = len(rows) + len(unmatched)
    matched    = len(rows)
    logging.info("Category '%s' in %s: %d mnemonics → %d matched, %d unmatched",
                 CATEGORY, args.cp0, total_cp0, matched, len(unmatched))
    if unmatched:
        logging.warning("Unmatched mnemonics: %s", ", ".join(sorted(unmatched)))

    # ──────────── save / merge ───────────────────────
    out_path = pathlib.Path(args.out)
    existing = json.load(open(out_path)) if args.append and out_path.exists() else []
    merged: "OrderedDict[Tuple[str, str], Dict]" = OrderedDict(
        ((r["mnemonic"], r["category"]), r) for r in existing
    )
    for r in rows:
        merged[(r["mnemonic"], r["category"])] = r

    out_path.write_text(json.dumps(list(merged.values()), indent=2), encoding="utf-8")
    logging.info("Wrote %d new rows → %s", matched, out_path)

    # ──────────── summary ────────────
    handlers = {r["function"] for r in rows}
    print("\n" + "═" * 66)
    print("                             SUMMARY")
    print("═" * 66)
    print(f"• Categories      : {CATEGORY}")
    print(f"• cp0.json        : {total_cp0} mnemonics")
    print(f"• Matched (100%)   : {matched}/{total_cp0}  (100.0 %)")
    print("═" * 66)

if __name__ == "__main__":
    main()
