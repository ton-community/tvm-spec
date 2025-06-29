from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple

import requests


#  ───────────────────────────  Constants & tiny helpers ─────────────────────────── 
ARITHOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/arithops.cpp"
)
CATEGORY = "compare_int"

_BAR = "═" * 65


def fetch(url: str) -> str:
    """Download *url* and return its text."""
    logging.info("↳ fetching %s", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  ✓ %-12s (%d bytes)", Path(url).name, len(r.text))
    return r.text


def exec_lines(code: str) -> Dict[str, int]:
    """
    Return `exec_fn → 1-based line number` for *arithops.cpp*.
    We only need five distinct handlers.
    """
    rx = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
    out: Dict[str, int] = {}
    for m in rx.finditer(code):
        fn = m.group(1)
        out[fn] = code.count("\n", 0, m.start()) + 1
    # Sanity: must have the five handlers we care about
    need = {"exec_cmp", "exec_cmp_int", "exec_sgn", "exec_is_nan", "exec_chk_nan"}
    if not need.issubset(out):
        logging.error("Missing expected exec_* declarations – abort")
        sys.exit(1)
    return out


#  ───────────────────────────  cp0.json helpers ─────────────────────────── 
def load_mnemonics(cp0_path: str | Path) -> List[str]:
    """Return all mnemonics with doc.category == 'compare_int'."""
    with open(cp0_path, encoding="utf-8") as f:
        data = json.load(f)
    instr = data.get("instructions", data)
    return [
        ins["mnemonic"]
        for ins in instr
        if (ins.get("doc", {}).get("category") or ins.get("category")) == CATEGORY
    ]

#  ───────────────────────────  Build rows (deterministic map) ─────────────────────────── 
def build_rows(mnems: List[str], lines: Dict[str, int]) -> List[Dict]:
    """Create the JSON-serialisable rows for the report."""
    # fixed mapping tables
    special = {
        "SGN":     "exec_sgn",
        "ISNAN":   "exec_is_nan",
        "CHKNAN":  "exec_chk_nan",
        "CMP":     "exec_cmp",
    }
    cmp_set      = {"LESS", "EQUAL", "LEQ", "GEQ", "GREATER", "NEQ"}
    cmp_int_set  = {"EQINT", "LESSINT", "GTINT", "NEQINT"}

    rows: List[Dict] = []
    for m in mnems:
        if m in special:
            fn = special[m]
        elif m in cmp_set:
            fn = "exec_cmp"
        elif m in cmp_int_set:
            fn = "exec_cmp_int"
        else:                       # fallback – still deterministic
            fn = "exec_cmp_int"

        rows.append(
            {
                "mnemonic":   m,
                "function":   fn,
                "score":      1.0,
                "category":   CATEGORY,
                "source_path": ARITHOPS_URL,
                "source_line": lines[fn],
            }
        )
    return rows
#  ───────────────────────────  JSON persistence ─────────────────────────── 
def save_json(rows: List[Dict], dest: Path, append: bool) -> None:
    prev = json.load(dest.open()) if append and dest.exists() else []
    key  = lambda r: r["mnemonic"]
    merged = OrderedDict((key(r), r) for r in prev)
    for r in rows:
        merged[key(r)] = r
    json.dump(list(merged.values()), dest.open("w"), indent=2)
    logging.info("✎ report saved → %s  (%d total entries)", dest, len(merged))


# ───────────────────────────   CLI entry-point ─────────────────────────── 
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    # 1. cp0.json -------------------------------------------------------
    mnems = load_mnemonics(args.cp0)
    logging.info("• cp0.json        : %d compare_int mnemonics", len(mnems))

    # 2. arithops.cpp ---------------------------------------------------
    cpp_text = fetch(ARITHOPS_URL)
    line_tbl = exec_lines(cpp_text)

    # 3. build rows -----------------------------------------------------
    rows = build_rows(mnems, line_tbl)
    logging.info("• rows generated  : %d", len(rows))

    # 4. save / merge ---------------------------------------------------
    save_json(rows, Path(args.out), append=args.append)

    # 5. pretty summary -------------------------------------------------
    pct = len(rows) / len(mnems) * 100 if mnems else 100.0
    print(f"\n{_BAR}\n{'SUMMARY':^65}\n{_BAR}")
    print(f"• cp0.json        : {len(mnems)} mnemonics")
    print(f"• Matched         : {len(rows):>3}/{len(mnems)}  ({pct:5.1f} %)")
    if pct < 100.0:
        print("⚠ Something went wrong – not all mnemonics mapped!")
        sys.exit(1)
    else:
        print("✓ All compare_int mnemonics mapped")
    print(_BAR)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    main()
