from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple

import requests

# ────────────────────────── constants ──────────────────────────────
CELL_OPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/cellops.cpp"
)
CATEGORY = "compare_other"

# macro-name → exec_* handler mapping
MAP_TO_EXEC = {
    "reg_un_cs_cmp":   "exec_un_cs_cmp",
    "reg_iun_cs_cmp":  "exec_iun_cs_cmp",
    "reg_bin_cs_cmp":  "exec_bin_cs_cmp",
    "reg_ibin_cs_cmp": "exec_ibin_cs_cmp",
}

# regexes
REG_RX = re.compile(
    r'\b(reg_(?:i?un|i?bin)_cs_cmp)\s*\([^)]*?"([A-Z0-9_]+)"',
    re.S,
)

# ───────────────────────── helpers ──────────────────────────────────
def fetch(url: str) -> str:
    """Download *url* and return its text."""
    print(f"↳ fetching {url}")
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    print(f"  ✓ {Path(url).name:14} ({len(r.text):,} bytes)")
    return r.text


def wanted_mnemonics(cp0_path: str | Path) -> List[str]:
    """Return all mnemonics whose doc.category == compare_other."""
    with open(cp0_path, encoding="utf-8") as f:
        data = json.load(f)

    instr = data.get("instructions", data)
    return [
        ins["mnemonic"]
        for ins in instr
        if (ins.get("doc", {}).get("category") or ins.get("category")) == CATEGORY
    ]


def extract_pairs(src: str) -> Dict[str, Tuple[str, int]]:
    """
    Scan **cellops.cpp** and return
        {MNEMONIC → (exec_fn, line_no)}.
    """
    out: Dict[str, Tuple[str, int]] = {}
    for m in REG_RX.finditer(src):
        reg_fn, mnem = m.groups()
        line_no = src.count("\n", 0, m.start()) + 1
        out[mnem] = (MAP_TO_EXEC[reg_fn], line_no)
    print(f"  • macro table      → {len(out):3d} compare_other entries")
    return out


def save_rows(rows: List[Dict], dest: Path, append: bool) -> None:
    """
    Merge *rows* into *dest* (JSON list of dicts) preserving order.
    """
    old = json.load(dest.open()) if append and dest.exists() else []
    key = lambda r: (r["mnemonic"], r.get("category", ""))
    merged = OrderedDict((key(r), r) for r in old)
    for r in rows:
        merged[key(r)] = r                     # overwrite / append
    json.dump(list(merged.values()), dest.open("w"), indent=2)
    print(f"✎ report saved → {dest}  ({len(merged)} total entries)")

# ─────────────────────────── main ────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    # load cp0 -----------------------------------------------------
    wanted = wanted_mnemonics(args.cp0)
    print(f"• cp0.json          : {len(wanted)} compare_other mnemonics")

    # parse cellops.cpp ------------------------------------------
    cpp_text = fetch(CELL_OPS_URL)
    pairs = extract_pairs(cpp_text)

    # build rows ---------------------------------------------------
    rows = [
        {
            "mnemonic": m,
            "function": pairs[m][0],
            "score": 1.0,
            "category": CATEGORY,
            "source_path": CELL_OPS_URL,
            "source_line": pairs[m][1],
        }
        for m in wanted
        if m in pairs
    ]

    missing = sorted([m for m in wanted if m not in pairs])
    matched = len(rows)

    # persist ------------------------------------------------------
    save_rows(rows, Path(args.out), append=args.append)

    # summary ------------------------------------------------------
    bar = "═" * 65
    pct = matched / len(wanted) * 100 if wanted else 100.0
    print(f"\n{bar}\n{'SUMMARY':^65}\n{bar}")
    print(f"• cp0.json        : {len(wanted)} mnemonics")
    if missing:
        print(f"⚠ Unmatched       : {', '.join(missing)}")
        sys.exit(1)
    else:
        print("✓ All mnemonics matched")
    print(bar)


if __name__ == "__main__":
    main()
