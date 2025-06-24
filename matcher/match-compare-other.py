#!/usr/bin/env python3
"""
Collect `compare_other` mnemonics from cp0.json,
match them to reg_*_cs_cmp handlers in cellops.cpp,
and store everything in match_report.json (append-safe).

Usage examples
--------------

# first run – create a new file
python match-compare_other.py --out match_report.json

# subsequent runs – ADD to the same file
python match-compare_other.py --out match_report.json --append
"""
from __future__ import annotations

import argparse
import json
import re
import requests
from pathlib import Path
from collections import OrderedDict
from typing import Dict, List, Tuple

CELL_OPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/cellops.cpp"
)
CATEGORY = "compare_other"

REGISTER_REGEX = re.compile(
    r'(reg_\w+_cs_cmp)\(\s*cp0\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*\d+\s*,\s*"([^"]+)"\s*,'
)

# ──────────────────────────────────────────────────────────────────────────────
def fetch_cellops() -> List[str]:
    print("📥  Downloading cellops.cpp …")
    res = requests.get(CELL_OPS_URL, timeout=30)
    res.raise_for_status()
    return res.text.splitlines()


def load_compare_other_mnemonics(cp0_path: str) -> List[str]:
    data = json.load(open(cp0_path, encoding="utf-8"))
    instr = data["instructions"] if "instructions" in data else data
    return [
        i["mnemonic"]
        for i in instr
        if (i.get("doc", {}).get("category") or i.get("category")) == CATEGORY
    ]


def parse_matches(lines: List[str], wanted: List[str]) -> List[Dict]:
    matches: List[Dict] = []
    for lineno, line in enumerate(lines, 1):
        m = REGISTER_REGEX.search(line)
        if m:
            func, opcode, mnemonic = m.groups()
            if mnemonic in wanted:
                matches.append(
                    {
                        "mnemonic": mnemonic,
                        "function": func,
                        "category": CATEGORY,
                        "score": 1.0,
                        "source_path": CELL_OPS_URL,
                        "source_line": lineno,
                    }
                )
    return matches


# ──────────────────────────────────────────────────────────────────────────────
# JSON persistence (append-safe, keyed by (mnemonic, category))
# ──────────────────────────────────────────────────────────────────────────────
def _save_json(rows: List[Dict], out_path: Path, append: bool) -> None:
    prev: List[Dict] = json.load(open(out_path)) if append and out_path.exists() else []
    key = lambda r: (r["mnemonic"], r.get("category", ""))
    ordered: "OrderedDict[Tuple[str, str], Dict]" = OrderedDict((key(r), r) for r in prev)

    for r in rows:
        ordered[key(r)] = {**ordered.get(key(r), {}), **r}

    json.dump(list(ordered.values()), open(out_path, "w"), indent=2)
    print(f"✅  Saved {len(rows)} new rows   ➜  {out_path}  (total {len(ordered)})")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json", help="Path to cp0.json")
    ap.add_argument("--out", default="match_report.json", help="Output JSON file")
    ap.add_argument("--append", action="store_true", help="Merge with existing file")
    args = ap.parse_args()

    wanted = load_compare_other_mnemonics(args.cp0)
    lines = fetch_cellops()
    matches = parse_matches(lines, wanted)
    _save_json(matches, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
