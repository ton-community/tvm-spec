#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
import pathlib
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests

# ────────────────────────── constants ──────────────────────────────
CATEGORY     = "compare_other"

# macro-name → exec_* handler mapping
MAP_TO_EXEC = {
    "reg_un_cs_cmp":   "exec_un_cs_cmp",
    "reg_iun_cs_cmp":  "exec_iun_cs_cmp",
    "reg_bin_cs_cmp":  "exec_bin_cs_cmp",
    "reg_ibin_cs_cmp": "exec_ibin_cs_cmp",
}

# regex to pull out registrations like
#    reg_un_cs_cmp(cp0, 0xc700, 16, "SEMPTY", [](auto cs) { … });
REG_RX = re.compile(
    r'\b(reg_(?:i?un|i?bin)_cs_cmp)\s*\([^)]*?"([A-Z0-9_]+)"',
    re.S,
)

def load_src(local: str | None, url: str) -> Tuple[str, str]:
    """
    Returns (text, source_path). If `local` is set, read that file;
    otherwise fetch from GitHub.
    """
    if local:
        p = pathlib.Path(local)
        txt = p.read_text(encoding="utf-8")
        print(f"↳ loaded local {p.as_posix()} ({len(txt):,} bytes)")
        return txt, p.as_uri()
    else:
        print(f"↳ fetching {url}")
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        txt = r.text
        print(f"  ✓ downloaded remote ({len(txt):,} bytes)")
        return txt, url

def wanted_mnemonics(cp0_path: Path) -> List[str]:
    """Return all mnemonics in cp0_legacy.json with doc.category == compare_other."""
    data = json.load(cp0_path.open(encoding="utf-8"))
    instr = data.get("instructions", data)
    return [
        ins["mnemonic"]
        for ins in instr
        if (ins.get("doc", {}).get("category") or ins.get("category")) == CATEGORY
    ]

def extract_pairs(src: str) -> Dict[str, Tuple[str, int]]:
    """
    Scan cellops.cpp registrations and return {MNEMONIC → (exec_fn, macro_line)}.
    """
    out: Dict[str, Tuple[str, int]] = {}
    for m in REG_RX.finditer(src):
        reg_fn, mnem = m.group(1), m.group(2)
        line_no = src.count("\n", 0, m.start()) + 1
        out[mnem] = (MAP_TO_EXEC[reg_fn], line_no)
    print(f"  • macro table      → {len(out):3d} compare_other entries")
    return out

def extract_definitions(src: str) -> Dict[str, int]:
    """
    Find every exec_* definition and return {exec_fn → definition_line}.
    This regex now uses DOTALL + non-greedy to skip over inner “)” in templates.
    """
    out: Dict[str, int] = {}
    pattern = re.compile(
        r'^\s*(?:int|void)\s+'        # return type + whitespace
        r'(exec_[A-Za-z0-9_]+)\s*'     # capture the function name
        r'\(.*?\)\s*'                  # non-greedy everything up to the closing ')'
        r'\{',                         # the opening brace of the body
        re.MULTILINE | re.DOTALL
    )
    for m in pattern.finditer(src):
        fn = m.group(1)
        line_no = src.count("\n", 0, m.start()) + 2
        out[fn] = line_no
    print(f"  • definitions      → {len(out):3d} exec_* handlers")
    return out

def save_rows(rows: List[Dict[str,Any]], dest: Path, append: bool) -> None:
    """
    Merge *rows* into *dest* (JSON list of dicts), preserving existing entries.
    """
    existing = json.load(dest.open(encoding="utf-8")) if append and dest.exists() else []
    merged: "OrderedDict[Tuple[str,str],Dict]" = OrderedDict(
        ((r["mnemonic"], r.get("category","")), r) for r in existing
    )
    for r in rows:
        merged[(r["mnemonic"], r["category"])] = r
    dest.write_text(json.dumps(list(merged.values()), indent=2), encoding="utf-8")
    print(f"✎ report saved → {dest}  ({len(merged)} total entries)")

def main() -> None:
    p = argparse.ArgumentParser(description="Match compare_other mnemonics → exec_*")
    p.add_argument("--cp0",    default="cp0_legacy.json", help="path to legacy cp0.json")
    p.add_argument("--cpp",    help="local cellops.cpp (else fetch remote)")
    p.add_argument("--out",    default="match-report.json")
    p.add_argument("--append", action="store_true")
    p.add_argument("--rev", default="cee4c674ea999fecc072968677a34a7545ac9c4d",
                   help="TON repo revision (commit/tag) to fetch sources from")
    args = p.parse_args()

    # 1) load cp0
    wanted = wanted_mnemonics(Path(args.cp0))
    print(f"• cp0_legacy.json          : {len(wanted)} compare_other mnemonics")

    # 2) load & scan cellops.cpp (local or remote)
    src, source_path = load_src(args.cpp, f"https://raw.githubusercontent.com/ton-blockchain/ton/{args.rev}/crypto/vm/cellops.cpp")
    pairs = extract_pairs(src)
    defs  = extract_definitions(src)

    # 3) build rows, preferring definition line over macro line
    rows: List[Dict[str,Any]] = []
    missing: List[str]     = []
    for m in wanted:
        if m not in pairs:
            missing.append(m)
            continue
        fn, macro_line = pairs[m]
        def_line      = defs.get(fn, macro_line)
        rows.append({
            "mnemonic":    m,
            "function":    fn,
            "score":       1.0,
            "category":    CATEGORY,
            "source_path": source_path,
            "source_line": def_line,
        })

    # 4) report any unmatched → exit nonzero
    if missing:
        print("⚠ Unmatched mnemonics:", ", ".join(missing))
        sys.exit(1)

    # 5) write out JSON
    save_rows(rows, Path(args.out), append=args.append)

    # 6) summary
    bar = "═" * 65
    print(f"\n{bar}\n{'SUMMARY':^65}\n{bar}")
    print(f"• cp0_legacy.json        : {len(wanted)} mnemonics")
    print(f"✓ All mnemonics matched")
    print(bar)

if __name__ == "__main__":
    main()
