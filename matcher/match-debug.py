#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import pathlib
import re
import sys
from collections import OrderedDict
from typing import Dict, List, Tuple

import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ──────────────── CONFIG ────────────────────────
DEBUGOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/debugops.cpp"
)
CATEGORY = "debug"
FUZZ_MIN_SCORE = 0.80

# deterministic rules for mnemonics → handler
RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^DEBUG$"),     "exec_dummy_debug"),
    (re.compile(r"^DEBUGSTR$"),  "exec_dummy_debug_str"),
    (re.compile(r"^DUMPSTK$"),   "exec_dump_stack"),
    (re.compile(r"^STRDUMP$"),   "exec_dump_string"),
    (re.compile(r"^DUMP\d$"),   "exec_dump_value"),
]

try:
    from fuzzywuzzy import fuzz
    _have_fuzzy = True
except ImportError:
    _have_fuzzy = False

# ──────────────── UTILITIES ─────────────────────────
def fetch_cpp(local: str | None) -> str:
    if local:
        return pathlib.Path(local).read_text(encoding="utf-8")
    logging.info("Fetching debugops.cpp from GitHub …")
    resp = requests.get(DEBUGOPS_URL, timeout=30)
    resp.raise_for_status()
    logging.info("  OK  (%d bytes)", len(resp.text))
    return resp.text


def extract_exec_positions(src: str) -> Dict[str,int]:
    """
    Locate each exec_* definition (opening brace) and record its line number (+2 offset).
    """
    pattern = re.compile(
        r'^\s*(?:int|void)\s+'      # return type
        r'(exec_[A-Za-z0-9_]+)\s*'    # function name
        r'\(.*?\)\s*'               # signature
        r'\{',                        # brace
        re.MULTILINE | re.DOTALL
    )
    out: Dict[str,int] = {}
    for m in pattern.finditer(src):
        fn = m.group(1)
        ln = src.count("\n", 0, m.start()) + 2
        out[fn] = ln
    logging.info("Found %d exec_* definitions", len(out))
    return out


def load_debug_mnems(path: str) -> List[str]:
    data = json.load(open(path, encoding="utf-8"))
    instr = data.get("instructions", data)
    return [
        e["mnemonic"]
        for e in instr
        if (e.get("doc", {}).get("category") or e.get("category")) == CATEGORY
    ]


def rule_match(mnem: str) -> str | None:
    for rx, fn in RULES:
        if rx.match(mnem):
            return fn
    return None


def fuzzy_match(mnem: str, funcs: Dict[str,int]) -> Tuple[str|None, float]:
    if not _have_fuzzy:
        return None, 0.0
    best_fn, best_score = None, 0.0
    for fn in funcs:
        s = fuzz.ratio(fn.replace("exec_", ""), mnem.lower()) / 100.0
        if s > best_score:
            best_fn, best_score = fn, s
    return (best_fn, best_score) if best_score >= FUZZ_MIN_SCORE else (None, best_score)


def main() -> None:
    p = argparse.ArgumentParser(description="Match debugops mnemonics to exec_* handlers.")
    p.add_argument("--cp0", default="cp0_legacy.json", help="path to legacy cp0.json")
    p.add_argument("--cpp", help="local debugops.cpp (else fetch)")
    p.add_argument("--out", default="match-report.json", help="output JSON file")
    p.add_argument("--append", action="store_true", help="merge into existing report")
    p.add_argument("--show-missing", action="store_true", help="exit non-zero if missing")
    args = p.parse_args()

    src = fetch_cpp(args.cpp)
    exec_pos = extract_exec_positions(src)
    mnems = load_debug_mnems(args.cp0)

    rows, missing, fuzzy_used = [], [], []
    for m in mnems:
        fn = rule_match(m)
        score = 1.0
        if fn is None:
            fn, score = fuzzy_match(m, exec_pos)
            if fn:
                fuzzy_used.append(m)
        if fn is None:
            missing.append(m)
            continue

        rows.append({
            "mnemonic":    m,
            "function":    fn,
            "score":       round(score, 2),
            "category":    CATEGORY,
            "source_path": DEBUGOPS_URL if args.cpp is None else pathlib.Path(args.cpp).as_uri(),
            "source_line": exec_pos.get(fn, 0)
        })

    logging.info("Matched %d/%d mnemonics", len(rows), len(mnems))
    if missing:
        logging.warning("⚠ Unmatched: %s", ", ".join(missing))
    logging.info("Fuzzy used: %d", len(fuzzy_used))

    # merge with existing
    out_p = pathlib.Path(args.out)
    merged: "OrderedDict[Tuple[str,str],dict]" = OrderedDict()
    if args.append and out_p.exists():
        old = json.load(open(out_p, encoding="utf-8"))
        for r in old:
            key = (r["mnemonic"], r.get("category", ""))
            merged[key] = r

    for r in rows:
        merged[(r["mnemonic"], r.get("category", ""))] = r

    out_p.write_text(json.dumps(list(merged.values()), indent=2), encoding="utf-8")
    logging.info("Wrote %d entries → %s", len(merged), out_p)

    # summary print
    print("\n" + "═"*60)
    print("DEBUG MATCH SUMMARY")
    print("═"*60)
    print(f"• Category      : {CATEGORY}")
    print(f"• cp0.json      : {len(mnems)} mnemonics")
    print(f"• Matched       : {len(rows)}/{len(mnems)}")
    print(f"• Unmatched     : {len(missing)}")
    print("═"*60)

    if args.show_missing and missing:
        sys.exit(1)

if __name__ == "__main__":
    main()
