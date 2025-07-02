#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from fuzzywuzzy import fuzz  # pip install fuzzywuzzy python-Levenshtein

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ───── CONFIG ─────────────────────────────────────────────────────────
CONTOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/contops.cpp"
)
CATEGORY    = "codepage"
FUZZ_THRESH = 0.70

# Deterministic mappings for SETCP*/SETCPX
RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^SETCP$"),        "exec_set_cp"),
    (re.compile(r"^SETCP_SPECIAL$"),"exec_set_cp"),
    (re.compile(r"^SETCPX$"),       "exec_set_cp_any"),
]

def fetch_cpp(local: str|None) -> str:
    if local:
        return Path(local).read_text(encoding="utf-8")
    logging.info("Downloading contops.cpp from GitHub…")
    resp = requests.get(CONTOPS_URL, timeout=30)
    resp.raise_for_status()
    logging.info("  ✓ %d bytes", len(resp.text))
    return resp.text

def extract_exec_definitions(src: str) -> Dict[str,int]:
    """
    Find every `int|void exec_* ( ... ) {` definition and record its line number.
    """
    pattern = re.compile(
        r'^\s*(?:int|void)\s+'
        r'(exec_[A-Za-z0-9_]+)\s*'  # capture function name
        r'\(.*?\)\s*'               # non-greedy match through signature
        r'\{',                      # opening brace
        re.MULTILINE | re.DOTALL
    )
    lines: Dict[str,int] = {}
    for m in pattern.finditer(src):
        fn = m.group(1)
        lineno = src.count("\n", 0, m.start()) + 1
        lines[fn] = lineno
    logging.info("Found %d exec_* definitions", len(lines))
    return lines

def load_cp0(path: str) -> List[str]:
    data = json.load(open(path, encoding="utf-8"))
    instr = data.get("instructions", data)
    return [
        ins["mnemonic"]
        for ins in instr
        if (ins.get("doc",{}).get("category") or ins.get("category")) == CATEGORY
    ]

def rule_match(mnem: str) -> str|None:
    for rx, fn in RULES:
        if rx.fullmatch(mnem):
            return fn
    return None

def fuzzy_match(mnem: str, funcs: Dict[str,int]) -> Tuple[str|None,float]:
    best_fn, best_score = None, 0.0
    target = mnem.lower()
    for fn in funcs:
        name = fn.removeprefix("exec_").lower()
        score = fuzz.ratio(name, target) / 100.0
        if score > best_score:
            best_fn, best_score = fn, score
    return (best_fn, best_score) if best_score >= FUZZ_THRESH else (None, best_score)

def main() -> None:
    p = argparse.ArgumentParser(description="Match contops codepage mnemonics")
    p.add_argument("--cp0",  default="cp0.json", help="path to cp0.json")
    p.add_argument("--cpp",  help="local contops.cpp (else download)")
    p.add_argument("--out",  default="match-report.json")
    p.add_argument("--append", action="store_true")
    args = p.parse_args()

    # 1) grab C++ and index exec_* definitions
    cpp_src  = fetch_cpp(args.cpp)
    exec_map = extract_exec_definitions(cpp_src)

    # 2) load your cp0.json mnemonics for "codepage"
    mnems    = load_cp0(args.cp0)

    rows:       List[Dict] = []
    unmatched:  List[str]   = []

    # 3) match each mnemonic
    for m in mnems:
        fn = rule_match(m)
        score = 1.0

        # if no hard rule, try fuzzy
        if fn is None:
            fn, score = fuzzy_match(m, exec_map)

        if fn is None:
            unmatched.append(m)
            continue

        rows.append({
            "mnemonic":    m,
            "function":    fn,
            "score":       round(score, 2),
            "category":    CATEGORY,
            "source_path": Path(args.cpp).as_uri() if args.cpp else CONTOPS_URL,
            "source_line": exec_map.get(fn, 0),
        })

    # 4) merge / append into existing report if desired
    out_path = Path(args.out)
    existing = json.load(open(out_path)) if args.append and out_path.exists() else []
    merged = { (r["mnemonic"],r["category"]): r for r in existing }
    for r in rows:
        merged[(r["mnemonic"],r["category"])] = r

    out_list = list(merged.values())
    out_path.write_text(json.dumps(out_list, indent=2), encoding="utf-8")
    logging.info("Wrote %d entries → %s", len(out_list), out_path)

    # 5) summary
    total   = len(mnems)
    matched = len(rows)
    logging.info("\n" + "═"*60)
    logging.info("SUMMARY")
    logging.info("═"*60)
    logging.info(f"• Category       : {CATEGORY}")
    logging.info(f"• cp0.json       : {total} mnemonics")
    logging.info(
        f"• Matched (rule+fuzzy≥{int(FUZZ_THRESH*100)}%) : {matched}/{total} "
        f"({matched/total*100:.1f}%)"
    )
    if unmatched:
        logging.warning("⚠ Unmatched      : %s", ", ".join(unmatched))


if __name__ == "__main__":
    main()
