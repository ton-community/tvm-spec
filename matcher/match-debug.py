#!/usr/bin/env python3
"""
Match DEBUG-family mnemonics from cp0.json to exec_* handlers.

usage:
  python matcher/match-debug.py --cp0 cp0.json
         [--cpp debugops.cpp] [--out match_debug.json] [--append]

Notes
─────
*   Only cp0-instructions whose `category` is exactly **"debug"** are processed.
*   The script prints
      • how many “debug” instructions exist in cp0.json  
      • how many were successfully written to <out>.  
    If some remain unmatched, their mnemonics are listed as warnings.
"""

from __future__ import annotations
import argparse, json, logging, pathlib, re, requests
from collections import OrderedDict
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ───── configurable locations ────────────────────────────────────────────
DEBUGOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/debugops.cpp"
)

CATEGORY = "debug"            # the **only** category we touch
FUZZ_MIN_SCORE = .80          # threshold for optional fuzzy fallback

try:
    from fuzzywuzzy import fuzz
    _have_fuzzy = True
except ImportError:
    _have_fuzzy = False

# ───── deterministic rules (regex → (handler, score=1.0)) ───────────────
RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^DEBUG$")          , "exec_debug"),          # sample names –
    (re.compile(r"^DEBUGSTRI?$")     , "exec_debug_str"),      # adjust to real
    (re.compile(r"^DUMPSTK$")        , "exec_dump_stack"),     # names in your
    (re.compile(r"^STRDUMP$")        , "exec_dump_string"),    # debugops.cpp
    (re.compile(r"^DUMP\d$")         , "exec_dump_value"),
]

EXEC_RX = re.compile(r"(?:int|void)\s+(exec_[A-Za-z0-9_]+)\s*\(")

# ───── helpers ───────────────────────────────────────────────────────────
def fetch_cpp(local: str | None) -> str:
    if local:
        return pathlib.Path(local).read_text(encoding="utf-8")
    logging.info("Downloading debugops.cpp …")
    r = requests.get(DEBUGOPS_URL, timeout=30); r.raise_for_status()
    logging.info("  OK  (%d bytes)", len(r.text))
    return r.text

def exec_positions(src: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for m in EXEC_RX.finditer(src):
        fn = m.group(1)
        out[fn] = src.count("\n", 0, m.start()) + 1
    logging.info("Found %d exec_* handlers", len(out))
    return out

def load_debug_mnems(cp0: str) -> List[str]:
    data = json.load(open(cp0, encoding="utf-8"))
    entries = data["instructions"] if "instructions" in data else data
    return [e["mnemonic"] for e in entries
            if (e.get("doc", {}).get("category") or e.get("category")) == CATEGORY]

def rule_match(mnem: str) -> str | None:
    for rx, fn in RULES:
        if rx.match(mnem):
            return fn
    return None

def fuzzy_match(mnem: str, funcs: Dict[str, int]) -> Tuple[str | None, float]:
    if not _have_fuzzy:
        return None, 0.0
    best, score = None, 0.0
    for fn in funcs:
        s = fuzz.ratio(fn.replace("exec_", ""), mnem.lower()) / 100.0
        if s > score:
            best, score = fn, s
    return (best, score) if score >= FUZZ_MIN_SCORE else (None, score)

# ───── main ──────────────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--cp0", default="cp0.json",
               help="cp0.json path")
    p.add_argument("--cpp", help="local debugops.cpp (else remote)")
    p.add_argument("--out", default="match-report.json")
    p.add_argument("--append", action="store_true")
    args = p.parse_args()

    cpp_src  = fetch_cpp(args.cpp)
    exec_pos = exec_positions(cpp_src)
    mnems    = load_debug_mnems(args.cp0)
    total_cp0 = len(mnems)

    rows, missed, fuzzy = [], [], []
    for m in mnems:
        fn = rule_match(m)
        score = 1.0
        if fn is None:                       # fuzzy fallback
            fn, score = fuzzy_match(m, exec_pos)
            if fn: fuzzy.append(m)
        if fn is None:
            missed.append(m); continue

        rows.append(dict(
            mnemonic    = m,
            function    = fn,
            score       = round(score, 2),
            category    = CATEGORY,
            source_path = DEBUGOPS_URL if args.cpp is None
                           else pathlib.Path(args.cpp).as_uri(),
            source_line = exec_pos.get(fn, 0)
        ))

    matched_cnt = len(rows)
    logging.info("DEBUG mnemonics in cp0.json: %d", total_cp0)
    logging.info("Successfully matched        : %d", matched_cnt)

    if missed:
        logging.warning("Unmatched: %s", ", ".join(missed))
    logging.info("Fuzzy matches used: %d", len(fuzzy))

    # save / merge
    out_p = pathlib.Path(args.out)
    prev = json.load(open(out_p)) if args.append and out_p.exists() else []
    merged = OrderedDict(((r["mnemonic"], r["category"]), r) for r in prev)
    for r in rows:
        merged[(r["mnemonic"], r["category"])] = r
    out_p.write_text(json.dumps(list(merged.values()), indent=2), encoding="utf-8")
    logging.info("Wrote %d new rows → %s", matched_cnt, out_p)


    # summary
    print("\n" + "═" * 66)
    print("                             SUMMARY")
    print("═" * 66)
    print(f"• Categories      : {CATEGORY}")
    print(f"• cp0.json        : {total_cp0} mnemonics")
    print(f"• Matched (≥ {FUZZ_MIN_SCORE:.2f})   : {matched_cnt}/{total_cp0}  ({(matched_cnt/total_cp0)*100:.1f} %)")
    print(f"• Unmatched       : {len(missed)}")
    print("═" * 66)

if __name__ == "__main__":
    main()
