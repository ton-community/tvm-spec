#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Match arithmetic mnemonics from cp0.json to exec_* handlers in arithops.cpp.

Usage examples
--------------
python3 match.py --cp0 cp0.json               # writes match.json
python3 match.py --cp0 cp0.json --out out.json
python3 match.py --append                     # keep previous rows

Exit status is non-zero if --fail-on-missing is given and any mnemonics
remain unmatched.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import defaultdict, OrderedDict
from pathlib import Path
from typing import Dict, Tuple

import requests
from fuzzywuzzy import fuzz          # pip install "fuzzywuzzy[speedup]"

# ─────────────────────────── configuration ────────────────────────────
ARITHOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/arithops.cpp"
)
CATEGORIES = {
    "const_int",
    "arithm_basic",
    "arithm_div",
    "arithm_logical",
    "arithm_quiet",
}

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


# ──────────────────────────── helpers ─────────────────────────────────
def _download(url: str) -> str:
    logging.info("↳ fetching %s", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  ✓ %s (%d bytes)", Path(url).name, len(r.text))
    return r.text


EXEC_RX  = re.compile(
    r"(?:template<[^>]+>\s*)?(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M
)
MACRO_RX = re.compile(r'"([A-Z0-9_\- ]+)"[^\)]*?(exec_\w+)', re.S)


def _extract_exec(src: str, path: str) -> Dict[str, Tuple[str, int]]:
    """Return dict: exec_fn → (src_path, 1-based line)."""
    out: Dict[str, Tuple[str, int]] = {}
    for m in EXEC_RX.finditer(src):
        fn = m.group(1)
        out[fn] = (path, src.count("\n", 0, m.start()) + 1)
    logging.info("    • %-20s → %3d exec_* handlers",
                 Path(path).name, len(out))
    return out


def _extract_pairs(src: str) -> Dict[str, str]:
    """Return dict: mnemonic → exec_fn from OpcodeInstr macro table."""
    pairs: Dict[str, str] = {}
    for mnem, fn in MACRO_RX.findall(src):
        pairs.setdefault(mnem.strip(), fn)
    logging.info("    • explicit pairs from OpcodeInstr: %d", len(pairs))
    return pairs


# ─────────────—— canonicalisation & similarity helpers —─────────────
_VAR_RX = re.compile(r"_?VAR$", re.I)


def _canon(text: str, *, is_fn: bool = False) -> str:
    text = text.removeprefix("exec_") if is_fn else text
    text = _VAR_RX.sub("", text).replace("_", "")
    return text.upper()


def _split(text: str, *, is_fn: bool = False) -> Tuple[str, str]:
    if is_fn:
        text = text.removeprefix("exec_")
    text = _VAR_RX.sub("", text)
    digits  = "".join(re.findall(r"\d+", text))
    letters = re.sub(r"[^a-z]", "", text.lower())
    return digits, letters


# ─────────── fixed similarity helper ───────────
def _similarity(mnem: str, fn: str) -> float:
    """
    Heuristic similarity score in [0,1].

    • Exact or substring matches → 0.95
    • Otherwise Levenshtein / token-set ratio on letters
      with a small bonus when embedded decimal parts match.
    """
    m_can, f_can = _canon(mnem), _canon(fn, is_fn=True)
    if m_can in f_can or f_can in m_can:
        return 0.95

    md, ml = _split(mnem)              # digits, letters
    fd, fl = _split(fn, is_fn=True)

    # mismatching numeric tags (e.g. 4 vs 8) → impossible
    if md and fd and md != fd:
        return 0.0

    base = max(fuzz.ratio(ml, fl),
               fuzz.token_set_ratio(ml, fl)) / 100.0
    if md and fd and md == fd:
        base += 0.05                   # bonus when numbers line up
    return min(base, 0.95)             # cap so overrides hit 1.0


# ─────────── definitive override table ───────────
_divmod_re  = re.compile(r"^Q?(DIV|MOD)(C|R)?$", re.I)
_pushint_re = re.compile(r"^PUSHINT_(\d+|LONG)$", re.I)

def _override(mnem: str) -> str | None:
    """Return the exact exec_* handler for tricky opcode families."""
    up = mnem.upper()

    # 1) ADDDIVMOD ±(R|C) → exec_divmod
    if up.startswith('ADDDIVMOD'):
        return "exec_divmod"

    # 2) plain DIV / MOD (+ Q,R,C) → exec_divmod
    if _divmod_re.match(up):
        return "exec_divmod"

    # 3) right-shift / addr-shift with remainder or rounding
    if ('ADDRSHIFT' in up) or up.startswith(('RSHIFTMOD', 'RSHIFTRMOD',
                                             'RSHIFTCMOD', 'MODPOW2')):
        return "exec_shrmod"
    if up.startswith('RSHIFT') and up not in ('RSHIFT', 'RSHIFT_VAR'):
        return "exec_shrmod"

    # 4) LSHIFT…DIV/MOD (const & _VAR) → exec_shldivmod
    if up.startswith('LSHIFT') and ('DIV' in up or 'MOD' in up):
        return "exec_shldivmod"

    # 5) MUL… + (RSHIFT | POW2 | ADDRSHIFT) → exec_mulshrmod
    if up.startswith('MUL') and (
        'RSHIFT' in up or 'POW2' in up or 'ADDRSHIFT' in up):
        return "exec_mulshrmod"

    # 6) MUL…DIV/MOD (+ ADD, R, C) → exec_muldivmod
    if up.startswith('MUL') and ('DIV' in up or 'MOD' in up):
        return "exec_muldivmod"

    # 7) PUSHINT_* literals
    m = _pushint_re.match(up)
    if m:
        tag = m.group(1)
        return {
            "4":   "exec_push_tinyint4",
            "8":   "exec_push_tinyint8",
            "16":  "exec_push_smallint",
            "LONG": "exec_push_int",
        }[tag]

    # 8) one-offs
    one_offs = {
        "PUSHPOW2DEC": "exec_push_pow2dec",
        "PUSHNEGPOW2": "exec_push_negpow2",
        "ADDCONST":    "exec_add_tinyint8",
        "MULCONST":    "exec_mul_tinyint8",
    }
    if up in one_offs:
        return one_offs[up]

    # 9) ── generic fallback for quiet opcodes (prefix “Q”) ──  ← NEW
    if up.startswith('Q') and len(up) > 1:                       # NEW
        return _override(up[1:])      # strip the Q and reuse rule  # NEW

    # nothing matched
    return None

# ───────────────────────────── cp0 helpers ────────────────────────────
def _load_cp0(path: str | Path) -> Dict[str, str]:
    """Return dict: mnemonic → category (only arithmetic categories)."""
    data = json.load(open(path, encoding="utf-8"))
    return {
        ins["mnemonic"]:
            (ins.get("doc", {}) or {}).get("category",
                                           ins.get("category", ""))
        for ins in data.get("instructions", data)
        if ((ins.get("doc", {}) or {}).get("category",
                                           ins.get("category", "")) in CATEGORIES)
    }


# ─────────────────────────────── CLI flow ─────────────────────────────
def _print_summary(total: int, funcs: dict[str, Tuple[str, int]],
                   per_file: dict[str, int], matched: int,
                   unmatched: list[str]) -> None:
    w = max(len(n) for n in per_file) if per_file else 0
    border = "═" * 66
    print(border, "SUMMARY".center(66), border, sep="\n")
    print(f"• cp0.json mnemonics : {total}")
    print(f"• exec_* handlers    : {len(funcs)} across {len(per_file)} file(s)")
    for f, n in per_file.items():
        print(f"   – {f.ljust(w)} : {n:3}")
    pct = matched / total * 100 if total else 0
    print(f"• Matched (≥ thr)    : {matched}/{total}  ({pct:5.1f} %)")
    if unmatched:
        print(f"⚠ Unmatched          : {len(unmatched)} → {', '.join(unmatched)}")
    print(border)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0",    default="cp0.json")
    ap.add_argument("--thr",    type=float, default=0.70)
    ap.add_argument("--out",    default="match-report.json")
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--fail-on-missing", action="store_true")
    args = ap.parse_args()

    # 1 load mnemonics -------------------------------------------------
    mnems = _load_cp0(args.cp0)
    logging.info("• arithmetic mnemonics in cp0.json: %d", len(mnems))

    # 2 parse arithops.cpp --------------------------------------------
    src   = _download(ARITHOPS_URL)
    funcs = _extract_exec(src, ARITHOPS_URL)
    pairs = _extract_pairs(src)

    per_file: dict[str, int] = defaultdict(int)
    for _, (pth, _) in funcs.items():
        per_file[Path(pth).name] += 1

    # 3 matching loop --------------------------------------------------
    rows, unmatched = [], []
    for mnem, cat in mnems.items():
        # hard override?
        ov = _override(mnem)
        if ov and ov in funcs:
            p, l = funcs[ov]
            rows.append(dict(mnemonic=mnem, function=ov, score=1.0,
                             category=cat, source_path=p, source_line=l))
            continue

        # explicit macro?
        if mnem in pairs and pairs[mnem] in funcs:
            p, l = funcs[pairs[mnem]]
            rows.append(dict(mnemonic=mnem, function=pairs[mnem], score=1.0,
                             category=cat, source_path=p, source_line=l))
            continue

        # similarity fallback
        best, best_s, best_p, best_l = None, 0.0, "", 0
        for fn, (pth, ln) in funcs.items():
            s = _similarity(mnem, fn)
            if s > best_s:
                best, best_s, best_p, best_l = fn, s, pth, ln
        if best and best_s >= args.thr:
            rows.append(dict(mnemonic=mnem, function=best,
                             score=round(best_s, 2), category=cat,
                             source_path=best_p, source_line=best_l))
        else:
            unmatched.append(mnem)

    # 4 summary & optional failure ------------------------------------
    _print_summary(len(mnems), funcs, dict(per_file), len(rows), unmatched)
    if args.fail_on_missing and unmatched:
        sys.exit(1)

    # 5 persist --------------------------------------------------------
    out_p = Path(args.out)
    prev  = json.load(open(out_p)) if args.append and out_p.exists() else []
    ordered = OrderedDict((r["mnemonic"], r) for r in prev)
    for r in rows:
        ordered[r["mnemonic"]] = r
    json.dump(list(ordered.values()), open(out_p, "w"), indent=2)
    logging.info("✎ report saved → %s  (%d total rows)", out_p, len(ordered))


if __name__ == "__main__":
    main()
