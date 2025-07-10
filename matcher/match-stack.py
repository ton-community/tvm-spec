from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import requests
from fuzzywuzzy import fuzz

# ─────────────────────────────── logging ──────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ──────────────────────────── constants ───────────────────────────────
DEFAULT_CATEGORIES = ["stack_basic", "stack_complex"]
CATEGORY_ORDER = {c: i for i, c in enumerate(DEFAULT_CATEGORIES)}

CPP_FALLBACK_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/stackops.cpp"
)

EXEC_HEAD_RX = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
_SPLIT_NON_ALPHA = re.compile(r"[^A-Za-z]")


# Manual aliases for weird or ambiguous names                       
# ------------------------------------------------------------------+
MANUAL_OVERRIDES = {
    "REVX": "exec_reverse_x",     
}

# ───────────────────────────── cp0 helpers ────────────────────────────
def _load_cp0(path: Path | str, cats: List[str]) -> Dict[str, Dict[str, str]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        ins["mnemonic"]: {
            "description": ins.get("doc", {}).get("description", ""),
            "category": ins.get("doc", {}).get("category", ""),
        }
        for ins in data["instructions"]
        if ins.get("doc", {}).get("category", "") in cats
    }


def _discover_all_categories(path: Path | str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {ins.get("doc", {}).get("category", "") for ins in data["instructions"]}


# ───────────────────────────── C++ helpers ────────────────────────────
def _download_cpp(url: str) -> str:
    logging.info("↳ fetching %s", url)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    logging.info("  ✓ %s (%d bytes)", Path(url).name, len(resp.text))
    return resp.text


def _extract_exec_bodies(code: str, src_path: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for m in EXEC_HEAD_RX.finditer(code):
        name = m.group(1)
        brace, i = 1, m.end()
        while i < len(code) and brace:
            brace += code[i] == "{"
            brace -= code[i] == "}"
            i += 1
        out[name] = {
            "body": code[m.end(): i],
            "line": code.count("\n", 0, m.start()) + 1,
            "path": src_path,
        }
    logging.info("    • %-20s → %3d exec_* handlers", Path(src_path).name, len(out))
    return out


def _is_reverse_variant(mnem: str, fn: str) -> bool:
    m_rev = mnem.startswith("-") or mnem.lower().endswith("rev")
    f_rev = fn.lower().endswith("rev")
    return m_rev == f_rev


# ─────────────────────────── matching engine ──────────────────────────
def _split_word(word: str, *, drop_exec: bool = False) -> Tuple[str, str]:
    if drop_exec and word.startswith("exec_"):
        word = word[5:]
    digits = "".join(re.findall(r"\d+", word))
    letters = _SPLIT_NON_ALPHA.sub("", word).lower().removesuffix("rev")
    return digits, letters


def _match_all(
    funcs: Dict[str, Dict[str, Any]],
    mnems: Dict[str, Dict[str, str]],
) -> Dict[str, Tuple[str | None, float, str, str, int]]:

    matched: Dict[str, Tuple[str | None, float, str, str, int]] = {}

    for mnem, meta in mnems.items():

        # 0) manual override (e.g. REVX)
        if mnem in MANUAL_OVERRIDES and MANUAL_OVERRIDES[mnem] in funcs:
            fn = MANUAL_OVERRIDES[mnem]
            info = funcs[fn]
            matched[mnem] = (fn, 1.0, meta["category"], info["path"], info["line"])
            continue

        m_d, m_b = _split_word(mnem)
        best_fn, best_sc, path, line = None, 0.0, "", 0

        for fn, info in funcs.items():
            if not _is_reverse_variant(mnem, fn):
                continue
            f_d, f_b = _split_word(fn, drop_exec=True)
            if m_d != f_d:
                continue

            score = 1.0 if f_b == m_b else fuzz.ratio(f_b, m_b) / 100
            if score > best_sc:
                best_fn, best_sc, path, line = fn, score, info["path"], info["line"]
                if score == 1.0:
                    break

        matched[mnem] = (best_fn, best_sc, meta["category"], path, line)

    return matched


# ───────────────────────────── reporting ───────────────────────────────
def _make_rows(
    matches: Dict[str, Tuple[str | None, float, str, str, int]],
    thr: float,
) -> List[Dict[str, Any]]:
    return [
        {
            "mnemonic": m,
            "function": fn,
            "score": round(sc, 2),
            "category": cat,
            "source_path": path,
            "source_line": line,
        }
        for m, (fn, sc, cat, path, line) in matches.items()
        if fn and sc >= thr
    ]


def _save_json(rows: List[Dict[str, Any]], dest: Path, append: bool) -> None:
    prev = json.load(dest.open()) if append and dest.exists() else []
    ordered: "OrderedDict[str, Dict[str, Any]]" = OrderedDict((r["mnemonic"], r) for r in prev)
    for r in rows:
        ordered[r["mnemonic"]] = r
    json.dump(list(ordered.values()), dest.open("w"), indent=2)
    logging.info("✎ report saved → %s  (%d entries)", dest, len(ordered))


# ─────────────────────────────── CLI ───────────────────────────────────
def main() -> None:

    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0_legacy.json", help="path to cp0.json")
    ap.add_argument("--cats", nargs="+", default=None, help="'all' or list of categories")
    ap.add_argument(
        "--cpp",
        nargs="+",
        default=[CPP_FALLBACK_URL],
        help="one or more GitHub raw URLs with exec_* defs",
    )
    ap.add_argument("--thr", type=float, default=0.70, help="min similarity threshold (0-1)")
    ap.add_argument("--out", default="match-report.json", help="output JSON path")
    ap.add_argument("--append", action="store_true", help="merge with existing JSON")
    ap.add_argument("--fail-on-missing", action="store_true", help="exit 1 if any unmapped mnemonic")
    args = ap.parse_args()

    # 1. categories
    cats = (
        DEFAULT_CATEGORIES
        if args.cats is None
        else sorted(_discover_all_categories(args.cp0), key=lambda c: CATEGORY_ORDER.get(c, 99))
        if args.cats == ["all"]
        else args.cats
    )
    logging.info("• categories      : %s", ", ".join(cats))

    # 2. load mnemonics
    mnems = _load_cp0(args.cp0, cats)
    logging.info("• cp0.json        : %d mnemonics", len(mnems))

    # 3. collect exec_* handlers
    funcs: Dict[str, Dict[str, Any]] = {}
    for url in args.cpp:
        funcs.update(_extract_exec_bodies(_download_cpp(url), url))
    logging.info("• exec_* handlers : %d", len(funcs))

    # 4. match
    matches = _match_all(funcs, mnems)
    rows = _make_rows(matches, args.thr)

    matched_cnt = len(rows)
    unmatched = [m for m, (fn, sc, *_rest) in matches.items() if fn is None or sc < args.thr]

    # 5. pretty summary
    print("\n" + "═" * 65)
    print("SUMMARY".center(65))
    print("═" * 65)
    print(f"• Categories      : {', '.join(cats)}")
    print(f"• cp0.json        : {len(mnems)} mnemonics")
    for url in args.cpp:
        print(f"   – {Path(url).name:<18}: {len([f for f in funcs if funcs[f]['path'] == url]):3d}")
    print(f"• Matched (≥ {args.thr:0.2f}) : {matched_cnt}/{len(mnems)}  ({matched_cnt/len(mnems)*100:5.1f} %)")
    if unmatched:
        print(f"⚠ Unmatched       : {len(unmatched)} → {', '.join(unmatched)}")
    print("═" * 65 + "\n")

    # 6. optional CI fail
    if args.fail_on_missing and unmatched:
        sys.exit("Some mnemonics are still unmapped")

    # 7. persist
    _save_json(rows, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
