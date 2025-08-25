#!/usr/bin/env python3
from __future__ import annotations

import argparse, json, logging, re, sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import requests
from fuzzywuzzy import fuzz  # pip install fuzzywuzzy python-Levenshtein

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

DEFAULT_CATS = ["const_data", "cell_build", "cell_parse"]
FUZZ_THRESH  = 0.70

def _load_cp0(path: Path|str, cats: List[str]) -> Dict[str,Dict[str,str]]:
    data = json.load(open(path, encoding="utf-8"))
    return {
        ins["mnemonic"]: {
            "description": ins.get("doc",{}).get("description",""),
            "category":    ins.get("doc",{}).get("category",""),
        }
        for ins in data["instructions"]
        if ins.get("doc",{}).get("category") in cats
    }

def _discover_all_cats(path: Path|str) -> Set[str]:
    data = json.load(open(path, encoding="utf-8"))
    return {ins.get("doc",{}).get("category","") for ins in data["instructions"]}

def _download(url: str) -> str:
    logging.info("↳ fetching %s", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    txt = r.text
    logging.info("  ✓ %d bytes", len(txt))
    return txt

def _extract_exec_bodies(src: str, src_path: str) -> Dict[str,Dict[str,Any]]:
    """
    Find the real definition line of each exec_* handler—even when its signature
    spans multiple lines—so we point at the opening brace of the function body.
    """
    # match ANY exec_* definition, even if signature spans multiple lines
    pattern = re.compile(
        r'^\s*(?:int|void)\s+'         # return type + whitespace
        r'(exec_[A-Za-z0-9_]+)\s*'     # capture fn name
        r'\(.*?\)\s*'                  # non-greedy signature up to ')'
        r'\{',                         # the opening brace
        re.MULTILINE | re.DOTALL
    )
    out: Dict[str,Dict[str,Any]] = {}
    for m in pattern.finditer(src):
        fn   = m.group(1)
        line = src.count("\n", 0, m.start()) + 2
        out[fn] = {"line": line, "path": src_path}
    logging.info("    • %-20s → %3d definitions", Path(src_path).name, len(out))
    return out

_MACRO_RX = re.compile(r'"([A-Z0-9_ ]+)"[^\)]*?(exec_\w+)', re.S)
def _extract_reg_pairs(src: str) -> Dict[str,Tuple[str,int]]:
    pairs: Dict[str,Tuple[str,int]] = {}
    for m in _MACRO_RX.finditer(src):
        mnem = m.group(1).strip()
        fn   = m.group(2)
        line = src.count("\n", 0, m.start()) + 1
        pairs.setdefault(mnem, (fn, line))
    logging.info("    • found %d explicit pairs", len(pairs))
    return pairs

def _override_from_pattern(mnem: str, funcs: Dict[str,Any]) -> str|None:
    up = mnem.upper()

    # INT loads/stores (STI*/LDU*, etc.)
    if up.startswith(("LDI","LDU")):
        return "exec_load_int_var" if "X" in up else "exec_load_int_fixed"
    if up.startswith(("PLDI","PLDU")):
        return "exec_preload_ref_fixed"
    if up.startswith(("STI","STU")):
        return "exec_store_int_var" if "X" in up else "exec_store_int_fixed"
    if up == "PLDREFIDX":
        return "exec_preload_ref_fixed"

    # special zero-load
    if up == "PLDUZ":
        return "exec_load_zero"

    # slice-const
    if up == "STSLICECONST":
        return "exec_store_const_slice"

    # builder/ref reverse
    if up == "STREF_ALT":
        return "exec_store_ref_rev"
    if up == "STBREFR_ALT":
        return "exec_store_builder_as_ref_rev"

    # slice-begins const
    if up in ("SDBEGINS","SDBEGINSQ"):
        return "exec_slice_begins_with_const"

    # builder chk-bits
    if up.startswith("BCHKBITS"):
        return "exec_builder_chk_bits_refs"

    return None

_SPLIT = re.compile(r"[^A-Za-z]")
def _split(txt: str, *, strip_exec: bool=False) -> Tuple[str,str]:
    if strip_exec and txt.startswith("exec_"):
        txt = txt[5:]
    digits = "".join(re.findall(r"\d+", txt))
    base   = _SPLIT.sub("", txt).lower().removesuffix("rev")
    return digits, base

def _same_reverse_flag(mnem: str, fn: str) -> bool:
    return mnem.lower().endswith("rev") == fn.lower().endswith("rev")

def _best_match(mnem: str, funcs: Dict[str,Dict[str,Any]]
)->Tuple[str|None,float,str,int]:
    m_d, m_b = _split(mnem)
    best_fn,best_s,best_p,best_l = None, 0.0, "", 0
    for fn, info in funcs.items():
        if not _same_reverse_flag(mnem, fn):
            continue
        f_d, f_b = _split(fn, strip_exec=True)
        if m_b == f_b:
            return fn, 1.0, info["path"], info["line"]
        s = fuzz.ratio(f_b, m_b) / 100
        if s > best_s:
            best_fn, best_s, best_p, best_l = fn, s, info["path"], info["line"]
    return best_fn, best_s, best_p, best_l

def _match_all(
    mnems: Dict[str,Dict[str,str]],
    funcs: Dict[str,Dict[str,Any]],
    regs:  Dict[str,Tuple[str,int]],
    thr:   float,
    default_path: str,
) -> Tuple[List[Dict[str,Any]], List[str]]:
    rows, missing = [], []

    for mnem, meta in mnems.items():
        # 1) explicit macro registrations
        if mnem in regs:
            fn, reg_line = regs[mnem]
            info = funcs.get(fn, {"path": default_path, "line": reg_line})
            rows.append({
                "mnemonic":    mnem,
                "function":    fn,
                "score":       1.0,
                "category":    meta["category"],
                "source_path": info["path"],
                "source_line": info["line"],
            })
            continue

        # 2) pattern-based overrides
        ov = _override_from_pattern(mnem, funcs)
        if ov and ov in funcs:
            info = funcs[ov]
            rows.append({
                "mnemonic":    mnem,
                "function":    ov,
                "score":       0.9,
                "category":    meta["category"],
                "source_path": info["path"],
                "source_line": info["line"],
            })
            continue

        # 3) fuzzy fallback
        fn, sc, p, ln = _best_match(mnem, funcs)
        if fn and sc >= thr:
            rows.append({
                "mnemonic":    mnem,
                "function":    fn,
                "score":       round(sc, 2),
                "category":    meta["category"],
                "source_path": p,
                "source_line": ln,
            })
        else:
            missing.append(mnem)

    return rows, missing

def _save_json(rows: List[Dict[str,Any]], path: Path, append: bool) -> None:
    prev   = json.load(open(path)) if append and path.exists() else []
    merged = OrderedDict(((r["mnemonic"], r["category"]), r) for r in prev)
    for r in rows:
        merged[(r["mnemonic"], r["category"])] = r
    json.dump(list(merged.values()), open(path, "w"), indent=2)
    logging.info("✎ report saved → %s (%d entries)", path, len(merged))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0_legacy.json")
    ap.add_argument("--cats", nargs="+", default=None)
    ap.add_argument("--thr", type=float, default=FUZZ_THRESH)
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--show-missing", action="store_true")
    ap.add_argument("--rev", default="cee4c674ea999fecc072968677a34a7545ac9c4d",
                    help="TON repo revision (commit/tag) to fetch sources from")
    args = ap.parse_args()

    cats = DEFAULT_CATS if args.cats is None \
        else (_discover_all_cats(args.cp0) if args.cats == ["all"] else args.cats)
    logging.info("• categories      : %s", ", ".join(cats))

    mnems = _load_cp0(args.cp0, cats)
    logging.info("• cp0_legacy.json        : %d mnemonics", len(mnems))

    url = f"https://raw.githubusercontent.com/ton-blockchain/ton/{args.rev}/crypto/vm/cellops.cpp"
    src   = _download(url)
    funcs = _extract_exec_bodies(src, url)
    regs  = _extract_reg_pairs(src)
    logging.info("• exec_* handlers : %d", len(funcs))

    rows, missing = _match_all(mnems, funcs, regs, args.thr, url)
    ok = len(rows)
    logging.info("• matched (≥%.2f): %d/%d (%.1f%%)",
                 args.thr, ok, len(mnems), ok/len(mnems)*100)
    if missing:
        logging.warning("⚠ unmatched      : %s", ", ".join(missing))
        if args.show_missing:
            sys.exit(1)

    _save_json(rows, Path(args.out), append=args.append)

    logging.info("\n" + "═"*60)
    logging.info("SUMMARY")
    logging.info("═"*60)
    logging.info("• Categories      : %s", ", ".join(cats))
    logging.info("• cp0.json        : %d mnemonics", len(mnems))
    logging.info("• Matched (≥%.2f): %d/%d (%.1f%%)",
                 args.thr, ok, len(mnems), ok/len(mnems)*100)
    if not missing:
        logging.info("✓ All matched")
    else:
        logging.warning("⚠ %d unmatched", len(missing))

if __name__=="__main__":
    main()
