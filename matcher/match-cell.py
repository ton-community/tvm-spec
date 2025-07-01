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
from fuzzywuzzy import fuzz            # pip install fuzzywuzzy python-Levenshtein

# ───────────────────────────── logging ──────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ──────────────────────────── constants ─────────────────────────────
RAW_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/cellops.cpp"
)
DEFAULT_CATS = ["const_data", "cell_build", "cell_parse"]

# ═══════════════════════════ cp0 helpers ════════════════════════════
def _load_cp0(path: Path | str, cats: List[str]) -> Dict[str, Dict[str, str]]:
    """Return mnemonic → {description, category} filtered by *cats*."""
    data = json.load(open(path, encoding="utf-8"))
    return {
        ins["mnemonic"]: {
            "description": ins.get("doc", {}).get("description", ""),
            "category": ins.get("doc", {}).get("category", ""),
        }
        for ins in data["instructions"]
        if ins.get("doc", {}).get("category") in cats
    }


def _discover_all_cats(path: Path | str) -> Set[str]:
    data = json.load(open(path, encoding="utf-8"))
    return {ins.get("doc", {}).get("category", "") for ins in data["instructions"]}

# ═══════════════════════ download + C++ helpers ═════════════════════
def _download(url: str) -> str:
    logging.info("↳ fetching %s", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  ✓ %s (%d bytes)", Path(url).name, len(r.text))
    return r.text


def _extract_exec_bodies(src: str, src_path: str) -> Dict[str, Dict[str, Any]]:
    """Return exec_* → {line, path} (body is unused but kept for future)."""
    out: Dict[str, Dict[str, Any]] = {}
    rx = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
    for m in rx.finditer(src):
        fn = m.group(1)
        out[fn] = {
            "line": src.count("\n", 0, m.start()) + 1,
            "path": src_path,
        }
    logging.info("    • %-28s → %3d handlers", Path(src_path).name, len(out))
    return out


_MACRO_RX = re.compile(r'"([A-Z0-9_ ]+)"[^\)]*?(exec_\w+)', re.S)

def _extract_reg_pairs(src: str) -> Dict[str, Tuple[str, int]]:
    """Return mnemonic → (exec_fn, macro_line)."""
    pairs: Dict[str, Tuple[str, int]] = {}
    for m in _MACRO_RX.finditer(src):
        mnem, fn = m.group(1).strip(), m.group(2)
        pairs.setdefault(mnem, (fn, src.count("\n", 0, m.start()) + 1))
    logging.info("Found %d explicit pairs from OpcodeInstr macros", len(pairs))
    return pairs

# ═══════════════════════ manual overrides ═══════════════════════════
def _override_from_pattern(mnem: str, funcs: Dict[str, Dict[str, Any]]) -> str | None:
    """Return an exec_* handler for tricky mnemonics, or None."""
    up = mnem.upper()

        # ─── specific known cellops variants ─────────────────────────────
    if up == "PUSHCONT_SHORT":
        return "exec_push_cont_simple"
    if up == "PUSHREFSLICE":
        return "exec_push_ref"  # mode = 1
    if up == "PUSHREFCONT":
        return "exec_push_ref"  # mode = 2
    if up == "PUSHSLICE_LONG":
        return "exec_push_slice_r2"
    if up == "PUSHCONT_SHORT":
        return "exec_push_cont_simple"     

    # (A) SDBEGINS family – four variants routed to two exec_* fns
    if up.startswith("SDBEGINSX"):
        return "exec_slice_begins_with" if "exec_slice_begins_with" in funcs else None
    if up.startswith("SDBEGINS"):
        return "exec_slice_begins_with_const" if "exec_slice_begins_with_const" in funcs else None

    # (B) legacy hard-coded aliases
    if up in ("PLDSLICEX", "PLDSLICEXQ"):
        return "exec_load_slice"
    if up in ("PLDSLICE", "PLDSLICEQ"):
        return "exec_load_slice_fixed2"
    if up == "PLDREFIDX":
        return "exec_preload_ref_fixed"

    if up.startswith(("PLD", "PLDU", "PLDI")):
        return "exec_load_int_fixed2"

    if up.startswith(("STI", "STU")):
        if "X" in up:
            return "exec_store_int_var"
        if up.endswith("ALT"):
            return "exec_store_int_fixed"
        return "exec_store_int"

    if up.startswith(("LDI", "LDU")):
        return "exec_load_int_var" if "X" in up else "exec_load_int_fixed"

    if up.startswith("BCHKBITS"):
        return "exec_builder_chk_bits"
    if up.startswith(("BCHK", "BCHKBIT")):
        return "exec_builder_chk_bits_refs"

    if up.startswith("STBREF"):
        return "exec_store_builder_as_ref_rev" if "R" in up[6:] else "exec_store_builder_as_ref"
    if up.startswith("STBR"):
        return "exec_store_builder_rev"
    if up == "STB":
        return "exec_store_builder"

    if up.startswith("STREF"):
        return "exec_store_ref_rev" if "R" in up[5:] else "exec_store_ref"
    if up.startswith("STSLICE"):
        return "exec_store_slice_rev" if "R" in up[7:] else "exec_store_slice"

    return None

# ═══════════════════════ fuzzy matching bits ════════════════════════
_SPLIT_NON_ALPHA = re.compile(r"[^A-Za-z]")

def _split(txt: str, *, strip_exec: bool = False) -> Tuple[str, str]:
    if strip_exec and txt.startswith("exec_"):
        txt = txt[5:]
    digits = "".join(re.findall(r"\d+", txt))
    base   = _SPLIT_NON_ALPHA.sub("", txt).lower().removesuffix("rev")
    return digits, base


def _same_reverse_flag(mnem: str, fn: str) -> bool:
    mn_rev = mnem.lower().endswith("rev") or mnem.startswith("-")
    fn_rev = fn.lower().endswith("rev")
    return mn_rev == fn_rev


def _best_match(mnem: str, funcs: Dict[str, Dict[str, Any]]
) -> Tuple[str | None, float, str, int]:
    """Return (best_fn, score, path, line)."""
    m_d, m_b = _split(mnem)
    best_fn, best_s, best_p, best_l = None, 0.0, "", 0
    for fn, info in funcs.items():
        if not _same_reverse_flag(mnem, fn):
            continue
        f_d, f_b = _split(fn, strip_exec=True)
        if m_d and f_d and m_d != f_d:
            continue
        if f_b == m_b:
            return fn, 1.0, info["path"], info["line"]
        s = fuzz.ratio(f_b, m_b) / 100
        if s > best_s:
            best_fn, best_s, best_p, best_l = fn, s, info["path"], info["line"]
    return best_fn, best_s, best_p, best_l

# ═════════════════════ main matching routine ════════════════════════
def _match_all(
    mnems: Dict[str, Dict[str, str]],
    funcs: Dict[str, Dict[str, Any]],
    regs: Dict[str, Tuple[str, int]],
    thr: float,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    rows, missing = [], []

    for mnem, meta in mnems.items():
        # 1) direct macro hit
        if mnem in regs:
            fn_name, macro_line = regs[mnem]
            info = funcs.get(fn_name, {"path": RAW_URL, "line": macro_line})
            rows.append(
                dict(
                    mnemonic=mnem,
                    function=fn_name,
                    score=1.0,
                    category=meta["category"],
                    source_path=info["path"],
                    source_line=info["line"],
                )
            )
            continue

        # 2) rule-based override
        ov = _override_from_pattern(mnem, funcs)
        if ov and ov in funcs:
            info = funcs[ov]
            rows.append(
                dict(
                    mnemonic=mnem,
                    function=ov,
                    score=0.9,
                    category=meta["category"],
                    source_path=info["path"],
                    source_line=info["line"],
                )
            )
            continue

        # 3) fuzzy fallback
        fn, sc, p, ln = _best_match(mnem, funcs)
        if fn and sc >= thr:
            rows.append(
                dict(
                    mnemonic=mnem,
                    function=fn,
                    score=round(sc, 2),
                    category=meta["category"],
                    source_path=p,
                    source_line=ln,
                )
            )
        else:
            missing.append(mnem)

    return rows, missing

# ═════════════════════ persistence helper ════════════════════════════
def _save_json(rows: List[Dict[str, Any]], path: Path, append: bool) -> None:
    prev = json.load(open(path)) if append and path.exists() else []
    key  = lambda r: (r["mnemonic"], r.get("category", ""))
    merged = OrderedDict((key(r), r) for r in prev)
    for r in rows:
        merged[key(r)] = r
    json.dump(list(merged.values()), open(path, "w"), indent=2)
    logging.info("✎ report saved → %s  (%d entries)", path, len(merged))

# ═════════════════════════════ CLI ═══════════════════════════════════
def main() -> None:
    ap = argparse.ArgumentParser(description="Match cell-ops mnemonics to exec_* handlers.")
    ap.add_argument("--cp0", default="cp0.json", help="path to cp0.json")
    ap.add_argument("--cats", nargs="+", default=None, help="'all' or explicit list")
    ap.add_argument("--thr", type=float, default=0.70, help="min similarity threshold")
    ap.add_argument("--out", default="match.json", help="output JSON file")
    ap.add_argument("--append", action="store_true", help="merge with existing report")
    ap.add_argument("--show-missing", action="store_true", help="exit 1 if anything unmatched")
    args = ap.parse_args()

    # 1) categories ---------------------------------------------------
    cats = (
        DEFAULT_CATS
        if args.cats is None
        else sorted(_discover_all_cats(args.cp0)) if args.cats == ["all"] else args.cats
    )
    logging.info("• categories     : %s", ", ".join(cats))

    # 2) mnemonics ----------------------------------------------------
    mnems = _load_cp0(args.cp0, cats)
    logging.info("• cp0.json       : %d mnemonics", len(mnems))

    # 3) C++ scraping -------------------------------------------------
    src   = _download(RAW_URL)
    funcs = _extract_exec_bodies(src, RAW_URL)
    regs  = _extract_reg_pairs(src)
    logging.info("• exec_* handlers: %d", len(funcs))

    # 4) match --------------------------------------------------------
    rows, missing = _match_all(mnems, funcs, regs, args.thr)
    ok = len(rows)
    logging.info("• matched (≥ %.2f): %d/%d  (%.1f %%)", args.thr, ok, len(mnems), ok/len(mnems)*100)
    if missing:
        logging.warning("⚠ unmatched      : %d → %s", len(missing), ", ".join(missing))

    if args.show_missing and missing:
        sys.exit(1)

    # 5) persist ------------------------------------------------------
    _save_json(rows, Path(args.out), append=args.append)

    # 6) pretty summary ----------------------------------------------
    logging.info("")
    logging.info("═════════════════════════════════════════════════════════════════")
    logging.info("                             SUMMARY                              ")
    logging.info("═════════════════════════════════════════════════════════════════")
    logging.info("• Categories      : %s", ", ".join(cats))
    logging.info("• cp0.json        : %d mnemonics", len(mnems))
    logging.info("• Matched (≥ %.2f) : %d/%d  (%.1f %%)", args.thr, ok, len(mnems), ok / len(mnems) * 100)
    if not missing:
        logging.info("✓ All mnemonics matched")
    else:
        logging.warning("⚠ %d mnemonics unmatched", len(missing))
    logging.info("")


# entry-point
if __name__ == "__main__":
    main()
