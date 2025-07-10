from __future__ import annotations

import argparse
import json
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Tuple

import requests
from fuzzywuzzy import fuzz

# ───────────────────────────── logging ──────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="%(levelname)s: %(message)s")

# ─────────────────────────── constants ──────────────────────────────
CPP_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/tupleops.cpp"
)
CATEGORY = "tuple"
EXEC_HEAD_RX = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)

# ─────────────────────── C++ helpers ────────────────────────────────
def download_cpp(url: str) -> str:
    logging.info("↳ fetching %s", url)
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    logging.info("  ✓ %-18s (%d bytes)", Path(url).name, len(resp.text))
    return resp.text


def extract_exec_bodies(code: str, src_path: str) -> Dict[str, Dict[str, Any]]:
    """
    Return {exec_name → {'body', 'line', 'path'}}.  (1-based line #).
    """
    out: Dict[str, Dict[str, Any]] = {}
    for m in EXEC_HEAD_RX.finditer(code):
        name = m.group(1)
        level, i = 1, m.end()
        while i < len(code) and level:
            level += code[i] == "{"
            level -= code[i] == "}"
            i += 1
        out[name] = {
            "body": code[m.end(): i],
            "line": code.count("\n", 0, m.start()) + 1,
            "path": src_path,
        }
    logging.info("    • %-18s → %3d exec_* handlers", Path(src_path).name, len(out))
    return out


def extract_macro_pairs(code: str) -> Dict[str, str]:
    """
    From `mksimple/mkfixed` macros build {MNEMONIC → exec_fn}.
    """
    pairs: Dict[str, str] = {}
    for macro in ("mksimple", "mkfixed"):
        for mm in re.finditer(rf"{macro}\([^)]*\)", code, re.S):
            mnem = re.search(r'"([A-Z0-9_ ]+)"', mm.group())
            fn   = re.search(r"exec_\w+", mm.group())
            if mnem and fn:
                pairs[mnem.group(1).strip()] = fn.group()
    # handy alias: PUSHNULL ⇆ NULL
    if "PUSHNULL" in pairs and "NULL" not in pairs:
        pairs["NULL"] = pairs["PUSHNULL"]
    return pairs


def add_index_aliases(reg_pairs: Dict[str, str], funcs: Dict[str, Any]) -> None:
    """Add INDEX2 / 3 when the corresponding exec exists."""
    for fn in funcs:
        m = re.match(r"exec_tuple_index([23])$", fn)
        if m:
            reg_pairs[f"INDEX{m.group(1)}"] = fn

# ───────────────────── heuristic similarity ─────────────────────────
def _norm(txt: str) -> str:
    return re.sub(r"[^a-z0-9]", "", txt.lower())


def similarity(mnem: str, fn: str, body: str, desc: str) -> float:
    # mnemonic literally emitted in the body? → perfect
    if re.search(rf"\b{re.escape(mnem)}\b", body, re.I):
        return 1.0

    score = fuzz.ratio(_norm(mnem), _norm(fn)) / 100.0
    if desc:
        words_b = set(body.lower().split())
        overlap = len(set(desc.lower().split()) & words_b)
        score = max(score, 0.6 + 0.4 * overlap / max(len(desc.split()), 1))
    return score

# ───────────────────── matching ------------------------------------------------
def match_all(
    mnems: Dict[str, Dict[str, str]],
    funcs: Dict[str, Dict[str, Any]],
    reg_pairs: Dict[str, str],
) -> Dict[str, Tuple[str | None, float, str, int]]:
    matched: Dict[str, Tuple[str | None, float, str, int]] = {}

    for mnem, meta in mnems.items():
        # macro link
        fn_name = reg_pairs.get(mnem)
        if fn_name and fn_name in funcs:
            info = funcs[fn_name]
            matched[mnem] = (fn_name, 1.0, info["path"], info["line"])
            continue

        # best-effort similarity
        best_fn, best_sc, best_path, best_ln = None, 0.0, "", 0
        for fn, info in funcs.items():
            sc = similarity(mnem, fn, info["body"], meta.get("description", ""))
            if sc > best_sc:
                best_fn, best_sc, best_path, best_ln = fn, sc, info["path"], info["line"]
        matched[mnem] = (best_fn, best_sc, best_path, best_ln)

    return matched

# ─────────────────────── persist JSON -----------------------------------------
def save_json(rows: List[Dict[str, Any]], dest: Path, append: bool) -> None:
    prev = json.load(dest.open()) if append and dest.exists() else []
    ordered: "OrderedDict[str, Dict[str, Any]]" = OrderedDict((r["mnemonic"], r) for r in prev)
    for r in rows:
        ordered[r["mnemonic"]] = r
    json.dump(list(ordered.values()), dest.open("w"), indent=2)
    logging.info("✎ report saved → %s  (%d entries)", dest, len(ordered))

# ────────────────────────── pretty summary ------------------------------------
def pretty_summary(total_mnem: int,
                   file_handlers: int,
                   matched: int,
                   unmatched: List[str],
                   thr: float) -> None:
    bar = "═" * 65
    logging.info("\n%s\n%*s%s\n%s", bar, 36, "SUMMARY", "", bar)
    logging.info("• Category         : %s", CATEGORY)
    logging.info("• cp0.json         : %d mnemonics", total_mnem)
    pct = matched / total_mnem * 100
    logging.info("• Matched (≥ %.2f)  : %d/%d  (%.1f %%)", thr, matched, total_mnem, pct)
    if unmatched:
        logging.warning("⚠ Unmatched        : %d → %s", len(unmatched), ", ".join(unmatched))
    else:
        logging.info("✓ All mnemonics matched")
    logging.info(bar)

# ───────────────────────────── CLI --------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0_legacy.json")
    ap.add_argument("--thr", type=float, default=0.70)
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    # load tuple mnemonics -------------------------------------------------
    cp0 = json.load(open(args.cp0, encoding="utf-8"))
    mnems = {
        ins["mnemonic"]: {"description": ins.get("doc", {}).get("description", "")}
        for ins in cp0["instructions"]
        if ins.get("doc", {}).get("category") == CATEGORY
    }
    logging.info("• mnemonics loaded : %d", len(mnems))

    # grab & parse tupleops.cpp -------------------------------------------
    code  = download_cpp(CPP_URL)
    funcs = extract_exec_bodies(code, CPP_URL)
    regs  = extract_macro_pairs(code)
    add_index_aliases(regs, funcs)

    # match ---------------------------------------------------------------
    matches = match_all(mnems, funcs, regs)
    rows = [
        {
            "mnemonic": m,
            "function": fn,
            "score": round(sc, 2),
            "category": CATEGORY,
            "source_path": path,
            "source_line": line,
        }
        for m, (fn, sc, path, line) in matches.items()
        if fn and sc >= args.thr
    ]
    matched = len(rows)
    unmatched = [m for m, (fn, sc, *_r) in matches.items()
                 if not fn or sc < args.thr]

    # save ----------------------------------------------------------------
    save_json(rows, Path(args.out), append=args.append)

    # summary -------------------------------------------------------------
    pretty_summary(len(mnems), len(funcs), matched, unmatched, args.thr)


if __name__ == "__main__":
    main()
