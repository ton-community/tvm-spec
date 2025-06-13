from __future__ import annotations

import argparse
import json
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from fuzzywuzzy import fuzz

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

TUPLEOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/tupleops.cpp"
)
CATEGORY = "tuple"

# ──────────────────────────────────────────────────────────────────────────────
# C++ helpers
# ──────────────────────────────────────────────────────────────────────────────
def download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text


def extract_exec_bodies(code: str, src_path: str) -> Dict[str, Dict]:
    """
    Return exec_name → {body, line, path}.
    `line` is the 1-based line number where the `exec_*` definition starts.
    """
    out: Dict[str, Dict] = {}
    pat = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.MULTILINE)
    for m in pat.finditer(code):
        name = m.group(1)
        start = m.end()
        brace = 1
        i = start
        while i < len(code) and brace:
            brace += code[i] == "{"
            brace -= code[i] == "}"
            i += 1
        body = code[start:i]
        line_nr = code.count("\n", 0, m.start()) + 1
        out[name] = {"body": body, "line": line_nr, "path": src_path}
    logging.info("Extracted %d exec_* fns from %s", len(out), src_path)
    return out


def extract_reg_pairs(code: str) -> Dict[str, str]:
    """Map MNEMONIC → exec_func using mksimple / mkfixed macros."""
    pairs: Dict[str, str] = {}
    for macro in ("mksimple", "mkfixed"):
        for m in re.finditer(rf"{macro}\([^)]*\)", code, re.DOTALL):
            mnem = re.search(r'\"([A-Z0-9_ ]+)\"', m.group(0))
            fn   = re.search(r"exec_\w+", m.group(0))
            if mnem and fn:
                pairs[mnem.group(1).strip()] = fn.group(0)
    if "PUSHNULL" in pairs:          # handy alias
        pairs["NULL"] = pairs["PUSHNULL"]
    return pairs


def add_function_aliases(regs: Dict[str, str], funcs: Dict[str, Dict]) -> None:
    """Add INDEX2 / INDEX3 aliases when those exec_* handlers exist."""
    for fn in funcs:
        m = re.match(r"exec_tuple_index([23])$", fn)
        if m:
            regs[f"INDEX{m.group(1)}"] = fn

# ──────────────────────────────────────────────────────────────────────────────
# Matching logic
# ──────────────────────────────────────────────────────────────────────────────
def _norm(t: str) -> str:
    return re.sub(r"[^a-z0-9]", "", t.lower())


def _similarity(mnem: str, fn: str, body: str, desc: str) -> float:
    if re.search(rf"execute\s+{re.escape(mnem)}", body, re.IGNORECASE):
        return 1.0
    score = fuzz.ratio(_norm(mnem), _norm(fn)) / 100
    if desc:
        overlap = len(set(desc.lower().split()) & set(body.lower().split()))
        score = max(score, 0.6 + 0.4 * overlap / max(len(desc.split()), 1))
    return score


def match_all(
    mnems: Dict[str, Dict],
    funcs: Dict[str, Dict],
    regs: Dict[str, str],
) -> Dict[str, Tuple[str, float, str, int]]:
    """
    Return mnemonic → (exec_fn, score, path, line).
    """
    out: Dict[str, Tuple[str, float, str, int]] = {}
    for mnem, meta in mnems.items():
        # 1) explicit macro link
        if regs.get(mnem) in funcs:
            fn = regs[mnem]
            info = funcs[fn]
            out[mnem] = (fn, 1.0, info["path"], info["line"])
            continue

        # 2) similarity fallback
        best, best_s, best_path, best_ln = None, 0.0, "", 0
        for fn, info in funcs.items():
            s = _similarity(mnem, fn, info["body"], meta.get("description", ""))
            if s > best_s:
                best, best_s = fn, s
                best_path, best_ln = info["path"], info["line"]
        out[mnem] = (best, best_s, best_path, best_ln)
    return out

# ──────────────────────────────────────────────────────────────────────────────
# JSON save helper
# ──────────────────────────────────────────────────────────────────────────────
def save_json(rows: List[Dict], out_path: Path, append: bool) -> None:
    old: List[Dict] = []
    if append and out_path.exists():
        old = json.load(open(out_path, "r", encoding="utf-8"))

    ordered: "OrderedDict[str, Dict]" = OrderedDict((r["mnemonic"], r) for r in old)
    for r in rows:
        if r["mnemonic"] in ordered:
            ordered[r["mnemonic"]].update(r)
        else:
            ordered[r["mnemonic"]] = r   # new → bottom

    json.dump(list(ordered.values()), open(out_path, "w", encoding="utf-8"), indent=2)
    logging.info("Saved %d entries → %s", len(ordered), out_path)

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--thr", type=float, default=0.7)
    ap.add_argument("--out", default="match_report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    # -------- cp0.json (tuple mnemonics only)
    cp0 = json.load(open(args.cp0, encoding="utf-8"))
    mnems = {
        ins["mnemonic"]: {"description": ins.get("doc", {}).get("description", "")}
        for ins in cp0["instructions"]
        if ins.get("doc", {}).get("category", "") == CATEGORY
    }

    # -------- C++ extraction
    code = download(TUPLEOPS_URL)
    funcs = extract_exec_bodies(code, TUPLEOPS_URL)
    regs  = extract_reg_pairs(code)
    add_function_aliases(regs, funcs)

    # -------- match
    matches = match_all(mnems, funcs, regs)
    rows = [
        {
            "mnemonic": m,
            "function": fn,
            "score"   : round(sc, 2),
            "category": CATEGORY,
            "source_path" : path,
            "source_line" : line,
        }
        for m, (fn, sc, path, line) in matches.items()
        if fn and sc >= args.thr
    ]

    save_json(rows, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
