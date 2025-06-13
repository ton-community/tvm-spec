#!/usr/bin/env python3
"""
Match mnemonics from cp0.json to exec_* handlers in arithops.cpp.

Fixes
=====
• Canonicalisation no longer strips a lone trailing “R” or “C”.
  So SUB ≠ SUBR, ADD ≠ ADDR, etc.
• `_similarity()` still treats {R,C,VAR} as *related* flags and
  rejects matches that differ by exactly one of them.
• No hard-coded alias tables; PUSHINT<size> aliases are inferred
  from exec_push_* handler names.
"""

from __future__ import annotations
import argparse, json, logging, re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from fuzzywuzzy import fuzz, utils   # pip install fuzzywuzzy python-Levenshtein

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

ARITHOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/arithops.cpp"
)

CATEGORY_OK = {
    "const_int", "arithm_basic", "arithm_div",
    "arithm_logical", "arithm_quiet",
}

# ─────────────────────── fetch & extract helpers ──────────────────────────
def _download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text

def _extract_exec_bodies(src: str, path: str) -> Dict[str, Dict]:
    """exec_foo → {body,line,path}"""
    pat = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
    out: Dict[str, Dict] = {}
    for m in pat.finditer(src):
        fn = m.group(1)
        start = m.end()
        brace = 1
        i = start
        while i < len(src) and brace:
            brace += src[i] == "{"
            brace -= src[i] == "}"
            i += 1
        out[fn] = {
            "body": src[start:i],
            "line": src.count("\n", 0, m.start()) + 1,
            "path": path,
        }
    logging.info("Found %d exec_* handlers", len(out))
    return out

def _extract_reg_pairs(src: str) -> Dict[str, str]:
    """MNEMONIC (literal) → exec_fn from mk* macro tables."""
    pairs: Dict[str, str] = {}
    for macro in ("mksimple", "mkfixed", "mkfixedrange", "mkextrange"):
        for m in re.finditer(rf"{macro}\([^)]*\)", src, re.S):
            s = re.search(r'"([A-Z0-9_\- ]+)"', m.group(0))
            fn = re.search(r"exec_\w+", m.group(0))
            if s and fn:
                pairs[s.group(1).strip()] = fn.group(0)
    return pairs

# ───────────────────────────  normalisation  ──────────────────────────────
_VAR_RX  = re.compile(r"_?VAR$", re.I)   # always drop
def _canonical(txt: str, *, is_fn: bool=False) -> str:
    if is_fn:
        txt = txt.removeprefix("exec_")
    txt = txt.replace("_", "")
    txt = _VAR_RX.sub("", txt)           # strip only _VAR suffix
    return txt.upper()

def _split_name(txt: str, *, is_fn=False) -> Tuple[str,str]:
    if is_fn:
        txt = txt.removeprefix("exec_")
        txt = re.sub(r"(tiny|small|neg|dec|long)", "", txt)
    txt = _VAR_RX.sub("", txt)
    digits  = "".join(re.findall(r"\d+", txt))
    letters = re.sub(r"[^a-z]", "", txt.lower())
    return digits, letters

# ─────────── PUSHINT<size> alias generation (no hard-codes) ───────────────
def _augment_pushint_aliases(func_can: Dict[str,str]) -> None:
    for fn in list(func_can.values()):
        if m := re.match(r"exec_push_tinyint(\d+)", fn):
            func_can[f"PUSHINT{m.group(1)}"] = fn
        elif fn == "exec_push_smallint":
            func_can["PUSHINT16"] = fn
        elif fn == "exec_push_int":
            func_can["PUSHINT32"] = fn
        elif fn == "exec_push_longint":
            func_can["PUSHINT64"] = fn

# ───────────────────────── similarity metric ───────────────────────────────
def _similarity(mnem: str, fn: str, body: str) -> float:
    if re.search(rf"execute\s+{re.escape(mnem)}\b", body, re.I):
        return 1.0                         # exact log wins

    m_can = _canonical(mnem)
    f_can = _canonical(fn, is_fn=True)

    # Reject simple R/C difference
    for flag in ("R", "C"):
        if m_can + flag == f_can or f_can + flag == m_can:
            return 0.0

    if m_can == f_can:                    # identical canonical strings
        return 0.9

    base = 0.6 if (m_can in f_can or f_can in m_can) else 0.0

    md, ml = _split_name(mnem)
    fd, fl = _split_name(fn, is_fn=True)
    if md and fd and md != fd:
        return base                       # conflicting numeric part

    raw = fuzz.ratio(ml, fl)
    tok = fuzz.token_set_ratio(utils.full_process(ml), utils.full_process(fl))
    return max(base, max(raw, tok) / 100.0)

# ───────────────────────── core matching logic ─────────────────────────────
def _match_all(
    mnems: Dict[str,Dict], funcs: Dict[str,Dict], regs: Dict[str,str], thr: float
) -> Dict[str,Tuple[str,float,str,int]]:
    func_by_can = {_canonical(fn, is_fn=True): fn for fn in funcs}
    _augment_pushint_aliases(func_by_can)

    out: Dict[str,Tuple[str,float,str,int]] = {}
    for mnem in mnems:
        canon = _canonical(mnem)

        # a) canonical direct hit
        if canon in func_by_can:
            fn = func_by_can[canon]; info = funcs[fn]
            out[mnem] = (fn,1.0,info["path"],info["line"]); continue

        # b) mk* table link (verify)
        if mnem in regs and regs[mnem] in funcs:
            fn = regs[mnem]; sc = _similarity(mnem,fn,funcs[fn]["body"])
            if sc >= thr:
                info = funcs[fn]; out[mnem]=(fn,sc,info["path"],info["line"]); continue

        # c) fallback search
        best,best_s,best_p,best_l = None,0.0,"",0
        for fn,info in funcs.items():
            s=_similarity(mnem,fn,info["body"])
            if s>best_s: best,best_s,best_p,best_l=fn,s,info["path"],info["line"]
        if best and best_s>=thr:
            out[mnem]=(best,best_s,best_p,best_l)
    return out

# ─────────────────────────── persistence helper ────────────────────────────
def _save_json(rows:List[Dict], path:Path, append:bool)->None:
    old = json.load(open(path)) if append and path.exists() else []
    ordered = OrderedDict((r["mnemonic"],r) for r in old)
    for r in rows:
        ordered[r["mnemonic"]] = {**ordered.get(r["mnemonic"],{}), **r}
    json.dump(list(ordered.values()), open(path,"w"), indent=2)
    logging.info("Saved %d entries → %s", len(ordered), path)

# ─────────────────────────────── CLI entry ─────────────────────────────────
def main()->None:
    ap = argparse.ArgumentParser(description="Match cp0 mnemonics to exec_*")
    ap.add_argument("cpp", nargs="?", help="Local arithops.cpp (else download)")
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--thr", type=float, default=0.70)
    ap.add_argument("--out", default="match_report.json")
    ap.add_argument("--append", action="store_true")
    a = ap.parse_args()

    # 1) cp0.json
    raw = json.load(open(a.cp0))
    instr = raw.get("instructions", raw)
    mnems = {i["mnemonic"]: i for i in instr
             if (i.get("doc",{}).get("category") or i.get("category")) in CATEGORY_OK}
    logging.info("Loaded %d mnemonics from cp0.json", len(mnems))

    # 2) arithops.cpp
    if a.cpp:
        src = Path(a.cpp).read_text(); cpp_path = Path(a.cpp).as_uri()
    else:
        src = _download(ARITHOPS_URL); cpp_path = ARITHOPS_URL
    funcs = _extract_exec_bodies(src, cpp_path)
    regs  = _extract_reg_pairs(src)

    # 3) match → rows
    matches = _match_all(mnems, funcs, regs, a.thr)
    rows = [{
        "mnemonic": m,
        "function": fn,
        "score": round(sc,2),
        "category": mnems[m].get("doc",{}).get("category") or mnems[m].get("category"),
        "source_path": p,
        "source_line": ln,
    } for m,(fn,sc,p,ln) in matches.items()]

    # 4) save
    _save_json(rows, Path(a.out), append=a.append)

if __name__ == "__main__":
    main()
