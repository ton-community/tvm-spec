#!/usr/bin/env python3
"""Match arithmetic mnemonics from cp0.json to exec_* handlers in arithops.cpp.

Highlights
==========
* **Zero manual alias tables** – every relationship is inferred at runtime.
* Canonical string normalisation (no underscores, no R/C/_VAR suffixes, case‑folded).
* Generic *push‑size* mapping: any `exec_push_*` handler is reachable via
  its **numeric** form only (e.g. `PUSHINT16`, `PUSHINT32`, `PUSHINT64`).
  No extra textual aliases like `PUSHINT_LONG` are emitted.
* Multi‑stage similarity metric (explicit log, substring, fuzzy) keeps matches
  reliable without lowering the threshold.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from fuzzywuzzy import fuzz, utils  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

ARITHOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/arithops.cpp"
)

# ───────────────────────── categories we care about ──────────────────────────
CATEGORY_OK: set[str] = {
    "const_int",
    "arithm_basic",
    "arithm_div",
    "arithm_logical",
    "arithm_quiet",
}

# ──────────────────────── fetch / parse helper functions ─────────────────────

def _download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text


def _extract_exec_bodies(code: str, path: str) -> Dict[str, Dict]:
    """Return mapping exec_* → {body, line, path}."""
    out: Dict[str, Dict] = {}
    pat = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.MULTILINE)
    for m in pat.finditer(code):
        fn = m.group(1)
        start = m.end()
        brace = 1
        i = start
        while i < len(code) and brace:
            brace += code[i] == "{"
            brace -= code[i] == "}"
            i += 1
        body = code[start:i]
        line_nr = code.count("\n", 0, m.start()) + 1
        out[fn] = {"body": body, "line": line_nr, "path": path}
    logging.info("Extracted %d exec_* handlers", len(out))
    return out


def _extract_reg_pairs(code: str) -> Dict[str, str]:
    """Literal MNEMONIC → exec_fn pairs present in mk* macro calls."""
    pairs: Dict[str, str] = {}
    for macro in ("mksimple", "mkfixed", "mkfixedrange", "mkextrange"):
        for m in re.finditer(rf"{macro}\([^)]*\)", code, re.DOTALL):
            s = re.search(r'"([A-Z0-9_\- ]+)"', m.group(0))
            fn = re.search(r"exec_\w+", m.group(0))
            if s and fn:
                pairs[s.group(1).strip()] = fn.group(0)
    return pairs


# ───────────────────────────── name normalisation ────────────────────────────
_SUFFIX_RX = re.compile(r"(?:_?VAR|R|C)$", re.I)


def _strip_suffixes(text: str) -> str:
    return _SUFFIX_RX.sub("", text)


def _canonical(text: str, *, is_fn: bool = False) -> str:
    """Canonical form → upper‑case, no underscores, suffix‑less."""
    if is_fn:
        text = text.removeprefix("exec_")
    text = text.replace("_", "")
    text = _strip_suffixes(text)
    return text.upper()


def _split_name(text: str, *, is_fn: bool = False) -> Tuple[str, str]:
    """Granular breakdown (digits, letters) used by fuzzy metric."""
    if is_fn:
        text = text.removeprefix("exec_")
        text = re.sub(r"(tiny|small|neg|dec|long)", "", text)
    text = _strip_suffixes(text)
    digits = "".join(re.findall(r"\d+", text))
    letters = re.sub(r"[^a-z]", "", text.lower())
    return digits, letters


# ───────────────────── generic PUSHINT‑size augmentation ─────────────────────

_SIZE_HINTS = {
    "tinyint": lambda m: int(m.group(1)),                 # exec_push_tinyint4 → 4
    "smallint": lambda _: 16,
    "int": lambda _: 32,
    "longint": lambda _: 64,
}


def _augment_pushint_aliases(func_by_can: Dict[str, str]) -> None:
    """Expose numeric PUSHINT<size> aliases based on exec handler names."""
    for fn in list(func_by_can.values()):  # snapshot to avoid concurrent modification
        for label, sz_get in _SIZE_HINTS.items():
            if label == "tinyint":
                m = re.match(r"exec_push_tinyint(\d+)", fn)
                if m:
                    size = sz_get(m)
                    func_by_can[f"PUSHINT{size}"] = fn
                continue

            if fn == f"exec_push_{label}":
                size = sz_get(None)
                func_by_can[f"PUSHINT{size}"] = fn
                break


# ───────────────────────────── similarity metric ─────────────────────────────

def _similarity(mnem: str, fn: str, body: str) -> float:
    # 1) explicit log in function body wins
    if re.search(rf"execute\s+{re.escape(mnem)}\b", body, re.I):
        return 1.0

    # 2) substring hit on canonical forms (for «MOD» ↔ «DIVMOD», etc.)
    m_can = _canonical(mnem)
    f_can = _canonical(fn, is_fn=True)
    if m_can in f_can or f_can in m_can:
        return 0.9

    # 3) granular fuzzy metric
    md, ml = _split_name(mnem)
    fd, fl = _split_name(fn, is_fn=True)
    if md and fd and md != fd:
        return 0.0

    raw = fuzz.ratio(ml, fl)
    tok = fuzz.token_set_ratio(utils.full_process(ml), utils.full_process(fl))
    return max(raw, tok) / 100.0


# ─────────────────────────── core matching logic ────────────────────────────

def _match_all(
    mnems: Dict[str, Dict],
    funcs: Dict[str, Dict],
    regs: Dict[str, str],
    thr: float,
) -> Dict[str, Tuple[str, float, str, int]]:
    """Return: mnemonic → (exec_fn, score, path, line)."""

    # O(1) canonical lookup table
    func_by_can: Dict[str, str] = {_canonical(fn, is_fn=True): fn for fn in funcs}
    _augment_pushint_aliases(func_by_can)  # numeric PUSHINT<sz> forms

    out: Dict[str, Tuple[str, float, str, int]] = {}
    for mnem in mnems:
        # a) canonical exact hit --------------------------------------------------
        canon = _canonical(mnem)
        if canon in func_by_can:
            fn = func_by_can[canon]
            info = funcs[fn]
            out[mnem] = (fn, 1.0, info["path"], info["line"])
            continue

        # b) literal registration table -----------------------------------------
        if regs.get(mnem) in funcs:
            fn = regs[mnem]
            info = funcs[fn]
            out[mnem] = (fn, 1.0, info["path"], info["line"])
            continue

        # c) fuzzy / body‑log search --------------------------------------------
        best, best_s, best_path, best_ln = None, 0.0, "", 0
        for fn, info in funcs.items():
            s = _similarity(mnem, fn, info["body"])
            if s > best_s:
                best, best_s, best_path, best_ln = fn, s, info["path"], info["line"]
        out[mnem] = (best, best_s, best_path, best_ln)

    # filter by threshold
    return {k: v for k, v in out.items() if v[0] and v[1] >= thr}

# ─────────────────────────── persistence helper ─────────────────────────────

def _save_json(rows: List[Dict], path: Path, append: bool) -> None:
    old: List[Dict] = []
    if append and path.exists():
        old = json.load(open(path, "r", encoding="utf-8"))

    ordered: "OrderedDict[str, Dict]" = OrderedDict((r["mnemonic"], r) for r in old)
    for r in rows:
        ordered[r["mnemonic"]] = {**ordered.get(r["mnemonic"], {}), **r}

    json.dump(list(ordered.values()), open(path, "w", encoding="utf-8"), indent=2)
    logging.info("Saved %d entries → %s", len(ordered), path)


# ─────────────────────────────────── CLI ─────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Match cp0 mnemonics to exec_* handlers without manual aliases.")
    ap.add_argument("cpp", nargs="?", help="Path to local arithops.cpp (defaults to upstream)")
    ap.add_argument("--cp0", default="cp0.json", help="cp0.json file from TL‑B generator")
    ap.add_argument("--thr", type=float, default=0.70, help="Min similarity (0‑1) to keep a match")
    ap.add_argument("--out", default="match_report.json", help="Destination JSON for matches")
    ap.add_argument("--append", action="store_true", help="Append to existing --out instead of overwrite")
    args = ap.parse_args()

    # 1) load cp0 --------------------------------------------------------------
    raw = json.load(open(args.cp0, encoding="utf-8"))
    instructions = raw.get("instructions", raw)
    mnems = {
        ins["mnemonic"]: ins
        for ins in instructions
        if (ins.get("doc", {}).get("category") or ins.get("category")) in CATEGORY_OK
    }
    logging.info("Found %d relevant mnemonics in cp0.json", len(mnems))

    # 2) get arithops.cpp -----------------------------------------------------
    if args.cpp:
        logging.info("Reading local %s", args.cpp)
        code = Path(args.cpp).read_text(encoding="utf-8")
        cpp_path = Path(args.cpp).as_uri()
    else:
        code = _download(ARITHOPS_URL)
        cpp_path = ARITHOPS_URL

    funcs = _extract_exec_bodies(code, cpp_path)
    regs = _extract_reg_pairs(code)

    # 3) match ---------------------------------------------------------------
    matches = _match_all(mnems, funcs, regs, args.thr)
    rows = [
        {
            "mnemonic": m,
            "function": fn,
            "score": round(sc, 2),
            "category": mnems[m].get("doc", {}).get("category") or mnems[m].get("category"),
            "source_path": path,
            "source_line": line,
        }
        for m, (fn, sc, path, line) in matches.items()
    ]

    # 4) write output -------------------------------------------------------
    _save_json(rows, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
