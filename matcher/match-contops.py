from __future__ import annotations

import argparse
import json
import logging
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Set, Tuple

import requests
from fuzzywuzzy import fuzz

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

RAW_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/contops.cpp"
)
DEFAULT_CATS = [
    "cont_basic",
    "cont_conditional",
    "cont_loops",
    "cont_registers",
]

# ───────────────────────────────
# 🔸 MANUAL MAP  (one-offs) 🔸
MANUAL_MAP: Dict[str, str] = {
    "CALLREF": "exec_do_with_ref",
}
# ───────────────────────────────


# ───────────────────────────── cp0 helpers ─────────────────────────────
def _load_cp0(path: str | Path, cats: List[str]) -> Dict[str, Dict]:
    data = json.load(open(path, encoding="utf-8"))
    return {
        ins["mnemonic"]: {
            "description": ins.get("doc", {}).get("description", ""),
            "category": ins.get("doc", {}).get("category", ""),
        }
        for ins in data["instructions"]
        if ins.get("doc", {}).get("category") in cats
    }


def _discover_all_cats(path: str | Path) -> Set[str]:
    data = json.load(open(path, encoding="utf-8"))
    return {ins.get("doc", {}).get("category", "") for ins in data["instructions"]}


# ────────────────────────── download + C++ helpers ─────────────────────────
def _download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  OK (%d bytes)", len(r.text))
    return r.text


def _extract_exec_bodies(src: str, src_path: str) -> Dict[str, Dict]:
    rx = re.compile(
        r"(?:template<[^>]+>\s*)?" r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*\{", re.M
    )
    out: Dict[str, Dict] = {}
    for m in rx.finditer(src):
        fn = m.group(1)
        line = src.count("\n", 0, m.start()) + 1
        out[fn] = {"line": line, "path": src_path}
    logging.info("Extracted %d exec_* handlers", len(out))
    return out


def _find_func_line(src: str, name: str) -> int | None:
    m = re.search(rf"\b{name}\s*\(", src)
    return None if m is None else src.count("\n", 0, m.start()) + 1


# ───────── explicit “MNEMONIC” ↔ exec_* pairs from OpcodeInstr macros ────────
_MACRO_RX_MAIN = re.compile(r'"([A-Z0-9_ ]+)"[^\)]*?(exec_[A-Za-z0-9_]+)', re.S)
_MACRO_RX_EXTRA = re.compile(r'"([A-Z0-9_ ]+)"[\s\S]*?(exec_[A-Za-z0-9_]+)', re.S)


def _extract_reg_pairs(src: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for mnem, fn in _MACRO_RX_MAIN.findall(src):
        pairs.setdefault(mnem.strip(), fn)
    for mnem, fn in _MACRO_RX_EXTRA.findall(src):
        pairs.setdefault(mnem.strip(), fn)
    logging.info("Found %d explicit pairs from OpcodeInstr macros", len(pairs))
    return pairs


# ─────────────────────────── override helper ───────────────────────────
def _override_from_pattern(mnem: str) -> str | None:
    return "exec_ret_bool" if mnem.upper() == "BRANCH" else None


# ─────────────────────────── fuzzy helpers ────────────────────────────
def _split(txt: str, *, strip_exec: bool = False) -> Tuple[str, str]:
    if strip_exec and txt.startswith("exec_"):
        txt = txt[5:]
    digits = "".join(re.findall(r"\d+", txt))
    base = re.sub(r"[^A-Za-z]", "", txt).lower()
    return digits, base


def _best_match(
    mnem: str, funcs: Dict[str, Dict]
) -> Tuple[str | None, float, str, int]:
    m_d, m_b = _split(mnem)
    best_fn, best_s, best_p, best_l = None, 0.0, "", 0
    for fn, info in funcs.items():
        f_d, f_b = _split(fn, strip_exec=True)
        if m_d and f_d and m_d != f_d:
            continue
        if f_b == m_b:
            return fn, 1.0, info["path"], info["line"]
        s = fuzz.ratio(f_b, m_b) / 100
        if s > best_s:
            best_fn, best_s, best_p, best_l = fn, s, info["path"], info["line"]
    return best_fn, best_s, best_p, best_l


# ───────────────────────────── master matcher ──────────────────────────────
def _match_all(
    mnems: Dict[str, Dict], funcs: Dict[str, Dict], regs: Dict[str, str], raw_src: str
) -> List[Dict]:
    rows: List[Dict] = []
    for mnem, meta in mnems.items():
        # 0) literal manual map
        if mnem in MANUAL_MAP:
            fn = MANUAL_MAP[mnem]
            info = funcs.get(fn) or {
                "path": RAW_URL,
                "line": _find_func_line(raw_src, fn) or 0,
            }
            rows.append(
                {
                    "mnemonic": mnem,
                    "function": fn,
                    "score": 1.0,
                    "category": meta["category"],
                    "source_path": info["path"],
                    "source_line": info["line"],
                }
            )
            continue

        # 1) macro-table exact
        if mnem in regs:
            fn = regs[mnem]
            info = funcs.get(fn) or {
                "path": RAW_URL,
                "line": _find_func_line(raw_src, fn) or 0,
            }
            rows.append(
                {
                    "mnemonic": mnem,
                    "function": fn,
                    "score": 1.0,
                    "category": meta["category"],
                    "source_path": info["path"],
                    "source_line": info["line"],
                }
            )
            continue

        # 2) rule-based override
        fn = _override_from_pattern(mnem)
        if fn and fn in funcs:
            info = funcs[fn]
            rows.append(
                {
                    "mnemonic": mnem,
                    "function": fn,
                    "score": 0.9,
                    "category": meta["category"],
                    "source_path": info["path"],
                    "source_line": info["line"],
                }
            )
            continue

        # 3) fuzzy fallback
        fn, sc, p, ln = _best_match(mnem, funcs)
        if fn:
            rows.append(
                {
                    "mnemonic": mnem,
                    "function": fn,
                    "score": round(sc, 2),
                    "category": meta["category"],
                    "source_path": p,
                    "source_line": ln,
                }
            )
    return rows


# ─────────────────────────── JSON persistence ───────────────────────────
def _save_json(rows: List[Dict], out_path: Path, append: bool) -> None:
    prev = json.load(open(out_path)) if append and out_path.exists() else []

    # merge key = (category, mnemonic)  → safe dedup across categories
    def key(r: Dict) -> Tuple[str, str]:
        return (r.get("category", ""), r["mnemonic"])

    ordered: "OrderedDict[Tuple[str, str], Dict]" = OrderedDict((key(r), r) for r in prev)
    for r in rows:
        ordered[key(r)] = {**ordered.get(key(r), {}), **r}

    json.dump(list(ordered.values()), open(out_path, "w"), indent=2)
    logging.info(
        "Report saved → %s  (now %d total rows, %d new/updated)",
        out_path,
        len(ordered),
        len(rows),
    )


# ─────────────────────────────────── CLI ──────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--cats", nargs="+", default=None)
    ap.add_argument("--thr", type=float, default=0.70)
    ap.add_argument("--out", default="cont_match.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    cats = (
        DEFAULT_CATS
        if args.cats is None
        else sorted(_discover_all_cats(args.cp0))
        if args.cats == ["all"]
        else args.cats
    )
    logging.info("Categories: %s", ", ".join(cats))

    mnems = _load_cp0(args.cp0, cats)
    logging.info("Loaded %d mnemonics", len(mnems))

    src = _download(RAW_URL)
    funcs = _extract_exec_bodies(src, RAW_URL)
    regs = _extract_reg_pairs(src)

    rows = [r for r in _match_all(mnems, funcs, regs, src) if r["score"] >= args.thr]
    logging.info("Matched %d mnemonics (≥ %.2f)", len(rows), args.thr)

    _save_json(rows, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
