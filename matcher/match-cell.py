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
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/cellops.cpp"
)
DEFAULT_CATS = ["cell_build", "cell_parse", "const_data"]

# ──────────────────────────────────────────────────────────────────────────────
# cp0.json helpers
# ──────────────────────────────────────────────────────────────────────────────
def _load_cp0(path: Path | str, cats: List[str]) -> Dict[str, Dict]:
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

# ──────────────────────────────────────────────────────────────────────────────
# download / C++ helpers
# ──────────────────────────────────────────────────────────────────────────────
def _download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  OK (%d bytes)", len(r.text))
    return r.text


def _extract_exec_bodies(src: str, src_path: str) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    rx = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
    for m in rx.finditer(src):
        fn = m.group(1)
        start = m.end()
        brace = 1
        i = start
        while i < len(src) and brace:
            brace += src[i] == "{"
            brace -= src[i] == "}"
            i += 1
        line = src.count("\n", 0, m.start()) + 1
        out[fn] = {"body": src[start:i], "line": line, "path": src_path}
    logging.info("Extracted %d exec_* handlers", len(out))
    return out

# ──────────────────────────────────────────────────────────────────────────────
# ❶  explicit “MNEMONIC” ←→ exec_* pairs from the macro table
#     (now also returns the line number of the macro)
# ──────────────────────────────────────────────────────────────────────────────
_MACRO_RX = re.compile(
    r'"([A-Z0-9_ ]+)"'          # mnemonic literal
    r'[^\)]*?'                  # any chars inside the macro arg list
    r'(exec_[A-Za-z0-9_]+)',    # first exec_* before the ')'
    re.S,
)


def _extract_reg_pairs(src: str) -> Dict[str, Tuple[str, int]]:
    pairs: Dict[str, Tuple[str, int]] = {}
    for m in _MACRO_RX.finditer(src):
        mnem, fn = m.group(1).strip(), m.group(2)
        pairs.setdefault(mnem, (fn, src.count("\n", 0, m.start()) + 1))
    logging.info("Found %d explicit pairs from OpcodeInstr macros", len(pairs))
    return pairs

# ──────────────────────────────────────────────────────────────────────────────
# ❷  tiny rule-based override for tricky names
# ──────────────────────────────────────────────────────────────────────────────
def _override_from_pattern(mnem: str) -> str | None:
    up = mnem.upper()

    # int / uint stores & loads
    if up.startswith(("STI", "STU")):
        if "X" in up:
            return "exec_store_int_var"
        if up.endswith("ALT"):
            return "exec_store_int_fixed"
        return "exec_store_int"
    if up.startswith(("LDI", "LDU")):
        if "X" in up:
            return "exec_load_int_var"
        return "exec_load_int_fixed"
    if up.startswith(("PLD", "PLDU", "PLDI")):
        return "exec_load_int_fixed2"

    # builder helpers
    if up.startswith("BCHKBITS"):
        return "exec_builder_chk_bits"
    if up.startswith(("BCHK", "BCHKBIT")):
        return "exec_builder_chk_bits_refs"

    # builder ref / builder reverse helpers
    if up.startswith("STBREF"):
        return (
            "exec_store_builder_as_ref_rev"
            if "R" in up[6:]
            else "exec_store_builder_as_ref"
        )
    if up.startswith("STBR"):
        return "exec_store_builder_rev"
    if up == "STB":
        return "exec_store_builder"

    # ref / slice store variants
    if up.startswith("STREF"):
        return "exec_store_ref_rev" if "R" in up[5:] else "exec_store_ref"
    if up.startswith("STSLICE"):
        return "exec_store_slice_rev" if "R" in up[7:] else "exec_store_slice"

    return None

# ──────────────────────────────────────────────────────────────────────────────
# fuzzy helpers
# ──────────────────────────────────────────────────────────────────────────────
def _split(txt: str, *, strip_exec: bool = False) -> Tuple[str, str]:
    if strip_exec and txt.startswith("exec_"):
        txt = txt[5:]
    digits = "".join(re.findall(r"\d+", txt))
    base = re.sub(r"[^A-Za-z]", "", txt).lower().removesuffix("rev")
    return digits, base


def _same_reverse_flag(mnem: str, fn: str) -> bool:
    mn_rev = mnem.lower().endswith("rev") or mnem.startswith("-")
    fn_rev = fn.lower().endswith("rev")
    return mn_rev == fn_rev


def _best_match(
    mnem: str, funcs: Dict[str, Dict]
) -> Tuple[str | None, float, str, int]:
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

# ──────────────────────────────────────────────────────────────────────────────
# master matcher
# ──────────────────────────────────────────────────────────────────────────────
def _match_all(
    mnems: Dict[str, Dict], funcs: Dict[str, Dict], regs: Dict[str, Tuple[str, int]]
) -> List[Dict]:
    rows: List[Dict] = []
    for mnem, meta in mnems.items():
        # 1) exact from macro table
        if mnem in regs:
            fn_name, macro_line = regs[mnem]
            if fn_name in funcs:
                f = funcs[fn_name]
                rows.append(
                    {
                        "mnemonic": mnem,
                        "function": fn_name,
                        "score": 1.0,
                        "category": meta["category"],
                        "source_path": f["path"],
                        "source_line": f["line"],
                    }
                )
            else:  # handler body is in another file – still record the match
                rows.append(
                    {
                        "mnemonic": mnem,
                        "function": fn_name,
                        "score": 1.0,
                        "category": meta["category"],
                        "source_path": RAW_URL,
                        "source_line": macro_line,
                    }
                )
            continue

        # 2) rule-based override
        ov = _override_from_pattern(mnem)
        if ov and ov in funcs:
            f = funcs[ov]
            rows.append(
                {
                    "mnemonic": mnem,
                    "function": ov,
                    "score": 0.9,
                    "category": meta["category"],
                    "source_path": f["path"],
                    "source_line": f["line"],
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

# ──────────────────────────────────────────────────────────────────────────────
# JSON persistence
# ──────────────────────────────────────────────────────────────────────────────
def _save_json(rows: List[Dict], out_path: Path, append: bool) -> None:

    prev: List[Dict] = json.load(open(out_path)) if append and out_path.exists() else []

    key = lambda r: (r["mnemonic"], r.get("category", ""))          # (<MN>, <CAT>)
    ordered: "OrderedDict[tuple[str, str], Dict]" = OrderedDict((key(r), r) for r in prev)

    for r in rows:
        k = key(r)
        if k in ordered:
            ordered[k].update(r)   # refresh with newest data
        else:
            ordered[k] = r

    json.dump(list(ordered.values()), open(out_path, "w"), indent=2)
    logging.info("Report saved → %s  (%d entries)", out_path, len(ordered))


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument(
        "--cats", nargs="+", default=None, help="'all' or list of categories"
    )
    ap.add_argument("--thr", type=float, default=0.70)
    ap.add_argument("--out", default="match_report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    cats = (
        DEFAULT_CATS
        if args.cats is None
        else sorted(_discover_all_cats(args.cp0)) if args.cats == ["all"] else args.cats
    )
    logging.info("Categories: %s", ", ".join(cats))

    mnems = _load_cp0(args.cp0, cats)
    logging.info("Loaded %d mnemonics", len(mnems))

    src = _download(RAW_URL)
    funcs = _extract_exec_bodies(src, RAW_URL)
    regs = _extract_reg_pairs(src)

    rows = [r for r in _match_all(mnems, funcs, regs) if r["score"] >= args.thr]
    logging.info("Matched %d mnemonics (≥ %.2f)", len(rows), args.thr)

    _save_json(rows, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
