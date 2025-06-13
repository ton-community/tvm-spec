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

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_CATS: List[str] = ["stack_basic", "stack_complex"]
CAT_ORDER: Dict[str, int] = {c: i for i, c in enumerate(DEFAULT_CATS)}


# ---------------------------------------------------------------------------
# cp0.json helpers
# ---------------------------------------------------------------------------
def load_cp0_json(path: Path | str, cats: List[str]) -> Dict[str, Dict]:
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


def discover_categories(path: Path | str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {ins.get("doc", {}).get("category", "") for ins in data["instructions"]}


# ---------------------------------------------------------------------------
# C++ helpers
# ---------------------------------------------------------------------------
def download_cpp(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  OK (%d bytes)", len(r.text))
    return r.text


def extract_exec_bodies(code: str, src_path: str) -> Dict[str, Dict]:
    """
    Return  exec_name → {"body": str, "line": int, "path": src_path}
    (line numbers are 1-based).
    """
    out: Dict[str, Dict] = {}
    regex = re.compile(
        r"(?:(?:int|void)\s+)(exec_\w+)\s*\([^)]*\)\s*{", re.MULTILINE
    )

    for m in regex.finditer(code):
        name = m.group(1)
        body_start = m.end()
        brace_level = 1
        i = body_start
        while i < len(code) and brace_level:
            if code[i] == "{":
                brace_level += 1
            elif code[i] == "}":
                brace_level -= 1
            i += 1
        body = code[body_start : i]
        line_nr = code.count("\n", 0, m.start()) + 1
        out[name] = {"body": body, "line": line_nr, "path": src_path}
    logging.info("Extracted %d exec_* functions from %s", len(out), src_path)
    return out


def is_reverse_variant(mnem: str, fn: str) -> bool:
    m_rev = mnem.startswith("-") or mnem.lower().endswith("rev")
    f_rev = fn.lower().endswith("rev")
    return m_rev == f_rev


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def match_functions(
    funcs: Dict[str, Dict],
    mnems: Dict[str, Dict],
) -> Dict[str, Tuple[str | None, float, str, str, int]]:
    """
    Return  mnemonic → (best_fn, score, cat, path, line)
    """
    def split(word: str, drop_exec=False) -> Tuple[str, str]:
        if drop_exec and word.startswith("exec_"):
            word = word[5:]
        digits = "".join(re.findall(r"\d+", word))
        base = re.sub(r"[^A-Za-z]", "", word).lower().removesuffix("rev")
        return digits, base

    result = {}
    for mnem, meta in mnems.items():
        m_dig, m_base = split(mnem)
        best_fn, best_sc, best_path, best_line = None, 0.0, "", 0
        for fn, info in funcs.items():
            if not is_reverse_variant(mnem, fn):
                continue
            f_dig, f_base = split(fn, True)
            if m_dig != f_dig:
                continue

            # perfect base match
            if f_base == m_base:
                best_fn, best_sc = fn, 1.0
            else:
                sc = fuzz.ratio(f_base, m_base) / 100
                if sc > best_sc:
                    best_fn, best_sc = fn, sc

            if best_sc == 1.0:
                best_path, best_line = info["path"], info["line"]
                break

        if best_fn:
            best_path, best_line = funcs[best_fn]["path"], funcs[best_fn]["line"]
        result[mnem] = (best_fn, best_sc, meta["category"], best_path, best_line)
    return result


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------
def generate_report(
    matches: Dict[str, Tuple[str | None, float, str, str, int]], thr: float
) -> List[Dict]:
    rows = []
    for m, (fn, sc, cat, path, line) in matches.items():
        if fn and sc >= thr:
            rows.append(
                {
                    "mnemonic": m,
                    "function": fn,
                    "score": round(sc, 2),
                    "category": cat,
                    "source_path": path,
                    "source_line": line,
                }
            )
    return rows


def save_report(rows: List[Dict], outfile: Path, append: bool):
    current: List[Dict] = []
    if append and outfile.exists():
        current = json.load(open(outfile, "r", encoding="utf-8"))

    ordered: "OrderedDict[str, Dict]" = OrderedDict(
        (r["mnemonic"], r) for r in current
    )
    for r in rows:
        if r["mnemonic"] in ordered:
            ordered[r["mnemonic"]].update(r)  # keep position
        else:
            ordered[r["mnemonic"]] = r        # append at bottom

    json.dump(list(ordered.values()), open(outfile, "w", encoding="utf-8"), indent=2)
    logging.info("Report saved → %s  (%d entries)", outfile, len(ordered))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument(
        "--cats", nargs="+", default=None,
        help="'all' for every category or list of categories"
    )
    ap.add_argument(
        "--cpp", nargs="+", default=[
            "https://raw.githubusercontent.com/ton-blockchain/ton"
            "/cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/stackops.cpp"
        ],
        help="One or more GitHub raw URLs with exec_* implementations"
    )
    ap.add_argument("--thr", type=float, default=0.7)
    ap.add_argument("--out", default="match_report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    # categories
    cats = (
        DEFAULT_CATS
        if args.cats is None
        else discover_categories(args.cp0) if args.cats == ["all"]
        else args.cats
    )
    logging.info("Categories: %s", ", ".join(cats))

    # load mnemonics
    mnems = load_cp0_json(args.cp0, cats)

    # gather all exec_* definitions
    funcs: Dict[str, Dict] = {}
    for url in args.cpp:
        funcs.update(extract_exec_bodies(download_cpp(url), url))

    # match + write
    matches = match_functions(funcs, mnems)
    report_rows = generate_report(matches, args.thr)
    save_report(report_rows, Path(args.out), append=args.append)


if __name__ == "__main__":
    main()
