#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
import re
from pathlib import Path
from collections import OrderedDict
from typing import Dict, List, Tuple

import requests

# --------------------------------------------------------------------------- #
ARITHOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/arithops.cpp"
)
CATEGORY_OK = {"compare_int"}

# --------------------------------------------------------------------------- #
def _download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  OK (%d bytes)", len(r.text))
    return r.text


def _extract_exec_bodies(src: str, path: str) -> Dict[str, Dict]:
    pat = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
    out: Dict[str, Dict] = {}
    for m in pat.finditer(src):
        fn = m.group(1)
        brace, i = 1, m.end()
        while i < len(src) and brace:
            brace += src[i] == "{"
            brace -= src[i] == "}"
            i += 1
        out[fn] = {
            "body": src[m.end() : i],
            "line": src.count("\n", 0, m.start()) + 1,
            "path": path,
        }
    logging.info("Extracted %d exec_* handlers", len(out))
    return out


# --------------------------------------------------------------------------- #
def _load_compare_int_mnemonics(cp0_path: str) -> List[Tuple[str, str]]:
    data = json.load(open(cp0_path, encoding="utf-8"))
    instr = data.get("instructions", data)
    return [
        (
            i["mnemonic"],
            (i.get("doc", {}).get("category") or i.get("category") or "compare_int"),
        )
        for i in instr
        if (i.get("doc", {}).get("category") or i.get("category")) in CATEGORY_OK
    ]


# --------------------------------------------------------------------------- #
def _build_rows(mnems: List[Tuple[str, str]], funcs: Dict[str, Dict]) -> List[Dict]:
    get_line = lambda fn: funcs[fn]["line"]
    rows: List[Dict] = []

    cmp_int_line = get_line("exec_cmp_int")
    cmp_line = get_line("exec_cmp")
    sgn_line = get_line("exec_sgn")
    isnan_line = get_line("exec_is_nan")
    chknan_line = get_line("exec_chk_nan")

    special = {
        "SGN": ("exec_sgn", sgn_line),
        "ISNAN": ("exec_is_nan", isnan_line),
        "CHKNAN": ("exec_chk_nan", chknan_line),
        "CMP": ("exec_cmp", cmp_line),
    }
    cmp_int_set = {"EQINT", "LESSINT", "GTINT", "NEQINT"}
    cmp_set = {"LESS", "EQUAL", "LEQ", "GEQ", "GREATER", "NEQ"}

    for mnem, cat in mnems:
        if mnem in special:
            fn, line = special[mnem]
        elif mnem in cmp_int_set:
            fn, line = "exec_cmp_int", cmp_int_line
        elif mnem in cmp_set:
            fn, line = "exec_cmp", cmp_line
        else:               
            fn, line = "exec_cmp_int", cmp_int_line

        rows.append(
            {
                "mnemonic": mnem,
                "function": fn,
                "score": 1.0,
                "category": cat,
                "source_path": ARITHOPS_URL,
                "source_line": line,
            }
        )

    logging.info("Prepared %d compare_int rows", len(rows))
    return rows


# --------------------------------------------------------------------------- #
def _save_json(rows: List[Dict], out_path: Path, append: bool) -> None:
    prev = json.load(open(out_path)) if append and out_path.exists() else []
    key = lambda r: (r.get("category", ""), r["mnemonic"])
    ordered: "OrderedDict[Tuple[str, str], Dict]" = OrderedDict((key(r), r) for r in prev)

    for r in rows:
        ordered[key(r)] = {**ordered.get(key(r), {}), **r}

    json.dump(list(ordered.values()), open(out_path, "w"), indent=2)
    logging.info(
        "✅  Saved %d new / updated rows  →  %s  (total %d)",
        len(rows),
        out_path,
        len(ordered),
    )


# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Strict matcher for compare_int mnemonics (append-safe)."
    )
    parser.add_argument("--cp0", default="cp0.json", help="Path to cp0.json")
    parser.add_argument("--out", default="match_report.json", help="Output JSON file")
    parser.add_argument("--append", action="store_true", help="Merge with existing file")
    args = parser.parse_args()

    mnems = _load_compare_int_mnemonics(args.cp0)
    src = _download(ARITHOPS_URL)
    funcs = _extract_exec_bodies(src, ARITHOPS_URL)
    rows = _build_rows(mnems, funcs)
    _save_json(rows, Path(args.out), append=args.append)


# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    main()
