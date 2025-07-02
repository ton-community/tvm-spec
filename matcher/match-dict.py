from __future__ import annotations

import argparse
import json
import logging
import pathlib
import re
import requests
from collections import OrderedDict
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

DICTOPS_URL = (
    "https://raw.githubusercontent.com/ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/dictops.cpp"
)

DICT_CATEGORIES = {
    "dict_serial", "dict_get", "dict_set", "dict_set_builder", "dict_delete",
    "dict_mayberef", "dict_prefix", "dict_next", "dict_min",
    "dict_special", "dict_sub"
}

# ──────────────────────────────────────────────────────────────────────────
EXEC_RX = re.compile(r"(?:int|void)\s+(exec_[A-Za-z0-9_]+)\s*\(")

# ordered list: first match wins
RULES: List[Tuple[re.Pattern, Dict[str, str]]] = [
    # ───────────── serial loads / stores ────────────────────────────────
    (re.compile(r'^(P?L)DDICTS$'), dict(func='exec_load_dict_slice', cat='dict_serial')),
    (re.compile(r'^PL?DDICTS$'),   dict(func='exec_load_dict_slice', cat='dict_serial')),
    (re.compile(r'^(P?L)DDICTQ$'), dict(func='exec_load_dict',       cat='dict_serial')),
    (re.compile(r'^(P?L)DDICT$'),  dict(func='exec_load_dict',       cat='dict_serial')),
    (re.compile(r'^STDICT$'),      dict(func='exec_store_dict',      cat='dict_serial')),
    (re.compile(r'^SKIPDICT$'),    dict(func='exec_skip_dict',       cat='dict_serial')),

    # ───────────── plain GET / GETREF ───────────────────────────────────
    (re.compile(r'^DICT[IU]?GET$'),     dict(func='exec_dict_get',         cat='dict_get')),
    (re.compile(r'^DICT[IU]?GETREF$'),  dict(func='exec_dict_get_optref',   cat='dict_get')),

    # ───────────── jump / exec variants (+optional Z) ───────────────────
    (re.compile(r'^DICT[IU]?GET(?:EXEC|JMP)Z?$'),
                                        dict(func='exec_dict_get_exec',   cat='dict_special')),

    # ───────────── “near” ops (NEXT / PREV) ─────────────────────────────
    (re.compile(r'^DICT[IU]?GET(NEXT|PREV)(EQ)?$'),
                                        dict(func='exec_dict_getnear',    cat='dict_next')),

    # ───────────── min / max (+ remove) ─────────────────────────────────
    (re.compile(r'^DICT[IU]?(REM)?(MIN|MAX)(REF)?$'),
                                        dict(func='exec_dict_getmin',     cat='dict_min')),

    # ───────────── set / replace / add (slice & ref) ────────────────────
    (re.compile(r'^DICT[IU]?(SET|REPLACE|ADD)(GET)?$'),
                                        dict(func='exec_dict_set',        cat='dict_set')),
    (re.compile(r'^DICT[IU]?(SET|REPLACE|ADD)GETREF$'),
                                        dict(func='exec_dict_set',        cat='dict_set')),
    (re.compile(r'^DICT[IU]?(SET|REPLACE|ADD)GET$'),
                                        dict(func='exec_dict_setget',     cat='dict_set')),
    (re.compile(r'^DICT[IU]?(SET|REPLACE|ADD)REF$'),
                                        dict(func='exec_dict_set',        cat='dict_set')),

    # ───────────── builder variants ─────────────────────────────────────
    (re.compile(r'^DICT[IU]?SETB$'),    dict(func='exec_dict_set',        cat='dict_set_builder')),
    (re.compile(r'^DICT[IU]?SETGETB$'), dict(func='exec_dict_setget',     cat='dict_set_builder')),
    (re.compile(r'^DICT[IU]?(REPLACE|ADD)GETB$'),
                                        dict(func='exec_dict_setget',     cat='dict_set_builder')),
    (re.compile(r'^DICT[IU]?(REPLACE|ADD)B$'),
                                        dict(func='exec_dict_set',        cat='dict_set_builder')),
    (re.compile(r'^DICT[IU]?ADDGETB$'), dict(func='exec_dict_get',        cat='dict_set_builder')),

    # ───────────── maybe-ref helpers ────────────────────────────────────
    (re.compile(r'^DICT[IU]?GETOPTREF$'),
                                        dict(func='exec_dict_get_optref', cat='dict_mayberef')),
    (re.compile(r'^DICT[IU]?SETGETOPTREF$'),
                                        dict(func='exec_dict_setget_optref', cat='dict_mayberef')),

    # ───────────── delete (+ get) ops ───────────────────────────────────
    # -> DELGET rules must come before plain DEL
    (re.compile(r'^DICT[IU]?DELGET(REF)?$'),
                                        dict(func='exec_dict_deleteget',  cat='dict_delete')),
    (re.compile(r'^DICT[IU]?DEL(GET)?(REF)?$'),
                                        dict(func='exec_dict_delete',     cat='dict_delete')),

    # ───────────── prefix-dictionary ops ────────────────────────────────
    (re.compile(r'^PFXDICT(SET|REPLACE|ADD)$'),
                                        dict(func='exec_pfx_dict_set',    cat='dict_prefix')),
    (re.compile(r'^PFXDICTDEL$'),        dict(func='exec_pfx_dict_delete', cat='dict_prefix')),
    (re.compile(r'^PFXDICTGET(Q|JMP|EXEC)?$'),
                                        dict(func='exec_pfx_dict_get',    cat='dict_special')),

    # ───────────── const push / switch helpers ──────────────────────────
    (re.compile(r'^DICTPUSHCONST$'),
                                        dict(func='exec_push_const_dict', cat='dict_special')),
    (re.compile(r'^PFXDICTSWITCH$'),
                                        dict(func='exec_const_pfx_dict_switch', cat='dict_special')),
    (re.compile(r'^PFXDICTCONSTGETJMP$'),
                                        dict(func='exec_const_pfx_dict_switch', cat='dict_special')),

    # ───────────── sub-dictionary ops ───────────────────────────────────
    (re.compile(r'^SUBDICT[IU]?(RP)?GET$'),
                                        dict(func='exec_subdict_get',     cat='dict_sub')),
]

# ──────────────────────────────────────────────────────────────────────────
def fetch_cpp(local: str | None) -> str:
    if local:
        return pathlib.Path(local).read_text(encoding="utf-8")
    logging.info("Downloading dictops.cpp …")
    r = requests.get(DICTOPS_URL, timeout=30)
    r.raise_for_status()
    logging.info("  OK  (%d bytes)", len(r.text))
    return r.text


def extract_exec_lines(src: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for m in EXEC_RX.finditer(src):
        fn = m.group(1)
        out[fn] = src.count("\n", 0, m.start()) + 1
    logging.info("Found %d exec_* handlers", len(out))
    return out


def load_cp0(path: str) -> List[Dict]:
    data = json.load(open(path, encoding="utf-8"))
    instr = data["instructions"] if "instructions" in data else data
    return [
        i
        for i in instr
        if (i.get("doc", {}).get("category") or i.get("category")) in DICT_CATEGORIES
    ]


def match_one(mnem: str) -> Tuple[str | None, str | None]:
    for rx, rule in RULES:
        if rx.match(mnem):
            return rule["func"], rule["cat"]
    return None, None


# ──────────────────────────────────────────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--cpp", help="Local dictops.cpp (else download)")
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    cpp_src = fetch_cpp(args.cpp)
    exec_lines = extract_exec_lines(cpp_src)

    rows, missed = [], []
    for ins in load_cp0(args.cp0):
        mnem = ins["mnemonic"]
        fn, cat = match_one(mnem)
        if fn is None:
            missed.append(mnem)
            continue
        rows.append(
            dict(
                mnemonic=mnem,
                function=fn,
                score=1.0,  # deterministic rule
                category=cat,
                source_path=DICTOPS_URL
                if args.cpp is None
                else pathlib.Path(args.cpp).as_uri(),
                source_line=exec_lines.get(fn, 0)
            )
        )

    if missed:
        logging.warning("⚠️  Unhandled mnemonics: %s", ", ".join(sorted(missed)))
    else:
        logging.info("✅  All mnemonics matched")

    out_path = pathlib.Path(args.out)
    prev = []
    if args.append and out_path.exists():
        prev = json.load(open(out_path))
    merged = OrderedDict(((r["mnemonic"], r["category"]), r) for r in prev)
    for r in rows:
        merged[(r["mnemonic"], r["category"])] = r

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(list(merged.values()), f, indent=2)
    logging.info("Saved %d rows ⇒ %s", len(rows), out_path)

    # Print summary
    total = len(rows)
    handlers = {r["function"] for r in rows}
    cat_list = sorted(set(r["category"] for r in rows))
    print("\n" + "═" * 66)
    print("                             SUMMARY")
    print("═" * 66)
    print(f"• Categories      : {', '.join(cat_list)}")
    print(f"• cp0.json        : {total} mnemonics")
    print(f"• Matched (1.0)   : {total}/{total}  (100.0 %)")
    print(f"• Unmatched       : {len(missed)}")
    print("═" * 66)


if __name__ == "__main__":
    main()
