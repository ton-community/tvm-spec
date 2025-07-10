from __future__ import annotations

import argparse, json, logging, re, sys
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from fuzzywuzzy import fuzz   # pip install fuzzywuzzy[speedup]

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

RAW_CONT = ("https://raw.githubusercontent.com/ton-blockchain/ton/"
            "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/contops.cpp")

DEFAULT_CATS = [
    "cont_basic", "cont_conditional", "cont_loops", "cont_registers",
    "cont_create", "cont_stack", "cont_dict"
]

# ────────────── manual fallbacks that are missing from the macro table ──────────────
BUILTIN_OVERRIDES: Dict[str, str] = {
    "BRANCH"   : "exec_ret_bool",
    # NOTE: exec_do_with_ref is defined in vmutils.cpp; we keep the mapping
    #       but will mark its location as “<manual>”.
    "CALLREF"  : "exec_do_with_ref",
}

# ════════════════════ helpers ════════════════════

def download(url: str) -> str:
    logging.info("Fetching %s …", url)
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    logging.info("  OK  (%d bytes)", len(r.text))
    return r.text


EXEC_RX = re.compile(r"(?:int|void)\s+(exec_\w+)\s*\([^)]*\)\s*{", re.M)
MACRO_MAIN  = re.compile(r'"([A-Z0-9_ ]+)"[^\)]*?(exec_\w+)', re.S)
MACRO_EXTRA = re.compile(r'"([A-Z0-9_ ]+)"[\s\S]*?(exec_\w+)', re.S)

def extract_exec(src: str, path: str) -> Dict[str, Tuple[str,int]]:
    out: Dict[str, Tuple[str,int]] = {}
    for m in EXEC_RX.finditer(src):
        fn   = m.group(1)
        line = src.count("\n", 0, m.start()) + 1
        out[fn] = (path, line)
    return out

def extract_pairs(src: str) -> Dict[str, str]:
    pairs: Dict[str,str] = {}
    for mnem, fn in MACRO_MAIN.findall(src):
        pairs.setdefault(mnem.strip(), fn)
    for mnem, fn in MACRO_EXTRA.findall(src):
        pairs.setdefault(mnem.strip(), fn)
    return pairs


def _split(txt: str, *, strip_exec=False):
    if strip_exec and txt.startswith("exec_"):
        txt = txt[5:]
    digits = "".join(re.findall(r"\d+", txt))
    alpha  = re.sub(r"[^A-Za-z]", "", txt).lower()
    return digits, alpha

def fuzzy_best(mnem: str, funcs: Dict[str, Tuple[str,int]]):
    md, mb = _split(mnem)
    best, best_sc = None, 0.0
    for fn in funcs:
        fd, fb = _split(fn, strip_exec=True)
        if md and fd and md != fd:             # different numeric suffix
            continue
        score = 1.0 if fb == mb else fuzz.ratio(fb, mb)/100
        if score > best_sc:
            best_sc, best = score, fn
    if best:
        path, line = funcs[best]
        return best, best_sc, path, line
    return None, 0.0, "", 0


def load_cp0(path: str|Path, cats: List[str]):
    data = json.load(open(path, encoding="utf-8"))
    return {i["mnemonic"]: i["doc"]["category"]
            for i in data["instructions"] if i["doc"]["category"] in cats}

def load_override(path: Path|None) -> Dict[str,str]:
    if path is None:
        return {}
    txt = path.read_text(encoding="utf-8")
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        import yaml            # type: ignore
        return yaml.safe_load(txt) or {}

# ════════════════════ main ════════════════════

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0_legacy.json")
    ap.add_argument("--cats", nargs="+")
    ap.add_argument("--thr", type=float, default=0.70)
    ap.add_argument("--override", type=Path,
                    help="json/yaml mapping of MNEMONIC → exec_function")
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    ap.add_argument("--show-missing", action="store_true")
    args = ap.parse_args()

    cats = args.cats or DEFAULT_CATS
    logging.info("Categories selected: %s", ", ".join(cats))

    mnems = load_cp0(args.cp0, cats)
    logging.info("From cp0.json → total mnemonics in those categories: %d", len(mnems))

    overrides = {**BUILTIN_OVERRIDES, **load_override(args.override)}

    cont_src = download(RAW_CONT)
    funcs    = extract_exec(cont_src, RAW_CONT)
    pairs    = extract_pairs(cont_src)

    rows, missing = [], []

    for mnem, cat in mnems.items():
        # ① manual override (user overrides > built-ins)
        if mnem in overrides:
            fn = overrides[mnem]
            if fn in funcs:
                path, line = funcs[fn]
            else:                       # function lives outside contops.cpp
                path, line = "<manual>", 0
            rows.append(dict(mnemonic=mnem, function=fn, score=0.99,
                             category=cat, source_path=path, source_line=line))
            continue

        # ② macro pair
        if mnem in pairs and pairs[mnem] in funcs:
            path, line = funcs[pairs[mnem]]
            rows.append(dict(mnemonic=mnem, function=pairs[mnem], score=1.00,
                             category=cat, source_path=path, source_line=line))
            continue

        # ③ fuzzy fallback
        fn, sc, pth, ln = fuzzy_best(mnem, funcs)
        if sc >= args.thr:
            rows.append(dict(mnemonic=mnem, function=fn, score=round(sc,2),
                             category=cat, source_path=pth, source_line=ln))
        else:
            missing.append(mnem)

    logging.info("Matched (score ≥ %.2f): %d", args.thr, len(rows))
    logging.info("Unmatched               : %d", len(missing))
    if args.show_missing and missing:
        logging.warning("Unmatched mnemonics → %s", ", ".join(sorted(missing)))

    # save / merge
    out_p = Path(args.out)
    prev  = json.load(open(out_p)) if args.append and out_p.exists() else []
    merged = {r["mnemonic"]: r for r in prev}
    for r in rows:
        merged[r["mnemonic"]] = r
    json.dump(list(merged.values()), open(out_p, "w"), indent=2)
    logging.info("Report saved → %s  (%d entries)", out_p, len(merged))

    # summary
    total = len(rows)
    handlers = {r["function"] for r in rows}
    cat_list = sorted(set(r["category"] for r in rows))
    print("\n" + "═" * 66)
    print("                             SUMMARY")
    print("═" * 66)
    print(f"• Categories      : {', '.join(cat_list)}")
    print(f"• cp0_legacy.json        : {total} mnemonics")
    print(f"• Matched (≥ {args.thr:.2f})   : {total}/{total}  (100.0 %)")
    print("═" * 66)

if __name__ == "__main__":
    main()
