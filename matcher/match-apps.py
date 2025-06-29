#!/usr/bin/env python3
"""
Improved “app_*” matcher – covers *every* mnemonic in the app-category
subset of cp0.json (≈ 96 in tonops.cpp at the commit below).

▪ deterministic regex → exact category / function
▪ manual one-offs  → to catch the weird spellings
▪ fuzzy fallback    → normalised strings, 75 % cutoff
"""

from __future__ import annotations
import argparse, json, logging, pathlib, re, sys, unicodedata
from collections import OrderedDict
from typing import Dict, List, Tuple
import requests

try:
    from rapidfuzz import process, fuzz          # preferred
    _best = lambda q, cs, c: process.extractOne(q, cs,
                                               processor=None,
                                               scorer=fuzz.ratio,
                                               score_cutoff=c)
except ModuleNotFoundError:                      # pragma: no cover
    from fuzzywuzzy import process, fuzz         # type: ignore
    _best = lambda q, cs, c: process.extractOne(q, cs,
                                               scorer=fuzz.ratio,
                                               score_cutoff=c)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

CPP_URL = ("https://raw.githubusercontent.com/ton-blockchain/ton/"
           "cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/tonops.cpp")

APP_CATS = {
    "app_actions","app_addr","app_currency","app_misc","app_crypto",
    "app_global","app_config","app_rnd","app_gas",
}

#──────────────────────────── deterministic layer ───────────────────────────#
_RULES: List[Tuple[re.Pattern, Dict[str, str]]] = [
    # gas / commit
    (re.compile(r'^(ACCEPT|SETGASLIMIT|GASCONSUMED|COMMIT)$'),
        dict(func=lambda m: m.lower(), cat='app_gas')),
    # rng
    (re.compile(r'^RANDU256$'), dict(func='randu256', cat='app_rnd')),
    (re.compile(r'^RAND$'),     dict(func='rand_int', cat='app_rnd')),
    (re.compile(r'^SETRAND$'),  dict(func='set_rand', cat='app_rnd')),
    (re.compile(r'^ADDRAND$'),  dict(func='add_rand', cat='app_rnd')),

    # config-related
    (re.compile(r'^(GETPARAM|CONFIGPARAM)$'),
        dict(func=lambda m:{'GETPARAM':'get_var_param',
                            'CONFIGPARAM':'get_config_param'}[m],
             cat='app_config')),
    (re.compile(r'^CONFIGOPTPARAM$'),
        dict(func='get_config_opt_param',cat='app_config')),
    (re.compile(r'^CONFIGDICT$'), dict(func='get_config_dict', cat='app_config')),
    (re.compile(r'^GLOBALID$'),   dict(func='get_global_id',   cat='app_config')),
    (re.compile(r'^GETGASFEE$'),  dict(func='get_gas_fee',     cat='app_config')),
    (re.compile(r'^GETSTORAGEFEE$'),dict(func='get_storage_fee',cat='app_config')),
    (re.compile(r'^GETFORWARDFEE$'),dict(func='get_forward_fee',cat='app_config')),
    (re.compile(r'^GETPRECOMPILEDGAS$'),dict(func='get_precompiled_gas',cat='app_config')),
    (re.compile(r'^GETORIGINALFWDFEE$'),dict(func='get_original_fwd_fee',cat='app_config')),
    (re.compile(r'^GETGASFEESIMPLE$'),  dict(func='get_gas_fee_simple',cat='app_config')),
    (re.compile(r'^GETFORWARDFEESIMPLE$'),dict(func='get_forward_fee_simple',cat='app_config')),

    # global vars
    (re.compile(r'^GETGLOBVAR$'), dict(func='get_global_var', cat='app_global')),
    (re.compile(r'^GETGLOB$'),    dict(func='get_global',     cat='app_global')),
    (re.compile(r'^SETGLOBVAR$'), dict(func='set_global_var', cat='app_global')),
    (re.compile(r'^SETGLOB$'),    dict(func='set_global',     cat='app_global')),

    # previous blocks
    (re.compile(r'^PREVMCBLOCKS$'), dict(func='prev_mc_blocks', cat='app_misc')),
    (re.compile(r'^PREVKEYBLOCK$'), dict(func='prev_key_block', cat='app_misc')),

    # cryptographic hashes (HASHEXT*, HASHEXTR*, etc.)
    (re.compile(r'^HASH(C|S)U$'),
        dict(func=lambda m:'compute_hash_'+m[4:].lower(), cat='app_crypto')),
    (re.compile(r'^HASHEXT_'),  dict(func=lambda m:'hash_ext_'+m.split('_',1)[1].lower(),
                                     cat='app_crypto')),
    (re.compile(r'^HASHEXTR_'), dict(func=lambda m:'hash_extr_'+m.split('_',1)[1].lower(),
                                     cat='app_crypto')),
    (re.compile(r'^HASHEXTA_'), dict(func=lambda m:'hash_exta_'+m.split('_',1)[1].lower(),
                                     cat='app_crypto')),
    (re.compile(r'^HASHEXTAR_'),dict(func=lambda m:'hash_extar_'+m.split('_',1)[1].lower(),
                                     cat='app_crypto')),

    # SHA / BLS / EC etc (fallback to lower)
    (re.compile(r'^(SHA256U|ECRECOVER|BLS_|RIST255_)'),
        dict(func=lambda m:m.lower(), cat='app_crypto')),

    # signatures
    (re.compile(r'^(CHKSIGN[US]|P256_CHKSIGN[US])$'),
        dict(func=lambda m:m.lower(), cat='app_crypto')),

    # Ristretto large set (validate/add/sub/mul/…)
    (re.compile(r'^(RIST255_|RIST255_Q)'),
        dict(func=lambda m:m.lower(), cat='app_crypto')),

    # cell / slice data size helpers
    (re.compile(r'^(CDATASIZEQ?|SDATASIZEQ?)$'),
        dict(func=lambda m:m.lower(), cat='app_misc')),

    # coins & var-ints (LDGRAMS / STVARINT16 / …)
    (re.compile(r'^(LD|ST)GRAMS$'),        dict(func=lambda m:m.lower(), cat='app_currency')),
    (re.compile(r'^(LD|ST)VAR(INT|UINT)(16|32)$'),
        dict(func=lambda m:m.lower(), cat='app_misc')),

    # address rewriting / parsing
    (re.compile(r'^(LDMSGADDRQ?|PARSEMSGADDRQ?|REWRITE(STD|VAR)ADDRQ?)$'),
        dict(func=lambda m:m.lower(), cat='app_addr')),

    # rawreserve
    (re.compile(r'^RAWRESERVEX?$'), dict(func=lambda m:m.lower(), cat='app_actions')),

    # send / set-code actions
    (re.compile(r'^(SENDRAWMSG|SENDMSG|SETCODE|SETLIBCODE|CHANGELIB)$'),
        dict(func=lambda m:m.lower(), cat='app_actions')),
]

#──────────── fuzzy helpers ────────────#
def _norm(txt: str) -> str:
    """lower-case, strip underscores & non-alnum, fold accents."""
    txt = unicodedata.normalize("NFKD", txt).encode("ascii", "ignore").decode()
    return re.sub(r'[^0-9a-z]', '', txt.lower())

def _fuzzy(mnem: str, choices: List[str], cutoff: int = 75) -> str|None:
    hit = _best(_norm(mnem), [_norm(c) for c in choices], cutoff)
    if hit is None:
        return None
    # we got the *normalised* text; map back to original choice
    idx = [_norm(c) for c in choices].index(hit[0])
    return choices[idx]

_EXEC_RX = re.compile(r'(?:int|void)\s+([a-zA-Z0-9_]+)\s*\(')

#──────────────────────────── core ────────────────────────────#
def _load_cpp(path: str|None) -> Tuple[str, Dict[str,int]]:
    src = pathlib.Path(path).read_text() if path else requests.get(CPP_URL, timeout=30).text
    lines = {m.group(1): src.count("\n", 0, m.start())+1 for m in _EXEC_RX.finditer(src)}
    logging.info("Found %d callable handlers", len(lines))
    return src, lines

def _load_cp0(cp0: str):
    data = json.load(open(cp0))
    instr = data["instructions"] if "instructions" in data else data
    return [i for i in instr if (i.get("doc",{}).get("category") or i.get("category")) in APP_CATS]

def _deterministic(mnem: str):
    for rx, spec in _RULES:
        if rx.match(mnem):
            fn = spec["func"](mnem) if callable(spec["func"]) else spec["func"]
            return fn, spec["cat"]
    return None, None

def _category(entry):   # fallback to whatever cp0 says
    return entry.get("doc",{}).get("category") or entry.get("category") or "unknown"

def _save(rows: List[Dict], dst: pathlib.Path, *, append: bool):
    prev = json.load(open(dst)) if append and dst.exists() else []
    key  = lambda r:(r["mnemonic"], r["category"])
    merged: "OrderedDict[Tuple[str,str],Dict]" = OrderedDict((key(r),r) for r in prev)
    for r in rows:
        merged[key(r)] = r
    dst.write_text(json.dumps(list(merged.values()), indent=2))
    logging.info("✅ saved %d rows → %s", len(rows), dst)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cp0", default="cp0.json")
    ap.add_argument("--cpp")
    ap.add_argument("--out", default="match-report.json")
    ap.add_argument("--append", action="store_true")
    args = ap.parse_args()

    _, exec_lines = _load_cpp(args.cpp)
    choices = list(exec_lines)

    rows, unmatched = [], []

    for entry in _load_cp0(args.cp0):
        mnem = entry["mnemonic"]
        fn, cat = _deterministic(mnem)
        if not fn:
            fn = _fuzzy(mnem, choices)
            cat = _category(entry)
            score = round((_best(_norm(mnem), [_norm(fn)], 0)[1] if fn else 0)/100,2)
        else:
            score = 1.0
        if fn:
            rows.append(dict(
                mnemonic = mnem,
                function = fn,
                score    = score,
                category = cat,
                source_path = CPP_URL if not args.cpp else pathlib.Path(args.cpp).as_uri(),
                source_line = exec_lines.get(fn, 0),
                cp0_path = str(pathlib.Path(args.cp0).resolve()),
            ))
        else:
            unmatched.append(mnem)

    if unmatched:
        logging.warning("Still unmatched: %s", ", ".join(unmatched))
    else:
        logging.info("🎉 all mnemonics matched")

    _save(rows, pathlib.Path(args.out), append=args.append)


    # summary
    print("\n" + "═" * 66)
    print("                             SUMMARY")
    print("═" * 66)
    print(f"• Categories      : {', '.join(sorted(APP_CATS))}")
    print(f"• cp0.json        : {len(rows) + len(unmatched)} mnemonics")
    print(f"• exec_* handlers : {len(set(r['function'] for r in rows))} unique handlers")
    print(f"• Matched (≥ 0.75): {len(rows)}/{len(rows) + len(unmatched)}  ({(len(rows)/(len(rows)+len(unmatched))*100):.1f} %)")
    print(f"• Unmatched       : {len(unmatched)}")
    print("═" * 66)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
