#!/usr/bin/env python3
import re
import sys
import json
import requests
from pathlib import Path
from collections import OrderedDict

# ─── CONFIG ─────────────────────────────────────────────────────────────────────

TONOPS_URL  = (
    "https://raw.githubusercontent.com/"
    "ton-blockchain/ton/"
    "cee4c674ea999fecc072968677a34a7545ac9c4d/"
    "crypto/vm/tonops.cpp"
)
APP_CATEGORIES = {
    'app_actions','app_addr','app_config','app_crypto',
    'app_currency','app_gas','app_global','app_misc','app_rnd'
}

# ─── END CONFIG ─────────────────────────────────────────────────────────────────

def load_app_mnemonics(cp0_json):
    data = json.loads(cp0_json.read_text(encoding="utf-8"))
    ins = data.get("instructions") if isinstance(data, dict) else data
    if not isinstance(ins, list):
        print("❌ cp0_legacy.json must be a list or dict with 'instructions'", file=sys.stderr)
        sys.exit(1)

    apps = [
        e for e in ins
        if isinstance(e, dict)
        and e.get("mnemonic")
        and e.get("doc",{}).get("category") in APP_CATEGORIES
    ]
    print(f"→ Loaded {len(apps)} mnemonics in categories {sorted(APP_CATEGORIES)}")
    return apps

def fetch_tonops():
    print(f"→ Downloading tonops.cpp from {TONOPS_URL}")
    r = requests.get(TONOPS_URL)
    r.raise_for_status()
    src = r.text
    print(f"→ Retrieved {len(src.splitlines())} lines of C++")
    return src

def build_registration_map(src):
    reg = {}
    for mnem, fn in re.findall(
        r'\.mksimple\([^)]*?"([A-Z0-9_]+)"\s*,\s*([a-zA-Z0-9_]+)\)',
        src
    ):
        reg[mnem] = fn
    for mnem, fn in re.findall(
        r'"([A-Z0-9_]+)"\s*,\s*std::bind\(\s*(exec_[A-Za-z0-9_]+)',
        src
    ):
        reg.setdefault(mnem, fn)
    for mnem, fn in re.findall(
        r'"([A-Z0-9_]+)"\s*,\s*(exec_[A-Za-z0-9_]+)',
        src
    ):
        reg.setdefault(mnem, fn)
    for mnem, fn in re.findall(
        r'\.mkfixedrange\([^)]*?dump_1c(?:_and)?\([^,]+,\s*"([A-Z]+)"\)\s*,\s*([A-Za-z0-9_]+)\)',
        src
    ):
        reg.setdefault(mnem, fn)
    print(f"→ Parsed {len(reg)} registrations from tonops.cpp")
    return reg

def find_definitions(src_lines):
    defs = {}
    pat = re.compile(r'^\s*(?:int|void)\s+(exec_[A-Za-z0-9_]+)\s*\(')
    for i, line in enumerate(src_lines, start=1):
        m = pat.match(line)
        if m:
            defs.setdefault(m.group(1), i)
    return defs

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--cp0", default="cp0_legacy.json")
    p.add_argument("--out", default="match-report.json")
    p.add_argument("--append", action="store_true",
                   help="merge into existing match-report.json instead of overwriting")
    args = p.parse_args()

    output_file = Path(args.out)
    cp0_json = Path(args.cp0)

    apps  = load_app_mnemonics(cp0_json)
    src   = fetch_tonops()
    regs  = build_registration_map(src)
    lines = src.splitlines()
    defs  = find_definitions(lines)

    # synthesize missing mappings
    for m,f in [("GETPARAM","exec_get_var_param"),
                ("GETGLOB", "exec_get_global"),
                ("SETGLOB", "exec_set_global")]:
        regs.setdefault(m, f)
    for e in apps:
        m = e["mnemonic"]
        if m.startswith("HASHEXT") and m not in regs:
            regs[m] = "exec_hash_ext"

    # load existing if appending
    existing = {}
    if args.append and output_file.exists():
        for entry in json.loads(output_file.read_text(encoding="utf-8")):
            key = entry["mnemonic"]
            existing[key] = entry

    # build & merge
    output = OrderedDict(existing)  # start from existing
    for e in apps:
        m  = e["mnemonic"]
        fn = regs.get(m)
        def_line = defs.get(fn) if fn else None
        entry = {
            "mnemonic":    m,
            "function":    fn or None,
            "category":    e["doc"]["category"],
            "source_path": TONOPS_URL if def_line else "implicit",
            "source_line": def_line,
        }
        output[m] = entry

    # write out
    output_file.write_text(json.dumps(list(output.values()), indent=2),
                           encoding="utf-8")
    print(f"✔ Wrote mapping to {output_file} ({len(output)} entries)")

    total   = len(output)
    matched = sum(1 for o in output.values() if o["function"])
    print(f"→ Matched handlers: {matched}/{total} ({matched/total*100:.1f}%)")
    if matched < total:
        print("→ Unmatched mnemonics:")
        for o in output.values():
            if not o["function"]:
                print(f"  {o['mnemonic']}")

if __name__ == "__main__":
    main()
