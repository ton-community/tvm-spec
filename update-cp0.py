from __future__ import annotations
import argparse, json, logging, re
from pathlib import Path
from collections import OrderedDict

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def load_match(path: Path) -> dict[str, dict]:
    """mnemonic -> {function, category}"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {d["mnemonic"]: d for d in data}

def load_cp0(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {inst["mnemonic"]: inst for inst in data["instructions"]}

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--popular", default="common-instructions.txt")
    ap.add_argument("--match",   default="match_report.json")
    ap.add_argument("--cp0",     default="cp0.json")
    ap.add_argument("--out",     default="cp0_new.json")
    args = ap.parse_args()

    popular_path = Path(args.popular)
    match_map    = load_match(Path(args.match))
    cp0_map      = load_cp0(Path(args.cp0))

    picked: list[dict] = []
    for raw in popular_path.read_text().splitlines():
        # accept “XCHG_0I 651492”, ignore the count
        mnem = raw.strip().split()[0] if raw.strip() else ""
        if not mnem or mnem.startswith("#"):
            continue
        if mnem not in cp0_map:
            logging.warning("Popular mnemonic %s not found in cp0.json", mnem)
            continue
        if mnem not in match_map:
            logging.warning("Popular mnemonic %s has no match_report entry", mnem)
            continue

        inst = cp0_map[mnem]
        # attach implementation info
        match = match_map[mnem]
        inst["implementation"] = [{
            "path": match["source_path"],
            "line": match["source_line"],
            "function_name": match["function"]
        }] if "source_path" in match else [{
            "path": "<unknown>", "line": 0, "function_name": match["function"]
        }]
        picked.append(inst)

    logging.info("✅ wrote %d instructions → %s", len(picked), args.out)
    json.dump(
    {
        "$schema": "./schema.json",
        "instructions": picked,
        "aliases": []
    },
    open(args.out, "w", encoding="utf-8"),
    indent=2,              # 2-space indent keeps it readable but tight
    separators=(",", ": "), # no extra spaces after “,”, single space after “:”
    ensure_ascii=False
)

if __name__ == "__main__":
    main()


