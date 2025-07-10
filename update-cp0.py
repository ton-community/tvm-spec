from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


# ───────────────────────────── helpers ──────────────────────────────────
def load_match(path: Path) -> Dict[str, dict]:
    with path.open(encoding="utf-8") as f:
        return {d["mnemonic"]: d for d in json.load(f)}


def load_cp0(path: Path) -> Dict[str, dict]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return {inst["mnemonic"]: inst for inst in data["instructions"]}


def is_primitive(v):  # small util
    return isinstance(v, (str, int, float, bool)) or v is None


def is_flat(obj: dict) -> bool:
    if len(obj) > 3:
        return False
    for v in obj.values():
        if isinstance(v, dict) and v:
            return False
        if isinstance(v, list) and any(isinstance(e, dict) for e in v):
            return False
        if not (is_primitive(v) or v in ({}, [])):
            return False
    return True


def to_compact(data, lvl=0, indent=2):
    pad = " " * (lvl * indent)
    if isinstance(data, dict):
        if not data:
            return "{}"
        if is_flat(data):
            inner = ", ".join(
                f"{json.dumps(k)}: {to_compact(v, 0, indent)}"
                for k, v in data.items()
            )
            return f"{{ {inner} }}"
        body = ",\n".join(
            f"{pad}{' ' * indent}{json.dumps(k)}: {to_compact(v, lvl + 1, indent)}"
            for k, v in data.items()
        )
        return "{\n" + body + f"\n{pad}}}"
    if isinstance(data, list):
        if not data:
            return "[]"
        body = ",\n".join(
            f"{pad}{' ' * indent}{to_compact(x, lvl + 1, indent)}" for x in data
        )
        return "[\n" + body + f"\n{pad}]"
    return json.dumps(data)


def write_compact_json(obj, path: Path, indent=2):
    path.write_text(to_compact(obj, 0, indent) + "\n", encoding="utf-8")


# ───────────────────────────── main ─────────────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--popular", default="common-instructions.txt",
                    help="text file with mnemonics (one per line)")
    ap.add_argument("--match", default="match-report.json",
                    help="file produced by matcher scripts")
    ap.add_argument("--cp0", default="cp0_legacy.json",
                    help="canonical legacy cp0.json")
    ap.add_argument("--out", default="cp0.json",
                    help="where to save the filtered cp0 subset")
    args = ap.parse_args()

    popular_path = Path(args.popular)
    match_map = load_match(Path(args.match))
    cp0_map = load_cp0(Path(args.cp0))

    picked: List[dict] = []
    missing: List[str] = []

    for raw in popular_path.read_text().splitlines():
        token = raw.strip()
        if not token or token.startswith("#"):
            continue
        mnem = token.split()[0]

        if mnem not in cp0_map or mnem not in match_map:
            missing.append(mnem)
            continue

        inst = cp0_map[mnem]
        match = match_map[mnem]
        src = match.get("source_path", "<unknown>")

        inst["implementation"] = [{
            "file": Path(src).name,
            "path": src,
            "line": match.get("source_line", 0),
            "function_name": match["function"]
        }]
        picked.append(inst)

    # ── summary ─────────────────────────────────────────────────────────
    logging.info(
        "cp0 contains: %d  •  match_report: %d  →  picked: %d  •  missing: %d",
        len(cp0_map), len(match_map), len(picked), len(missing)
    )

    if missing:
        logging.warning("The following mnemonics were requested but NOT exported:")
        for m in sorted(missing):
            phrase = ("absent in cp0_legacy.json" if m not in cp0_map
                      else "absent in match-report.json")
            logging.warning("  %-20s • %s", m, phrase)
        # exit with 1 so CI fails when something is missing
        sys.exit(1)

    # ── write compact json ─────────────────────────────────────────────
    write_compact_json({
        "$schema": "./schema.json",
        "instructions": picked,
        "aliases": []
    }, Path(args.out))
    logging.info("✅ wrote %d instructions → %s", len(picked), args.out)


if __name__ == "__main__":
    main()
