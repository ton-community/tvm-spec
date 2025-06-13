from __future__ import annotations
import argparse, json, logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def load_match(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {d["mnemonic"]: d for d in data}

def load_cp0(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {inst["mnemonic"]: inst for inst in data["instructions"]}

# ─────────────────────── formatting helpers ────────────────────────
def _is_primitive(val) -> bool:
    return isinstance(val, (str, int, float, bool)) or val is None

def _is_flat(obj: dict) -> bool:
    """Flat = ≤ 3 keys and values are primitive or empty list/dict."""
    if len(obj) > 3:
        return False
    for v in obj.values():
        if isinstance(v, dict) and v:
            return False
        if isinstance(v, list) and any(isinstance(e, dict) for e in v):
            return False
        if not (_is_primitive(v) or v == [] or v == {}):
            return False
    return True

def _to_compact(data, lvl=0, indent=2) -> str:
    pad = " " * (lvl * indent)

    if isinstance(data, dict):
        if not data:
            return "{}"
        if _is_flat(data):
            inner = ", ".join(
                f"{json.dumps(k)}: {_to_compact(v, 0, indent)}"
                for k, v in data.items()
            )
            return f"{{ {inner} }}"
        body = ",\n".join(
            f"{pad}{' ' * indent}{json.dumps(k)}: {_to_compact(v, lvl+1, indent)}"
            for k, v in data.items()
        )
        return "{\n" + body + f"\n{pad}}}"

    if isinstance(data, list):
        if not data:
            return "[]"
        body = ",\n".join(
            f"{pad}{' ' * indent}{_to_compact(x, lvl+1, indent)}"
            for x in data
        )
        return "[\n" + body + f"\n{pad}]"

    return json.dumps(data)

def write_compact_json(obj, path: Path, indent: int = 2):
    with open(path, "w", encoding="utf-8") as f:
        f.write(_to_compact(obj, 0, indent) + "\n")

# ───────────────────────────── main logic ─────────────────────────────
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--popular", default="common-instructions.txt")
    ap.add_argument("--match",   default="match_report.json")
    ap.add_argument("--cp0",     default="cp0.json")
    ap.add_argument("--out",     default="cp0_new.json")
    args = ap.parse_args()

    match_map = load_match(Path(args.match))
    cp0_map   = load_cp0(Path(args.cp0))
    picked: list[dict] = []

    for raw in Path(args.popular).read_text().splitlines():
        mnem = raw.strip().split()[0] if raw.strip() else ""
        if not mnem or mnem.startswith("#"):
            continue
        if mnem not in cp0_map:
            logging.warning("Popular mnemonic %s not found in cp0.json", mnem)
            continue
        if mnem not in match_map:
            logging.warning("Popular mnemonic %s has no match_report entry", mnem)
            continue

        inst  = cp0_map[mnem]
        match = match_map[mnem]
        inst["implementation"] = [{
            "path": match.get("source_path", "<unknown>"),
            "line": match.get("source_line", 0),
            "function_name": match["function"]
        }]
        picked.append(inst)

    logging.info("✅ wrote %d instructions → %s", len(picked), args.out)

    final_obj = {
        "$schema": "./schema.json",
        "instructions": picked,
        "aliases": []
    }
    write_compact_json(final_obj, Path(args.out), indent=2)

if __name__ == "__main__":
    main()
