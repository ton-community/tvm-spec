from pathlib import Path
import json

def extract_aliases(cp0_path: str, out_path: str):
    # load the legacy cp0
    with open(cp0_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # aliases are a top-level array
    aliases = data.get("aliases", [])

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(aliases, f, indent=2, ensure_ascii=False)

    print(f"✅ Extracted {len(aliases)} aliases → {out_path}")


if __name__ == "__main__":
    extract_aliases("cp0_legacy.json", "aliases.json")
