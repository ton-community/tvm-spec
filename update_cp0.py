import json
import re
import requests
from pathlib import Path

def load_cp0_json(json_path):
    with open(json_path, "r") as f:
        return json.load(f)

def download_cpp_from_github(github_raw_url):
    print(f"Fetching {github_raw_url}...")
    response = requests.get(github_raw_url)
    if response.status_code == 200:
        print("File downloaded successfully.")
        return response.text.splitlines()
    else:
        print(f"Failed to download file. Status code: {response.status_code}")
        return []

def update_cp0_with_implementation(cp0_data, matches, cpp_lines, github_raw_url):
    for instr in cp0_data.get("instructions", []):
        mnemonic = instr.get("mnemonic")
        matched_func = matches.get(mnemonic, (None, 0.0))[0]
        if matched_func:
            for idx, line in enumerate(cpp_lines, 1):
                if re.search(rf"\b{re.escape(matched_func)}\s*\(", line):
                    instr["implementation"] = [{
                        "path": github_raw_url,
                        "line": idx,
                        "function_name": matched_func
                    }]
                    break
    return cp0_data

def save_cp0_json(cp0_data, out_path):
    with open(out_path, "w") as f:
        json.dump(cp0_data, f, indent=2)
    print(f"✅ Enriched file saved as {out_path}")

def main():
    cp0_path = Path("cp0.json")
    matches_path = Path("match_report.json")
    enriched_cp0_path = Path("cp0_new.json")
    github_raw_url = "https://raw.githubusercontent.com/ton-blockchain/ton/cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/stackops.cpp"


    with open(matches_path, "r") as f:
        matches_list = json.load(f)
        matches = {m["mnemonic"]: (m["function"], m["score"]) for m in matches_list}

    cp0_data = load_cp0_json(cp0_path)
    cpp_lines = download_cpp_from_github(github_raw_url)
    updated_cp0 = update_cp0_with_implementation(cp0_data, matches, cpp_lines, github_raw_url)
    save_cp0_json(updated_cp0, enriched_cp0_path)

if __name__ == "__main__":
    main()
