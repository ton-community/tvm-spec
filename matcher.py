import json
import re
import requests
from pathlib import Path
from fuzzywuzzy import fuzz
import logging

logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# Load JSON
# ---------------------------------------------------------------------------
def load_cp0_json(json_path):
    with open(json_path, "r") as f:
        data = json.load(f)
    return {i["mnemonic"]: i.get("description", "") for i in data.get("instructions", [])}

# ---------------------------------------------------------------------------
# Download C++ file from GitHub
# ---------------------------------------------------------------------------
def download_cpp_from_github(github_raw_url):
    logging.info(f"Fetching {github_raw_url}...")
    response = requests.get(github_raw_url)
    if response.status_code == 200:
        logging.info("File downloaded successfully.")
        return response.text
    else:
        logging.error(f"Failed to download file. Status code: {response.status_code}")
        return ""

# ---------------------------------------------------------------------------
# Extract C++ functions
# ---------------------------------------------------------------------------
def extract_functions_cpp(code_text):
    functions = re.findall(
        r"(?:int|void)\s+(exec_\w+)\s*\(.*?\)\s*{([^{}]*(?:{[^{}]*}[^{}]*)*)}",
        code_text,
        re.DOTALL,
    )
    logging.info(f"Extracted {len(functions)} functions from source code.")
    return {name: body for name, body in functions}

# ---------------------------------------------------------------------------
# Reverse-flag helper  (leading “-” OR trailing “REV”)
# ---------------------------------------------------------------------------
def is_reverse_variant(mnemonic: str, func_name: str) -> bool:
    m_rev = mnemonic.startswith("-") or mnemonic.lower().endswith("rev")
    f_rev = re.search(r"rev$", func_name, re.IGNORECASE) is not None
    return m_rev == f_rev

# ---------------------------------------------------------------------------
# Core matcher
# ---------------------------------------------------------------------------
def match_functions_to_mnemonics(func_map, mnemonics):
    def split_name(name: str, drop_exec=False):
        if drop_exec and name.startswith("exec_"):
            name = name[5:]
        digits  = "".join(re.findall(r"\d+", name))
        letters = re.sub(r"[^A-Za-z]", "", name).lower()
        letters = re.sub(r"rev$", "", letters)
        return digits, letters

    matches = {}
    for mnemonic, desc in mnemonics.items():
        m_digits, m_base = split_name(mnemonic)
        best_match, best_score = None, 0.0

        for func_name, body in func_map.items():
            if not is_reverse_variant(mnemonic, func_name):
                continue

            f_digits, f_base = split_name(func_name, drop_exec=True)
            if m_digits != f_digits:
                continue

            if f_base == m_base:
                best_match, best_score = func_name, 1.0
                break

            score = fuzz.ratio(f_base, m_base) / 100.0

            if f_base.startswith("reverse") and m_base.startswith("rev"):
                score += 0.25

            if score > best_score:
                best_match, best_score = func_name, score

            if desc and best_score < 0.9:
                overlap = len(set(desc.lower().split()) & set(body.lower().split()))
                desc_score = overlap / max(len(desc.split()), 1)
                if desc_score > best_score:
                    best_match, best_score = func_name, desc_score

        matches[mnemonic] = (best_match, best_score)
    return matches


def generate_report(matches, threshold=0.7):
    return [
        {
            "mnemonic": m,
            "function": f,
            "score": round(s, 2),
            "status": "✅ Matched" if f and s >= threshold else "⚠️ Review Needed",
        }
        for m, (f, s) in matches.items()
    ]

def save_report(report, output_path):
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    logging.info(f"Report saved to {output_path}")


def main():
    cp0_path = Path("cp0.json")
    out_path = Path("match_report.json")
    github_raw_url = "https://raw.githubusercontent.com/ton-blockchain/ton/cee4c674ea999fecc072968677a34a7545ac9c4d/crypto/vm/stackops.cpp"

    mnemonics = load_cp0_json(cp0_path)
    cpp_code  = download_cpp_from_github(github_raw_url)
    func_map  = extract_functions_cpp(cpp_code)
    report    = generate_report(
        match_functions_to_mnemonics(func_map, mnemonics), threshold=0.7
    )
    save_report(report, out_path)

if __name__ == "__main__":
    main()
