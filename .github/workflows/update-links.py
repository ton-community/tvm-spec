import sys, subprocess, json, os

def main(cp0_path, ton_path):
    with open(cp0_path) as f:
        cp0 = json.load(f)
    cpp_paths = {os.path.join(ton_path, "crypto/vm", impl["file"]) for insn in cp0["instructions"] for impl in insn["implementation"]}
    tags = [x.split()[:4] for x in subprocess.check_output(["ctags", "-x", "--languages=C++", "--kinds-C++=f", *cpp_paths], text=True).split("\n") if x]
    tags_map = {}
    for func_name, _, line, path in tags:
        p = os.path.basename(path)
        m = tags_map.get(p, {})
        m[func_name] = int(line)
        tags_map[p] = m
    rev = subprocess.check_output(["git", "-C", ton_path, "rev-parse", "HEAD"], text=True).strip()
    for insn in cp0["instructions"]:
        for impl in insn["implementation"]:
            impl["line"] = tags_map[impl["file"]][impl["function_name"]]
            impl["path"] = f"https://raw.githubusercontent.com/ton-blockchain/ton/{rev}/crypto/vm/{impl['file']}"
    with open(cp0_path, "w") as f:
        json.dump(cp0, f, ensure_ascii=False, indent=2)
        f.write("\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <cp0.json> <ton-repo>")
    main(sys.argv[1], sys.argv[2])
