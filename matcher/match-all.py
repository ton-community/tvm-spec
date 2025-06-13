#!/usr/bin/env python3
import subprocess, sys

# always run stack first, then tuple
for script in ("match-stack.py", "match-tuple.py"):
    cmd = [sys.executable, script]
    if script != "match-stack.py":          # tuple should merge
        cmd.append("--append")
    subprocess.run(cmd, check=True)