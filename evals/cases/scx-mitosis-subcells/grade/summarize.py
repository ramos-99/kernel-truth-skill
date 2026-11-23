# Usage: python3 -I summarize.py <console-log>
# Prints scheduler log lines, guest checks, and per-subcell stats of every JSON sample.
import json, re, sys

text = re.sub(r"\x1b\[[0-9;]*m", "", open(sys.argv[1], errors="replace").read())
samples, depth, start, rest = [], 0, None, []
for i, ch in enumerate(text):
    if ch == "{":
        if depth == 0:
            start = i
        depth += 1
    elif ch == "}" and depth:
        depth -= 1
        if depth == 0:
            try:
                samples.append(json.loads(text[start:i + 1]))
            except ValueError:
                pass
for line in text.splitlines():
    if line.startswith("  worker") or (line.strip() and not line.startswith((" ", "{", "}", '"'))):
        print(line[:220])
for n, s in enumerate(samples):
    for cid, cell in sorted(s.get("cells", {}).items()):
        subs = cell.get("subcells", {})
        if len(subs) < 2:
            continue
        print(f"sample {n} cell {cid} cpus={cell.get('num_cpus')}: " + "  ".join(
            f"{v.get('name')}: cpus={v.get('num_cpus')} util={v.get('util_pct', 0):.0f}% "
            f"demand={v.get('demand', 0):.2f} smoothed={v.get('smoothed_demand', 0):.2f}"
            for _, v in sorted(subs.items(), key=lambda kv: int(kv[0]))))
