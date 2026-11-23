#!/bin/sh
# Usage: ./stage.sh <scheduler-binary> <cell-config.json> <out-dir> [scheduler args...]
# Puts the binary (as /sched), its libraries, the config (as /cfg.json) and the
# argument list (as /cmd, one per line) into out-dir, for VM_EXTRA.
set -e
bin=$1 cfg=$2 out=$3
shift 3
rm -rf "$out"
mkdir -p "$out/usr/lib"
cp -L "$bin" "$out/sched"
for lib in $(ldd "$bin" | grep -o '/[^ ]*' | grep '\.so'); do
	mkdir -p "$out$(dirname "$lib")"
	cp -L "$lib" "$out$lib"
done
cp "$cfg" "$out/cfg.json"
: > "$out/cmd"
for a in "$@"; do
	printf '%s\n' "$a" >> "$out/cmd"
done
