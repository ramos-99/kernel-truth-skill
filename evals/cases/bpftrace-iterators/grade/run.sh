#!/bin/sh
# Usage: grade/run.sh <bpftrace binary> <vmlinuz>
# Boots the kernel, runs each script in grade/guest.c with that bpftrace, then
# grade/check prints the verdict. Exit 0 PASS, 1 FAIL, 2 ENV.
here=$(dirname "$(realpath "$0")")
extra=$(mktemp -d)
trap 'rm -rf "$extra"' EXIT
cp "$1" "$extra/bpftrace" || exit 2
for lib in $(ldd "$1" | grep -o '/[^ ]*\.so[^ ]*'); do
	mkdir -p "$extra$(dirname "$lib")"
	cp -L "$lib" "$extra$lib"
done
VM_EXTRA=$extra "$here/../../../vm/run.sh" "$here" "$2" > "$extra/out" 2>&1
cat "$extra/out"
"$here/check" "$extra/out"
