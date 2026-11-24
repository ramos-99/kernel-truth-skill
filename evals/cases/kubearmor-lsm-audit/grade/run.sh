#!/bin/sh
# Usage: grade/run.sh <kubearmor-tree> [vmlinuz...]
# Builds the tree's KubeArmor/BPF enforcer objects and runs grade/guest.c on
# each kernel (default: v6.15 and Arch 7.3.5). Supported kernels are mainline
# 6.15 or newer booted with bpf in lsm=; the guest answers ENV on others.
# Check grade/adapter.h against the implementation first. ADAPTER=<file>
# uses that file in place of grade/adapter.h (selftest uses it for ok-*).
# Last line: VERDICT PASS (exit 0), FAIL (exit 1) or ENV (exit 2).
dir=$(dirname "$(realpath "$0")")
case_dir=$(dirname "$dir")
kernels=$(realpath "$case_dir/../../runs/kernels")
tree=$1
shift
[ $# -gt 0 ] || set -- "$kernels/v6.15/vmlinuz" "$kernels/arch-7.3.5/vmlinuz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! command -v clang >/dev/null || ! command -v bpftool >/dev/null; then
	echo "VERDICT ENV (clang or bpftool missing)"
	exit 2
fi
mkdir -p "$tmp/obj" "$tmp/extra"
if ! sh "$dir/build-ka.sh" "$tree" "$tmp/obj" worktree >"$tmp/build.log" 2>&1 ||
	[ ! -f "$tmp/obj/worktree-enforcer.bpf.o" ]; then
	tail -20 "$tmp/build.log"
	echo "VERDICT FAIL (BPF objects don't build)"
	exit 1
fi
guest=$dir
if [ -n "$ADAPTER" ]; then
	guest=$tmp/guest
	mkdir -p "$guest"
	cp "$dir/guest.c" "$guest/"
	cp "$ADAPTER" "$guest/adapter.h"
fi
for f in enforcer.bpf enforcer_path.bpf event-layout; do
	[ ! -f "$tmp/obj/worktree-$f.o" ] || cp "$tmp/obj/worktree-$f.o" "$tmp/extra/$f.o"
done

fails= envs=
for k in "$@"; do
	name=$(basename "$(dirname "$k")")
	VM_EXTRA=$tmp/extra sh "$case_dir/run-lsm.sh" "$guest" "$k" >"$tmp/out" 2>&1
	sed "s/^/[$name] /" "$tmp/out"
	if ! grep -q '^=== KERNEL' "$tmp/out"; then
		envs="$envs $name:no-boot"
	elif grep -q '^ENV' "$tmp/out"; then
		envs="$envs $name:$(grep -m1 '^ENV' "$tmp/out" | cut -c5- | tr ' ' '_')"
	elif ! grep -q '^=== DONE' "$tmp/out"; then
		fails="$fails $name:guest-did-not-finish"
	else
		for c in $(grep '^FAIL' "$tmp/out" | cut -d: -f1 | cut -c6- | tr ' ' '_'); do
			fails="$fails $name:$c"
		done
		grep -q '^RESULT PASS' "$tmp/out" || [ -n "$(grep '^FAIL' "$tmp/out")" ] ||
			fails="$fails $name:no-RESULT-PASS"
	fi
done

if [ -n "$fails" ]; then
	echo "VERDICT FAIL ($(echo $fails))"
	exit 1
elif [ -n "$envs" ]; then
	echo "VERDICT ENV ($(echo $envs))"
	exit 2
fi
echo "VERDICT PASS"
exit 0
