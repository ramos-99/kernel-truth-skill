#!/bin/sh
# Usage: ./build-ka.sh <kubearmor-repo> <out-dir> [commit|worktree...]
# Compiles KubeArmor's BPF LSM objects with bpf2go's flags. "worktree"
# builds the repo's checked-out files, uncommitted changes included.
set -e

repo=$(realpath "$1")
out=$(realpath -m "$2")
shift 2
[ $# -gt 0 ] || set -- ee4fbe28 dc96b08 f2b2da64
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$tmp/vmlinux.h" 2>/dev/null
for c in "$@"; do
	mkdir -p "$tmp/$c/KubeArmor"
	if [ "$c" = worktree ]; then
		cp -r "$repo/KubeArmor/BPF" "$tmp/$c/KubeArmor/"
	else
		git -C "$repo" archive "$c" KubeArmor/BPF | tar -x -C "$tmp/$c"
	fi
	bpf="$tmp/$c/KubeArmor/BPF"
	cp "$tmp/vmlinux.h" "$bpf/"
	for f in enforcer enforcer_path process_monitor; do
		[ -f "$bpf/$f.bpf.c" ] || continue
		clang -O2 -mcpu=v1 -g -target bpfel -fno-stack-protector -Wno-missing-declarations \
			-I/usr/include/ -I"$bpf" -D__TARGET_ARCH_x86 -c "$bpf/$f.bpf.c" -o "$out/$c-$f.bpf.o"
	done
done
ls "$out"
