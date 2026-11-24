#!/bin/sh
# Usage: run.sh <scx_cidland binary> [vmlinuz]
# Boots the kernel with grade/guest.c as init, runs the workloads under the
# binary and grades them with grade/check. Last line is PASS, FAIL or ENV;
# exit 0, 1 or 2. EEVDF=1 also runs the workloads under the kernel's own
# scheduler first, for reference (not graded). OUT=<file> keeps the VM output.
#
# Kernel: only Arch 7.2.9 (evals/runs/kernels/host) can load the scheduler.
# cid-form sched_ext starts in v7.2, Ubuntu mainline v7.2 has BTF from a
# pahole too old for the KF_IMPLICIT_ARGS kfuncs, and 7.3 changed
# scx_bpf_cid_topo(). Anything else is ENV.
g=$(dirname "$(realpath "$0")")
evals=$(realpath "$g/../../..")
bin=$1
kernel=${2:-$evals/runs/kernels/host/vmlinuz}
want=7.2.9-arch1-1

env() { echo "ENV: $*"; exit 2; }
[ -x "$bin" ] || env "no binary at $bin"
file -L "$kernel" | grep -q "version $want " || env "kernel is not $want"

. "$g/adapter.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/case" "$tmp/root"
cp "$g/guest.c" "$tmp/case/"
cp "$bin" "$tmp/root/scx_cidland"
for lib in $(ldd "$bin" | grep -o '/[^ ]*\.so[^ ]*'); do
	mkdir -p "$tmp/root$(dirname "$lib")"
	cp -L "$lib" "$tmp/root$lib"
done
echo "$ARGS" > "$tmp/root/cidland.args"
[ -z "$EEVDF" ] || touch "$tmp/root/eevdf"

out=${OUT:-$tmp/out.txt}
VM_EXTRA=$tmp/root "$evals/vm/run.sh" "$tmp/case" "$kernel" > "$out" 2>&1
"$g/check" "$out"
