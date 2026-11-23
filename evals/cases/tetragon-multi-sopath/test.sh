#!/bin/sh
# Usage: ./test.sh <tetragon-tree> <vmlinuz> [policy.yaml...]
# Builds tetragon's BPF objects and agent in the tree, then boots one VM per
# policy and runs targets.c under it. Needs a 6.18+ kernel.
# SCENARIOS='<exit> <mode>\n...' replaces the default scenarios.
set -e

case_dir=$(dirname "$(realpath "$0")")
tree=$(realpath "$1")
kernel=$(realpath "$2")
shift 2
[ $# -gt 0 ] || set -- selectors.yaml selectors-nomulti.yaml two-uprobes.yaml

# The bpf Makefile doesn't track headers for the multi-uprobe objects.
rm -rf "$tree/bpf/objs" "$tree/bpf/deps"
make -s -C "$tree" tetragon-bpf LOCAL_CLANG=1 >/dev/null
make -s -C "$tree" tetragon >/dev/null 2>&1

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/bpf" "$stage/t" "$stage/bin"
for o in "$tree"/bpf/objs/*.o; do
	llvm-objcopy --strip-debug "$o" "$stage/bpf/$(basename "$o")"
done
cp "$tree/tetragon" "$stage/tetragon"
gcc -O2 -Wall "$case_dir/ldd.c" -o "$stage/bin/ldd"
gcc -O2 -Wall "$case_dir/targets.c" -o "$stage/t/targets" -pthread
for n in 1 2; do
	gcc -O2 -Wall -fPIC -shared -DVALUE=$n "$case_dir/lib.c" -o "$stage/t/lib$n.so"
done

for p in "$@"; do
	cp "$case_dir/$p" "$stage/policy.yaml"
	case ${SCENARIOS:+custom}$p in
	custom*) printf "$SCENARIOS" ;;
	two-uprobes.yaml) printf '1 1\n24 other\n' ;;
	*) printf '1 1\n2 2\n3 3\n27 seq\n21 exec\n21 fork\n' ;;
	esac > "$stage/scenarios"
	echo "--- $p"
	VM_EXTRA=$stage "$case_dir/../../vm/run.sh" "$case_dir" "$kernel"
done
