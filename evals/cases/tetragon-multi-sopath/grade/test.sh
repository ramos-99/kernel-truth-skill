#!/bin/sh
# Usage: grade/test.sh <tetragon-tree> <vmlinuz>
# Builds tetragon's BPF objects and agent in the tree, then boots one VM per
# policy below and runs targets.c under it. The last line is the verdict:
# PASS (exit 0), FAIL: <checks> (exit 1), or ENV: <reason> (exit 2).
#
# Kernels: v6.18 and v7.3 (evals/runs/kernels). Others give ENV.
# Nothing here depends on how the implementation is written: the policies use
# only the pre-existing sopath/argNewSymbol/matchArgs API, and the build uses
# the repo's own make targets. So there's no adapter file.
# Two threads resolving at once ("race", 16 runs) is graded only on crashes and
# wrong values: the merged PR sometimes leaves a call un-overridden there, but
# never crashed in our runs. A per-process (not per-thread) state crashes.
#
# GOCACHE: used if set, else a temp dir that's deleted at the end.
# SKIP_BUILD=1 reuses bpf/objs and ./tetragon already in the tree.

case_dir=$(dirname "$(realpath "$0")")
tree=$(realpath "$1")
kernel=$(realpath "$2")
fails=

verdict() { # <PASS|FAIL|ENV> [detail]
	case $1 in
	PASS) echo PASS; exit 0 ;;
	FAIL) echo "FAIL:$2"; exit 1 ;;
	*) echo "ENV: $2"; exit 2 ;;
	esac
}

[ -d "$tree" ] && [ -f "$kernel" ] || verdict ENV "usage: test.sh <tetragon-tree> <vmlinuz>"
release=$(file -L "$kernel" | sed -n 's/.*version \([^ ]*\).*/\1/p')
case $release in
6.18.0-061800-generic | 7.3.0-070300-generic) ;;
*) verdict ENV "kernel '$release' isn't one this grader was checked on (v6.18, v7.3)" ;;
esac
[ -r /dev/kvm ] && [ -w /dev/kvm ] || verdict ENV "no access to /dev/kvm"
for t in go make clang llvm-objcopy gcc nm qemu-system-x86_64 bpftool cpio; do
	command -v $t >/dev/null || verdict ENV "missing $t"
done

stage=$(mktemp -d)
cleanup=$stage
if [ -z "$GOCACHE" ]; then
	GOCACHE=$(mktemp -d)
	cleanup="$cleanup $GOCACHE"
fi
export GOCACHE GOMAXPROCS=4 GOFLAGS="${GOFLAGS:+$GOFLAGS }-p=4"
trap 'chmod -R u+w $cleanup 2>/dev/null; rm -rf $cleanup' EXIT

if [ -z "$SKIP_BUILD" ]; then
	# The bpf Makefile doesn't track headers for the multi-uprobe objects.
	rm -rf "$tree/bpf/objs" "$tree/bpf/deps" "$tree/tetragon"
	make -s -C "$tree" tetragon-bpf LOCAL_CLANG=1 JOBS=4 >"$stage/build.log" 2>&1 &&
		make -s -C "$tree" tetragon >>"$stage/build.log" 2>&1 || {
		tail -20 "$stage/build.log"
		verdict FAIL " build"
	}
fi
ls "$tree"/bpf/objs/*.o >/dev/null 2>&1 && [ -x "$tree/tetragon" ] || verdict FAIL " build (no bpf/objs or tetragon binary)"

mkdir -p "$stage/vm/bpf" "$stage/vm/t" "$stage/vm/bin"
for o in "$tree"/bpf/objs/*.o; do
	llvm-objcopy --strip-debug "$o" "$stage/vm/bpf/$(basename "$o")"
done
cp "$tree/tetragon" "$stage/vm/tetragon"
gcc -O2 -Wall "$case_dir/ldd.c" -o "$stage/vm/bin/ldd" &&
	gcc -O2 -Wall -rdynamic "$case_dir/targets.c" -o "$stage/vm/t/targets" -pthread &&
	gcc -O2 -Wall -fPIC -shared -DVALUE=1 "$case_dir/lib.c" -o "$stage/vm/t/lib1.so" &&
	gcc -O2 -Wall -fPIC -shared -DVALUE=2 "$case_dir/lib.c" -o "$stage/vm/t/lib2.so" &&
	gcc -O2 -Wall -fPIC -shared "$case_dir/lib3.c" -o "$stage/vm/t/lib3.so" ||
	verdict ENV "can't build the test programs"
# lib1 and lib2 must have repl at different offsets, or a symbol offset taken
# from the wrong library would still work.
off() { nm -D "$stage/vm/t/$1" | awk '$3 == "repl" { print $1 }'; }
[ -n "$(off lib1.so)" ] && [ "$(off lib1.so)" != "$(off lib2.so)" ] ||
	verdict ENV "repl is at the same offset in lib1.so and lib2.so"

# <policy> <load|reject> [<want exit> <mode>]...
#  selectors*: 1 -> lib1, 2 -> lib2, 3 -> in-binary symbol, then mixes on one
#    thread (seq), resolve then exec (stale per-slot state and libc addresses
#    after exec), resolve then fork (child starts with no task storage).
#  two-uprobes: two uprobes share slots in one policy, then 16 race runs (two
#    threads resolving arg_target(1) at once; per-thread state).
#  five-ok: exactly 5 sopath selectors load, and all 5 slots work on one thread.
#  nested: lib3.so's constructor calls other_target() while arg_target(1) is
#    still being resolved; that must not start a second resolution.
#  too-many: 6 sopath selectors in a multi-uprobe policy must be rejected.
#    The PR's limit is 5 per multi-uprobe sensor (one program and one slot
#    store for all its uprobes), so it spans uprobes. With uprobe-multi
#    disabled each uprobe is its own sensor and the PR doesn't limit across
#    uprobes, so that case isn't tested.
check() {
	p=$1 want=$2
	shift 2
	: >"$stage/vm/scenarios"
	n=0
	while [ $# -gt 0 ]; do
		echo "$1 $2" >>"$stage/vm/scenarios"
		n=$((n + 1))
		shift 2
	done
	cp "$case_dir/$p" "$stage/vm/policy.yaml"
	echo "--- $p (want $want)"
	VM_EXTRA=$stage/vm "$case_dir/../../../vm/run.sh" "$case_dir" "$kernel" >"$stage/out" 2>&1
	cat "$stage/out"
	# A known FAIL from an earlier policy wins over a later boot problem.
	grep -q '^=== KERNEL' "$stage/out" || { [ -n "$fails" ] && verdict FAIL "$fails"; verdict ENV "VM didn't boot for $p"; }
	grep -q "^=== KERNEL $release\$" "$stage/out" || verdict ENV "VM booted a different kernel than $release"
	if ! grep -q '^=== DONE' "$stage/out"; then
		fails="$fails $p:vm-did-not-finish"
	elif [ "$want" = reject ]; then
		grep -q '^policy NOT loaded' "$stage/out" || fails="$fails $p:not-rejected"
	elif ! grep -q '^policy loaded' "$stage/out"; then
		fails="$fails $p:not-loaded"
	else
		ok=$(grep -c ' exit .*, want .*  ok$' "$stage/out")
		[ "$ok" -eq "$n" ] || fails="$fails $p:$((n - ok))/$n-scenarios-failed"
	fi
}

check selectors.yaml load 1 1 2 2 3 3 27 seq 21 exec 21 fork
check selectors-nomulti.yaml load 1 1 2 2 3 3 27 seq 21 exec 21 fork
check two-uprobes.yaml load 1 1 24 other $(for i in $(seq 16); do printf '0 race '; done)
check five-ok.yaml load 1 1 2 2 1 4 2 5 24 other 8 all5
check nested.yaml load 1 1 24 other
check too-many.yaml reject

[ -z "$fails" ] && verdict PASS
verdict FAIL "$fails"
