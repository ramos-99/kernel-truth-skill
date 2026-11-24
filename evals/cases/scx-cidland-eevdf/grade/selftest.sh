#!/bin/sh
# Usage: selftest.sh <scx clone>
# Builds scx_cidland from the merged PR, its parent and the merged PR with
# each grade/variants/*.patch applied, and grades each with run.sh on Arch
# 7.2.9. Merged must PASS, the parent and wrong variants must FAIL. A patch
# whose first line starts "Want: PASS" is correct but different and must
# PASS; one starting "Not caught:" is wrong but known to pass, and says why.
# MERGED_RUNS=n grades the merged build n times (default 2). The clone is
# left at the merged commit with a clean tree, and its target/ is deleted at the end
# unless KEEP_TARGET=1.
set -u
g=$(dirname "$(realpath "$0")")
src=$(realpath "$1")
merged=6e01d48ac53a
parent=8b2479571c07
bins=$(mktemp -d)
trap 'rm -rf "$bins"' EXIT
summary=""

build() {	# build <name> <commit> [patch]
	git -C "$src" checkout -q --detach "$2" && git -C "$src" checkout -q -- . || return 1
	if [ -n "${3:-}" ]; then git -C "$src" apply "$3" || return 1; fi
	(cd "$src" && cargo build -q --release -j4 -p scx_cidland) || return 1
	cp "$src/target/release/scx_cidland" "$bins/$1"
	git -C "$src" checkout -q -- .
}

one() {	# one <name> <want> <commit> [patch]
	name=$1 want=$2
	shift 2
	if build "$name" "$@"; then
		echo "== $name"
		OUT=$bins/$name.out "$g/run.sh" "$bins/$name"
		code=$?
	else
		echo "== $name: build failed"
		code=3
	fi
	report "$name" "$want" $code
}

report() {	# report <name> <want> <exit code>
	case $3 in 0) got=PASS ;; 1) got=FAIL ;; 2) got=ENV ;; *) got=BUILD ;; esac
	want=$2 res=WRONG
	[ "$got" = "$want" ] && res=ok
	if [ "$want" = KNOWN ]; then
		want="FAIL, not caught"
		case $got in PASS) res=known ;; FAIL) res=ok ;; esac
	fi
	summary="$summary$(printf '%-5s %-20s %-5s (want %s)' "$res" "$1" "$got" "$want")
"
}

one merged PASS $merged
i=1
while [ $i -lt "${MERGED_RUNS:-2}" ]; do
	i=$((i + 1))
	echo "== merged run $i"
	OUT=$bins/merged$i.out "$g/run.sh" "$bins/merged"
	report "merged run $i" PASS $?
done
one parent FAIL $parent
for p in "$g"/variants/*.patch; do
	case $(head -1 "$p") in
	"Want: PASS"*) want=PASS ;;
	"Not caught:"*) want=KNOWN ;;
	*) want=FAIL ;;
	esac
	one "$(basename "$p" .patch)" $want $merged "$p"
done
git -C "$src" checkout -q --detach $merged
[ "${KEEP_TARGET:-}" = 1 ] || rm -rf "$src/target"

echo "== summary"
printf '%s' "$summary"
case $summary in *WRONG*) exit 1 ;; esac
exit 0
