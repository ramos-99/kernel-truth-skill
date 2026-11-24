#!/bin/sh
# Usage: grade/selftest.sh <kubearmor-clone> [vmlinuz...]
# The clone needs both ee4fbe28 (parent) and f2b2da64 (merged). Runs the
# grader on the merged PR (must PASS), the parent (must FAIL), each
# variants/*.patch applied to the merged tree (must FAIL), and each
# variants/ok-*.patch (correct but different, must PASS). A variant's
# <name>.adapter.h, if present, replaces grade/adapter.h for that run.
dir=$(dirname "$(realpath "$0")")
repo=$(realpath "$1")
shift
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
summary= bad=0

tree() { # <name> <commit> [patch]
	mkdir -p "$tmp/$1"
	git -C "$repo" archive "$2" KubeArmor/BPF | tar -x -C "$tmp/$1"
	[ -z "$3" ] || patch -s -p1 -d "$tmp/$1" <"$3"
}

grade() { # <name> <want> [vmlinuz...]
	n=$1 want=$2
	shift 2
	echo "##### $n (want $want)"
	ad=
	[ ! -f "$dir/variants/$n.adapter.h" ] || ad=$dir/variants/$n.adapter.h
	ADAPTER=$ad sh "$dir/run.sh" "$tmp/$n" "$@" >"$tmp/$n.out" 2>&1
	grep -v '\] ok  ' "$tmp/$n.out"
	got=$(tail -1 "$tmp/$n.out" | cut -d' ' -f2)
	mark=ok
	[ "$got" = "$want" ] || { mark=WRONG; bad=1; }
	summary="$summary
$(printf '%-6s %-40s want %-4s got %s' "$mark" "$n" "$want" "$got")"
}

tree merged f2b2da64
grade merged PASS "$@"
tree parent ee4fbe28
grade parent FAIL "$@"
for p in "$dir"/variants/*.patch; do
	n=$(basename "$p" .patch)
	tree "$n" f2b2da64 "$p"
	case $n in ok-*) grade "$n" PASS "$@" ;; *) grade "$n" FAIL "$@" ;; esac
done
echo "##### summary$summary"
exit $bad
