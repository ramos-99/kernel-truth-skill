#!/bin/sh
# Usage: grade/selftest.sh <parent-tree> <merged-tree> <vmlinuz>
# Trees: tetragon at 65012b07c and with the PR applied (4318271484).
# Runs test.sh on copies of the merged tree (must PASS), the parent (must
# FAIL) and the merged tree with each variants/*.patch applied (must FAIL).
# variants: v1 recomputes libc addresses only once, v2 keeps one exec id for
# all slots, v3 drops the nested-resolution guard, v4 drops the >5 limit,
# v5 only uses 4 of the 5 slots, v6 detects exec by a pid_tgid change instead
# of self_exec_id, v7 keeps the state in a hash map keyed by tgid instead of
# task storage (crashes under "race"), v8 recognises the mmap/dlopen detour
# return only for slot 0.
dir=$(dirname "$(realpath "$0")")
parent=$(realpath "$1")
merged=$(realpath "$2")
kernel=$3
tmp=$(mktemp -d)
if [ -z "$GOCACHE" ]; then
	export GOCACHE="$tmp/gocache"
	mkdir -p "$GOCACHE"
fi
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
summary= bad=0

grade() { # <name> <want> <tree> [patch]
	n=$1 want=$2
	echo "##### $n (want $want)"
	rm -rf "$tmp/tree"
	mkdir "$tmp/tree"
	tar -C "$3" --exclude=.git -cf - . | tar -C "$tmp/tree" -xf -
	[ -z "$4" ] || patch -s -p1 -d "$tmp/tree" <"$4" || { echo "patch failed"; bad=1; }
	sh "$dir/test.sh" "$tmp/tree" "$kernel" >"$tmp/out" 2>&1
	grep -v '^  arg_target\|^  other_target\| ok$' "$tmp/out"
	got=$(tail -1 "$tmp/out" | cut -d: -f1)
	mark=ok
	[ "$got" = "$want" ] || { mark=WRONG; bad=1; }
	summary="$summary
$(printf '%-6s %-22s want %-4s got %s' "$mark" "$n" "$want" "$(tail -1 "$tmp/out")")"
}

grade merged PASS "$merged"
grade parent FAIL "$parent"
for p in "$dir"/variants/*.patch; do
	grade "$(basename "$p" .patch)" FAIL "$merged" "$p"
done
rm -rf "$tmp/tree"
echo "##### summary$summary"
exit $bad
