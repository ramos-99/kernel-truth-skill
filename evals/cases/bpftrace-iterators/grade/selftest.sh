#!/bin/sh
# Usage: grade/selftest.sh <bpftrace checkout> <build dir> [vmlinuz...]
# Builds the merged PR (4552f27b), its parent (3f97ba56) and merged plus each
# patch in variants/, then grades each one on every kernel given (default
# v7.3 and v6.12). Merged must PASS, everything else must FAIL.
# A patch can name its own kernels in a "Kernels: v6.6" line above the diff;
# merged and parent are graded on those kernels too.
# The checkout must be clean; the build dir is configured if it's empty.
# Binaries are kept in <build dir>/selftest-bin, so a second run skips builds.
here=$(dirname "$(realpath "$0")")
src=$(realpath "$1")
build=$(realpath -m "$2")
shift 2
kdir=$here/../../../runs/kernels
kernels=${*:-"$kdir/v7.3/vmlinuz $kdir/v6.12/vmlinuz"}
bin=$build/selftest-bin
mkdir -p "$bin"

# v3 drops the forced 8-byte alignment of the iterator state. LLVM already puts
# that slot at an aligned offset, so the program still loads and nothing can catch it.
may_pass="v3-noalign"

own_kernels() { # patch
	for k in $(sed -n 's/^Kernels: //p' "$1"); do
		echo "$kdir/$k/vmlinuz"
	done
}

extra=""
for p in "$here"/variants/*.diff; do
	extra="$extra $(own_kernels "$p")"
done
all_kernels=$(echo $kernels $extra | tr ' ' '\n' | awk 'NF && !seen[$0]++')

build_one() { # name commit [patch]
	[ -x "$bin/$1" ] && return
	git -C "$src" checkout -q "$2" || exit 2
	[ -z "$3" ] || git -C "$src" apply "$3" || exit 2
	[ -f "$build/CMakeCache.txt" ] ||
		cmake -S "$src" -B "$build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF > "$build/cmake.log" 2>&1
	echo "building $1"
	make -C "$build" -j4 bpftrace > "$build/make-$1.log" 2>&1 && cp "$build/src/bpftrace" "$bin/$1"
	git -C "$src" checkout -q -- .
}

build_one merged 4552f27b
for p in "$here"/variants/*.diff; do
	build_one "$(basename "$p" .diff)" 4552f27b "$p"
done
build_one parent 3f97ba56
git -C "$src" checkout -q 4552f27b

summary=""
bad=0
grade() { # name kernel
	name=$1
	kname=$(basename "$(dirname "$2")")
	if [ ! -x "$bin/$name" ]; then
		got="no build"
	else
		"$here/run.sh" "$bin/$name" "$2" > "$build/grade-$name-$kname.txt" 2>&1
		case $? in 0) got=PASS ;; 1) got=FAIL ;; *) got=ENV ;; esac
	fi
	want=FAIL
	[ "$name" = merged ] && want=PASS
	note=""
	case " $may_pass " in *" $name "*) [ "$got" = PASS ] && want=PASS && note=" (known, see may_pass)" ;; esac
	[ "$got" = "$want" ] && mark=ok || { mark=WRONG; bad=1; }
	line=$(printf '%-8s %-28s %-5s want %-5s %s%s' "$kname" "$name" "$got" "$want" "$mark" "$note")
	echo "$line   $(grep '^VERDICT' "$build/grade-$name-$kname.txt" 2>/dev/null)"
	summary="$summary$line\n"
}

for k in $all_kernels; do
	grade merged "$k"
	grade parent "$k"
done
for p in "$here"/variants/*.diff; do
	ks=$(own_kernels "$p")
	for k in ${ks:-$kernels}; do
		grade "$(basename "$p" .diff)" "$k"
	done
done
printf '\nSummary:\n%b' "$summary"
exit $bad
