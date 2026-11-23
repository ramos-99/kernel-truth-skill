#!/bin/sh
# Usage: ./get-modules.sh v5.0
# Fetches kvm.ko and irqbypass.ko from Ubuntu's mainline build, and prints the
# directory to pass to run.sh as VM_EXTRA.
set -e

v=$1
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
dir="$root/evals/runs/kernels/$v/mods"
base="https://kernel.ubuntu.com/mainline/$v"

if [ ! -d "$dir" ]; then
	for sub in amd64/ ""; do
		deb=$(curl -fsS "$base/$sub" 2>/dev/null |
			grep -oE 'linux-modules-[^"<>]*generic[^"<>]*_amd64\.deb' |
			sort -u | head -1)
		[ -n "$deb" ] && break
	done
	[ -n "$deb" ] || { echo "no modules for $v" >&2; exit 1; }
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	cd "$tmp"
	curl -fsSO "$base/$sub$deb"
	bsdtar -xf "$deb" 'data.tar*'
	bsdtar -xf data.tar* --include='*/kvm/kvm.ko*' --include='*/irqbypass.ko*' 2>/dev/null || true
	mkdir -p "$dir"
	for f in kvm irqbypass; do
		found=$(find . -name "$f.ko*" | head -1)
		[ -z "$found" ] || cp "$found" "$dir/$f.ko"
	done
fi
echo "$dir"
