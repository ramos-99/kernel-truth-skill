#!/bin/sh
# Usage: ./get-kernel.sh v5.15
# Fetches Ubuntu's mainline build and prints the path to its vmlinuz.
set -e

v=$1
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
dir="$root/evals/runs/kernels/$v"
base="https://kernel.ubuntu.com/mainline/$v"

if [ ! -f "$dir/vmlinuz" ]; then
	for sub in amd64/ ""; do
		deb=$(curl -fsS "$base/$sub" 2>/dev/null |
			grep -oE 'linux-image-(unsigned-)?[^"<>]*generic[^"<>]*_amd64\.deb' |
			sort -u | head -1)
		[ -n "$deb" ] && break
	done
	[ -n "$deb" ] || { echo "no image for $v" >&2; exit 1; }
	mkdir -p "$dir"
	cd "$dir"
	curl -fsSO "$base/$sub$deb"
	bsdtar -xf "$deb" 'data.tar*'
	bsdtar -xf data.tar* --include='boot/vmlinuz*'
	cp boot/vmlinuz* vmlinuz
	rm -rf "$deb" data.tar* boot
fi
echo "$dir/vmlinuz"
