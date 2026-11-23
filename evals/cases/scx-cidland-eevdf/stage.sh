#!/bin/sh
# Usage: [KCONFIG=<config> KREL=<uname -r>] ./stage.sh <scx_cidland binary> <out-dir> [scheduler args...]
# Copies the binary and its shared libraries into out-dir, for VM_EXTRA.
# libbpf needs the kernel config for __kconfig externs, so kernels without
# /proc/config.gz need KCONFIG and KREL.
set -e

bin=$1
out=$2
shift 2
rm -rf "$out"
mkdir -p "$out"
cp "$bin" "$out/scx_cidland"
for lib in $(ldd "$bin" | grep -o '/[^ ]*\.so[^ ]*'); do
	mkdir -p "$out$(dirname "$lib")"
	cp -L "$lib" "$out$lib"
done
if [ -n "$KCONFIG" ]; then
	mkdir -p "$out/boot"
	cp "$KCONFIG" "$out/boot/config-$KREL"
fi
echo "$@" > "$out/cidland.args"
