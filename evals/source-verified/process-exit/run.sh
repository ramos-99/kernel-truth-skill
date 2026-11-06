#!/bin/sh
# Usage: ./run.sh <vmlinuz>
# Boots the kernel in KVM with guest.c as init. Needs /dev/kvm, not root.
set -e

kernel=$(realpath "$1")
src=$(dirname "$(realpath "$0")")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -w -I. -c "$src/probe.bpf.c" -o probe.bpf.o
gcc -O2 "$src/guest.c" -o guest -lbpf -pthread

mkdir -p root/usr/lib
for lib in $(ldd guest | grep -o '/[^ ]*'); do
	mkdir -p "root$(dirname "$lib")"
	cp -L "$lib" "root$lib"
done
cp -L "$(gcc -print-file-name=libgcc_s.so.1)" root/usr/lib/libgcc_s.so.1
ln -s usr/lib root/lib
cp guest root/init
cp guest root/exitwork
cp probe.bpf.o root/
(cd root && find . -print0 | cpio --null -H newc -o --quiet) > test.cpio

timeout -k 5 150 qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 1500M \
	-nographic -no-reboot -kernel "$kernel" -initrd test.cpio \
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=3' </dev/null |
	tr -d '\r' | sed -n '/=== KERNEL/,/=== DONE/p'
