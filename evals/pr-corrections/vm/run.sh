#!/bin/sh
# Usage: ./run.sh <case-dir> <vmlinuz>
# Boots the kernel in KVM with the case's guest.c as init. Needs /dev/kvm, not root.
# Files in the directory named by VM_EXTRA get copied to the guest's root.
set -e

case_dir=$(realpath "$1")
kernel=$(realpath "$2")
vm=$(dirname "$(realpath "$0")")
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null
for src in "$case_dir"/*.bpf.c; do
	[ -e "$src" ] || continue
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -DBPF_NO_KFUNC_PROTOTYPES -w -I. \
		-c "$src" -o "$(basename "${src%.c}").o"
done
gcc -O2 -w -I"$vm" "$case_dir/guest.c" -o guest -lbpf -pthread

mkdir -p root/usr/lib
for lib in $(ldd guest | grep -o '/[^ ]*' | grep '\.so'); do
	mkdir -p "root$(dirname "$lib")"
	cp -L "$lib" "root$lib"
done
cp -L "$(gcc -print-file-name=libgcc_s.so.1)" root/usr/lib/libgcc_s.so.1
ln -s usr/lib root/lib
cp guest root/init
for obj in *.o; do
	[ -e "$obj" ] && cp "$obj" root/
done
[ -z "$VM_EXTRA" ] || cp -r "$VM_EXTRA"/. root/
(cd root && find . -print0 | cpio --null -H newc -o --quiet) > test.cpio

timeout -k 5 120 qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 1500M \
	-nographic -no-reboot -kernel "$kernel" -initrd test.cpio \
	-append 'console=ttyS0 rdinit=/init panic=-1 loglevel=3' </dev/null |
	tr -d '\r' | sed -n '/=== KERNEL/,/=== DONE/p'
