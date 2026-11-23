#!/bin/sh
# Usage: grade/run.sh <enforcer.bpf.o> <vmlinuz> [audit-bit]
# Boots the grading guest with bpf in lsm= and the given enforcer object.
set -e
dir=$(dirname "$(realpath "$0")")
kernel=$(realpath "$2")
extra=$(mktemp -d)
trap 'rm -rf "$extra"' EXIT
cp "$1" "$extra/enforcer.bpf.o"
[ -z "$3" ] || echo "$3" > "$extra/audit_bit"
cd "$dir/../.."
VM_EXTRA=$extra sh kubearmor-lsm-audit/run-lsm.sh kubearmor-lsm-audit/grade "$kernel"
