#!/bin/sh
# Like vm/run.sh, but boots with bpf in lsm= so BPF LSM programs run.
vm=$(realpath "$(dirname "$0")/../../vm")
tmp=$(mktemp)
sed -e "s|loglevel=3'|loglevel=3 lsm=capability,landlock,lockdown,yama,bpf'|" \
	-e "s|^vm=.*|vm=$vm|" "$vm/run.sh" > "$tmp"
sh "$tmp" "$@"
rc=$?
rm -f "$tmp"
exit $rc
