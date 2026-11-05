# File paths in LSM programs

Based on the kernel rule itself, not on a bug report. Checkout: aya `13ad5a0c1be4`.

Run twice before this answer was committed, once without a hint and once with the sentence from the README, and the answer changed after seeing those runs. So this case helped shape the skill and doesn't count as an unseen test.

```text
I want to add a way for LSM programs in aya-ebpf to get a file's full path, then log the path of each file from the `file_permission` hook. Before I implement it: what should I use, which hooks and kernel versions does it work on, and what are the constraints? Don't change any files or run anything that needs root.
```

## Answer

"Loads" and "rejected" below were tested on one Arch 7.2.9 x86_64 kernel with `paths.bpf.c` and `load-test.c`, which load programs without attaching them. Everything about other versions comes from source.

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c paths.bpf.c -o paths.bpf.o
cc load-test.c -o load-test -lbpf
sudo ./load-test paths.bpf.o
```

- `bpf_d_path` is rejected on `file_permission`, because that hook isn't in `sleepable_lsm_hooks` (`kernel/trace/bpf_trace.c:983-984`, `kernel/bpf/bpf_lsm.c:291-387`). The error is `helper call is not allowed in probe` (`kernel/bpf/verifier.c:10880-10881`).
- The check is on the hook, not the program. A non-sleepable `lsm/file_open` program calling it loads. The commit says the helper "is not restricted to sleepable programs and merely uses the list of sleepable hooks as the initial subset" (`6f100640ca5b`).
- Marking the program sleepable on `file_permission` doesn't help, because the verifier uses the same list (`kernel/bpf/verifier.c:20047`). The load fails with `bpf_lsm_file_permission is not sleepable`.
- The list depends on the version. `path_*` hooks joined in v6.8 (`b13cddf63356`) and need `CONFIG_SECURITY_PATH`, two removexattr hooks in v6.15 (`7587d735b150`), and others were removed in v7.1 (`beaf0e96b1da`) and v7.3 (`2ce3f548cfc6`).
- `file_permission` isn't on the list at any version sampled from v5.11 to current. I found no source saying why, so don't claim the hook is unsafe, only that it isn't listed.
- The helper came in v5.10 (`6e22ab9da793`), and LSM use in v5.11 (`6f100640ca5b`).
- The `bpf_path_d_path` kfunc (v6.12, `d08e2045ebf0`) is for LSM programs, sleepable or not (`fs/bpf_fs_kfuncs.c`). It loads on `file_permission`, though no selftest uses it on this hook and returning the right path at runtime wasn't tested.
- Fentry on `security_file_permission` with `bpf_d_path` loads (`bpf_trace.c:963`), so the rule depends on program type. Fentry on `vfs_read`, which isn't on that allowlist, is rejected.
- Master has moved past the pin: `3a00ecc89069` adds a second, fentry-only list with `filp_close_sync`, and `5da4a9f26fca` adds `MEM_UNINIT` to the helper's buffer argument. Answers based on master that mention either are correct.
- Iterator programs can call the helper since v5.12.
