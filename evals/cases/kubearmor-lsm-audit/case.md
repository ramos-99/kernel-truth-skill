# Audit alerts from the BPF-LSM enforcer

The task is a whole feature from [KubeArmor#1644](https://github.com/kubearmor/KubeArmor/pull/1644): the BPF-LSM enforcer sends Audit alerts itself. Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
KubeArmor's BPF-LSM enforcer only sends alerts for Block. Audit policy alerts still come from the system monitor, so the enforcer can't work without it. Make the BPF-LSM enforcer send Audit alerts itself for process, file, network and capability rules, and add a config option to turn off the system monitor when BPF-LSM is the enforcer. While you're at it, handle owner-only + allow policies under an audit default posture, and put the owner id in owner-only alerts from BPF-LSM. Implement it in this repo. Don't use sudo.
```

Run in a clone of KubeArmor at `ee4fbe28e132d4dcf9bdd5c320c93477e61aab8c`, the commit before the PR (squash-merged as `f2b2da64`), with later tags and objects removed.

## Facts

"All 8 kernels" means Ubuntu mainline v6.6, v6.11, v6.12, v6.15, v6.16, v6.18 and v7.2, booted with `bpf` in `lsm=`, plus Arch 7.3.5. Objects were built with clang 23.1.5 for the parent, `dc96b08` (the PR head when reviewed) and the merged commit.

1. BPF LSM programs exist since v5.7 (fc611f47f218) and run only when `bpf` is in the active LSM list (`security/bpf/hooks.c:30`). Tested only that every kernel used lists `bpf`. That programs stay idle without it is read in source only.
2. A nonzero return from an int LSM hook ends the chain. `call_int_hook` stops at the first `RC != 0` (`security/security.c:781`, v6.6), and the x86 trampoline skips the remaining BPF programs (`arch/x86/net/bpf_jit_comp.c:2273-2286`). Tested on all 8 kernels with two programs on `file_open`. So Audit has to return 0 and send its alert from inside the program.
3. Since v6.12 (5d99e198be27) the verifier limits LSM returns to `[-4095, 0]` for int hooks and `[0, 1]` for bool hooks (`kernel/bpf/bpf_lsm.c:427-447`). v6.11 accepts any value. Tested: returning an internal `AUDIT=1`, or a constant 1 on `file_open` and `bprm_check_security`, loads on v6.6 and v6.11 and is rejected from v6.12 with `should have been in [-4095, 0]`. Ending in `retval == BLOCK ? -EPERM : 0` loads everywhere.
4. Before v6.12 a positive return goes through to the kernel. Tested on v6.6 and v6.11: `file_open` returning 1 makes `open()` fail with `EINVAL`, and `bprm_check_security` returning 1 makes `execve()` return 0 while the old image keeps running (`fs/exec.c:1727-1729` and `1781-1783`, v6.6).
5. The verifier has to prove the range. `dc96b08`'s `enforce_proc` returns `-EPERM` or the hook's `ret` through a zero-extended 32-bit stack slot, so it sees `R0 [0, 0xffffffff]`. AryanBakliwal [hit this](https://github.com/kubearmor/KubeArmor/pull/1644#pullrequestreview-4979455670) on kernel 7.0, and nyrahul [asked for](https://github.com/kubearmor/KubeArmor/pull/1644#discussion_r2161147630) `retval = (retval == DENY) ? -EPERM : 0;`. Tested: the review's exact message on v6.12, v6.15, v6.16, v6.18, v7.2 and Arch 7.3.5, and it loads on v6.6 and v6.11. The merged code loads wherever the parent loads, and a plain `return ret;` loads on every kernel.
6. `bpf_get_current_uid_gid()` returns `gid << 32 | uid` (`kernel/bpf/helpers.c:243`, v6.6). Tested on all 8 kernels: uid 1000 gid 2000 gives `0x7d0000003e8`. Owner checks compare the low 32 bits with the inode's `i_uid`, which is also the owner id to report.
7. `path_mkdir` and `path_mknod` get a negative dentry with no owner yet, and reading `d_inode->i_uid` through CO-RE gives 0, so owner-only has to check the parent, as [daemon1024 said](https://github.com/kubearmor/KubeArmor/pull/1644#discussion_r1507290522). Tested on all 8 kernels: `negative_dentry=1 dentry_uid=0 parent_uid=0`. The parent commit already uses `d_parent` for these two events (`KubeArmor/BPF/shared.h:944-946`).
8. In v6.16 (155fd6c3e2f0) `child_pid` in the `sched_process_fork` record moved from offset 44 to 20, and the PR's new `process_monitor.bpf.c` copies the system monitor's struct, which reads 44. Tested: v6.6 to v6.15 get an `exec_pids` entry, and on v6.16, v6.18 and v7.2 attach fails with `EACCES`. Nobody raised this in the review, and the parent has the same struct. The child's u64 map value also has stack garbage in its upper bits.
9. A kprobe at `execve` entry can't fault user pages in, so argv strings on untouched pages read as `""`. Tested on all 8 kernels with the merged `process_monitor`: string literals read empty and stack copies read correctly. The PR moves this code out of the system monitor unchanged.
10. `kprobe/__x64_sys_execve` only exists on x86. arm64 uses `__arm64_sys_execve` (`arch/arm64/include/asm/syscall_wrapper.h:53`, v6.6), and the follow-up [#2948](https://github.com/kubearmor/KubeArmor/pull/2948) replaced the kprobe with a tracepoint. Read in source only.

## Grading

1. Build the objects with `evals/cases/kubearmor-lsm-audit/grade/build-ka.sh <repo> <out>/ka worktree ee4fbe28` (needs clang and bpftool).
2. Run `VM_EXTRA=<out> evals/cases/kubearmor-lsm-audit/run-lsm.sh evals/cases/kubearmor-lsm-audit <vmlinuz>` on at least v6.6, v6.12, v6.16 and v7.2. Nothing may be rejected that the parent loads on that kernel (facts 3, 5). With clang 23.1.5 the parent already fails 2/8 `enforcer` and 11/11 `enforcer_path` programs on v6.6 to v6.12, and none from v6.15. The fork check (fact 8) is extra credit, since the merged PR fails it on v6.16+.
3. Run `evals/cases/kubearmor-lsm-audit/grade/run.sh <out>/ka/worktree-enforcer.bpf.o <vmlinuz> [audit-bit]`. With no rule, exec and open give `events=0`. Audit gives `events=1 retval=0` (event ids 352 and 450), and Block gives `Permission denied` with `events=1 retval=-13` (KubeArmor's `EPERM` is 13). The guest assumes the parent's map and event layouts and Audit as `1 << 10`, so adapt `grade/guest.c` if those changed.
4. Read the diff for facts 2, 4, 6 and 7.

The merged version passes step 3 on v6.16 and Arch 7.3.5, and for exec only on v6.6 and v6.12, where `enforce_file` doesn't load for any version. The parent gives no Audit events, and `dc96b08`'s `enforce_proc` doesn't load on v6.12 and v6.16.

## Results

Not run yet.

Not tested: the Go side (Audit vs Block precedence in `insertRule`, the system monitor flag), network, DNS and capability audit paths, arm64, kernels older than v6.6, alert throttling, and whether the programs stay idle without `bpf` in the lsm list.
