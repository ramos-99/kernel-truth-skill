# Audit alerts from the BPF-LSM enforcer

The task is a whole feature from [KubeArmor#1644](https://github.com/kubearmor/KubeArmor/pull/1644): the BPF-LSM enforcer sends Audit alerts itself. Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
KubeArmor's BPF-LSM enforcer only sends alerts for Block. Audit policy alerts still come from the system monitor, so the enforcer can't work without it. Make the BPF-LSM enforcer send Audit alerts itself for process, file, network and capability rules, and add a config option to turn off the system monitor when BPF-LSM is the enforcer. While you're at it, handle owner-only + allow policies under an audit default posture, and put the owner id in owner-only alerts from BPF-LSM. Implement it in this repo. Don't use sudo on this machine.
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

1. Read the implementation and fill in `grade/adapter.h`: how a rule's Audit and Block actions go into the inner-map value, the value size, and the names of the event id, retval and owner id fields. The defaults match the merged PR. Scoring doesn't depend on them.
2. Run `evals/cases/kubearmor-lsm-audit/grade/run.sh <tree> [vmlinuz...]`. It builds `enforcer` and `enforcer_path` with clang and bpftool, plus `grade/event-layout.c` against the tree's own `shared.h` so the guest can find the event fields through BTF. Then it boots each kernel with `bpf` in `lsm=` (by default v6.15 and Arch 7.3.5). The merged tree also passes on v6.16, v6.18 and v7.2.
3. The guest loads and attaches every program in both objects, as KubeArmor does, so a rejected program anywhere is a failure (facts 3, 5). Then it runs no rule, Audit and Block for exec, file open, a write under a read-only rule, UDP `socket` and `connect`, and `CAP_CHOWN`. Audit has to allow the operation and send one event with retval >= 0. Block has to deny it and send an event with retval < 0. With no rule there must be no event. Owner-only rules run as uid 1000, gid 2000, against files, a directory and a binary owned by uid 3000. Opening your own file sends nothing. Open, exec and `mkdir` on uid 3000's things must alert under Audit and be denied under Block, and a write must alert under Audit, all with owner id 3000 in the event. `mkdir` in your own directory is allowed (fact 7). An owner-only allow rule under audit posture lets the open through and alerts.
4. The last line is `VERDICT PASS`, `FAIL (...)` or `ENV (...)`, with exit code 0, 1 or 2. The guest answers ENV on kernels older than 6.15, where clang 23 builds of the parent already fail to load, and when `bpf` isn't an active LSM.
5. `grade/selftest.sh <clone with both commits>` runs the grader on merged (PASS), parent (FAIL), `grade/variants/*.patch` (FAIL) and `ok-*.patch` (PASS, correct implementations that move the owner id next to uid, or rename it and move the Audit bit). A variant's `<name>.adapter.h` replaces `grade/adapter.h` for its run (`ADAPTER=<file> run.sh`).

The Go side isn't graded (writing the Audit bit into the rule maps, the system monitor config flag, decoding the event), so the case only tests the BPF part.

Also not graded: fact 8's fork tracepoint and argv reads, because `process_monitor.bpf.c` is a merged-PR choice and fails on v6.16+ anyway, and the `ret` pass-through in `enforce_proc`, since a nonzero earlier verdict stops the chain before `enforce_proc` runs (fact 2). Under block posture the merged PR lets a non-owner open through an owner-only allow rule, where the parent blocked it. The guest prints that check as `info` and doesn't score it.

### Claim audit

The procedure is in the [README](../../../README.md#claim-audit).

| Run | Claims | Right | Too broad | Wrong | Unverified |
|---|---|---|---|---|---|
| As is | 20 | 11 | 8 | 0 | 1 |
| With the sentence | 21 | 12 | 8 | 0 | 1 |

Too broad in both runs:

- The owner is the inode's raw `i_uid`. That ignores idmapped mounts, and `path_symlink` and `path_link` run on a dentry with no inode yet, which reads as owner 0.
- A non-owner is a task whose uid differs from `i_uid`. `bpf_get_current_uid_gid()` returns the real uid, and the kernel's ownership checks use the fsuid.
- Non-read-only rules need no alert at the write, because the open was audited. A descriptor that was inherited, passed over a socket (`security_file_receive()`) or opened before the rule never hits `file_open` under that rule.
- Read-only rules are covered by `file_permission`. Shared mappings and truncation aren't, and truncation calls `security_file_truncate()` from v6.2.
- Audited operations are allowed. A later LSM can still deny them if `bpf` isn't last, and the operation itself can fail.
- `is_pts()` means a pseudo-terminal. It tests for any controlling tty.
- A uid fits in `int32`.

Also too broad: "up to three alerts per connection" (as is), since each non-blocking `connect()` or `accept()` retry calls the hook again, and `capable_noaudit()` (with the sentence), which exists only in v7.3.

Unverified in both: verifier acceptance before v6.15.

## Results

Sonnet 5.5 at medium effort, one fresh headless session per run with Write/Edit allowed, isolated from this repo. Graded by `grade/run.sh`.

Both runs FAIL on v6.15 and Arch 7.3.5, on one check. All other scored checks pass and every program loads. The check opens another user's file for writing and writes to it under an owner-only Audit rule, and wants an alert from `file_permission`. Both runs alert at the open and deliberately not at the write. The prompt doesn't say whether the write needs its own alert, so this is a difference from the merged PR.

- As is: `grade/adapter.h` unchanged. No kernel source lookups in the log.
- With the sentence: the adapter maps owner-only Audit to bit 12 and read-only Audit to bit 14. It read the 7.3.5 headers, and skips Audit alerts for capability checks with `CAP_OPT_NOAUDIT`.

Neither loaded its BPF code, though QEMU and `/dev/kvm` were available.

Not tested: the Go side (Audit vs Block precedence in `insertRule`, the system monitor flag), DNS and `socket_accept` audit, arm64, kernels older than 6.15, alert throttling, and whether the programs stay idle without `bpf` in the lsm list.
