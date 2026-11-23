# Multiple sopath overrides in Tetragon uprobes

The task is a whole feature from [cilium/tetragon#5904](https://github.com/cilium/tetragon/pull/5904), fixing [#5882](https://github.com/cilium/tetragon/issues/5882): let each selector have its own `sopath` override. Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
Tetragon's uprobe Override action can load the replacement function from a shared library with `sopath`, but only once: a uprobe can have just one selector with a `sopath` override, and a multi-uprobe policy only one in the whole policy. I want to lift that limit so that up to MAX_SELECTORS selectors can each have their own `sopath` override. For example, matchArgs on the first argument sending 1 to repl() in /lib/libimpl-1.so and 2 to repl() in /lib/libimpl-2.so, with another selector still overriding to a symbol in the binary itself, and the same across different uprobes in one policy. Policies with more than that should still be rejected. Please implement it in this repo, with tests. Don't use sudo.
```

Run in a clone of cilium/tetragon at `65012b07c9e7651923a4c91a919fee266fcb688d`, the commit before the PR, where a second `sopath` is rejected. The PR was merged as `4318271484443516e82736b18a78cb70c2db3a05`.

## Facts

Line numbers are for v6.18. The fact tests are `guest.c` and `test.bpf.c` in this directory, run with `evals/vm/run.sh evals/cases/tetragon-multi-sopath <vmlinuz>`.

1. A uprobe program can rewrite user registers, ip included, from v6.18 (`7384893d970e`), and `sopath` relied on this before the PR too. `kprobe_prog_is_valid_access` records the ctx write (`kernel/trace/bpf_trace.c:1350`) and attach allows it only for a uprobe (`kernel/events/core.c:11249`). Tested indirectly: the merged tree works on v6.18 and 7.2.9, and on v6.16 Tetragon refuses the policy with "can't use override regs action, no kernel support".
2. Task storage (`BPF_MAP_TYPE_TASK_STORAGE`, v5.11, `4cf1bc1f1045`) is per thread, so each thread runs its own state machine. Tested: a new thread finds no entry.
3. A new task starts with no task storage, and a new entry is zeroed (`kernel/fork.c:2144`, `kernel/bpf/bpf_local_storage.c:93`). Slots start at `STAGE_NONE` with `sym_id` 0, which is why [andrewstrohman asked](https://github.com/cilium/tetragon/pull/5904#discussion_r4394057236) for `STAGE_NONE` slots to be skipped. Tested: a forked child and a new thread both have found=0, zeroed=1.
4. Task storage survives execve. It's freed only in `free_task` (`kernel/fork.c:511`). Tested: the child still has its old value after exec.
5. `task->self_exec_id` goes up by 1 on each exec (`fs/exec.c:1251`) and fork and threads inherit it. It's `u64` from v5.7 (`d1e7fd6462ca`), and the PR widened the parent's `__u32`. With fact 3 this gives [kkourt's check](https://github.com/cilium/tetragon/pull/5904#discussion_r4413385507) `libc_exec_id != self_exec_id`. Tested: pid 1 has 1, the forked child 1, the child after exec 2, a new thread 1. Kernel threads that never exec stay at 0, which doesn't matter here (read in source only).
6. After an exec, libc sits at a new randomized address (`randomize_va_space`, `mm/memory.c:121`), so cached mmap, dlopen and symbol addresses go stale. This is [the review's exec point](https://github.com/cilium/tetragon/pull/5904#discussion_r4412662164). Tested by mutation on v6.18: recomputing libc addresses only when `libc_exec_id == 0` (M1), or dropping the per-slot `self_exec_id` check (M3), segfaults (139) in the exec scenario. That the crash comes from stale addresses is inferred, not traced.
7. In multi-uprobe mode one program and one task storage map serve every uprobe in the policy (`uprobe_multi`, v6.6, `89ae89f53d20`), so slot keys need the uprobe ID, as [andrewstrohman added](https://github.com/cilium/tetragon/pull/5904#discussion_r4414580593). The sharing is Tetragon's design, so this is only partly a kernel fact. Tested by mutation M2, which compares only the low 16 bits of `sym_id`: `other_target()` gets lib1's `repl` (exit 22, want 24).
8. The verifier allows variable-offset access into a map value only when it can prove the range fits (`check_map_access`, `kernel/bpf/verifier.c:5992`). Read in source only. The merged code loads on v6.18 and 7.2.9, and I didn't build a failing variant.

## Grading

Run `evals/cases/tetragon-multi-sopath/grade/test.sh <tree> <vmlinuz> [policy...]` on a 6.18+ kernel (fact 1). It rebuilds Tetragon's BPF objects and agent, then boots one VM per policy with `grade/targets.c` and two libraries built from `grade/lib.c`. On a low-disk host, set `GOCACHE` to a tmpfs dir.
`selectors.yaml` (multi-uprobe) and `selectors-nomulti.yaml` send arg 1 to lib1, 2 to lib2 and 3 to a symbol in the binary, over single calls and the `seq`, `exec` (facts 4-6) and `fork` (facts 3, 5) scenarios. `two-uprobes.yaml` alternates two uprobes on one thread (fact 7). A pass needs all three policies to load and every scenario to print `ok`.
Also check that a policy with more than 5 `sopath` selectors is rejected. The PR's Go unit tests cover that, and the VM run doesn't.
The merged tree passes on v6.18 and Arch 7.2.9 and refuses to load on v6.16. At the parent all three policies fail to load, and mutations M1, M2 and M3 each fail the scenario they target.

## Results

Not run yet.

Not tested: two threads of one process resolving at once (flaky at the parent too, 3/10 with one `sopath`, and 1/5 and 2/5 on the merged tree, so left out of the default scenarios), arm64, the library-constructor exec case from the review, the >5 limit in a VM, nested resolution, and kernels between v6.18 and 7.2.9.
