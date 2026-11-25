# Multiple sopath overrides in Tetragon uprobes

The task is a whole feature from [cilium/tetragon#5904](https://github.com/cilium/tetragon/pull/5904), fixing [#5882](https://github.com/cilium/tetragon/issues/5882): let each selector have its own `sopath` override. Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
Tetragon's uprobe Override action can load the replacement function from a shared library with `sopath`, but only once: a uprobe can have just one selector with a `sopath` override, and a multi-uprobe policy only one in the whole policy. I want to lift that limit so that up to MAX_SELECTORS selectors can each have their own `sopath` override. For example, matchArgs on the first argument sending 1 to repl() in /lib/libimpl-1.so and 2 to repl() in /lib/libimpl-2.so, with another selector still overriding to a symbol in the binary itself, and the same across different uprobes in one policy. Policies with more than that should still be rejected. Please implement it in this repo, with tests. Don't use sudo on this machine.
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

Run `evals/cases/tetragon-multi-sopath/grade/test.sh <tree> <vmlinuz>` on v6.18 or v7.3; other kernels give ENV. It builds Tetragon's BPF objects and agent with the repo's own make targets (`-j4`, and a temporary `GOCACHE` unless you set one), then boots one VM per policy with `grade/targets.c` and three small libraries. lib2.so has a 4 KiB pad before `repl`, so a symbol offset taken from the wrong library doesn't work by luck. The policies use only the `sopath` API that existed before the PR, so there's no adapter to fill in.

- `selectors.yaml` (multi-uprobe) and `selectors-nomulti.yaml` send arg 1 to lib1, 2 to lib2 and 3 to a symbol in the binary, over single calls, a mix on one thread, exec (facts 4-6) and fork (facts 3, 5).
- `two-uprobes.yaml` alternates two uprobes on one thread (fact 7), then runs `race` 16 times: two threads of one process call `arg_target(1)` at once (fact 2). A crash or a wrong value fails. A call left un-overridden is allowed, because the merged PR does that too.
- `five-ok.yaml` has exactly 5 `sopath` selectors and must load, and all five slots have to work on one thread.
- `nested.yaml` overrides to `lib3.so`, whose constructor calls another overridden symbol while it's being loaded. Without a guard against starting a second resolution there, the target segfaults.
- `too-many.yaml` is a multi-uprobe policy with 6 `sopath` selectors across two uprobes and must be rejected. The PR's limit is 5 per multi-uprobe policy, since all its uprobes share one program and one slot store. With uprobe-multi disabled it sets no limit across uprobes, and that isn't tested.

The last line is `PASS`, `FAIL: <policy:problem ...>` or `ENV: <reason>`, with exit code 0, 1 or 2. `grade/selftest.sh <parent-tree> <merged-tree> <vmlinuz>` checks that the merged tree passes, and that the parent and each `grade/variants/*.patch` fail. v6-v8 came from the second audit: exec detected by PID, state in a map keyed by process ID instead of task storage, and the detour return recognised only for slot 0.

On v6.18 the merged PR crashed in none of 80 `race` runs, and left 30 of their 320 calls un-overridden. The process-keyed variant crashed in 37 of 80, so 16 runs miss it with odds of about 1 in 20,000.

### Claim audit

The procedure is in the [README](../../../README.md#claim-audit).

| Run | Claims | Right | Too broad | Wrong | Unverified |
|---|---|---|---|---|---|
| As is | 16 | 13 | 1 | 1 | 1 |
| With the sentence | 17 | 14 | 2 | 0 | 1 |

Only the two runs without a VM wrapper were audited.

As is:

- Wrong: a test skip message says the `SubString` operator needs `bpf_copy_from_user_str`. The tests use `Equal` on integers, and substring search uses `bpf_strnstr`.
- Too broad: the check for clashing library names compares `sopath` basenames. A symlinked `sopath` is mapped under its target's name.

With the sentence:

- Too broad: "If any step fails, the failure is cached". `call_mmap()` returns before saving `self_exec_id` when there's no libc, so the next hit starts over.
- Too broad: libraries are found by file name alone, and two with the same name aren't rejected.

Unverified in both: whether the verifier accepts the changed cache access. Every program loaded in the graded runs.

## Results

Sonnet 5.5 at medium effort, one fresh headless session per run with Write/Edit allowed, isolated from this repo. All four runs PASS on v6.18 and v7.3 with `grade/test.sh`.

- As is and with the sentence, prompt ending in "Don't use sudo.": both keep one cached address per `sopath` selector. Neither loaded its BPF code, citing the lack of root, though QEMU and `/dev/kvm` were available.
- The same two with a VM wrapper in the prompt: both ran their own and the existing `sopath` policytests on v6.18 and v7.3, and each fixed a test failure that way.

Two libraries with the same file name in different directories (`/t/a/lib.so`, `/t/b/lib.so`) resolve to whichever is mapped first, so a child that resolves 2 and then 1 calls lib1's offset inside lib2. Tested on v6.18 and v7.3. The run as is without a VM rejects such a policy. The other three call the wrong function, and so does the merged PR, so it isn't scored.

The docs example in the run as is without a VM has unquoted `- 1` values, which v7.3 refused ("cannot unmarshal JSON number into Go string").

`pad()` in `lib.c` returns its argument, so lib1's offset used inside lib2 returns 1 for `arg_target(1)`, which looks right. With `return 99` in a scratch copy all four runs still pass on v7.3.

The grader passes the merged tree on v6.18 and fails the parent and all eight variants there. The version before `race` and the lib2 pad also passed the merged tree on v7.3. The current one hasn't been run on v7.3 with the merged tree.

Not tested: whether two threads at once get every call overridden (the merged PR misses some, so `race` only checks for crashes and wrong values), arm64, the library-constructor exec case from the review, and kernels between v6.18 and 7.2.9.
