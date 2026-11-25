# Open-coded iterators in bpftrace for loops

Add `iter_task`, `iter_threads`, `iter_task_threads` and `iter_task_vma` loops to bpftrace, as in [bpftrace#5386](https://github.com/bpftrace/bpftrace/pull/5386). Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
I'd like bpftrace to support the kernel's open-coded BPF iterators, through the existing for loop syntax:

    for ($t : iter_task()) { ... }

Start with these:
- iter_task(): every process
- iter_threads(): every thread
- iter_task_threads(task): the threads of one task, e.g. iter_task_threads(curtask)
- iter_task_vma(task[, addr]): the VMAs of a task, yielding struct vm_area_struct

The loop variable should be the kernel struct pointer, so $t->pid or $v->vm_start just work. They should work like the other for loops do. Give a clear error when the kernel doesn't support them. Add parser, semantic and runtime tests, and update the docs and changelog. Don't use sudo on this machine.
```

Run in a clone of bpftrace at `3f97ba560b5a4f324cda1d519f311daf843baa96`, the commit before the PR.

## Facts

The kernel facts were tested with plain libbpf programs (`guest.c`, `test.bpf.c`), not bpftrace, on v6.6, v6.7, v6.11, v6.12, v6.13, v6.16, v6.17, v6.18, v6.19, v7.0, v7.1, v7.3 and Arch 7.2.9.

1. The task and task_vma iterator kfuncs came in c68a78ffe2cb and 4ac454682158, both first in v6.7. On v6.6, libbpf can't find `bpf_iter_task_destroy`. Tested.
2. The three task modes are flags 0, 1 and 2 to `bpf_iter_task_new`, from an enum in `kernel/bpf/task_iter.c` that isn't in UAPI. Flag 2 with a NULL task, or flag 3, returns -EINVAL. Flags 0 and 1 count one more task than `/proc`, because the walk starts at `init_task`. Tested from v6.7.
3. `bpf_iter_task_new` is `KF_RCU_PROTECTED` (dfab99df147b, v6.7). Sleepable `uprobe.s` programs are rejected unless the loop sits inside `bpf_rcu_read_lock()`. raw_tp, kprobe, tracepoint and perf_event programs load. Tested from v6.7. The PR doesn't handle sleepable probes.
4. `bpf_iter_task_vma_new` is `KF_RCU`. It rejects a pointer from `bpf_get_current_task()` and accepts one from `bpf_get_current_task_btf()`. Tested from v6.7.
5. Before 4cc8c50c9abc (first in v6.12), the task that `bpf_iter_task_next` returns can't be passed to `bpf_iter_task_vma_new` ("R2 must be a rcu pointer"). Rejected on v6.7 and v6.11, loads from v6.12. Tested.
6. `_destroy` must run even after `_new` fails, or the verifier reports "Unreleased reference". `bpf_iter_task_vma_new` returns -ENOENT for tasks without an mm. Tested from v6.7.
7. The iterator state must be on the stack, at an 8-byte aligned offset. It's rejected in a global and at stack offset -36. The kernel identifies it through the kfunc's own BTF (`is_kfunc_arg_iter` in `kernel/bpf/verifier.c`, v7.3), so the name of the program's struct doesn't matter. Tested from v6.7. The BTF part is read in source only.
8. A stack counter incremented in the loop and tested afterwards never converges ("BPF program is too large. Processed 1000001 insn"). Kept in a map value, as bpftrace's scratch variables are, it loads. Tested from v6.7. This matches the author's reply in [r4351121638](https://github.com/bpftrace/bpftrace/pull/5386#discussion_r4351121638). The widening mechanism (`widen_imprecise_scalars`) is read in source only.
9. An iterator loop that always breaks, inside a `bpf_loop` callback that writes its stack context, fails with "verifier bug: add backedge: no SCC in verification path" on v6.17, v6.18 and v6.19. This came in with 96c6aa4c63af and c9e31900b54c (v6.17) and was fixed by f597664454bd (v7.0). Tested.
10. From v7.1, d8e27d2d22b6 makes `bpf_iter_task_vma_new` return -EBUSY whenever interrupts are off. In `tp_btf/sched_switch` it gets EBUSY every time from v7.1, and 0 or ENOENT up to v7.0. Tested.

Note on fact 5: the PR's nested-iterator runtime tests say `MIN_KERNEL 6.7`, but the merged bpftrace's `nested_iter` script fails to load (-22) on v6.7 and v6.11.
Note on fact 9: the PR's error message says 6.17 to 6.18, and its test needs 7.1. In our tests v6.19 also fails and v7.0 passes. We couldn't check stable backports.

## Grading

Build bpftrace from the checkout (`cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF && make -C build -j4 bpftrace`), then run `evals/cases/bpftrace-iterators/grade/run.sh build/src/bpftrace <vmlinuz>`. It runs 16 scripts with `bpftrace -e`, then the 15 iterator scripts again with `config = { on_stack_limit = 0 }`, which moves variables to a scratch map and catches iterator state moved with them (fact 7). The last line is PASS (exit 0), FAIL with the failed scripts (exit 1) or ENV (exit 2). The scripts only use the prompt's syntax, so no adapter is needed.

The guest starts 8 extra threads, so `iter_task` and `iter_threads` must give different counts, both checked against `/proc`. `iter_task_threads` must yield exactly 9 tasks, `iter_task_vma` with an address must start at the VMA holding it, and a vma loop must run in `sched_switch` with interrupts off.

Accepted kernels: v6.6, v6.7, v6.11 to v6.13, v6.15 to v6.19, v7.0 to v7.3 and Arch 7.3. Anything else is ENV. On v6.6 every iterator script must fail with an error from a feature check that names the kernel; the loader's own "not present in kernel BTF" doesn't count. `nested_iter` may fail on v6.7 and v6.11 (fact 5), and `range_uncond_break` on v6.17 to v6.19 (fact 9). Scripts are killed after 8 s, so a hanging bpftrace fails instead of timing out the VM.

`grade/selftest.sh <bpftrace checkout> <build dir>` grades the merged PR, its parent and the patches in `grade/variants/` on v7.3 and v6.12 (v6.6 for `v8-nofeaturecheck`).

### Claim audit

The procedure is in the [README](../../../README.md#claim-audit).

| Run | Claims | Right | Too broad | Wrong | Unverified |
|---|---|---|---|---|---|
| As is | 38 | 30 | 6 | 0 | 2 |
| With the sentence | 38 | 26 | 7 | 1 | 4 |

Too broad in both runs:

- The task of an outer iterator can be passed to `iter_task_vma`. Rejected on v6.7 to v6.11 (fact 5).
- A failed VMA lookup means a contended mmap lock. From v7.1 the iterator takes per-VMA locks (bee9ef4a40a2).
- `_new`, `_next` and `_destroy` must be called from one frame. The state has to be on the stack, but a subprogram can advance it (`iter_pass_iter_ptr_to_subprog` in the selftests, v6.7).
- The kfuncs being in BTF means the iterator works. From v7.1 `bpf_iter_task_vma_new()` returns `-EOPNOTSUPP` without `CONFIG_PER_VMA_LOCK`.

As is, also too broad: `iter_task_threads(curtask)` yields every thread of the process. From v6.8 (5a34f9dabd9a) it skips the threads before a non-leader.

With the sentence:

- Wrong: kfuncs are resolved against the BTF of the machine compiling the program. They're `.ksyms` externs, which libbpf resolves at load.
- Too broad: the v6.8 thread order is documented for 6.7 too, where `next_thread()` wraps around.
- Too broad: address 0 visits all VMAs. From v7.1 a VMA whose lock can't be taken is skipped.
- Too broad: `task` must be a trusted pointer. `bpf_iter_task_vma_new()` also takes RCU pointers.

The unverified claims need a run: convergence, a few probe contexts and address layouts outside x86_64.

## Results

Sonnet 5.5 at medium effort, one fresh headless session per run with Write/Edit allowed, isolated from this repo. Capped at 6 cores and 8 GB. The run with the sentence was graded on a copy with the pinned libbpf, because it had built libbpf outside the repo.

Both runs PASS on v6.6 and FAIL on v6.7 (`prompt`, `loop_local`, `vma_addr`) and on v6.12, v6.18, v7.0 and v7.3 (the same three and `nested_iter`). For `prompt` the verifier says "BPF program is too large. Processed 1000001 insn" in both, on v6.12 and v7.3 (fact 8). The other three scripts were checked only by error code. Neither run loaded its code, though QEMU and `/dev/kvm` were available.

The merge (`4552f27b`) passes on every accepted kernel and is ENV on Ubuntu 6.8.0-149. The base (`3f97ba56`) fails every iterator script. Nine of the ten variants fail: swapped task flags, loop variables left on the stack, destroy only after a successful new, `addr` ignored, wrong `iter_task_threads` walks, no feature check, state in a scratch map and a hang. `v3-noalign` passes, because LLVM already aligns the iterator state.

Not tested: stable kernels with f597664454bd backported, kprobes with interrupts off on v7.1 and later (only the `sched_switch` tracepoint is checked), `PREEMPT_RT`, and whether the v6.7 and v6.11 load failure is "R2 must be a rcu pointer" in bpftrace's own output.
