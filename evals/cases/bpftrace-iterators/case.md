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

The loop variable should be the kernel struct pointer, so $t->pid or $v->vm_start just work. These loops should behave like the other for loops: break, continue and return work, they can be nested in a range loop or in each other, and scripts like this one should load and print a count:

    begin { $n = 0; for ($t : iter_threads()) { $n++; } if ($n > 1) { print($n); } }

Give a clear error when the kernel doesn't support them. Add parser, semantic and runtime tests, and update the docs and changelog. Don't use sudo.
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

Note on fact 5: the PR's nested-iterator runtime tests say `MIN_KERNEL 6.7`. Whether bpftrace's generated code hits this rule on v6.7 to v6.11 hasn't been checked.
Note on fact 9: the PR's error message says 6.17 to 6.18, and its test needs 7.1. In our tests v6.19 also fails and v7.0 passes. We couldn't check stable backports.

## Grading

Build bpftrace from the checkout (`cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF`). Copy it into the guest with VM_EXTRA and run `bpftrace -e` on the prompt's script, the PR's `tests/runtime/for` cases, and the nested-iterator and break-in-range-loop scripts. Use v6.6, v6.7, v6.11, v6.12, v6.19, v7.0 and v7.3. Run `evals/vm/run.sh evals/cases/bpftrace-iterators <vmlinuz>` to see what each kernel itself allows. Not yet validated against the base or the merged PR, because bpftrace's build stops on the missing libcereal headers.

## Results

Not run yet.

Not tested: bpftrace's own codegen on any kernel, stable kernels with f597664454bd backported, kprobes with interrupts off on v7.1 and later, or `PREEMPT_RT`.
