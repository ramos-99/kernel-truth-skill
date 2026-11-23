# scx_mitosis subcells weighted by demand

The task is a whole feature from [sched-ext/scx#3817](https://github.com/sched-ext/scx/pull/3817): cells defined by a JSON config, split into subcells sized by demand. Facts from the PR's review and commits, checked against kernel source and tested in VMs.

## Prompt

```text
In scx_mitosis, cells can only come from the direct children of --cell-parent-cgroup, and each cell is one undivided pool of CPUs. I want to define cells from a JSON config file instead: each cell matches cgroups anywhere in the tree, and a cell can be split into subcells that pick up tasks by thread-name prefix (unmatched tasks go to a default subcell). Split each cell's CPUs between its subcells according to how much CPU each subcell's tasks actually need, so a busy subcell grows and an idle one shrinks, while sibling subcells can still use each other's idle CPUs. Rescan the cgroup tree periodically so cells follow cgroups as they come and go. Show per-subcell CPU count, utilization and demand in the stats. Implement it in this repo. Don't use sudo.
```

Run in a clone of sched-ext/scx at `6468d1b3c491b072cf87843c48b66672bcd6271d`, the commit before the PR. The PR's 22 commits end at `3e41326dd28cdcfd2ac7b0fd90a9cdab2ca8a91b` and were merged as `b502cf300dc6`.

## Facts

The probe is `probe.bpf.c` and `guest.c`, run with `VM_QEMU_ARGS="-smp 4,sockets=1,cores=2,threads=2" evals/vm/run.sh evals/cases/scx-mitosis-subcells <vmlinuz>` on Ubuntu v6.18 and Arch 7.3.5.

1. `ops.dispatch(cpu, prev)` can run on a CPU other than `cpu`, and only under core scheduling (v7.3 `dispatch_core_pick()` at `kernel/sched/ext/ext.c:3354`, v6.18 under `sched_core_enabled()` at `kernel/sched/ext.c:2171`), as [dschatzberg said](https://github.com/sched-ext/scx/pull/3817#discussion_r4145154339). Tested on both kernels with 4 hogs over 1s: 0 of ~34k dispatches differed without a cookie, and ~60k of ~94k did with a `PR_SCHED_CORE` cookie per hog.
2. `scx_bpf_now()` reads the executing CPU's rq through `this_rq()` (v6.18 `ext.c:6652`, v7.3 `ext.c:10780`). `scx_clock_task(cpu)`, which [dschatzberg suggested](https://github.com/sched-ext/scx/pull/3817#discussion_r4145183387), isn't a kfunc. It's a helper in `scheds/include/scx/common.bpf.h:1109` that reads the given CPU's `rq->clock_task`. Read in source only.
3. `rq->clock_task` leaves out IRQ time only with `CONFIG_IRQ_TIME_ACCOUNTING`, and steal time only with `CONFIG_PARAVIRT_TIME_ACCOUNTING` (`update_rq_clock_task()`, v7.3 `kernel/sched/core.c:~810`). The Ubuntu v7.3 config has `IRQ_TIME_ACCOUNTING` off. Read in source only. The header's note that the clock goes stale on a remote idle CPU was not checked.
4. If dispatch refills a still-queued `prev`'s slice, `prev` keeps running without `ops.stopping()` or `ops.running()` (v6.18 `SCX_RQ_BAL_KEEP` at `ext.c:2113`, v7.3 `SCX_DSP_PREV` at `ext.c:2995`), so time charged only in `stopping` reads zero for a solo task. This is commit 37905edcf. `scx_bpf_task_set_slice()` first appeared in v6.19 (`3035addfaf28`). Tested on both kernels with a pinned solo hog over 1s: with the refill, 0 `running`, 0 `stopping`, 167 refills and 1000 ticks. Without it, on 7.3.5, 167 running/stopping pairs.
5. With `SCX_OPS_ENQ_LAST` and no refill, the lone task goes to `ops.enqueue()` with `SCX_ENQ_LAST`, and before v7.3 putting it back on its own local DSQ stalls it. The fix is `7a9df7667963`, first in v7.3. Mitosis takes this path when a solo task needs re-placing (`mitosis.bpf.c:1228`). Tested: in 1s the hog got 40 ticks and 7 enqueues on v6.18, against 1000 ticks and 167 enqueues on 7.3.5.
6. `ops.quiescent()` gets `SCX_DEQ_SLEEP` only when the task actually sleeps. A property change such as `sched_setaffinity()` gives `quiescent` without `SLEEP` and then `runnable`, with no `running` between (v7.3 `core.c:9547`, `ext.c:2333-2336`). Tested on both kernels: a `usleep(500)` sleeper got ~1740 runnable/quiescent pairs, all with `SLEEP`, and 200 affinity changes added 17 (7.3.5) and 30 (6.18) without it.
7. `ops.tick()` runs on every tick for the running task. The PR uses it to close long demand windows for tasks that never stop. Tested: 1000 ticks/s on both kernels (HZ=1000).
8. `scx_bpf_create_dsq()` returns `-EINVAL` for the builtin bit, `-EEXIST` for a duplicate and `-ENODEV` with no scheduler. It's `KF_SLEEPABLE`, so `ops.init()` and syscall programs can call it. A syscall program gets `scx_root` in v6.18, and from v7.1 (`105dcd005be2`) `scx_prog_sched(aux)`, which is still the root unless the root sets `ops.sub_attach`. Mitosis doesn't. Tested from a syscall program on both kernels: -19 before attach, 0 after attach (associated or not), -17 for a duplicate, -22 for the builtin bit. `bpf_program__assoc_struct_ops` fails with EINVAL on 6.18 (`BPF_PROG_ASSOC_STRUCT_OPS` arrived in v7.0).
9. The first `scx_bpf_error()` call wins and the program keeps running after it (`scx_claim_exit()`, `atomic_try_cmpxchg` on `exit_kind`, v7.3 `ext.c:6747-6756`), so code has to return the error itself. This agrees with [tommy-u](https://github.com/sched-ext/scx/pull/3817#discussion_r4263773140) and [kkdwvd](https://github.com/sched-ext/scx/pull/3817#discussion_r4263877759). Tested on both kernels with two calls: code after them ran, the exit message was "first error" (kind 1025) and the state went to disabled.
10. A cgroup's BPF id (`kn->id`) equals the cgroupfs directory's inode number (`cgroup_id()` in `include/linux/cgroup.h:398`, `kernfs_ino()` in `include/linux/kernfs.h:370`). Tested: `p->cgroups->dfl_cgrp->kn->id` equalled `st_ino` 32/32 on 7.3.5 and 31/31 on 6.18.
11. A cgroup can vanish between listing its parent and opening it, which gives ENOENT and used to kill the scheduler. This is commit f0bf0e158, the "cgroup vanishing addressed" in tommy-u's approval. Partly tested: the merged scheduler stayed attached through cgroup churn with 2s rescans on every kernel. I didn't confirm the race actually happened.

Commit 4cca98626 says that applying subcells from a syscall program fails with -ENODEV "on this tree", and moves all DSQ creation into `ops.init()`. Stock v6.18 and v7.3 source and the probe give 0 while a scheduler without `sub_attach` is attached. The author may have meant a different kernel tree. Creating everything in `init` works either way, and this point is left out of grading.

## Grading

Build with `cargo build --release -p scx_mitosis`. Stage with `evals/cases/scx-mitosis-subcells/grade/stage.sh <binary> evals/cases/scx-mitosis-subcells/grade/cfg.json <dir> <args>`, translating `cfg.json` (one cell for `workload.slice` with subcells `worker-a*`, `worker-b*` and a default, plus a catch-all cell) to the implementation's format. The merged args were `--cell-config /cfg.json --enable-rebalancing --reconfiguration-interval-s 2 --monitor-sync 1`. Ubuntu mainline guests also need the kernel config at `<dir>/boot/config-<uname -r>`, or libbpf fails with EINVAL.
Run `VM_EXTRA=<dir> VM_QEMU_ARGS="-smp 8" evals/vm/run.sh evals/cases/scx-mitosis-subcells/grade <vmlinuz> > out.txt`, then `python3 -I evals/cases/scx-mitosis-subcells/grade/summarize.py out.txt`. A pass needs the scheduler alive after ~10s of cgroup churn and rescans (facts 8, 9, 11), `worker-a`, `worker-b` and `worker-c` on disjoint CPUs, `a` holding most of the cell, demand of about 6 / 1 / 1, and steady ~100% utilization for the solo subcells (fact 4).
The merged version passed on Ubuntu v7.3, Arch 7.3.5 and v6.18, with the v7.3 config standing in on v6.18. The parent rejects `--cell-config` at argument parsing.

## Results

Not run yet.

Not tested: whether the dispatch clock fix (facts 2, 3) changes any number, LLC-chunked placement (the VM has one LLC), the `ops.sub_attach` case where an unassociated program gets -ENODEV, whether the vanishing-cgroup race fired, and the parent binary in a VM.
