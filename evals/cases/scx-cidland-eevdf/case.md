# scx_cidland as an EEVDF port

The task is a whole feature from [sched-ext/scx#3800](https://github.com/sched-ext/scx/pull/3800): turn scx_cidland into a port of fair.c's EEVDF on top of sched_ext. Facts from the PR and its review, checked against kernel source and tested in VMs.

## Prompt

```text
scx_cidland (scheds/experimental/scx_cidland) is a cid-form sched_ext scheduler with a vruntime/deadline queue borrowed from scx_cosmos. I want to turn it into a port of the kernel's EEVDF scheduler (fair.c) on top of sched_ext, as a baseline playground: close enough to upstream that changes can be applied to it incrementally and measured against the default kernel scheduler. Use fair.c's placement and fairness rules: order tasks by virtual deadline against a per-runqueue reference, keep lag across sleeps, charge runtime by weight the way fair.c does, and follow its wakeup preemption and wakeup CPU selection. Nice levels, SCHED_IDLE, a task's sched_runtime, cpu.weight and sched_yield() should all behave the way they do under EEVDF. It doesn't have to be a complete 1:1 port, but list what's missing in the README. Our machines run Linux 7.2. Implement it in this repo. Don't use sudo on this machine.
```

Run in a clone of sched-ext/scx at `8b2479571c0768310510c061960d2c40cb64d160`, the commit before the PR. The PR's 66 commits end at `38b355f2010b1abb91b07acd9141d7773cc17acd` and were merged as `6e01d48ac53a`.

## Facts

Source refs are at v7.2 unless noted. Kernels: Ubuntu mainline v7.2 and v7.3, Arch 7.2.9 and Arch 7.3.5, all HZ=1000.

1. A sched_ext slice is only acted on at the tick. `task_tick_scx()` reschedules when `scx.slice` is 0 and there is no hrtick path (`kernel/sched/ext/ext.c:3540-3558`). Tested on all three 7.2/7.3 kernels: 100us and 700us slices ran about 0.93ms, 1000us ran 1.8-1.9ms and 2500us about 3ms, which is why the PR keeps the default at 700us.
2. `p->scx.weight` is `sched_weight_to_cgroup()`, `clamp(DIV_ROUND_CLOSEST(w * 100, 1024), 1, 10000)` (`kernel/sched/sched.h:266`). Tested through `ops.set_weight`: nice 0 gives 100, nice -20 gives 8668, and nice 19 and SCHED_IDLE both give 1. Charging by it gets nice 19 about 100x instead of 68x.
3. `p->se.load.weight` is stale for a sched_ext task, because `reweight_task_scx()` doesn't store into `se.load` (`ext.c:3963-3987`). Tested: 1048576 at every nice level and for SCHED_IDLE. The merged code goes back to `sched_prio_to_weight[]` via `static_prio` and `policy`.
4. `sched_attr.sched_runtime` sets `se.custom_slice` and clamps `se.slice` to 100us..100ms for every fair policy, SCHED_EXT included (`__setparam_fair()`, `kernel/sched/fair.c:5951-5964`). Tested: 3ms, 20us and 500ms gave 3000000, 100000 and 100000000, and SCHED_EXT with 3ms gave 3000000 with `custom_slice` 1.
5. Nothing maintains PELT (`p->se.avg`) for a sched_ext task. There is no `update_load_avg()` caller under `kernel/sched/ext/`. Read in source only.
6. A waking task keeps whatever slice it had left. The kernel refills `scx.slice` only when it is 0 (`ext.c:3233-3251`, `refill_task_slice_dfl()` at `ext.c:1416`). Tested: a task running 3ms and sleeping 5ms under a 20ms slice woke 5 of 5 times with slice left (mean 15-17ms).
7. Once `ops.yield` is defined, `yield_task_scx()` no longer zeroes `p->scx.slice` (`ext.c:2197-2217`). The op has to end the slice itself, for example with `scx_bpf_task_set_slice()` (v6.19). Tested without an op only: a yielder beside a hog stopped with slice 0 in 9-10 of 13-14 stops. The grading run catches an op that forgets it. The merged comment names `scx_task_slice_ended()` and `SCX_TASK_PROTECTED`, which exist only from v7.3.
8. Re-enqueue reasons are in `p->scx.flags`: `SCX_ENQ_REENQ` plus `SCX_TASK_REENQ_REASON_MASK` with `SCX_TASK_REENQ_IMMED` or `SCX_TASK_REENQ_PREEMPTED` (`include/linux/sched/ext.h:138-143`), first in v7.1 (`98d709cba319`) with `SCX_ENQ_IMMED`. Read in source only.
9. The cid form's cgroup weight op was `cgroup_set_weight` in v7.2 (`bba2c3615bd6`) and became `cpuctl_set_weight` in v7.3 (`b20dfde5ec54`). The merged scheduler only enables cgroup weights when it finds the new name. Tested on Arch 7.2.9: it logs "cgroup weights: off", and `cpu.weight` 400 vs 100 splits 1.00 where EEVDF gives 3.98.
10. `scx_bpf_cid_topo()` gained a size argument in v7.3 (`94480606a677`). Tested: the merged binary fails to load on Ubuntu v7.3 and Arch 7.3.5 with "kfunc 'scx_bpf_cid_topo' is referenced but wasn't resolved".
11. Loading needs BTF from pahole 1.26 or later for the `KF_IMPLICIT_ARGS` kfuncs, and the kernel config for `__kconfig` externs. Tested: on Ubuntu mainline v7.2 the merged binary refuses to start and names the malformed prototypes. Ubuntu kernels have no `/proc/config.gz`, so `stage.sh` takes `KCONFIG=`. Arch 7.2.9 is the only kernel here where it loads.
12. The watchdog ends the scheduler when a runnable task waits past `ops.timeout_ms` (`check_rq_for_timeouts()`, `ext.c:3463-3483`). The merged code floors the weight used for deadlines and lag at 256 for this reason. Read in source only, and no stall happened in any run.
13. A `may_goto` loop with a precise counter never converges, because the verifier widens only imprecise scalars (`kernel/bpf/verifier.c:15966-15980`). htejun's [comment](https://github.com/sched-ext/scx/pull/3800#issuecomment-5637263934) and [review](https://github.com/sched-ext/scx/pull/3800#discussion_r3999936840) step the counter by a writable `volatile` value. Tested with `loops.bpf.c` on v7.2, v7.3 and Arch 7.2.9: a plain counter is rejected at 1000001 insns, a writable `volatile u32 one` step loads, a `const volatile` step is rejected and `bpf_for()` loads. An unknown start alone also loaded, but my loop body doesn't make the counter precise again. The 8192 jump-sequence limit is not tested.

The PR says `cpu.weight` is honored, measured on "Linux v7.2.2". At this commit the code turns cgroup weights off on Arch 7.2.9 (fact 9) and doesn't load on 7.3 (fact 10). The author's kernel may have had the rename backported. `cpu.weight` is left out of grading.

## Grading

Only Arch 7.2.9 (`evals/runs/kernels/host`) can load this scheduler. cid-form sched_ext starts in v7.2, Ubuntu's v7.2 BTF is too old (fact 11) and 7.3 changed `scx_bpf_cid_topo()` (fact 10). The grader says ENV on any other kernel.

Build with `cargo build --release -j4 -p scx_cidland`. If the implementation needs command-line arguments, put them in `grade/adapter.sh` (the merged PR needs none). Then run `evals/cases/scx-cidland-eevdf/grade/run.sh target/release/scx_cidland`. It boots Arch 7.2.9 with `grade/guest.c`, starts the scheduler, runs tasks on CPU 1 and scores them with `grade/check`. The last line is PASS, FAIL or ENV (exit 0, 1 or 2). ENV is only for setup problems: wrong kernel, no binary, a VM that doesn't boot. A scheduler that never reaches `enabled` on Arch 7.2.9 (verifier rejection, init error, crash while loading) is FAIL, and the log tail in the output says why. With `EEVDF=1` the same workloads first run under the kernel's own scheduler, for reference.

The checks (EEVDF and merged numbers are in `grade/check`):

- The scheduler is still enabled after the workloads.
- Weights (facts 2, 3), as CPU-time ratios: nice 0 vs 6 in 2.5..7.5 (EEVDF 3.75, merged 6.5), nice 0 vs 19 in 40..200, nice 17 vs 18 in 1.12..1.8, nice 18 vs 19 in 1.08..1.7, nice 19 vs SCHED_IDLE above 2.5. Charging by `p->scx.weight` passes the first two but gives 1.0, 2.9 and 1.0 on the rest.
- Yield (fact 7): spinner vs yielder above 10.
- Lag across sleeps: a task that runs 1ms of CPU and sleeps 50us next to a nice 5 spinner should get about its 3:1 share (ratio 0.15..0.6). Dropping lag at wakeup gives about 1. Turning off wakeup preemption fails this check too.
- sched_runtime (fact 4): two spinners asking for 100ms or 20ms switch at most 100 or 200 times a second. The default request gives about 500.
- Wakeup preemption: a task that sleeps 1ms next to a nice 0, SCHED_IDLE or 20ms-request hog gets the CPU back within 300us (median). Against the 20ms hog the 90th percentile must stay under 2ms. EEVDF takes 8us. Without preemption the task waits about 900us for the tick. The SCHED_IDLE hog is always past its share when the waker arrives, so this row goes through the ordinary eligibility path. It doesn't test the rule that an idle curr is preempted by any non-idle wakee.
- Wakeup CPU selection: a task that wakes with its previous CPU busy and two idle CPUs lands on an idle one at least 90 times out of 100.

`cpu.weight` is not graded on purpose. The merged PR doesn't honour it on 7.2 (fact 9: 400 vs 100 splits 1.00), so a check would fail the reference. For facts 1 and 5, read the code.

`grade/selftest.sh <scx clone>` builds the merged PR (graded twice), the parent and the merged PR with each patch in `grade/variants/` applied. Merged has to pass, the parent and the wrong variants have to fail, and c4 and c5 (correct but different) have to pass. b2 (no idle-curr rule) is marked "Not caught" and passes. Beside one SCHED_IDLE hog the merged code never treats the hog as owed service, and with two hogs, where EEVDF does show the rule (5us), the merged PR itself waits 899us for the tick.

### Claim audit

The procedure is in the [README](../../../README.md#claim-audit).

| Run | Claims | Right | Too broad | Wrong | Unverified |
|---|---|---|---|---|---|
| As is | 104 | 82 | 10 | 11 | 1 |
| With the sentence | 91 | 75 | 7 | 9 | 0 |

Judged on v7.2. Wrong in both runs: the imbalance is 125 outside the LLC. `sd_init()` uses 117, and 110 for SMT.

Wrong, as is:

- A task inserted from `ops.enqueue` is already in the DSQ. `mark_direct_dispatch()` only records it, and the insert happens after the op returns.
- `cfs_rq_min_slice()` never exceeds the base slice. It starts at `~0ULL`.
- Without `RUN_TO_PARITY` the minimum quantum is the scaled base slice. It's the normalized 0.7ms.
- Returning from `ops.dispatch` keeps the current task running. `main.rs` sets `SCX_OPS_ENQ_LAST`, so it's enqueued again.
- `ops.select_cid` runs for exec. `select_task_rq_scx()` returns early on `WF_EXEC`.
- After `scx_bpf_dsq_move()` the task isn't queued anywhere. It's on the local DSQ.
- Nothing in `fair.c` stops a task between ticks. `HRTICK` is on with `CONFIG_HRTIMER_REARM_DEFERRED`.
- The lag limit is double the slice. The code uses `max_slice + TICK_NSEC`, and the kernel's own comment is stale.
- `pick_next_task_fair()` and `newidle_balance()` are named as current. Neither exists in v7.2.

Wrong, with the sentence:

- `tg->shares` is unscaled. It's stored through `scale_load()`.
- `scx_bpf_dsq_move()` to a CPU the task can't use returns false. It ends the scheduler with an error.
- The slice scan in `ops.enqueue` sees the woken task. It isn't in the DSQ yet.
- The lowest vruntime in a capped walk is always eligible.
- The wakee's load is part of the previous CPU's load, so it's subtracted. That holds for PELT but not for this port's runnable weight.
- `wake_up_new_task()` is the only enqueue of a task never placed. Enabling the scheduler enqueues existing tasks too.
- Picking the same task again re-arms its slice protection. `put_prev_set_next_task()` returns early.
- `__setparam_fair()` is in `syscalls.c`. It's in `fair.c`.

The too broad claims are mostly limits left out: `sched_runtime` applies only to `fair_policy()` tasks, `resched_curr_lazy()` is lazy only with lazy preemption, and the x86 JIT refuses only fetching AND, OR and XOR on the arena.

## Results

The selftest is green on Arch 7.2.9. Merged passes twice, and the parent fails every weight, lag, sched_runtime and wakeup-latency check. v1 (`p->scx.weight`) fails nice 17/18, 18/19 and 19/IDLE. v2 (no lag) fails lag and the 20ms-hog p90 (19.8ms). v3 (no sched_runtime) fails both request checks. v4 (yield without ending the slice) fails yield. v5 (no wakeup preemption) fails lag and the latency checks. v6 (always the previous CPU) fails wakeup CPU selection. b1 (`se.load` weight) fails the weight checks, b3 (deadline scaled the wrong way) fails nice 5 vs burst, b4 (yield without forfeit) fails yield, b5 (lag sign) and b6 (kick without `SCX_KICK_PREEMPT`) fail lag and latency, and b7 (init error) is FAIL. c4 and c5 pass, and b2 passes as noted above.

Sonnet 5.5 at medium effort, one fresh headless session per run with Write/Edit allowed, isolated from this repo. Capped at 6 cores and 8 GB. Neither run loaded its code, though QEMU and `/dev/kvm` were available, and both said so.

As is: FAIL in 4 of 4 gradings on Arch 7.2.9, on both burst checks, both `sched_runtime` checks and the median latency beside the nice 0 and 20ms hogs (1899us). Weights, yield, `SCHED_IDLE` and CPU selection pass. A copy with two fixes passes:

- Wakeup preemption scans the DSQ for the woken task from `ops.enqueue`, before it's inserted. This causes the burst and latency failures.
- `rq_min_slice()` starts at the base slice, so longer requests aren't protected. This causes the `sched_runtime` failures.

With the sentence: FAIL in 3 of 3 gradings, because it doesn't load. The verifier stops `cidland_dispatch` at 1000001 instructions (fact 13). A copy with two fixes passes 2 of 2:

- Stepping the three `++n` scan counters by a writable `volatile` makes it load.
- It's then ejected ("SCX_DSQ_LOCAL[_ON] target CPU 3 not allowed"), because `pull_task()` doesn't check affinity. Checks after that point measure the kernel's own scheduler.

`cpu.weight`, tested separately on Arch 7.2.9 with two cgroups on one CPU at 400 and 100: 3.97 as is and 3.98 under EEVDF. The fixed copy of the run with the sentence gives 1.00, and 3.99 once `tg->shares` is scaled down.

Both fixed copies switch 51 to 53 times a second with a 100ms request, and EEVDF 23 to 25. The limit of 100 doesn't catch this. Their 20ms backstop slice is the likely cause.

On Arch 7.3.5 neither loads. `scx_bpf_cid_topo` isn't resolved (fact 10), seen in the verifier log as is and in libbpf's relocation log for the fixed copy with the sentence.

Not tested: re-enqueue reasons, PELT, the watchdog, the jump-sequence limit, load balancing, cpufreq, `cpu.weight` on 7.3 with a fixed `scx_bpf_cid_topo()` call, and the SCHED_IDLE preemption rule separately from its weight (a waker beats a weight-3 hog either way).
