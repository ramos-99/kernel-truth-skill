# scx_cidland as an EEVDF port

The task is a whole feature from [sched-ext/scx#3800](https://github.com/sched-ext/scx/pull/3800): turn scx_cidland into a port of fair.c's EEVDF on top of sched_ext. Facts from the PR and its review, checked against kernel source and tested in VMs.

## Prompt

```text
scx_cidland (scheds/experimental/scx_cidland) is a cid-form sched_ext scheduler with a vruntime/deadline queue borrowed from scx_cosmos. I want to turn it into a port of the kernel's EEVDF scheduler (fair.c) on top of sched_ext, as a baseline playground: close enough to upstream that changes can be applied to it incrementally and measured against the default kernel scheduler. Use fair.c's placement and fairness rules: order tasks by virtual deadline against a per-runqueue reference, keep lag across sleeps, charge runtime by weight the way fair.c does, and follow its wakeup preemption and wakeup CPU selection. Nice levels, SCHED_IDLE, a task's sched_runtime, cpu.weight and sched_yield() should all behave the way they do under EEVDF. It doesn't have to be a complete 1:1 port, but list what's missing in the README. Our machines run Linux 7.2. Implement it in this repo. Don't use sudo.
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

Build with `cargo build --release -p scx_cidland`, stage with `evals/cases/scx-cidland-eevdf/grade/stage.sh <binary> <dir>`, then run `VM_EXTRA=<dir> evals/vm/run.sh evals/cases/scx-cidland-eevdf <vmlinuz>` on Arch 7.2.9 (facts 10, 11). `VM_EXTRA` must be an absolute path.
Check the output with `evals/cases/scx-cidland-eevdf/grade/check <output>`. It needs the scheduler loaded and still enabled after the spinner pairs (facts 11-13), nice 0 vs 6 between 2.5 and 8, nice 0 vs 19 above 30, nice 19 vs SCHED_IDLE above 2.5 (facts 2, 3) and spinner vs yielder above 20 (fact 7). It prints `cpu.weight` 400 vs 100 without grading it. Read the code for facts 1, 4 and 5.
On Arch 7.2.9 the merged code passes every check and the parent fails the three weight checks. Merged gave 6.4 for nice 0 vs 6 against EEVDF's 3.75 over three runs. I didn't find out why, so the bounds are loose.

## Results

Not run yet.

Not tested: `ops.yield` with an op in place beyond the end result, re-enqueue reasons, PELT, the watchdog, the jump-sequence limit, latency and wakeup preemption, load balancing, cpufreq, multi-CPU placement, and `cpu.weight` on 7.3 with a fixed `scx_bpf_cid_topo()` call.
