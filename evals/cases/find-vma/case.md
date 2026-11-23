# bpf_find_vma called more than once

The task comes from a review comment on [bcc#4679](https://github.com/iovisor/bcc/pull/4679#discussion_r1340007477). Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
I have a BPF perf_event program that grabs the user stack with bpf_get_stack. For each frame I want to know which file it belongs to and its offset, so in the BPF program I'm going to loop over the frames, up to 8, and call bpf_find_vma on each one, then send it all through a ring buffer. We're on 6.6. Can you show me the BPF side? Don't write any files, and don't use sudo.
```

## Facts

1. The thread says `bpf_find_vma` can only be called once in NMI context such as a perf event: the first call gave correct results and the second didn't. It cites `tools/testing/selftests/bpf/progs/find_vma.c`, and the kernel selftest expects exactly this: `-EBUSY /* in nmi, irq_work is busy */` (`prog_tests/find_vma.c`). Nobody disputes it in the PR, which has only 3 comments and was never merged.
2. In a perf_event program the second call returns `-EBUSY` every time, with both hardware and software perf events, so only the first frame in the loop would resolve. From source, the callback doesn't run when that happens (`kernel/bpf/task_iter.c:753`). Tested on v5.17, v6.6, v6.18 and Arch 7.2.9.
3. A `tp_btf/sched_switch` program with interrupts off and no NMI behaves the same. The rule in source is `irqs_disabled()`, because `mmap_read_unlock()` has to wait for a per-CPU `irq_work` that can't be queued twice (`kernel/bpf/mmap_unlock_work.h`). Tested on the same kernels.
4. With interrupts on, as in `raw_tp/sys_enter`, both calls succeed every time. Tested on the same kernels.
5. Even the first call can return `-EBUSY`, which happened 5 times in 1890 on v5.17 with hardware events.
6. The helper came in v5.17 (`FN(find_vma)` in `include/uapi/linux/bpf.h`). Tested: the program fails to load on v5.16 and loads on v5.17.
7. `bpf_get_stack` with `BPF_F_USER_BUILD_ID` does work here, because it takes the lock once for the whole stack (`stack_map_get_build_id_offset`, `kernel/bpf/stackmap.c`). It returned a build ID for all 8 frames in every sample on v6.6, v6.18 and 7.2.9. `bpf_get_stackid` with that flag returns `-EINVAL` every time.

Our tests go further than the thread in two places. The limit isn't only NMI (fact 3). And in our runs the second call returned an error code, which checking the return value catches. I didn't confirm that the hardware perf event in the VM was delivered as an NMI.

## Grading

A good answer says the loop won't work in this context and offers something else, such as sending addresses to userspace. The test calls the helper twice per run in each context: `evals/vm/run.sh evals/cases/find-vma $(evals/vm/get-kernel.sh v6.18)`, on v5.17, v6.6, v6.18 and Arch 7.2.9.

## Results

Sonnet 5.5, medium effort, graded by Claude and not blind.

- Without a hint: no lookups. It wrote the loop and warned that `bpf_find_vma` "can fail often" with `-EBUSY`. The code as written doesn't compile. With `ENOENT` defined, frames 1 to 7 returned `-EBUSY` in all 15421 samples on v6.6, v6.18 and 7.2.9, and frame 0 resolved in all but one. It also suggested `bpf_get_stackid` with `BPF_F_USER_BUILD_ID`, which fails, and explained its `vm_start` check as necessary, when the helper only calls back if the address is inside the VMA.
- With the sentence: it read v6.6 source and said the loop can't work, with frame 0 resolved and the rest `-EBUSY`. It offered `bpf_get_stack` with `BPF_F_USER_BUILD_ID`. Its code compiled and loaded as written, and returned a valid build ID for every frame in all 15428 samples on the same kernels. It said it was inferring that perf_event programs run with interrupts off, and the test agrees for both event types. Whether the offsets are correct wasn't checked.

Not tested: `PREEMPT_RT`, which fails with `-EBUSY` from source.
