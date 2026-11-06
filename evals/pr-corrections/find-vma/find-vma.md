# bpf_find_vma called more than once

From [bcc#4679](https://github.com/iovisor/bcc/pull/4679#discussion_r1340007477).

```text
I have a BPF perf_event program that grabs the user stack with bpf_get_stack. For each frame I want to know which file it belongs to and its offset, so in the BPF program I'm going to loop over the frames, up to 8, and call bpf_find_vma on each one, then send it all through a ring buffer. We're on 6.6. Can you show me the BPF side? Don't write any files, and don't use sudo.
```

## Said in the thread

- `bpf_find_vma` can only be called once in NMI context such as a perf event. The first call gave correct results and the second didn't. It cites `tools/testing/selftests/bpf/progs/find_vma.c`.

## Checked

Tested with `vm/run.sh find-vma $(vm/get-kernel.sh v6.18)` on v5.17, v6.6, v6.18 and Arch 7.2.9, calling it twice per run in each context.

- The second call returns `-EBUSY` every time in a perf_event program, with both hardware and software perf events. So only the first frame in the loop would resolve. From source, the callback doesn't run when that happens (`kernel/bpf/task_iter.c:753`).
- The thread is right about perf events, and the kernel selftest expects exactly this: `-EBUSY /* in nmi, irq_work is busy */` (`prog_tests/find_vma.c`). Nobody disputes it in the PR, which has only 3 comments and was never merged.
- It isn't only NMI, though, which goes further than the thread. A `tp_btf/sched_switch` program with interrupts off and no NMI behaves the same. The rule in source is `irqs_disabled()`, because `mmap_read_unlock()` has to wait for a per-CPU `irq_work` that can't be queued twice (`kernel/bpf/mmap_unlock_work.h`). I didn't confirm that the hardware perf event in the VM was delivered as an NMI.
- The second call isn't a wrong result, as the thread suggests. It's an error code, so checking the return value catches it.
- With interrupts on, as in `raw_tp/sys_enter`, both calls succeed every time.
- Even the first call can return `-EBUSY`, which happened 5 times in 1890 on v5.17 with hardware events.
- The helper came in v5.17, so v5.16 can't load this (`FN(find_vma)` in `include/uapi/linux/bpf.h`).

A good answer says the loop won't work in this context and offers something else, such as sending addresses to userspace.

`bpf_get_stack` with `BPF_F_USER_BUILD_ID` does work here, because it takes the lock once for the whole stack (`stack_map_get_build_id_offset`, `kernel/bpf/stackmap.c`). It returned a build ID for all 8 frames in every sample on v6.6, v6.18 and 7.2.9. `bpf_get_stackid` with that flag returns `-EINVAL` every time. Not tested: `PREEMPT_RT`, which fails with `-EBUSY` from source.

## Runs

Sonnet 5.5, medium effort, graded by Claude and not blind.

- **No hint:** no lookups. It wrote the loop and warned that `bpf_find_vma` "can fail often" with `-EBUSY`. With `ENOENT` defined, because the code as written doesn't compile, frames 1 to 7 returned `-EBUSY` in all 15421 samples on v6.6, v6.18 and 7.2.9, and frame 0 resolved in all but one. It also suggested `bpf_get_stackid` with `BPF_F_USER_BUILD_ID`, which fails, and explained its `vm_start` check as necessary, when the helper only calls back if the address is inside the VMA.
- **With the sentence:** read v6.6 source and said the loop can't work, with frame 0 resolved and the rest `-EBUSY`. It offered `bpf_get_stack` with `BPF_F_USER_BUILD_ID`. Its code compiled and loaded as written, and returned a valid build ID for every frame in all 15428 samples on the same kernels. It said it was inferring that perf_event programs run with interrupts off, and the test agrees for both event types. Whether the offsets are correct wasn't checked.
