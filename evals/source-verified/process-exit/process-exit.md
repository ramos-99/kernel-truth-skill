# Process exit logger

I had Claude pick this case, and it seems to be something the model already knows well, so it says little about the skill. Keep it apart from cases taken from real reviews.

Based on `3e816361e94a`, whose message gives this use case. Run it in an empty directory. Run twice so far without a hint, once as this task and once ending in "how would you do it?" instead of asking for code. Those runs taught me the `active_mm` route and the fork handling below, which this answer had missed.

```text
I'm writing a small tool with libbpf in C that logs processes as they exit, so we can symbolize their stack traces later. For each process I want one line with the pid, the name and the load address of its main binary. Just one line per process, not one per thread. I was going to hook the `sched_process_exit` tracepoint. It'll run across our machines, some still on 5.15, others on the latest kernel. Keep it as small as you can, and don't use sudo, I'll test it myself.
```

## Answer

A good run either handles kernels before v6.16 or says plainly what won't work there. Whether `start_code` is exactly the load address isn't being graded.

"Tested" means booted in KVM with `./run.sh <vmlinuz>`: v5.10, v5.15, v6.1, v6.6, v6.12, v6.15, v6.16 and v6.18 from Ubuntu's mainline builds, plus Arch 7.2.9. Everything older comes from source.

- The tracepoint fired after `exit_mm()` from when it was added in 2008 (`0a16b6075843`) until v6.16 (`3e816361e94a`). Sampled from v2.6.32 to v6.15, and the order is the same throughout.
- The stable branches from 5.4.y to 6.15.y didn't backport the move. Distro kernels weren't checked, so an answer can't be marked down for raising them.
- Before v6.16, `task->mm` is NULL at the tracepoint and reading `mm->start_code` gives 0 with no error, so the tool logs 0. Tested from v5.10 to v6.15. From v6.16 it gives the real value.
- The `group_dead` field only exists from v6.16. On older kernels, a program reading it loads but fails to attach with `-EACCES` (`kernel/events/core.c:11732`). Tested.
- The tracepoint's `pid` is the thread id, and the last thread to exit may not be the main thread, so it isn't always the process id. Tested: with the main thread exiting first, the final event's `pid` differs from the tgid. The tool should log the tgid.
- `pid == tgid` doesn't mean the process ended, because the last live thread decides (`kernel/exit.c:933`). Tested: the main thread exits with `group_dead` 0 while a worker is still running.
- Before v6.16, `signal->live == 0` at the tracepoint is close but not exact. Tested with 9 threads exiting together: two threads saw 0 in 1 of 800 processes on v6.6, and none in 800 on v5.15 or 200 each on v5.10, v6.1, v6.12 and v6.15. A second tool using this check logged a process twice 3 times in 4000 across v5.10, v5.15, v6.6 and v6.15, the 3 being on v6.6 and v6.15. Only claiming it's exact counts as wrong.
- The `group_dead` at `kernel/exit.c:162` is a different variable, in `__exit_signal`, meaning `thread_group_leader(tsk)`.

Ways to do it on older kernels. A run may find others, which get judged on whether they work:

- `p->active_mm` at the tracepoint still points at the mm after `exit_mm()`, which takes a reference and only clears `current->mm` (v5.15 `kernel/exit.c`, inside `exit_mm()`). Reading `start_code` through it matched `/proc/self/stat` for every process on v5.10, v5.15, v6.6, v6.15, v6.16, v6.18 and 7.2.9, x86_64 only.
- `fentry/taskstats_exit` and `kprobe/acct_collect` both receive `group_dead` and run before `exit_mm()`. Tested on v5.10 and later: `mm` was set in every sampled event, and `taskstats_exit` reported `group_dead` for exactly one thread in all 200 processes per run. `acct_collect` wasn't counted in that test. They need `CONFIG_TASKSTATS` and `CONFIG_BSD_PROCESS_ACCT`, and without those they compile to nothing (`include/linux/taskstats_kern.h`, `include/linux/acct.h`).
- `sched_process_exec` has `mm` set and gave the same `start_code` as later events, so the address can be saved at exec and logged at exit. Tested, along with `AT_ENTRY` from `mm->saved_auxv` and copying the entry at `sched_process_fork`, which covers children that never exec. It misses processes that were already running.
- `fentry/do_exit` runs before `exit_mm()`. It loaded and attached on v5.10, v5.15, v6.6, v6.16, v6.18 and Arch 7.2.9, but `group_dead` isn't decided yet at that point.
- `fentry/exit_mm` isn't portable. It loaded on v5.15, v6.6, v6.15, v6.16 and v6.18, but not on v5.10 or Arch 7.2.9, where `exit_mm` isn't in BTF. The v5.10 reason wasn't checked.

Older kernels, from source only: the tracepoint order is unchanged, but the BPF features shrink. Kprobe programs arrived in v4.1, tracepoint programs in v4.7, `bpf_get_current_task` in v4.8, `CONFIG_DEBUG_INFO_BTF` in v5.2 and fentry in v5.5.

## Runs

Sonnet 5.5, medium effort, one run each, graded by Claude and not blind.

- **Task, no hint:** read no source until I typed "continue". It used `active_mm`, and its addresses were right on all 7 kernels tested. It logged a process twice 3 times in 4000 before v6.16, because it says only the last thread sees `live == 0`. It never mentioned v6.16.
- **Question, no hint:** no lookups at all, and it said so. It saved data at exec and copied it on fork. Claude built that from its description, and the values were right with no duplicates. It called the `live` check "race-free" and said `mm` is NULL with no version limit.
- **Question, with the sentence:** fetched source at 5 versions and found the v6.16 reorder and `group_dead`. It stopped saying "race-free" but didn't flag the race, and it dropped fork handling.
