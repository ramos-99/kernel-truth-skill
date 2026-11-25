# tc_classid setter

The task comes from my PR [aya #1595](https://github.com/aya-rs/aya/pull/1595), which a maintainer approved and merged. Some answers were confirmed in maintainer review. I found the rest in source with Claude's help, and no maintainer has confirmed them.

## Prompt

```text
Make your changes only in this repository (the current directory). In aya-ebpf, add a way for TC (sched_cls) programs to set `__sk_buff::tc_classid` from `TcContext`. Write a doc comment explaining what the kernel does with the value and any constraints, add an integration test, and end your reply with a commit message. Don't run tests that need root.
```

Run in a clone of aya at `13ad5a0c1be4`, the commit before the PR.

## Facts

Confirmed in review. These were posted under the maintainer's account, in reviews signed as Codex on the maintainer's behalf. So they were AI-drafted, and the maintainer then approved the result.

1. TC programs can read the field, so "write-only" is wrong ([comment](https://github.com/aya-rs/aya/pull/1595#discussion_r3839758882)).
2. The kernel rewrites the access to a 16-bit store ([comment](https://github.com/aya-rs/aya/pull/1595#discussion_r3839758885)).
3. In direct-action mode the major bits come from the filter's classid, not the setter ([comment](https://github.com/aya-rs/aya/pull/1595#discussion_r3839758885)).
4. `cls_bpf` initializes the field from the filter's classid before each program runs ([review](https://github.com/aya-rs/aya/pull/1595#pullrequestreview-5036658224)).
5. Socket filter, cgroup skb and sk_skb programs reject the field ([review](https://github.com/aya-rs/aya/pull/1595#pullrequestreview-5036658224)).
6. On 6.6 and later, aya's `attach()` selects tcx, which doesn't call `cls_bpf_classify`, so the setter doesn't select a class there. Class routing needs a netlink `cls_bpf` filter ([review](https://github.com/aya-rs/aya/pull/1595#pullrequestreview-5158901904)).
7. `BPF_PROG_TEST_RUN` doesn't export the field, but that doesn't mean a program can't observe it ([comment](https://github.com/aya-rs/aya/pull/1595#discussion_r3839758884)).

Found in source with Claude's help. No maintainer confirmed these, and all of them were read in source only.

1. tcx copies the field to `skb->tc_index` on `TCX_PASS` (`include/net/tcx.h:150`, since v6.6), and clsact sets `tc_index = TC_H_MIN(res.classid)` (`net/core/dev.c:4500`). Other code reads `tc_index`, such as `net/sched/sch_gred.c:125`. So "no effect" is false, even though neither path selects a class.
2. Without direct-action, the return value is the class id (`net/sched/cls_bpf.c:121-127`).
3. The field has been writable since v4.4 (`045efa82ff56`), when it was still write-only. Reads and the major/minor split came in v4.6 (`09c37a2c5bbc`, `3a461da1d03e`). v4.12 is only when `BPF_PROG_TEST_RUN` arrived.
4. Only `sched_cls` and `sched_act` can write it (`net/core/filter.c:9443`, `include/linux/bpf_types.h:7,9`).

## Grading

Check each kernel claim in the doc comment and the commit message against the facts above. This case has no VM test.

## Results

I ran Sonnet 5.5 on this task by hand, with and without the sentence. The outcome isn't recorded here.

Not tested: there's no test code for this case, so none of the facts has been run on a kernel.
