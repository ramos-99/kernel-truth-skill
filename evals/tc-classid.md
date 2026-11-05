# tc_classid setter

From [aya #1595](https://github.com/aya-rs/aya/pull/1595). Run on aya `13ad5a0c1be4`, the parent of the fix.

```text
Make your changes only in this repository (the current directory). In aya-ebpf, add a way for TC (sched_cls) programs to set `__sk_buff::tc_classid` from `TcContext`. Write a doc comment explaining what the kernel does with the value and any constraints, add an integration test, and end your reply with a commit message. Don't run tests that need root.
```

## Answer

- `__u32` in `__sk_buff`, but the kernel stores 16 bits (`include/net/sch_generic.h:458`, `net/core/filter.c:10174`).
- In direct-action `cls_bpf` the result is `TC_H_MAJ(prog->res.classid) | tc_classid` (`net/sched/cls_bpf.c:110-111`). Otherwise the return value is the class id (`cls_bpf.c:121-127`).
- `cls_bpf` sets the field to the filter's classid before each program, not to 0 (`cls_bpf.c:93`).
- Not only `cls_bpf` uses it. tcx copies it to `skb->tc_index` on `TCX_PASS` (`include/net/tcx.h:150`, since v6.6), and clsact sets `tc_index = TC_H_MIN(res.classid)` (`net/core/dev.c:4500`). `tc_index` is read elsewhere, e.g. `net/sched/sch_gred.c:125`. Neither path selects a class, but "no effect" is false.
- Only `sched_cls` and `sched_act` can write it (`filter.c:9443`, `include/linux/bpf_types.h:7,9`).
- Writable since v4.4 (`045efa82ff56`), when it was still write-only. Reads and the major/minor split came in v4.6 (`09c37a2c5bbc`, `3a461da1d03e`). v4.12 is only when `BPF_PROG_TEST_RUN` arrived.
- Aya's `attach()` uses tcx on 6.6 and later, so it doesn't always use direct-action (`aya/src/programs/tc.rs:240-245`).
