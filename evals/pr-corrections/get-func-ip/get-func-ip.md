# Where bpf_get_func_ip can be used

From [cilium/ebpf#375](https://github.com/cilium/ebpf/pull/375#issuecomment-1125922624).

```text
My tool loads a mix of kprobes, fentry programs and tracepoints, and I'd like them to record which function they're attached to using bpf_get_func_ip when the running kernel supports it. How should I detect that at startup? Don't write any files, and don't use sudo.
```

## Said in the thread

- The verifier only allows `Kprobe` and `Tracing` programs to call it, and other types get `ENOTSUPP`.
- bpftool and libbpf report false positives, because libbpf's check of the verifier log doesn't match that error.

## Checked

Mostly right, with one gap. Tested with `vm/run.sh get-func-ip $(vm/get-kernel.sh v5.15)` on v5.14, v5.15, v6.6 and Arch 7.2.9. These are load results only.

| Program | v5.14 | v5.15 and later |
|---|---|---|
| `kprobe`, `kretprobe`, `fentry`, `fexit` | Rejected, `invalid func` | Loads |
| `tp_btf`, `iter` | Rejected | Rejected, `ENOTSUPP`: "supported only for fentry/fexit/fmod_ret programs" |
| `raw_tp`, `tracepoint`, `perf_event`, `lsm` | Rejected | Rejected, `ENOTSUPP`: "not supported for program type" |
| `socket`, `xdp` | Rejected | Rejected, `EINVAL` |

- **The gap:** "Tracing" is too broad. `tp_btf` and `iter` are tracing programs and are rejected, because the check needs a trampoline (`check_get_func_ip`, `kernel/bpf/verifier.c`).
- **The false positive still exists.** With libbpf 1.7, `libbpf_probe_bpf_helper` returns 1 for `tracepoint`, `raw_tracepoint` and `perf_event` on v5.15, v6.6 and 7.2.9, though those programs can't load. It only treats "invalid func", "unknown func" and "program of this type cannot use helper" as unsupported (`src/libbpf_probes.c`).
- The author later recorded the same mismatch with bpftool in [cilium/ebpf#681](https://github.com/cilium/ebpf/issues/681), for `TracePoint/FnGetFuncIp` and `RawTracepoint/FnGetFuncIp`. Nobody disputes it in the PR.
- For `BPF_PROG_TYPE_TRACING` it returns `-EOPNOTSUPP` (-95), so it can't answer for fentry or `tp_btf` at all.
- The helper came in v5.15 (`9ffd9f3ff719`, `9b99edcae5c8`).

A good answer says tracepoints can't use the helper at any version, and that `libbpf_probe_bpf_helper` can't be trusted here: it says yes for tracepoints and can't answer for fentry. The reliable test is to load a small program of the real type.

Not tested: bpftool's own probe, older libbpf versions, and whether the value is right at runtime. Uprobes are `KPROBE` type too, and weren't tried.

These detection methods were also tested, on v5.14, v5.15, v6.6 and Arch 7.2.9:

- `bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip)` around the call loads on v5.14 in all four program types tried, because the branch is dropped. From v5.15, it still loads only for kprobe and fentry, and tracepoint and raw tracepoint programs are rejected with `ENOTSUPP`, so it only proves that the helper exists.
- A `const volatile bool` around the call works as a fallback: with it false, kprobe, fentry and tracepoint programs all load on every kernel tested. With it true, v5.14 fails with `EINVAL` ("invalid func") and a tracepoint on v5.15 and later fails with `ENOTSUPP` (524). A fallback has to handle both errors.

## Runs

Sonnet 5.5, medium effort, graded by Claude and not blind.

- **No hint:** no lookups, and it said it hadn't run anything. Mostly right: tracepoints can't use the helper, from v5.15 for kprobe and fentry, and loading is the "ground truth". Its CO-RE check and load-and-fallback both work as described. One false claim: for tracepoints "a probe will say 'unsupported' on every kernel", when `libbpf_probe_bpf_helper` returns 1 on v5.15 and later, and it recommended that probe as a pre-check. Its fallback also names `EINVAL` or "unknown func" as the trigger, which misses the `ENOTSUPP` a tracepoint gets, though it tells you not to call the helper in tracepoints anyway.
- **With the sentence, not a clean run:** sent as a follow-up in the no-hint session, so it had seen its own earlier answer. A `find /` also led it to this repo's Linux clone, though it read nothing under `evals/`. It dropped the false claim about the probe and now recommends the probe for kprobes only, but it never read `libbpf_probes.c` and doesn't warn about the false positive. It added that a kprobe not at function entry gets 0 from the helper, which matches source (`kernel/trace/bpf_trace.c`, `bpf_get_func_ip_kprobe`) but wasn't tested. Needs a fresh rerun.
- **With the sentence, clean, but on Opus 5.5 rather than Sonnet:** one message in a fresh session, source fetched from v7.2 including `tools/lib/bpf/libbpf_probes.c`, and it read nothing from this repo. It also looked at the aya checkout in `kt-eval`, which isn't relevant to the answer. It says not to use `libbpf_probe_bpf_helper`, because of the false positive, `-EOPNOTSUPP` on fentry, and `EPERM` counting as supported, and to load a small program per type instead. The claims I tested were right on v5.14, v5.15, v6.0, v6.1 and 7.2.9. Its points about bpftool and aya weren't tested. Sonnet still needs a clean run.

New facts from that run, tested:

- Without privileges, `libbpf_probe_bpf_helper` returns 1 for everything, including on v5.14 where the helper doesn't exist, and for a helper ID of 9999.
- A kprobe not at function entry gets its own address on v5.15 and v6.0, and 0 on v6.1 and later (`0e253f7e558a`, tested at +5 on v5.15, v6.0 and v6.1, and +9 on 7.2.9). On 7.2.9, which has IBT, +4 counts as the entry and returns the symbol.
- On every kernel tried, kprobe, kretprobe, fentry and fexit return the function's symbol address, on x86_64.
- The helper needs a GPL license, and fentry must return 0, or the probe fails for an unrelated reason.
- **With the sentence, clean:** read kernel `master` and libbpf's `libbpf_probes.c`. It says tracepoints can never use the helper, that libbpf can't probe fentry, and to write its own fentry probe, all of which is right. It still recommends `libbpf_probe_bpf_helper` for kprobes, which is right as root, but doesn't mention the false yes without privileges, or for tracepoints. Since it says not to probe tracepoints at all, the design works. The no-hint run's false claim is gone.
