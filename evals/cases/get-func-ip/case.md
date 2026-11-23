# Where bpf_get_func_ip can be used

The task is to detect at startup whether kprobes, fentry programs and tracepoints can call `bpf_get_func_ip`. It comes from [cilium/ebpf#375](https://github.com/cilium/ebpf/pull/375#issuecomment-1125922624). Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
My tool loads a mix of kprobes, fentry programs and tracepoints, and I'd like them to record which function they're attached to using bpf_get_func_ip when the running kernel supports it. How should I detect that at startup? Don't write any files, and don't use sudo.
```

## Facts

1. The helper came in v5.15 (`9ffd9f3ff719`, `9b99edcae5c8`). On v5.14 every program type is rejected, and kprobe and fentry get `invalid func`. Tested on v5.14, v5.15, v6.6 and Arch 7.2.9.
2. From v5.15, `kprobe`, `kretprobe`, `fentry` and `fexit` load. `tp_btf` and `iter` get `ENOTSUPP` ("supported only for fentry/fexit/fmod_ret programs"). `raw_tp`, `tracepoint`, `perf_event` and `lsm` get `ENOTSUPP` ("not supported for program type"). `socket` and `xdp` get `EINVAL`. Tested on v5.15, v6.6 and Arch 7.2.9, load results only.
3. The thread says the verifier allows `Kprobe` and `Tracing` programs and gives other types `ENOTSUPP`. That's mostly right, but `tp_btf` and `iter` are tracing programs and are still rejected, because the check needs a trampoline (`check_get_func_ip`, `kernel/bpf/verifier.c`).
4. The thread also says bpftool and libbpf give false positives, and that still holds. libbpf 1.7's `libbpf_probe_bpf_helper` returns 1 for `tracepoint`, `raw_tracepoint` and `perf_event`, though those programs can't load. It only counts "invalid func", "unknown func" and "program of this type cannot use helper" as unsupported (`src/libbpf_probes.c`). Tested on v5.15, v6.6 and 7.2.9. The author later recorded the same mismatch with bpftool in [cilium/ebpf#681](https://github.com/cilium/ebpf/issues/681), for `TracePoint/FnGetFuncIp` and `RawTracepoint/FnGetFuncIp`, and nobody disputes it in the PR.
5. For `BPF_PROG_TYPE_TRACING`, `libbpf_probe_bpf_helper` returns `-EOPNOTSUPP` (-95), so it can't answer for fentry or `tp_btf`. Without privileges it returns 1 for everything, including on v5.14 and for a helper ID of 9999. Tested.
6. A `bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip)` guard only proves the helper exists. On v5.14 it loads in all four program types tried, because the branch is dropped. From v5.15, tracepoint and raw tracepoint programs are rejected with `ENOTSUPP`. Tested on v5.14, v5.15, v6.6 and Arch 7.2.9.
7. A `const volatile bool` guard works as a fallback. Set to false, kprobe, fentry and tracepoint programs load on every kernel tested. Set to true, v5.14 fails with `EINVAL` ("invalid func") and a tracepoint on v5.15 and later fails with `ENOTSUPP` (524), so the fallback has to handle both. Tested on v5.14, v5.15, v6.6 and Arch 7.2.9.
8. A kprobe not at function entry gets its own address on v5.15 and v6.0, and 0 on v6.1 and later (`0e253f7e558a`). Tested at +5 on v5.15, v6.0 and v6.1, and at +9 on 7.2.9. On 7.2.9, which has IBT, +4 counts as the entry and returns the symbol.
9. Kprobe, kretprobe, fentry and fexit return the function's symbol address on x86_64, on every kernel tried. The helper needs a GPL license, and fentry must return 0, or a probe fails for an unrelated reason. Tested.

## Grading

Run `evals/vm/run.sh evals/cases/get-func-ip $(evals/vm/get-kernel.sh v5.15)`, and the same with v5.14 and v6.6. Arch 7.2.9 was also tested, using its own vmlinuz. A good answer says tracepoints can't use the helper on any version, and that `libbpf_probe_bpf_helper` can't be trusted here: it says yes for tracepoints and can't answer for fentry. The reliable test is to load a small program of the real type.

## Results

Sonnet 5.5 at medium effort unless noted, graded by Claude, not blind.

- No hint: no lookups, and it said it hadn't run anything. Mostly right, and its CO-RE check and load-and-fallback work as described. It wrongly said a probe reports tracepoints as unsupported on every kernel, and recommended that probe as a pre-check. Its fallback triggers on `EINVAL` or "unknown func" and misses a tracepoint's `ENOTSUPP`, though it also says not to call the helper from tracepoints.
- With the sentence, not clean: sent as a follow-up in the no-hint session. A `find /` led it to this repo's Linux clone, though it read nothing under `evals/`. It dropped the false claim and recommends the probe for kprobes only, but never read `libbpf_probes.c` and doesn't warn about the false positive. It added that a kprobe not at function entry gets 0, which matches `bpf_get_func_ip_kprobe` in `kernel/trace/bpf_trace.c` but wasn't tested in this run.
- Opus 5.5, with the sentence, clean: fetched v7.2 source, including `tools/lib/bpf/libbpf_probes.c`, and read nothing from this repo. It also looked at an unrelated aya checkout. It says not to use `libbpf_probe_bpf_helper`, because of the false positive, `-EOPNOTSUPP` on fentry and `EPERM` counting as supported, and to load a small program per type. The claims I tested were right on v5.14, v5.15, v6.0, v6.1 and 7.2.9. Its points about bpftool and aya weren't tested. The unprivileged result in fact 5, and facts 8 and 9, come from checking this run.
- With the sentence, clean: read kernel `master` and `libbpf_probes.c`. Right that tracepoints can never use the helper, that libbpf can't probe fentry, and that it should write its own fentry probe. It still recommends `libbpf_probe_bpf_helper` for kprobes, which is right as root, but doesn't mention the false yes without privileges or for tracepoints. Since it says not to probe tracepoints at all, the design works.

Not tested: bpftool's own probe, older libbpf versions, uprobes (also `KPROBE` type), and runtime values on architectures other than x86_64.
