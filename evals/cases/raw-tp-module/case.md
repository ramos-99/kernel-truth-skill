# Raw tracepoints in kernel modules

The task is attaching cheaply to `kvm_exit` on hosts as old as 4.19. It comes from [bcc#3477](https://github.com/iovisor/bcc/pull/3477#discussion_r654942196). Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
I'm writing a small libbpf tool that counts kvm_exit events by exit reason, and it has to stay cheap because it runs on busy hypervisors. Some of them are still on 4.19. What's the best way to attach to kvm_exit? Don't write any files, and don't use sudo.
```

## Facts

1. Raw tracepoints in modules came after raw tracepoints in built-in code, with `a38d1107f937`. The first release that contains it is v5.0 (`git tag --contains a38d1107f937`). The stable branches `linux-4.9.y`, `linux-4.14.y`, `linux-4.19.y` and `linux-4.20.y` don't have it, and `linux-5.0.y` does. The author raised this in review, and the maintainer agreed to a separate check instead of `BPF.support_raw_tracepoint()`.
2. With the real `kvm` module loaded, a raw tracepoint on `kvm_exit` fails with `ENOENT` on v4.17 and v4.20 and works on v5.0 and later. A regular tracepoint on it works on all of them. A raw tracepoint on built-in `sched_switch` works on all of them. Tested on v4.17, v4.20, v5.0, v5.15 and v6.6.
3. With `kvm` not loaded, a raw tracepoint on `kvm_exit` fails with `ENOENT` on every version. Tested on the same kernels.
4. The merged check, `support_raw_tracepoint_in_module()`, looks for `bpf_trace_modules` in kallsyms. It's absent on v4.17 and v4.20 and present from v5.0. Tested on the same kernels.
5. So on the prompt's 4.19 hosts the raw tracepoint fails and a regular tracepoint is the fallback. v4.19 wasn't booted. It's inferred from v4.17 and v4.20 on either side.
6. The maintainer said not to tie this to a kernel version, because of backports. Distro kernels weren't checked and could have backported it.

A remark in the thread says "looks like we need 4.20+", based on `git describe`. That's an easy mistake, because `git describe` gives the nearest earlier tag, not the first release that contains a commit, and v4.20 fails in the test. The remark was about the tool's stated requirement, was dropped straight after, and doesn't affect the answer.

## Grading

Run `VM_EXTRA=$(evals/cases/raw-tp-module/get-modules.sh v5.0) evals/vm/run.sh evals/cases/raw-tp-module $(evals/vm/get-kernel.sh v5.0)`, and the same with v4.17, v4.20, v5.15 and v6.6. `get-modules.sh` fetches `kvm.ko` and `irqbypass.ko` for that kernel. A good answer tries the raw tracepoint and falls back, or checks for support, rather than trusting a version number.

## Results

Sonnet 5.5 at medium effort, one fresh headless session each, isolated from this repo, graded by Claude, not blind.

- No hint: no lookups, and it says it's working from memory. Right: a raw tracepoint on `kvm_exit` fails on 4.19 with `ENOENT` because `kvm` is a module, so use the classic tracepoint there. Its other version claims weren't checked.
- With the sentence: read v4.19 to v5.4 source. Right, and more precise: module support is absent in v4.20 and present in v5.0, and the program should try the raw tracepoint and fall back on `ENOENT`.

Not tested: events firing, since that needs a VM inside the guest, so only attaching was checked.
