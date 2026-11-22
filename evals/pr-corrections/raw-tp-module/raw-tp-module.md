# Raw tracepoints in kernel modules

From [bcc#3477](https://github.com/iovisor/bcc/pull/3477#discussion_r654942196).

```text
I'm writing a small libbpf tool that counts kvm_exit events by exit reason, and it has to stay cheap because it runs on busy hypervisors. Some of them are still on 4.19. What's the best way to attach to kvm_exit? Don't write any files, and don't use sudo.
```

## Said in the thread

- A reviewer and a maintainer suggested `BPF.support_raw_tracepoint()` to decide whether to use a raw tracepoint on `kvm_exit`.
- The author pointed out two stages: raw tracepoints for in-kernel code first, and for modules later, with `a38d1107f937`. kvm is a module, so the check needs to be different.
- The maintainer agreed to a separate check, and it was merged as `support_raw_tracepoint_in_module()`, which looks for `bpf_trace_modules` in kallsyms. They also said not to tie this to a kernel version, because of backports.

## Checked

The correction is right. Tested with `VM_EXTRA=$(raw-tp-module/get-modules.sh v5.0) vm/run.sh raw-tp-module $(vm/get-kernel.sh v5.0)` on v4.17, v4.20, v5.0, v5.15 and v6.6, with the real `kvm` module loaded.

| | v4.17 and v4.20 | v5.0 and later |
|---|---|---|
| Raw tracepoint on `sched_switch`, built in | Works | Works |
| Raw tracepoint on `kvm_exit`, module loaded | `ENOENT` | Works |
| Raw tracepoint on `kvm_exit`, module not loaded | `ENOENT` | `ENOENT` |
| Regular tracepoint on `kvm_exit`, module loaded | Works | Works |
| `bpf_trace_modules` in kallsyms | No | Yes |

- The first release with module support is v5.0 (`git tag --contains a38d1107f937`), and v4.20 fails in the test. A remark in the thread says "looks like we need 4.20+", based on `git describe`. It was about the tool's stated requirement, was dropped straight after, and doesn't affect the answer.
- `git describe` gives the nearest earlier tag, not the first release that contains a commit, which makes this an easy mistake.
- So on the 4.19 hosts in the prompt, the raw tracepoint fails and a regular tracepoint is the fallback. `kvm` also has to be loaded first on every version.
- A good answer tries the raw tracepoint and falls back, or checks for it, rather than trusting a version number.

Not tested: events firing, since that needs running a VM inside the guest, so only attaching was checked. v4.19 wasn't booted, and is taken from v4.17 and v4.20 on either side.

The stable branches `linux-4.9.y`, `linux-4.14.y`, `linux-4.19.y` and `linux-4.20.y` don't have it, and `linux-5.0.y` does. Distro kernels weren't checked, and could have backported it, which is the maintainer's point about not trusting version numbers.

## Runs

Sonnet 5.5, medium effort, one fresh headless session each, isolated from this repo, graded by Claude and not blind.

- **No hint:** no lookups, and it says it's working from memory. Right: a raw tracepoint on `kvm_exit` fails on 4.19 with `ENOENT` because `kvm` is a module, so use the classic tracepoint there. Its other version claims weren't checked.
- **With the sentence:** read v4.19 to v5.4 source. Right, and more precise: module support is absent in v4.20 and present in v5.0, and the program should try the raw tracepoint and fall back on `ENOENT`.
