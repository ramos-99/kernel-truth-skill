# Dropping CAP_SYS_ADMIN for a perf and BPF tracer

The task is to replace `CAP_SYS_ADMIN` for a tracer that opens perf events on tracepoints and attaches BPF programs, on Ubuntu 22.04 and 24.04. It comes from [tracee#2033](https://github.com/aquasecurity/tracee/pull/2033#discussion_r935984415). Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
Our tracer runs in a container on Ubuntu 22.04 and 24.04 hosts. It opens perf events on tracepoints and attaches BPF programs to them. It has CAP_SYS_ADMIN at the moment and I want to drop that. What does it need instead? Don't write any files, and don't use sudo.
```

## Facts

1. Ubuntu defaults `perf_event_paranoid` to 4, and mainline to 2. Mainline accepts levels 3 and 4 and treats them like 2.
2. On older Ubuntu kernels at level 4, `CAP_BPF` plus `CAP_PERFMON` is denied and only `CAP_SYS_ADMIN` works. With no capabilities, even a process's own user-space events are denied. Tested on 5.15.0-25, -72, -116, -160 and -168, and 6.8.0-31 and -71.
3. Ubuntu fixed this at `5.15.0-170.180`, with "SAUCE: perf/core: Allow CAP_PERFMON for paranoid level 4" (LP: #2131046). On 5.15.0-170 and later, and 6.8.0-100 and later, `CAP_BPF` plus `CAP_PERFMON` works at level 4. Tested on every version tried in those ranges. On 6.8 the fix landed between -71 and -100, the nearest archive versions I tried.
4. On mainline at level 4, a process's own user-space events work with no capabilities, and `CAP_BPF` plus `CAP_PERFMON` works. Tested on v5.15, v6.18 and Arch 7.2.9. It's a distro patch, so mainline source can't show the Ubuntu behaviour.
5. At levels 2 and 3, Ubuntu 5.15.0-203 and 6.8.0-149 behave like mainline. Tested.
6. `CAP_PERFMON` alone can open the events but can't load the BPF program, so it needs `CAP_BPF` too. Tested.

In the thread, the author read the docs and mainline source and guessed that the `CAP_SYS_ADMIN` requirement above level 3 was an Ubuntu addition not updated for `CAP_PERFMON`. A maintainer traced it to grsecurity-derived patches and said mainline and Ubuntu differ above 2. The PR was merged and uses `CAP_SYS_ADMIN` when the value is above 3. That was right in 2022. Ubuntu changed it later, so the answer now depends on the kernel version.

## Grading

Run `evals/vm/run.sh evals/cases/perf-paranoid <vmlinuz>` on Ubuntu's own kernels from `archive.ubuntu.com` and on mainline. The test runs as uid 1000 with only the listed capabilities. A good answer gives `CAP_BPF` and `CAP_PERFMON`, and says older Ubuntu kernels at the default level 4 still need `CAP_SYS_ADMIN` or a lower sysctl value. Mainline source alone can't give this, so saying it couldn't verify Ubuntu's kernel also earns some credit.

## Results

Sonnet 5.5 at medium effort, one fresh headless session each, isolated from this repo, graded by Claude, not blind.

- No hint: no lookups. Says `CAP_BPF` plus `CAP_PERFMON`, and that `CAP_PERFMON` bypasses Ubuntu's level 4. Right on current Ubuntu kernels, wrong on 22.04 kernels before 5.15.0-170 and on early 24.04 kernels. It doesn't say the answer depends on the version.
- With the sentence: read mainline and Ubuntu's jammy and noble trees on Launchpad, and found the level 4 patch. Says `CAP_PERFMON` won't work at level 4, so lower the sysctl. Right for older kernels, wrong for current ones: Launchpad's default branch still has `!capable(CAP_SYS_ADMIN)`, while `master-next` has `!perfmon_capable()`. Its advice still works on every kernel, and it said it hadn't checked Ubuntu's configs.

Not tested: kprobes rather than tracepoints, containers, and other distros.
