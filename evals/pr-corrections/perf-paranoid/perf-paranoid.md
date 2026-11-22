# Dropping CAP_SYS_ADMIN for a perf and BPF tracer

From [tracee#2033](https://github.com/aquasecurity/tracee/pull/2033#discussion_r935984415).

```text
Our tracer runs in a container on Ubuntu 22.04 and 24.04 hosts. It opens perf events on tracepoints and attaches BPF programs to them. It has CAP_SYS_ADMIN at the moment and I want to drop that. What does it need instead? Don't write any files, and don't use sudo.
```

## Said in the thread

- The docs say `CAP_PERFMON` should be enough for perf, and the mainline source doesn't mention `perf_event_paranoid` levels 3 or 4. So the requirement for `CAP_SYS_ADMIN` above level 3 is probably an Ubuntu addition that wasn't updated for `CAP_PERFMON`.
- A maintainer traced this to grsecurity-derived patches, and said mainline and Ubuntu differ above 2.
- The PR was merged, and uses `CAP_SYS_ADMIN` when the value is above 3.

## Checked

The thread was right in 2022, but Ubuntu has since fixed it, so the answer depends on the kernel version. Tested with `vm/run.sh perf-paranoid <vmlinuz>`, on Ubuntu's own kernels from `archive.ubuntu.com` and on mainline, as uid 1000 with only the listed capabilities.

At `perf_event_paranoid=4`:

| Kernel | No capabilities | `CAP_BPF` + `CAP_PERFMON` | `CAP_SYS_ADMIN` |
|---|---|---|---|
| Ubuntu 5.15.0-25, -72, -116, -160, -168 and 6.8.0-31, -71 | Denied, even for its own user-space events | **Denied** | Works |
| Ubuntu 5.15.0-170 and later, and 6.8.0-100 and later (every version tried) | Denied | Works | Works |
| Mainline v5.15, v6.18 and Arch 7.2.9 | Own user-space events work, others denied | Works | Works |

- Ubuntu's changelog has the fix at `5.15.0-170.180`: "SAUCE: perf/core: Allow CAP_PERFMON for paranoid level 4" (LP: #2131046). It's a distro patch, so mainline source can't show any of this.
- Ubuntu defaults to level 4, and mainline to 2.
- Mainline accepts levels 3 and 4, and treats them like 2.
- At levels 2 and 3, the same 5.15.0-203 and 6.8.0-149 kernels behave like mainline.
- `CAP_PERFMON` alone can open the events but can't load the BPF program, so it needs `CAP_BPF` too.

A good answer gives `CAP_BPF` and `CAP_PERFMON`, and says older Ubuntu kernels at the default level 4 still need `CAP_SYS_ADMIN` or a lower sysctl value. A run can't get this from mainline source alone, so saying it couldn't verify Ubuntu's kernel also counts for something.

On 6.8 the fix landed somewhere between -71 and -100, and those are the nearest versions in the archive that I tried.

Not tested: kprobes rather than tracepoints, containers, and other distros.

## Runs

Sonnet 5.5, medium effort, one fresh headless session each, isolated from this repo, graded by Claude and not blind.

- **No hint:** no lookups. `CAP_BPF` plus `CAP_PERFMON`, and says `CAP_PERFMON` bypasses Ubuntu's level 4. That's right on current Ubuntu kernels, but wrong on 22.04 kernels before 5.15.0-170 and on early 24.04 kernels, where it fails. There's no mention that it depends on the version.
- **With the sentence:** read mainline and Ubuntu's jammy and noble trees on Launchpad, and found the level 4 patch. It says `CAP_PERFMON` won't work at level 4, so lower the sysctl. That's right for older kernels but wrong for current ones, because it read Launchpad's default branch, which still has `!capable(CAP_SYS_ADMIN)`, while `master-next` has `!perfmon_capable()`. Its advice still works on every kernel, and it said it hadn't checked Ubuntu's configs. Wrong in the opposite direction from the no-hint run.
