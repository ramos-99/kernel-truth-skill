# Measuring softirq latency

The task is the BPF side of a tool that histograms the time from softirq raise to entry, per softirq type. It comes from [ebpf_exporter#300](https://github.com/cloudflare/ebpf_exporter/pull/300#discussion_r1361375201). Facts from the PR's review, checked against kernel source and tested in VMs.

## Prompt

```text
I'd like a small libbpf tool that shows how long softirqs wait between being raised and starting to run, as a histogram per softirq type. Can you show me the BPF side? Don't write any files, and don't use sudo.
```

## Facts

1. Raises and entries don't pair one to one. With UDP sent out a virtual NIC on v6.18, a short run counted 9107 `NET_RX` raises, 7580 entries, 1526 raises again before entry and 6054 raises during the handler. A tool that overwrites its timestamp on each raise measures from the last raise, and a raise during the handler leaves a timestamp for the next entry. Tested on v6.18 only. These come from a short run in a VM, so don't read them as typical rates.
2. With UDP over loopback, `NET_RX` raises and entries matched exactly, with neither pattern in millions of events, so a loopback test won't show the problem. Tested on v5.15, v6.6, v6.18 and 7.2.9.
3. `__do_softirq` clears pending and enables interrupts before calling the handlers, and `softirq_raise` fires on every raise (v6.6 `kernel/softirq.c`). Read in source only.
4. The merged code keeps only the oldest raise, skips an entry with no raise, and skips a raise newer than the entry's timestamp, with the comment "re-rased after ts was obtained".

The author, testing their own example, saw both `raise-entry-raise-exit` and `raise-raise-entry-exit` in `perf` traces. They also saw a `softirq_raise` timestamp newer than the `softirq_entry` one. Their "working theory" was that a raise can land after entry started, and "there aren't too many of these, so we mostly ignore them". The newer timestamp never appeared in my tests. It's in the thread's traces from real hardware.

## Grading

Run `VM_QEMU_ARGS='-nic user,model=virtio-net-pci' evals/vm/run.sh evals/cases/softirq-latency <vmlinuz>` for the NIC test. Without `VM_QEMU_ARGS` the guest has no `eth0` and runs the loopback test. Both count per CPU and per softirq type. A good answer says raises and entries don't pair one to one and handles it, for example by keeping the first raise and guarding against a negative delta. Assuming they pair, without saying so, counts as wrong.

## Results

Sonnet 5.5 at medium effort, one fresh headless session each, isolated from this repo, graded by Claude, not blind. Neither program was compiled or run here.

- No hint: no lookups. Keeps the first raise, clears it at entry, skips an entry with no raise, and uses per-CPU state. It reads the time after the timestamp, so it can't get a negative delta. That handles the pairing problem.
- With the sentence: read the local tracepoint header and upstream `kernel/softirq.c`. Same design, with the reason from source: `trace_softirq_raise` fires on every raise, before the pending bit is set.

Not tested: real NICs, the NIC test on other kernels (v6.6 had no `virtio_net` built in), or how much the numbers change the histogram.
