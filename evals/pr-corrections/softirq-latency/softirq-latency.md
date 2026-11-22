# Measuring softirq latency

From [ebpf_exporter#300](https://github.com/cloudflare/ebpf_exporter/pull/300#discussion_r1361375201).

```text
I'd like a small libbpf tool that shows how long softirqs wait between being raised and starting to run, as a histogram per softirq type. Can you show me the BPF side? Don't write any files, and don't use sudo.
```

## Said in the thread

The author, testing their own example, found that raises and entries don't pair up:

- A timestamp from `softirq_raise` can be newer than the one from `softirq_entry`, which gives wrong metrics unless guarded against.
- They show both `raise-entry-raise-exit` and `raise-raise-entry-exit` in `perf` traces.
- Their "working theory" is that a raise can land after entry started, and "there aren't too many of these, so we mostly ignore them".

## Checked

The pairing problem is real, and the size depends on the workload. Tested with `vm/run.sh softirq-latency <vmlinuz>`, counting per CPU and per softirq type.

`NET_RX` with UDP sent out a virtual NIC, on v6.18:

| Raises | Entries | Raised again before entry | Raised during the handler |
|---|---|---|---|
| 9107 | 7580 | 1526 | 6054 |

- So a `NET_RX` raise doesn't mean one entry follows. A tool that overwrites its timestamp on each raise measures from the last raise, and a raise during the handler leaves a timestamp for the next entry.
- With UDP over loopback instead, on v5.15, v6.6, v6.18 and 7.2.9, `NET_RX` raises and entries matched exactly, with neither pattern in millions of events. So a loopback test wouldn't show this.
- The source explains why it's possible: `__do_softirq` clears pending and enables interrupts before calling the handlers (v6.6 `kernel/softirq.c`), and `softirq_raise` fires on every raise.
- A timestamp newer than the entry's, the thread's first symptom, **never appeared in my tests**. It's in the thread's traces from real hardware.
- The merged code handles this by keeping only the oldest raise, skipping an entry with no raise, and skipping a raise newer than the entry's timestamp, with the comment "re-rased after ts was obtained".

A good answer says raises and entries don't pair one to one and handles it, for example by keeping the first raise and guarding against a negative delta. Assuming they pair, without saying so, counts as wrong.

Not tested: real NICs, other kernels with the NIC test (v6.6 had no `virtio_net` built in), or how far the numbers change the histogram. These numbers come from a short run in a VM, so don't read them as typical rates.

## Runs

Sonnet 5.5, medium effort, one fresh headless session each, isolated from this repo, graded by Claude and not blind.

- **No hint:** no lookups. Keeps the first raise, clears it at entry, skips an entry with no raise, and uses per-CPU state. It reads the time after the timestamp, so it can't get a negative delta. That handles the pairing problem.
- **With the sentence:** read the local tracepoint header and upstream `kernel/softirq.c`. The same design, with the reason from source: `trace_softirq_raise` fires on every raise, before the pending bit is set.
- Neither program was compiled or run here.
