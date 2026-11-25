# kernel-truth

Test cases that measure how often coding agents write wrong Linux kernel facts into code, docs and articles. A Claude skill to reduce that comes next and isn't written yet.

I'm not a kernel expert. Each fact cites the commit, file or test it rests on, and most were checked by booting real kernels in VMs. If you find a mistake, please open an issue.

## Why

Review caught wrong kernel facts in two aya PRs I wrote with an LLM's help:

- [#1595](https://github.com/aya-rs/aya/pull/1595) said `__sk_buff::tc_classid` is write-only for `sched_cls`, which stopped being true in v4.6. After the correction, an automated LLM reviewer [repeated the claim](https://github.com/aya-rs/aya/pull/1595#discussion_r3868162847).
- In [#1497](https://github.com/aya-rs/aya/pull/1497), a maintainer [pointed out](https://github.com/aya-rs/aya/pull/1497#issuecomment-4133043795) undefined behaviour from iproute2's pinning values, and that its pin paths don't match aya's.

The corrections on #1595 were AI-drafted too, in reviews signed as Codex on the maintainer's behalf, which the maintainer then approved.

## Results

All runs are Sonnet 5.5 at medium effort, one fresh session per prompt. Session logs are checked to confirm that nothing was read from this repo. Each case runs as is, and again with one added sentence: "Before writing any claim about kernel behaviour, check it against the Linux kernel source instead of relying on memory."

| Case | As is | With the sentence |
|---|---|---|
| [find-vma](evals/cases/find-vma/case.md) | Code loses 7 of 8 stack frames in every sample | Correct, using a different helper |
| [get-func-ip](evals/cases/get-func-ip/case.md) | One false claim about libbpf's probe, design still works | Correct |
| [raw-tp-module](evals/cases/raw-tp-module/case.md) | Correct, from memory | Correct, with the exact version |
| [perf-paranoid](evals/cases/perf-paranoid/case.md) | Right for current Ubuntu kernels, wrong for older ones | Right for older ones, wrong for current ones |
| [softirq-latency](evals/cases/softirq-latency/case.md) | Correct, from memory | Correct |
| [tetragon-multi-sopath](evals/cases/tetragon-multi-sopath/case.md) | Passes | Passes |
| [kubearmor-lsm-audit](evals/cases/kubearmor-lsm-audit/case.md) | Fails one check the prompt doesn't spell out | Fails the same check |
| [bpftrace-iterators](evals/cases/bpftrace-iterators/case.md) | Verifier rejects a counting loop on every tested kernel with the iterators | Same rejection |
| [scx-cidland-eevdf](evals/cases/scx-cidland-eevdf/case.md) | Loads, but wakeup preemption and long `sched_runtime` requests don't work | Verifier rejects it |

In the question cases the sentence fixed most of what was wrong. It missed in `perf-paranoid`, where the model read an Ubuntu branch that doesn't match what Ubuntu ships. In the four feature cases it changed no verdict, and none of the runs without a VM wrapper loaded its code on a kernel.

Claims in the feature cases, audited as described below:

| Run | Claims | Right | Too broad | Wrong | Unverified |
|---|---|---|---|---|---|
| As is | 178 | 136 | 25 | 12 | 5 |
| With the sentence | 167 | 127 | 24 | 10 | 6 |

20 of the 22 wrong claims are in `scx-cidland-eevdf`. These are single runs, so the differences are within noise.

The skill has to beat that one sentence. It will also be compared with a line in `CLAUDE.md`, since [Vercel](https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals) found rules in `AGENTS.md` beating a skill that often didn't fire.

## Cases

Each folder in [evals/cases/](evals/cases/) has a `case.md` (prompt, facts, grading, results) and its test code.

- Two come from my aya PRs. Their answers are split into what maintainer review confirmed and what I found with Claude's help.
- Five come from comments where a developer corrected a kernel claim in a real PR.
- Four are whole features from PRs merged since July 2026, graded by building and running what the model writes.
- Two were picked by Claude and are kept apart, because a question Claude finds natural tends to be one the tested model already knows.

Cases from PRs are chosen like this:

1. The criteria are written down before searching.
2. Every PR that passes goes on a list, which is frozen with a hash.
3. The draw is random, seeded with the current Linux master commit.
4. Each fact is checked in kernel source and, where possible, by booting real kernels in KVM, including Ubuntu's own builds when a distro patch matters.
5. If a test disagrees with a maintainer, the case is dropped. If it disagrees with a PR's own description, the case says so.

[evals/vm/](evals/vm/) has the harness. `evals/vm/run.sh evals/cases/<name> <vmlinuz>` builds a case's test as a guest's init and boots it, without root on the host. `evals/vm/get-kernel.sh vX.Y` fetches Ubuntu's mainline builds.

Line numbers in the older cases are for linux `f47d223627f8` and iproute2 `e11870d5b941`, unless a case says otherwise.

## Claim audit

For the feature cases, an isolated Opus 5.5 session listed every kernel claim in the two runs' changes and final messages, and checked each against tagged Linux source. It saw the runs as A and B, without grades, logs or run names. A claim is too broad if it holds only for some versions, configs or cases and doesn't say so, and unverified if reading source can't settle it. Assumptions the code depends on count as claims.

A Sonnet 5.5 session then judged again every claim not marked right, plus 5 of the right ones per case, without seeing the first verdicts. It agreed on all 20 of those right claims, and the other right ones had a single reader. The two sessions disagreed on 40 of 102 claims. I settled those with Claude, not blind, keeping the first verdict in 29 and changing it in 11. Ten of those went from wrong to too broad, so the first reader's count of wrong claims was 18 as is and 14 with the sentence. Not all of the 40 were read again in source.

## How this was made

I built this with Claude Code. Claude searched the PRs, read kernel source, wrote the VM tests and prompts, ran the sessions and did the grading, which wasn't blind. I set the direction and method, and reviewed the prompts and results. Several of Claude's conclusions were wrong and were caught by a test or by that review. The case files record where.
