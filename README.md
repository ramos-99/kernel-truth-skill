# kernel-truth

A Claude skill to stop coding agents from writing wrong Linux kernel facts into code, docs and articles, plus the test cases used to measure it. The skill isn't written yet. The cases come first, so the skill can be judged against them.

**I'm not a kernel expert.** I can't confirm every answer here myself. Each fact cites the commit, file or test it rests on, and most were checked by booting real kernels in VMs. If you find a mistake, please open an issue.

## Why

It started with two of my aya PRs, written with an LLM's help, where review caught kernel facts the LLM got wrong:

- [#1595](https://github.com/aya-rs/aya/pull/1595) said `__sk_buff::tc_classid` is write-only for `sched_cls`. That was true before v4.6, so it was a stale fact, not an invented one. After the correction, an automated LLM reviewer [repeated the claim](https://github.com/aya-rs/aya/pull/1595#discussion_r3868162847).
- In [#1497](https://github.com/aya-rs/aya/pull/1497), a maintainer [pointed out](https://github.com/aya-rs/aya/pull/1497#issuecomment-4133043795) undefined behaviour from iproute2's pinning values, and that its pin paths don't match aya's.

The corrections on #1595 were AI-drafted too, in reviews signed as Codex on the maintainer's behalf, which the maintainer then approved.

## What I've found so far

All runs are Sonnet 5.5 at medium effort, one fresh session per prompt, and each session log is checked to confirm it read nothing from this repo. Each case runs twice: once as is, and once with one added sentence: "Before writing any claim about kernel behaviour, check it against the Linux kernel source instead of relying on memory."

| Case | As is | With the sentence |
|---|---|---|
| [find-vma](evals/cases/find-vma/case.md) | Code loses 7 of 8 stack frames in every sample | Correct, using a different helper |
| [get-func-ip](evals/cases/get-func-ip/case.md) | One false claim about libbpf's probe, design still works | Correct |
| [raw-tp-module](evals/cases/raw-tp-module/case.md) | Correct, from memory | Correct, with the exact version |
| [perf-paranoid](evals/cases/perf-paranoid/case.md) | Right for current Ubuntu kernels, wrong for older ones | Right for older ones, wrong for current ones |
| [softirq-latency](evals/cases/softirq-latency/case.md) | Correct, from memory | Correct |

From memory, Sonnet usually has the right idea and gets specific details wrong. How much that matters ranges from harmless to code that silently doesn't work. Told to check the source, it fixed most of it. The one clear miss with the sentence was `perf-paranoid`, where it read Ubuntu's real kernel source from a branch that doesn't match what Ubuntu ships.

So the skill has to beat that one sentence, or the sentence is the better tool. [Vercel](https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals) found rules in `AGENTS.md` beating a skill that often didn't fire, so that comparison comes next too.

These are single runs, graded by Claude and not blind, so they're early signals.

## The cases

Each case is a folder in [evals/cases/](evals/cases/) with a `case.md` (prompt, facts, grading, results) and the test code behind it.

- Two come from my aya PRs. Their answers are split into what maintainer review confirmed and what I found with Claude's help.
- Five come from comments where a developer corrected a kernel claim in a real PR, drawn at random from a list.
- Four are whole features from PRs merged since July 2026, so they're unlikely to be in the model's training data. Each depends on a chain of several kernel facts, and is graded by building and running what the model writes. These haven't been run yet.
- Two were picked by Claude. They're kept apart, because a question Claude finds natural tends to be one the tested model already knows.

How cases are chosen:

1. The criteria are written down before searching.
2. Every PR that passes goes on a list, which is frozen with a hash.
3. The draw is random, seeded with the current Linux master commit.
4. Each fact is checked in kernel source and, where possible, tested by booting real kernels in KVM, including Ubuntu's own builds when a distro patch matters.
5. If a test disagrees with a maintainer, the case is dropped. If it disagrees with a PR's own description, that's noted in the case.

[evals/vm/](evals/vm/) has the harness. `evals/vm/run.sh evals/cases/<name> <vmlinuz>` builds a case's test as a guest's init and boots it, without root on the host. `evals/vm/get-kernel.sh vX.Y` fetches Ubuntu's mainline builds.

## How this was made

I built this with Claude Code as a research assistant. Claude searched the PRs, read kernel source, wrote the VM tests and ran the test sessions. I set the direction and the method. Cases come from real PR reviews instead of Claude's own ideas, they're drawn at random, claims get tested in VMs before they count, and test runs are kept away from the answers. I also reviewed the results and pushed back on conclusions. Several of Claude's own conclusions turned out wrong along the way, caught by a test or by that review, and the case files record where. The prompts are drafted with Claude from each PR's description, and I review them.

Line numbers in the older cases are for linux `f47d223627f8` and iproute2 `e11870d5b941`, unless a case says otherwise.
