# kernel-truth

A Claude skill to stop coding agents writing wrong Linux kernel facts into code, docs and articles. Work in progress: the skill doesn't exist yet, only the test cases.

**I'm not a kernel expert.** Most of the answers here were found in source with Claude's assistance, and I can't independently confirm all of them. Each one cites where it came from, so if you find a mistake, please open an issue.

It started with two of my aya PRs, written with an LLM's help, where review caught kernel facts the LLM got wrong:

- [#1595](https://github.com/aya-rs/aya/pull/1595): it said `__sk_buff::tc_classid` is write-only for `sched_cls`. That was true before v4.6, so it's a stale fact rather than a made-up one. After the correction, an automated LLM reviewer [repeated the claim](https://github.com/aya-rs/aya/pull/1595#discussion_r3868162847). Review also caught that the docs ignored aya's default attach path on 6.6 and later.
- [#1497](https://github.com/aya-rs/aya/pull/1497): a maintainer [pointed out](https://github.com/aya-rs/aya/pull/1497#issuecomment-4133043795) undefined behaviour from iproute2's pinning values, and that its pin paths don't match aya's.

The kernel corrections on #1595 were themselves AI-drafted, in reviews signed as Codex on the maintainer's behalf, and the maintainer then approved the result. So this shows the errors reach review, not that only humans catch them.

## What I've seen so far

I ran Sonnet 5.5 on those two tasks by hand, without a skill. Without a hint, it read no kernel or iproute2 source in the runs I could check, and still wrote kernel behaviour into doc comments as fact. "tcx ignores `tc_classid`" came up in all three clean runs. Reading the source with Claude, that looks wrong, because `include/net/tcx.h` copies the value to `skb->tc_index`. No maintainer has confirmed this one: review only said tcx doesn't select a class.

Adding one sentence to the prompt, "check it against the Linux kernel source", fixed most of it. What was left needs more than reading the obvious file:

- It wrote "only consumed by `cls_bpf`" without searching for other users of the field.
- It guessed the path `net/core/tcx.c`, got a 404, moved on, and still reported the behaviour as checked.
- It read today's `bpf_elf.h` and parser, but never looked at the history, so no layout got tied to a version.
- It mapped iproute2's global pinning to aya's by-name pinning without noticing they use different paths.

That's the skill: search the whole tree before saying "only" or "never", treat a failed lookup as unverified, read history when there are variants, and read both sides of a mapping.

This is two tasks and a handful of runs, graded against source by Claude and not blind, so it's a signal and not a measurement.

## Testing it

The skill has to beat that one sentence, otherwise the sentence is the better tool. [Vercel](https://vercel.com/blog/agents-md-outperforms-skills-in-our-agent-evals) found rules in `AGENTS.md` beating a skill that often didn't fire, so that's worth comparing too.

Each case has a prompt and an answer. `evals/maintainer-reviewed/` has the two real PR cases, with each answer split into what review confirmed and what I found in source with Claude's assistance. `evals/source-verified/` is for cases whose answers were only checked against source with Claude's assistance.

Some cases will come from real commits in other projects, with prompts I write myself, because cases written by the same LLM that writes the skill flatter it. [SkillsBench](https://arxiv.org/abs/2602.12670) requires human-written instructions for the same reason.

Results get published even if the skill loses.

Line numbers in `evals/` are for linux `f47d223627f8` and iproute2 `e11870d5b941`, unless a case says otherwise.
