# iproute2 legacy map layouts

The task comes from my PR [aya #1497](https://github.com/aya-rs/aya/pull/1497), which is still open. Some answers were confirmed in maintainer review. I found the rest in source with Claude's help, and no maintainer has confirmed them.

## Prompt

```text
Make your changes only in this repository (the current directory). aya-obj should load eBPF objects whose legacy `maps` section was compiled for iproute2's tc loader. Update the parsing so these objects load correctly. Write a doc comment describing each on-disk layout it accepts and where each one comes from, add tests, and end your reply with a commit message. Don't run tests that need root.
```

Run in a clone of aya at `13ad5a0c1be4`.

## Facts

Confirmed in review, in [one maintainer comment](https://github.com/aya-rs/aya/pull/1497#issuecomment-4133043795) that carries no AI signature.

1. Reading iproute2's pinning values into aya's struct is undefined behaviour, because of `PIN_GLOBAL_NS` in `bpf_elf.h`.
2. iproute2 pinning works differently from aya and libbpf, and the paths don't match.
3. Aya doesn't support iproute2's style of map-of-maps.

The same maintainer suggested rejecting pinning != 0. That's a design choice, not a kernel fact.

Found in source with Claude's help. No maintainer confirmed these, and all of them were read in source only. Line numbers are for iproute2 `e11870d5b941`.

1. `struct bpf_elf_map` (`include/bpf_elf.h:32`) has been 20 B (v4.1.0, `6256f8c9`), 24 B (v4.5.0, `f6793eec`), 28 B (v4.6.0, `4dd3f50a`) and 36 B (v4.13.0, `612ff099`).
2. iproute2 takes the size as section size / symbol count, accepts 16 B up to the full struct, zero-fills the rest, and rejects anything larger (`lib/bpf_legacy.c:1945-1982`). I added this after the first run, when reading the parser turned it up.
3. The pinning values are `PIN_NONE` 0, `PIN_OBJECT_NS` 1 and `PIN_GLOBAL_NS` 2 (`bpf_elf.h:27-29`). Other values are custom and come from a config file (`etc/iproute2/bpf_pinning`). There's no `PIN_CUSTOM_NS`.
4. iproute2 pins global maps at `<bpffs>/tc/globals/<name>` (`bpf_legacy.c:1382`), and aya's `ByName` defaults to `/sys/fs/bpf/<name>` (`aya/src/bpf.rs:658-662`). Mapping one to the other silently makes a separate map unless `default_map_pin_directory` is set.
5. A 28-byte map with pinning 2 must be iproute2's, since aya only uses 0 and 1. A 28-byte map with pinning 1 is ambiguous.
6. The undefined read is at `aya-obj/src/obj.rs:1220`.

## Grading

Check the doc comment, the tests and the commit message against the facts above. This case has no VM test.

## Results

I ran Sonnet 5.5 on this task by hand, with and without the sentence. The README summarizes what it got wrong.

Not tested: there's no test code for this case, so none of the facts has been checked by loading an object.
