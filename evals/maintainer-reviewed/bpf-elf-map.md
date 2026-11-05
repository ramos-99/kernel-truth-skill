# iproute2 legacy map layouts

From my PR [aya #1497](https://github.com/aya-rs/aya/pull/1497), which is still open. Run on aya `13ad5a0c1be4`.

```text
Make your changes only in this repository (the current directory). aya-obj should load eBPF objects whose legacy `maps` section was compiled for iproute2's tc loader. Update the parsing so these objects load correctly. Write a doc comment describing each on-disk layout it accepts and where each one comes from, add tests, and end your reply with a commit message. Don't run tests that need root.
```

## Confirmed in review

From [one maintainer comment](https://github.com/aya-rs/aya/pull/1497#issuecomment-4133043795), which carries no AI signature.

- Reading iproute2's pinning values into aya's struct is undefined behaviour, because of `PIN_GLOBAL_NS` in `bpf_elf.h`.
- iproute2 pinning works differently from aya and libbpf, and the paths don't match.
- Aya doesn't support iproute2's style of map-of-maps.

The same maintainer suggested rejecting pinning != 0, which is a design choice and not a kernel fact.

## Found in source with Claude's assistance

No maintainer confirmed these. Line numbers are for iproute2 `e11870d5b941`.

- `struct bpf_elf_map` (`include/bpf_elf.h:32`) has been 20 B (v4.1.0, `6256f8c9`), 24 B (v4.5.0, `f6793eec`), 28 B (v4.6.0, `4dd3f50a`) and 36 B (v4.13.0, `612ff099`).
- iproute2 takes the size as section size / symbol count, accepts 16 B up to the full struct, zero-fills the rest, and rejects anything larger (`lib/bpf_legacy.c:1945-1982`). I added this after the first run, when reading the parser turned it up.
- Pinning: `PIN_NONE` 0, `PIN_OBJECT_NS` 1, `PIN_GLOBAL_NS` 2 (`bpf_elf.h:27-29`). Other values are custom and come from a config file (`etc/iproute2/bpf_pinning`). There's no `PIN_CUSTOM_NS`.
- The exact paths: iproute2 pins global maps at `<bpffs>/tc/globals/<name>` (`bpf_legacy.c:1382`), and aya's `ByName` defaults to `/sys/fs/bpf/<name>` (`aya/src/bpf.rs:658-662`), so mapping one to the other silently makes a separate map unless `default_map_pin_directory` is set.
- A 28-byte map with pinning 2 must be iproute2's, since aya only uses 0 and 1. A 28-byte map with pinning 1 is ambiguous.
- The undefined read is at `aya-obj/src/obj.rs:1220`.
