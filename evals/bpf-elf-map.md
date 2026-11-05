# iproute2 legacy map layouts

From [aya #1497](https://github.com/aya-rs/aya/pull/1497). Run on aya `13ad5a0c1be4`.

```text
Make your changes only in this repository (the current directory). aya-obj should load eBPF objects whose legacy `maps` section was compiled for iproute2's tc loader. Update the parsing so these objects load correctly. Write a doc comment describing each on-disk layout it accepts and where each one comes from, add tests, and end your reply with a commit message. Don't run tests that need root.
```

## Answer

- `struct bpf_elf_map` (`include/bpf_elf.h:32`) has been 20 B (v4.1.0, `6256f8c9`), 24 B (v4.5.0, `f6793eec`), 28 B (v4.6.0, `4dd3f50a`) and 36 B (v4.13.0, `612ff099`).
- iproute2 takes the size as section size / symbol count, accepts 16 B up to the full struct, zero-fills the rest, and rejects anything larger (`lib/bpf_legacy.c:1945-1982`).
- Pinning: `PIN_NONE` 0, `PIN_OBJECT_NS` 1, `PIN_GLOBAL_NS` 2 (`bpf_elf.h:27-29`). Other values are custom and come from a config file (`etc/iproute2/bpf_pinning`). There's no `PIN_CUSTOM_NS`.
- iproute2 pins global maps at `<bpffs>/tc/globals/<name>` (`bpf_legacy.c:1382`). Aya's `ByName` defaults to `/sys/fs/bpf/<name>` (`aya/src/bpf.rs:658-662`), so mapping one to the other silently makes a separate map unless `default_map_pin_directory` is set.
- A 28-byte map with pinning 2 must be iproute2's, since aya only uses 0 and 1. A 28-byte map with pinning 1 is ambiguous.
- The old code reads pinning straight into a Rust enum, which is undefined behaviour for 2 (`aya-obj/src/obj.rs:1220`).

I added the 16 B parser rule after the first run, when reading the parser turned it up.
