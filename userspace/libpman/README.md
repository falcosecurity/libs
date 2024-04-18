# Libpman

First of all, `pman` stands for "probe management".

The second question could be: why a library over `libbpf`?

1. Hide the complexities behind the probe initialization phase and all `libbpf` APIs. This approach fits very well with the `v-table` structure. The rationale is to provide a stable interface to `libscap` to instrument the BPF probe. Moreover, sometimes we have to use low-level details of `libbpf` for example look at `/src/ringbuffer.c`: we need to rewrite some pieces of `libbpf` src code to extract only one event at a time from the ring buffers.
2. The same interface provided by `libpman` could be also used to load the old probe (we just need to introduce `libbpf` library also there).  
3. We need to load the probe both for the userspace and for the test framework. This library allows us to do it in a few lines of code, without code duplication.