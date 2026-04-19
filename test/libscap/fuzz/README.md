# libscap fuzz harnesses

This directory contains the in-repo libFuzzer harnesses for `libscap`.

Current target:

- `fuzz_scap_event_decode.cc`

It exercises:

- `scap_event_getinfo()`
- `scap_event_decode_params()`

## What fuzzing means here

libFuzzer repeatedly calls the harness with mutated byte buffers. The harness
turns each byte buffer into one candidate event input, passes it into
`libscap`, and watches whether decoding stays safe and stable.

The goal is not to prove the decoder is perfect. The goal is to keep throwing
strange event-shaped inputs at it so sanitizer builds can catch memory bugs and
the harness can drive the decoder through more edge cases over time.

## Where this fits in Falco

`libscap` is Falco's low-level event decode layer.

1. kernel capture drivers, eBPF programs, or `.scap` savefiles provide raw
   event bytes
2. `libscap` turns those bytes into structured event fields
3. higher layers such as `libsinsp` and the Falco rule engine consume the
   decoded result

That makes `libscap` a good fuzz target because it is a byte parser boundary.

## What this target is testing

`scap_event_decode_params()` is not trying to fully interpret every parameter
value. Its job is more basic: given one event buffer, figure out where each
parameter starts and how large it is.

That means this target is mainly testing:

1. event schema lookup
2. parameter count handling
3. parameter length table decoding
4. parameter payload boundary calculation
5. decode plus basic follow-up reads through decoder-returned parameter ranges

## What a "parameter" means here

A parameter is one event argument or field inside a `scap_evt`.

The event layout is:

1. event header (`type`, `nparams`, `len`, ...)
2. parameter length table
3. parameter payload bytes

`type` selects the schema, which tells `libscap` how many parameters the event
should have and how their lengths should be interpreted.

## What the harness does to each input

For each fuzz input, the harness does four main things:

1. reads the first byte as a harness-only control byte
2. treats the remaining bytes as one `scap_evt` buffer
3. fixes up the event header so decoding starts from a self-consistent shape
4. runs `scap_event_decode_params()` and then performs small guarded reads
   through the decoded parameter ranges

Those final reads matter because they exercise more than just "the decoder
returned." They simulate a very small amount of follow-up consumption without
blindly dereferencing obviously invalid pointers from heavily corrupted inputs.

## Input layout

Each fuzz input looks like this:

```text
[1B control] [26B scap_evt header] [length table] [param payload]
```

The first byte is a harness-only control byte. It is not part of the real
`scap_evt` format. It exists so the harness can steer a mutated input toward
useful event schemas.

The remaining bytes are treated as a `scap_evt` buffer. Before decoding, the
harness fixes up the header fields it needs so the decoder sees a
self-consistent event length and an event type that matches the intended
schema.

### Control byte

Bits `[1:0]` select the event type category:

| `[1:0]` | Category |
|---------|----------|
| `0` | pass the raw type through |
| `1` | pick from a fixed set of regular event types |
| `2` | pick from the `EF_LARGE_PAYLOAD` event types |
| `3` | regular or large, depending on bit 7 |

Bit 6 controls `nparams` inflation. When it is set, the harness intentionally
makes header `nparams` larger than the schema count so
`scap_event_decode_params()` has to take its internal clamping path.

### Example seed

A synthetic seed for `PPME_GENERIC_X` (schema `nparams = 2`) looks like this:

```text
01                                # control: regular type, index 0 -> GENERIC_X
88 77 66 55 44 33 22 11           # ts
11 22 33 44 55 66 77 88           # tid
22 00 00 00                       # len = 34
01 00                             # type = 1
02 00 00 00                       # nparams = 2
02 00 02 00                       # parameter lengths: [2, 2]
4b 00                             # param[0] bytes
0a 00                             # param[1] bytes
```

## Seed corpus

A seed corpus is the small set of starting inputs that libFuzzer begins with
before it starts mutating them. This target uses two seed sources.

### Real seeds

These are extracted from in-repo sample captures under:

- `test/libsinsp_e2e/resources/captures/`

They cover normal syscall event shapes that already appear in Falco tests.

### Synthetic seeds

These are created by `recreate_seed_corpus.sh` to hit decoder paths that real
captures do not usually reach on their own, such as:

- `EF_LARGE_PAYLOAD` event types
- cases where header `nparams` is larger than the schema count
- zero-length parameter layouts
- mixed parameter size layouts

Real captures are important because they start from event shapes Falco already
uses in tests. Synthetic seeds are important because they can target decoder
branches that normal captures may never hit often enough on their own.

Generated seed files are not committed to the repository. Instead, the repo
keeps the source code and tooling needed to rebuild them locally from in-repo
sample captures plus the synthetic definitions.

To rebuild the corpus from the repository root:

```bash
./test/libscap/fuzz/tools/recreate_seed_corpus.sh
```

By default the generated corpus is written under:

`/tmp/falco-libs-corpus-rebuild/corpus/fuzz_scap_event_decode/`

Each run rebuilds that default path from scratch. If you override the output
location with `CORPUS_DIR=/path/to/corpus`, use an empty dedicated directory,
or one previously created by this script.

## Build and run locally

Build from a separate directory:

```bash
cmake -S . -B build-fuzz \
  -DUSE_BUNDLED_DEPS=ON \
  -DCREATE_TEST_TARGETS=ON \
  -DENABLE_LIBSCAP_TESTS=OFF \
  -DENABLE_LIBSCAP_FUZZERS=ON \
  -DUSE_ASAN=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target fuzz_scap_event_decode -j
```

For meaningful local fuzzing runs, keep `-DUSE_ASAN=ON` enabled so invalid
memory accesses turn into visible crash reports.

On macOS, Apple Command Line Tools `clang` often lacks the libFuzzer runtime.
If the link step fails looking for `libclang_rt.fuzzer_osx.a`, use Homebrew
LLVM explicitly:

```bash
cmake -S . -B build-fuzz \
  -DUSE_BUNDLED_DEPS=ON \
  -DCREATE_TEST_TARGETS=ON \
  -DENABLE_LIBSCAP_TESTS=OFF \
  -DENABLE_LIBSCAP_FUZZERS=ON \
  -DUSE_ASAN=ON \
  -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
cmake --build build-fuzz --target fuzz_scap_event_decode -j
```

Copy the generated corpus to a throwaway directory before running. libFuzzer
writes new interesting inputs back into the corpus directory it is using, and
you usually do not want those mixed into the clean baseline:

```bash
cp -R /tmp/falco-libs-corpus-rebuild/corpus/fuzz_scap_event_decode /tmp/fuzz-work-corpus

./build-fuzz/test/libscap/fuzz/fuzz_scap_event_decode \
  /tmp/fuzz-work-corpus \
  -dict=./test/libscap/fuzz/fuzz_scap_event_decode.dict \
  -max_total_time=60
```

## How to read the output

A typical libFuzzer line looks like this:

```text
cov: 56 ft: 98 corp: 44/6428b exec/s: 667180 rss: 466Mb
```

The most useful fields are:

- `cov`: how much instrumented code the run has reached
- `ft`: how many unique fuzzing features were reached
- `corp`: how many interesting inputs are now in the working corpus
- `exec/s`: how fast the target is running
- `rss`: memory usage

You may also see labels such as:

- `REDUCE`: libFuzzer is shrinking an existing corpus entry while keeping the
  same coverage
- `DONE`: the requested run completed cleanly
- `pulse`: a periodic status update

If a run completes cleanly, that means the harness stayed stable and did not
hit a sanitizer finding in that window. It does not mean the target is now
fully bug-free.

## Build model

Fuzz targets are opt-in and only built when `-DENABLE_LIBSCAP_FUZZERS=ON`.
They are not built by default test configurations.
