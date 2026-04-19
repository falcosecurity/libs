# Fuzzing

This page explains the initial fuzzing support currently living in `libs`.
It is written for maintainers who know Falco, but may be new to fuzzing.

## What fuzzing is

Fuzzing is an automated way to test code with large numbers of mutated inputs.
Instead of writing one test case at a time, we give a target function a small
set of starting inputs and let a fuzzing engine keep changing those inputs to
see what new code paths it can reach.

The engine used here is libFuzzer. It repeatedly calls the target harness with
byte buffers, keeps inputs that reach something new, and stops when it finds a
crash, hang, or sanitizer failure.

Fuzzing is especially useful for parser-like code because parser bugs often
show up only when the input is malformed in ways a normal unit test would not
think to try.

## Why start with `libscap`

`libscap` is the layer that turns raw event bytes into structured event data.
That makes it a good first fuzz target: it sits at an important parser
boundary, it is small enough to exercise with a focused harness, and mistakes
here can affect every layer above it.

At a high level, the flow looks like this:

1. kernel capture drivers, eBPF programs, or `.scap` savefiles provide raw
   event bytes
2. `libscap` decodes those bytes into event fields and parameter boundaries
3. higher layers such as `libsinsp` and the Falco rule engine consume the
   decoded result

The current target is `fuzz_scap_event_decode`. It exercises:

- `scap_event_getinfo()`
- `scap_event_decode_params()`

In simple terms, it feeds one event-shaped byte buffer into `libscap` and asks
the decoder to determine where each parameter starts and how large it is. That
is a good first target because it sits near the beginning of the decode path
and works directly on raw event data.

## What is in the repository today

The in-repo fuzzing baseline includes:

- an opt-in CMake target enabled with `-DENABLE_LIBSCAP_FUZZERS=ON`
- a libFuzzer dictionary in `test/libscap/fuzz/fuzz_scap_event_decode.dict`
- corpus generation tools in `test/libscap/fuzz/tools/`
- local usage docs in `test/libscap/fuzz/README.md`

Generated seed corpora are not committed to the repository. Instead, they are
rebuilt locally from sample `.scap` captures already present in the tree under:

- `test/libsinsp_e2e/resources/captures/`

That keeps the repository focused on source code and reproducible tooling
instead of generated binary artifacts, while still giving local users a simple
way to rebuild the same starting corpus.

## How the seed corpus works

A seed corpus is the small set of starting inputs that libFuzzer begins with
before it starts mutating them.

This target uses two seed sources.

### Real seeds

`extract_scap_events.cc` reads an in-repo `.scap` savefile and writes
individual events as `.bin` files that the harness can consume directly.
`recreate_seed_corpus.sh` uses that helper to extract events from the sample
captures and select a small deterministic subset.

These real seeds are useful because they reflect event shapes that already
appear in Falco tests.

### Synthetic seeds

Real sample captures mostly cover normal syscall events. They do not naturally
reach every branch in the parameter decoder, so the script also creates
synthetic events for cases such as:

- `EF_LARGE_PAYLOAD` event types, which use 32-bit parameter lengths
- events where header `nparams` is larger than the schema count
- zero-length or mixed-size parameter layouts

The synthetic seeds are not meant to model whole workloads. They exist to give
the fuzzer a better starting point around decoder edge cases.

By default the script writes the generated corpus under:

- `/tmp/falco-libs-corpus-rebuild/corpus/fuzz_scap_event_decode/`

Each run rebuilds that default path from scratch. If you override the
destination with `CORPUS_DIR=/path/to/output`, use an empty dedicated
directory, or one previously created by the script.

## What kinds of bugs this can find

This setup is mainly looking for problems such as:

- invalid memory reads or writes
- out-of-bounds parameter calculations
- crashes caused by malformed event layouts
- undefined behavior surfaced by sanitizers

Like any fuzz target, a clean run does not prove the code is bug-free. It is
best thought of as an automated stress test that gets stronger as the harness
and corpus improve.

## Local workflow

From the repository root, first generate the starting corpus:

```bash
./test/libscap/fuzz/tools/recreate_seed_corpus.sh
```

Then build the fuzz target with clang/libFuzzer:

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

For normal local fuzzing, use `-DUSE_ASAN=ON`. AddressSanitizer is what turns
invalid memory accesses into useful crash reports instead of silent corruption.

On macOS, Apple Command Line Tools `clang` often does not ship the libFuzzer
runtime. If the link step fails looking for `libclang_rt.fuzzer_osx.a`, point
CMake at Homebrew LLVM explicitly instead:

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

## What the fuzzer is doing while it runs

During a run, libFuzzer:

1. loads the seed corpus
2. runs the harness on each seed
3. mutates the most interesting inputs
4. keeps mutated inputs that reach new code or new input features
5. writes those interesting inputs back into the working corpus directory
6. stops early if a crash or sanitizer finding occurs

That is why the docs recommend copying the generated baseline corpus into a
throwaway working directory first.

## What a successful run tells you

A clean run does not prove the decoder is bug-free. It means:

- the harness started from a valid non-empty corpus
- the target stayed stable for the requested run
- sanitizers did not report an obvious memory bug in that window
- coverage can now be compared across corpus or harness changes

## How to read the output

A typical libFuzzer status line looks like this:

```text
cov: 56 ft: 98 corp: 44/6428b exec/s: 667180 rss: 466Mb
```

A simple way to read that is:

- `cov`: how much instrumented code has been reached
- `ft`: how many unique fuzzing features were reached
- `corp`: how many interesting inputs are now in the working corpus
- `exec/s`: throughput
- `rss`: memory usage

You may also see status labels such as:

- `REDUCE`: libFuzzer is minimizing an existing corpus entry while keeping the
  same coverage
- `DONE`: the requested run finished cleanly
- `pulse`: a periodic progress update, not a new bug or new coverage event

For this target, the most useful questions are:

- did coverage improve after a harness or corpus change?
- did the run stay stable?
- did a sanitizer report a real bug?

## Measuring coverage

To see which branches the fuzzer is actually reaching, rebuild with LLVM
source-based coverage instrumentation:

```bash
cmake -S . -B build-fuzz-cov \
  -DUSE_BUNDLED_DEPS=ON \
  -DCREATE_TEST_TARGETS=ON \
  -DENABLE_LIBSCAP_FUZZERS=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping"
cmake --build build-fuzz-cov --target fuzz_scap_event_decode -j
```

Run the fuzzer. This writes a `.profraw` profile:

```bash
cp -R /tmp/falco-libs-corpus-rebuild/corpus/fuzz_scap_event_decode /tmp/fuzz-cov-corpus
LLVM_PROFILE_FILE=/tmp/fuzz.profraw \
  ./build-fuzz-cov/test/libscap/fuzz/fuzz_scap_event_decode \
  /tmp/fuzz-cov-corpus \
  -dict=./test/libscap/fuzz/fuzz_scap_event_decode.dict \
  -runs=50000
```

Merge the profile and generate a report:

```bash
llvm-profdata merge -sparse /tmp/fuzz.profraw -o /tmp/fuzz.profdata
llvm-cov report \
  ./build-fuzz-cov/test/libscap/fuzz/fuzz_scap_event_decode \
  -instr-profile=/tmp/fuzz.profdata \
  userspace/libscap/scap_event.c \
  -show-functions
```

For annotated source with per-line hit counts and branch directions:

```bash
llvm-cov show \
  ./build-fuzz-cov/test/libscap/fuzz/fuzz_scap_event_decode \
  -instr-profile=/tmp/fuzz.profdata \
  userspace/libscap/scap_event.c \
  -show-branches=count
```

On macOS, if `llvm-profdata` or `llvm-cov` are missing from `PATH`, or do not
match the clang version used for the build, use the Homebrew LLVM versions
instead.

## Relationship to external fuzzing

This repository is intended to hold the harness, dictionary, and corpus
generation logic. A separate external integration, such as an OSS-Fuzz project,
can consume those pieces later for continuous fuzzing without making `libs`
depend on that external system for local development.
