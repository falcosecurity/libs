# libscap fuzz harnesses

This directory contains libFuzzer harness sources for `libscap`.

Current harness:

1. `fuzz_scap_event_decode.cc`
2. Calls `scap_event_getinfo` and `scap_event_decode_params`
3. Uses one raw `scap_evt`-shaped byte buffer as input

## `libscap` in Falco

`libscap` is Falco's low-level event decode layer.

1. Kernel capture drivers (or `.scap` files) provide raw event bytes.
2. `libscap` parses those bytes into event fields.
3. Upper layers (`libsinsp` and Falco's rule engine) consume that decoded data.

Because this is the byte parser boundary, it is a good fuzz target.

## What "parameter" means here

A parameter is one event argument/field inside a `scap_evt`.

Event layout:

1. Event header (`type`, `nparams`, etc.).
2. Parameter length table.
3. Parameter payload bytes.

`type` selects the event schema (which parameters exist and how they are read).

## What this harness exercises

1. Event metadata lookup (`scap_event_getinfo`).
2. Parameter-boundary decode (`scap_event_decode_params`).
3. Basic payload-byte access through decoder-returned parameter pointers (with bounds checks).

## Example event buffer

Example from a real savefile event:

```text
49 69 57 42 7e bc 4b 15   # ts      = 1534527348514711881
59 44 00 00 00 00 00 00   # tid     = 17497
22 00 00 00               # len     = 34 bytes total
01 00                     # type    = 1
02 00 00 00               # nparams = 2
02 00 02 00               # param lengths: [2, 2]
4b 00                     # param[0] bytes
0a 00                     # param[1] bytes
```

This matches generated seed `real_curl_google_type1_len34.bin`.

## Recreate local seed corpus

Checked-in seeds live under:

`test/libscap/fuzz/corpus/fuzz_scap_event_decode/`

From the libs repository root:

```bash
./test/libscap/fuzz/tools/recreate_seed_corpus.sh
```

Output directory:

`test/libscap/fuzz/corpus/fuzz_scap_event_decode/`

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

Run with checked-in corpus and dictionary (using temporary run dirs so checked-in seeds stay unchanged):

```bash
cp -R ./test/libscap/fuzz/corpus/fuzz_scap_event_decode /tmp/fuzz_scap_event_decode.in
mkdir -p /tmp/fuzz_scap_event_decode.out
./build-fuzz/test/libscap/fuzz/fuzz_scap_event_decode \
  /tmp/fuzz_scap_event_decode.in \
  /tmp/fuzz_scap_event_decode.out \
  -dict=./test/libscap/fuzz/fuzz_scap_event_decode.dict \
  -max_total_time=60
```

`ENABLE_LIBSCAP_FUZZERS` requires a clang toolchain with libFuzzer runtime.
On macOS, if Apple Command Line Tools clang does not provide libFuzzer,
use Homebrew LLVM clang/clang++.

Quick check:

```bash
SEED=./test/libscap/fuzz/corpus/fuzz_scap_event_decode/real_curl_google_type1_len34.bin
python3 - <<'PY' "$SEED"
import struct
import sys
from pathlib import Path

b = Path(sys.argv[1]).read_bytes()
ts, tid, elen, etype, nparams = struct.unpack_from("<QQIHI", b, 0)
l1, l2 = struct.unpack_from("<HH", b, 26)
print(f"size={len(b)} len={elen} type={etype} nparams={nparams}")
print(f"ts={ts} tid={tid} param_lens=[{l1},{l2}]")
PY
```

Expected output:

```text
size=34 len=34 type=1 nparams=2
ts=1534527348514711881 tid=17497 param_lens=[2,2]
```

## Build model

Fuzz targets are opt-in and only built when `-DENABLE_LIBSCAP_FUZZERS=ON`.
They are not built by default test configurations.
