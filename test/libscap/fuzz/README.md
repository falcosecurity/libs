# libscap fuzz harnesses

This directory contains libFuzzer harnesses for `libscap`.

The initial harness (`fuzz_scap_event_decode.cc`) targets:

1. `scap_event_getinfo`
2. `scap_event_decode_params`

using a raw `scap_evt`-shaped byte buffer input.

## Example event buffer

The harness input is treated as raw bytes and interpreted as:

1. `struct ppm_evt_hdr` (packed)
2. parameter length table (`nparams` entries, usually `uint16_t`)
3. parameter payload bytes

Concrete little-endian example (observed from a real Falco savefile event) with
2 params:

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

This matches one deterministic seed file generated as
`real_curl_google_type1_len34.bin`.

## Recreate local seed corpus

From the libs repository root:

```bash
./test/libscap/fuzz/tools/recreate_seed_corpus.sh
```

This creates a deterministic `fuzz_scap_event_decode` seed subset under:

`test/libscap/fuzz/corpus/fuzz_scap_event_decode/`

Supported environment overrides:

1. `CORPUS_DIR` (default: `test/libscap/fuzz/corpus/fuzz_scap_event_decode`)
2. `WORK_DIR` (default: `/tmp/falco-libs-corpus-rebuild`)
3. `MAX_EVENTS` (default: `500`)
4. `MAX_LEN` (default: `4096`)

Quick verification command (after running the script above):

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

Notes:

1. `len` is the full event size, including header + lengths + payload.
2. `type` drives metadata lookup in `scap_event_getinfo` and influences decode behavior.
3. Some events can use 32-bit length entries (`EF_LARGE_PAYLOAD`), so fuzzing both styles is useful.
4. The sample byte order reflects a little-endian capture source host.

## Build model

These files are intended to be consumed by external fuzzing integrations
(for example, OSS-Fuzz project build scripts) and are not wired into the
default `libs` CMake targets in this first pass.
