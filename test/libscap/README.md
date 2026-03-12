# Scap tests

## Compile tests

```bash
cmake -DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=On -DBUILD_DRIVER=Off -DENABLE_LIBSCAP_TESTS=On ..
make libscap_test
```

You can add tests for specific engines using their Cmake options:
- `-DBUILD_LIBSCAP_MODERN_BPF=On`
- `-DBUILD_DRIVER=ON` (this will require `make driver` before running tests)

## Run tests

From the build directory:

```bash
sudo ./test/libscap/libscap_test
```

## Fuzz harnesses

In-tree `libscap` fuzz harness sources live under:

- `test/libscap/fuzz/`

Fuzz targets are opt-in via:

- `-DENABLE_LIBSCAP_FUZZERS=ON`

When enabled, the current target is:

- `fuzz_scap_event_decode`

Deterministic local seed-corpus regeneration helpers live under:

- `test/libscap/fuzz/tools/`

Checked-in seed corpus and dictionary live under:

- `test/libscap/fuzz/corpus/fuzz_scap_event_decode/`
- `test/libscap/fuzz/fuzz_scap_event_decode.dict`
