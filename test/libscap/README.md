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

They are intended for external fuzzing integrations (for example OSS-Fuzz) and
are not part of default CMake test targets in this first pass.

Deterministic local seed-corpus regeneration helpers live under:

- `test/libscap/fuzz/tools/`
