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

`libscap` also has an opt-in local fuzzing target under:

- `test/libscap/fuzz/`

When fuzzing is enabled with `-DENABLE_LIBSCAP_FUZZERS=ON`, the current target is:

- `fuzz_scap_event_decode`

The fuzzing directory contains:

- the harness source
- the dictionary
- corpus generation tools
- local usage docs

Seed inputs are generated locally from in-repo sample captures in:

- `test/libsinsp_e2e/resources/captures/`

Run `./test/libscap/fuzz/tools/recreate_seed_corpus.sh` before fuzzing so the
starting corpus is rebuilt from those sample captures plus the synthetic seeds
used to cover decoder edge cases.

For full background, local build instructions, and an explanation of how the
seed corpus works, see:

- `docs/fuzzing.md`
- `test/libscap/fuzz/README.md`
