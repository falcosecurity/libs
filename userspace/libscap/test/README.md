# Scap tests

## Compile tests

```bash
cmake -DUSE_BUNDLED_DEPS=On -DBUILD_BPF=True -DCREATE_TEST_TARGETS=On -DBUILD_LIBSCAP_GVISOR=Off ..
make unit-test-libscap
```

You can add tests for specific engines using their Cmake options:
- `-DBUILD_LIBSCAP_MODERN_BPF=On`
- `-BUILD_LIBSCAP_GVISOR=On`

## Run tests

From the build directory:

```bash
sudo ./libscap/test/unit-test-libscap
```