# Scap tests

## Compile tests

```bash
cmake -DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=On -DBUILD_BPF=Off -DBUILD_DRIVER=Off -DBUILD_LIBSCAP_GVISOR=Off -DENABLE_LIBSCAP_TESTS=On ..
make libscap_test
```

You can add tests for specific engines using their Cmake options:
- `-DBUILD_LIBSCAP_MODERN_BPF=On`
- `-DBUILD_LIBSCAP_GVISOR=On`
- `-DBUILD_BPF=ON` (this will require `make bpf` before running tests)
- `-DBUILD_DRIVER=ON` (this will require `make driver` before running tests)

## Run tests

From the build directory:

```bash
sudo ./test/libscap/libscap_test
```
