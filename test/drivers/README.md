# BPF probe tests

## Build

To build the modern BPF probe tests:

```bash
cmake -DBUILD_LIBSCAP_MODERN_BPF=ON -DBUILD_MODERN_BPF_TEST=ON -DMODERN_BPF_DEBUG_MODE=ON ..
make bpf_test
```

If you want to build also very specific tests regarding internal behaviors like the ring buffer consumption you should add also this cmake option `BUILD_ENHANCED_MODERN_BPF_TEST`:

```bash
cmake -DBUILD_ENHANCED_MODERN_BPF_TEST=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DBUILD_MODERN_BPF_TEST=ON -DMODERN_BPF_DEBUG_MODE=ON ..
make bpf_test
```

## Run test

Here there is a useful reference to GoogleTest doc describing the [advanced run options](https://github.com/google/googletest/blob/main/docs/advanced.md#running-a-subset-of-the-tests).

- Type the following command to get all Test Suites with all available test cases:

```bash
sudo ./test/modern_bpf/bpf_test --gtest_list_tests
```

- Type the following command to run a specific Test Case (for example, here we test the close exit event in the test suite `SyscallExit`):

```bash
sudo ./test/modern_bpf/bpf_test --gtest_filter='SyscallExit.mkdirX'
```

- Run an entire test suite (here `SyscallExit`)

```bash
sudo ./test/modern_bpf/bpf_test --gtest_filter='SyscallExit.*'
```

- Stop at the first test that fails:

```bash
sudo ./test/modern_bpf/bpf_test --gtest_break_on_failure
```
