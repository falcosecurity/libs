# BPF probe tests

## Build

To build the modern BPF probe tests:

```bash
cmake -DUSE_BUNDLED_DEPS=ON -DUSE_MODERN_BPF=ON -DBUILD_MODERN_BPF_TEST=ON -DMODERN_BPF_DEBUG_MODE=ON ..
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
