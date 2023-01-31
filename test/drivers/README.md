# Drivers tests

## Rationale

This test suite should allow you to check the behavior of our 3 drivers: `modern_bpf`, `bpf`, `kernel module`. To assert against the output of our drivers we use the so-called `scap-engines`.
You don't have to build all the engines if you want to assert only some of the drivers, for example, the minimal build command is:

```bash
cmake -DUSE_BUNDLED_DEPS=On -DENABLE_DRIVERS_TESTS=On -DBUILD_LIBSCAP_GVISOR=Off -DCREATE_TEST_TARGETS=On ..
```

In this case, only the `kmod` engine will be built and you can assert only the behavior of the kernel module. If you want to assert also the bpf probe you have to add `-DBUILD_BPF=True`, while if you want to add the modern bpf probe engine you have to use `-DBUILD_LIBSCAP_MODERN_BPF=On`.

## Usage Example

Let's build all the 3 engines:

```bash
cmake -DUSE_BUNDLED_DEPS=On -DENABLE_DRIVERS_TESTS=On -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=On -DBUILD_LIBSCAP_MODERN_BPF=On -DCREATE_TEST_TARGETS=On -DMODERN_BPF_DEBUG_MODE=On ..
make drivers_test
```

Now all the engines should be built, but if you want to assert against the kmod or the bpf probe you have to build them:

```bash
make driver bpf
```

> __NOTE__: the modern bpf probe is bundled inside its engine so every time you type `make drivers_test` it will be automatically compiled without any additional command.

We are ready to run our tests:

```
sudo ./test/drivers/drivers_test -k
```

The `-k` option stands for kmod, so you are running all the tests against the kmod. Some other available options are:

- `-k` to run tests against the kernel module.
- `-m` to run tests against the modern bpf probe.
- `-b` to run tests against the bpf probe.
- `-d` to change the dimension of shared buffers between userspace and kernel. (advanced use case)

> __NOTE__: you can assert only one driver at time so you cannot run tests with more than one engine option `sudo ./test/drivers/drivers_test -k -m` ⚠️

Another important thing to know is that by default when you provide the `-k` option, tests will search under `./driver/scap.ko` for a valid kernel module (this is the default location when you type `make driver`) same for the bpf probe (`.driver/bpf/probe.o`) so if you run tests in the build directory you shouldn't have issues. If you run tests outside the build directory you should provide also the path with the option (`sudo ./test/drivers/drivers_test -k <path_to_the_kmod>`, same for bpf). The modern bpf probe is bundled so no need for explicit paths!

This is the suggested flow to run tests 👇

From repo root `/libs` type:

```bash
rm -rf build
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=On -DENABLE_DRIVERS_TESTS=On -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=True -DBUILD_LIBSCAP_MODERN_BPF=On -DCREATE_TEST_TARGETS=On ..
make drivers_test
make driver bpf
sudo ./test/drivers/drivers_test <option>
```

## Advanced Usage

Here there is a useful reference to GoogleTest doc describing the [advanced run options](https://github.com/google/googletest/blob/main/docs/advanced.md#running-a-subset-of-the-tests).

- Type the following command to get all Test Suites with all available test cases for the modern probe:

```bash
sudo ./test/drivers/drivers_test -m --gtest_list_tests
```

- Type the following command to run a specific Test Case (for example, here we test the close exit event in the test suite `SyscallExit` for the modern probe):

```bash
sudo ./test/drivers/drivers_test -m --gtest_filter='SyscallExit.mkdirX'
```

- Run an entire test suite (here `SyscallExit`)

```bash
sudo ./test/drivers/drivers_test -m --gtest_filter='SyscallExit.*'
```

- Stop at the first test that fails:

```bash
sudo ./test/drivers/drivers_test -m --gtest_break_on_failure
```

- Avoid running some specific tests

```bash
sudo ./test/drivers/drivers_test -m --gtest_filter=-'SyscallExit.mkdirX'
```
