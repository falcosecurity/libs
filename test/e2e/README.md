# e2e tests
The sources found in this folder are aimed at building containers for running
e2e tests on the libs. That is, tests that make use of the drivers, libscap and
libsinsp. Said tests are based around 2 containers:
- One running the `sinsp-example` binary
- Another one running the actual tests and verifying their outcome.

## Running the tests
The e2e tests use docker to run a few containers and execute commands in them
making it relatively easy to ensure events are the one we are looking for by
checking the `container.id` field in events. As the runner, pytest is used for
its flexibility and ease of configuration and a Python module is used to hold
common helper functions.

### Install Python dependencies
You can run the following commands for installing the python dependencies
needed for the e2e tests:

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make e2e-install-deps
```

It is recommended to use a virtual environment for installing Python
dependencies in order to prevent polluting your host. You can find instructions
on how to create a virtual environment here:
https://docs.python.org/3/tutorial/venv.html

### Run the tests
Once the python dependencies have been installed, you can configure the project
and run the e2e tests with the `e2e-tests` make target.

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make e2e-tests
```

An html report with the results and additional information useful for debugging
when something fails will be generated under `build/report/report.html`.

The e2e tests require that they be run with root privileges in order for
sinsp-example to insert the drivers, if you don't feel like compiling the
entire repo as root, you can use the following commands instead:

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make sinsp-example driver bpf
mkdir -p report/
sudo ../test/e2e/scripts/run_tests.sh
```

## Containerized tests
### sinsp container
A container holding the `sinsp-example` binary. Its entrypoint is set to the
binary, so it can be run in the same way as explained in [this README file](https://github.com/falcosecurity/libs/blob/master/userspace/libsinsp/examples/README.md).
The build for this container is based off of `containers/sinsp.Dockerfile`

### Drivers
The drivers used by `sinsp-example` to capture events on the system need to be
built as part of the tests. The drivers are embedded in the `sinsp-example`
container. The same container can be used with other drivers by mounting them
in and setting either the `KERNEL_MODULE` or `BPF_PROBE` environment variables.

### Tester container
This container is in charge of running any tests that are created under the
`tests/` subdirectory. The engine behind it is pytest and, as such, the tests
written need to follow the pattern `test_*/test_*.py` in order for them to be
properly picked up. Additionally, a module called `sinspqa` lives in
`tests/commons/`, it is installed directly to the tester container and is meant
to house any functions/classes that might be useful across multiple tests. The
dockerfile for this image can be found under `containers/tests.Dockerfile`.

### Running the tests
An `e2e-tests-container` target has been added. It requires the `BUILD_BPF`
option to be set.

## Potential future improvements
Aside from the obvious improvement of adding additional tests, here are some
ideas of things that could be changed to improve the quality of the tests:
- Implement a way to check non-deterministic values such as `pids` are found in
  subsequent events.
