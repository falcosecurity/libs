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
It is recommended to use a virtual environment for installing Python
dependencies in order to prevent polluting your host. In order to create a
virtual environment and install all dependencies in it, from the `test/e2e/`
directory run the following commands:

```sh
python3 -m venv e2e-venv
source e2e-venv/bin/activate
pip3 install -r tests/requirements.txt
pip3 install tests/commons
```

Once you are done running the tests, deactivate the virtual environment by
running `deactivate`. If you want to go back to the virtual environment to keep
running tests, simply source the `e2e-venv/bin/activate` script again.

More information can be found here: https://docs.python.org/3/tutorial/venv.html

### Run the tests
Once the python dependencies have been installed and the virtual environment
is active, you can go ahead and configure the project with `cmake` as usual,
the `e2e-tests` target will compile the `sinsp-example` binary, the kernel
module, the eBPF probe and run the e2e-tests, leaving an html report in the
build directory, under `report/report.html`.

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
