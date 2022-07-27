# e2e tests
The sources found in this folder are aimed at building containers for running
e2e tests on the libs. That is, tests that make use of the drivers, libscap and
libsinsp. Said tests are based around 2 containers:
- One running the `sinsp-example` binary
- Another one running the actual tests and verifying their outcome.

## sinsp container
A container holding the `sinsp-example` binary. Its entrpoint is set to the
binary, so it can be run in the same way as explained in [this README file](https://github.com/falcosecurity/libs/blob/master/userspace/libsinsp/examples/README.md).
The build for this container is based off of `containers/sinsp.Dockerfile`

## Drivers
The drivers used by `sinsp-example` to capture events on the system need to be
built as part of the tests. The drivers are embedded in the `sinsp-example`
container. The same container can be used with other drivers by mounting them
in and setting either the `KERNEL_MODULE` or `BPF_PROBE` environment variables.

## Tester container
This container is in charge of running any tests that are created under the
`tests/` subdirectory. The engine behind it is pytest and, as such, the tests
written need to follow the pattern `test_*/test_*.py` in order for them to be
properly picked up. Additionally, a module called `sinspqa` lives in
`tests/commons/`, it is installed directly to the tester container and is meant
to house any functions/classes that might be useful accross multiple tests. The
dockerfile for this image can be found under `containers/tests.Dockerfile`.

## Running the tests
An `e2e-tests` target has been added. It requires the `BUILD_BPF` option to be
set.

## Potential future improvements
Aside from the obvious improvement of adding additional tests, here are some
ideas of things that could be changed to improve the quality of the tests:
- Implement a way to check non-deterministic values such as `pids` are found in
  subsequent events.
