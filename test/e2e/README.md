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
cmake -DCREATE_TEST_TARGETS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
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
cmake -DCREATE_TEST_TARGETS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make e2e-tests
```

An html report with the results and additional information useful for debugging
when something fails will be generated under `build/report/report.html`.

The e2e tests require that they be run with root privileges in order for
sinsp-example to insert the drivers, if you don't feel like compiling the
entire repo as root, you can use the following commands instead:

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make sinsp-example driver bpf
mkdir -p report/
sudo ../test/e2e/scripts/run_tests.sh
```

#### Passing parameters to pytest
The last command in the previous block of code can take any parameter accepted
by pytest. A common use case for this could be to run a subset of tests by
passing the path to those tests:

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make sinsp-example driver bpf
mkdir -p report/
sudo ../test/e2e/scripts/run_tests.sh ../test/e2e/tests/test_network/
```

Another common option could be to stop at the first failure:

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make sinsp-example driver bpf
mkdir -p report/
sudo ../test/e2e/scripts/run_tests.sh -x ../test/e2e/tests/
```

The tests also provide an easy way to skip running the tests with some drivers
in case there is a need to narrow down the scope even further. If you wanted to
run the tests skipping the kernel module you can use the following commands:

```sh
mkdir -p build && cd build
cmake -DCREATE_TEST_TARGETS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON -DUSE_BUNDLED_DEPS=ON -DBUILD_BPF=ON -DBUILD_DRIVER=ON ..
make sinsp-example driver bpf
mkdir -p report/
sudo ../test/e2e/scripts/run_tests.sh --no-kmod ../test/e2e/tests/
```

These are the three accepted parameters for skipping drivers:

```
--no-kmod: Skip tests using the kernel module as driver
--no-ebpf: Skip tests using the eBPF probe as driver
--no-modern: Skip tests using the modern probe as driver
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

## Contributing new e2e tests
In order to add new tests, the simplest approach is to run `sinsp-example` with
the `-j -a` flags and manually run the commands you'd like to catch events
from. This will cause the events to be output to the terminal in JSON format,
you can then copy paste them to a new test_*.py file, modify them as needed
and write a test that runs the commands you ran manually previously.

As a simple example, imagine you want to catch a sleep command being run inside
a container. You could run `sinsp-example` in the following way:

```sh
sinsp-example -j -a -k -f "evt.category=process and not container.id=host"
```

Then on a separate terminal you could do:

```sh
docker run --rm debian:buster sleep 1
```

`sinsp-example` will output a bunch of events, one of which looks something
like this:
```json
{"container.id":"e397c8dcbb3f","evt.args":"res=0 exe=sleep args=1. tid=472318(sleep) pid=472318(sleep) ptid=472295(containerd-shim) cwd=<NA> fdlimit=1073741816 pgft_maj=1 pgft_min=1026 vm_size=364 vm_rss=4 vm_swap=0 comm=sleep cgroups=cpuset=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.cpu=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.cpuacct=/.io=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.memory=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.devices=/.freezer=/.net_cls=/.perf_event=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.net_prio=/.hugetlb=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.pids=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope.misc=/system.slice/docker-e397c8dcbb3fbf1dfdf05eb4bd5c45bb78066506ac662b481fb475b05cca28da.scope. env=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin.HOSTNAME=e397c8dcbb3f.HOME=/root. tty=0 pgid=1(systemd) loginuid=-1\(\<NONE\>\) flags=1(EXE_WRITABLE) cap_inheritable=0 cap_permitted=A80425FB cap_effective=A80425FB exe_ino=1213089 exe_ino_ctime=2023-02-10 09:33:30.56273065 exe_ino_mtime=2019-02-28 15:30:31.00000000 uid=0 ","evt.category":"process","evt.num":1483230,"evt.time":1678289852166558200,"evt.type":"execve","proc.cmdline":"sleep 1","proc.exe":"sleep","proc.pid":472318,"proc.ppid":472308}
```

Because JSON is valid Python, you can copy and paste it directly, we'll drop
the `evt.args` for readability, but you could turn it to a regex if there is a
need to validate some fields in it.

```python
expected_events = [{
  "container.id": "e397c8dcbb3f",
  "evt.category": "process",
  "evt.num": 1483230,
  "evt.time": 1678289852166558200,
  "evt.type": "execve",
  "proc.cmdline": "sleep 1",
  "proc.exe": "sleep",
  "proc.pid": 472318,
  "proc.ppid": 472308
}]
```
You should familiarize yourself with the sinspqa module and its helpers, the
previous event can be modified to be a bit more generic as follows:

```python
expected_events = [{
  "container.id": get_container_id(app_container),
  "evt.category": "process",
  "evt.num": SinspField.numeric_field(),
  "evt.time": SinspField.numeric_field(),
  "evt.type": "execve",
  "proc.cmdline": "sleep 1",
  "proc.exe": "sleep",
  "proc.pid": SinspField.numeric_field(),
  "proc.ppid": SinspField.numeric_field()
}]
```

## Potential future improvements
Aside from the obvious improvement of adding additional tests, here are some
ideas of things that could be changed to improve the quality of the tests:
- Implement a way to check non-deterministic values such as `pids` are found in
  subsequent events.
