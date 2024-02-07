# falcosecurity/libs

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) [![License](https://img.shields.io/github/license/falcosecurity/libs?style=for-the-badge)](./COPYING)

[![CI Build](https://github.com/falcosecurity/libs/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/falcosecurity/libs/actions/workflows/ci.yml)
[![Architectures](https://img.shields.io/badge/ARCHS-x86__64%7Caarch64%7Cs390x%7Criscv64%7Cppc64le-blueviolet)](#drivers-officially-supported-architectures)
[![Drivers](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/FedeDP/1cbc5d42edf8e3a02fb75e76625f1072/raw/kernel.json)](https://github.com/falcosecurity/libs/actions/workflows/latest-kernel.yml)
[![Github Pages](https://github.com/falcosecurity/libs/actions/workflows/pages.yml/badge.svg)](https://falcosecurity.github.io/libs/)

This repository contains **libsinsp**, **libscap**, the **kernel module** and the **eBPF probes** sources.

These components are at the foundation of [Falco](https://github.com/falcosecurity/falco) and other projects that work with the same kind of data.

This component stack mainly operates on syscall events. We monitor syscalls using either a kernel module or an eBPF probe, which we call *drivers*. On top of the drivers, `libscap` manages the data capture process, while `libsinsp` enriches the data, and provides a rich set of API to consume the data. Furthermore, these two libraries also implement a [plugin](https://github.com/falcosecurity/plugins) framework that extends this stack to potentially any other data sources. For further details, please refer to the [official documentation](https://falco.org/docs/).

An image is worth a thousand words, they say:

<img src="https://falco.org/img/falco-diagram-blog-contribution.png" width="600"/>


## Project Layout

* [_driver/_](./driver) contains kernel module and eBPF probe source code,
so-called **drivers**.       
* [_userspace/_](./userspace) contains libscap and libsinsp libraries code,
plus chisels related code and common utilities.
  * **libscap** (aka lib for *System CAPture*) is the userspace library
  that directly communicates with the drivers, reading syscall events from
  the ring buffer (where drivers place them), and forwarding them
  up to libsinsp. Moreover, libscap implements OS state collection and
  supports reading/writing to scap files.  
  * **libsinsp** (aka lib for *System INSPection*) receives events from
  libscap and enriches them with machine state: moreover, it performs
  events filtering with rule evaluation through its internal rule engine.
  Finally, it manages outputs. 
  * **chisels** are just little Lua scripts to analyze an event stream
  and perform useful actions. In this subfolder, the backend code for
  chisels support can be found.  
* [_proposals/_](./proposals) unexpectedly contains the list of proposals.
* [_cmake/modules/_](./cmake/modules) contains modules to build
external dependencies, plus the libscap and libsinsp ones; consumers
(like Falco) use those modules to build the libs in their projects.

## Drivers Officially Supported Architectures

Our drivers officially support the following architectures:

|             | Kernel module                                                                                | eBPF probe | Modern eBPF probe | Status |
| ----------- |----------------------------------------------------------------------------------------------| ---------- | ----------------- | ------ |
| **x86_64**  | >= 2.6                                                                                       | >= 4.14    | >= 5.8            | _STABLE_ |
| **aarch64** | >= [3.16](https://github.com/torvalds/linux/commit/055b1212d141f1f398fca548f8147787c0b6253f) | >= 4.17    | >= 5.8            | _STABLE_ |
| **s390x**   | >= 2.6                                                                                       | >= [5.5](https://github.com/torvalds/linux/commit/6ae08ae3dea) | >= 5.8            | _EXPERIMENTAL_ |
| **riscv64** | >= [5.0](https://github.com/torvalds/linux/commit/5aeb1b36cedd3a1dfdbfe368629fed52dee34103)  | N/A                                                            | N/A               | _EXPERIMENTAL_ |
| **ppc64le** | >=2.6  | >=4.18         | >= 5.8               | _EXPERIMENTAL_ |


To access up-to-date status reports on Falco drivers kernel testing, please visit this [page](https://falcosecurity.github.io/libs/). It provides a list of supported syscalls as well as the [report](https://falcosecurity.github.io/libs/report/).

> __NOTE:__ while we strive to achieve maximum compatibility, we cannot assure that drivers correctly build against a new kernel version minutes after it gets released, since we might need to make some adjustments.    
> To get properly notified whenever drivers stop building, we have a [CI workflow](.github/workflows/latest-kernel.yml) that tests the build against the [latest mainline kernel](https://www.kernel.org/) (RC too!)

> __NOTE:__ _STABLE_ state means that we have CI covering drivers tests on the architecture. _EXPERIMENTAL_ means that we are not able to run any CI test against it.

</br>

## Versioning

<details>
	<summary>Expand Versioning Details</summary>

This project utilizes two different numbering series for the _libs_ and _drivers_ components, both in accordance with [Semantic Versioning 2.0.0](https://semver.org/). In particular, the _drivers_ component versions include a `driver` suffix in the [build metadata](https://semver.org/#spec-item-10) part of the SemVer string (ie. `5.1.0+driver`) to differentiate them from the _libs_ versions (ie. `0.12.0`). Further details about how we manage the versioning of these components can be found in our [release process documentation](./release.md).

When building this project from a Git working directory, the build system (see [CMakeLists.txt](./CMakeLists.txt)) will automatically determine the correct version for all components.

For [officially released builds](https://github.com/falcosecurity/libs/releases), the corresponding Git tag will be used as the version.

For development versions, the following schema is applied:

`<x>.<y>.<z>-<count>+<commit>[-driver]`

Where:
- `<x>.<y>.<z>` represents the next version number, reflecting either a patch for release branches or a minor version for development branches.
- `<count>` is the number of commits ahead from either:
  - the latest tag on the branch, for release branches; or   
  - the closest common ancestor with the branch holding the latest tagged version, for development branches.
- `<commit>` refers to the first 7 digits of the commit hash.
- `[-driver]` is an optional suffix used specifically for _driver_ versions.

For example, `0.13.0-2+abcdef0` means that the current _HEAD_ (_G_, commit hash `abcdef0`) is the second commit ahead of the common ancestor (_E_) with the release branch that holds the tag for `0.12.0` (_C_):

```
      A---B---C (tag: 0.12.0, branch: release/0.12.x)
     /
D---E---F---G (HEAD -> abcdef0)
```

This scheme ensures the correct [precedence](https://semver.org/#spec-item-11) when comparing build version numbers, regardless of whether they are released or development builds.


If you are building this project outside of a Git working directory, or if you want to override the version numbers, you must correctly set the appropriate `cmake` variables. For example, use `-DFALCOSECURITY_LIBS_VERSION=x.y.z -DDRIVER_VERSION=a.b.c+driver`.

</details>

</br>

## Build

<details>
	<summary>Expand Build Instructions</summary>

For your convenience, we have included the instructions for building the `libs` modules here, in addition to the information available in the [official documentation](https://falco.org/docs/install-operate/source/). These instructions are designed for building and testing `libs` on your own Linux development machine. However, if you intend to adopt CI or build within containers, there are additional considerations to take into account. The official [website]((https://falco.org/docs/install-operate/source/)) continually extends its guidance in this respect.

The project utilizes the `cmake` build system, and the key `make` targets are as follows: 

* `driver` -> build the kmod
* `bpf` -> build the eBPF probe
* `scap` -> build libscap (`modern_bpf` driver will be bundled into `scap` if enabled)
* `sinsp` -> build libsinsp (depends upon `scap` target)
* `scap-open` -> build a small example binary for `libscap` to test the drivers (dependent on `scap`)
* `sinsp-example` -> build a small example binary for `libsinsp` to test the drivers and/or `libsinsp` functionality (dependent on `scap` and `sinsp`)

You can refer to the main [CMakeLists.txt](CMakeLists.txt) file to explore the available targets and flags.

To start, first create and move inside `build/` folder:
```bash
mkdir build && cd build
```

### Build userspace using bundled deps

The easiest way to build the project is to use `BUNDLED_DEPS` option (enabled by default), 
meaning that most of the dependencies will be fetched and compiled during the process:

```bash
cmake -DUSE_BUNDLED_DEPS=ON ../;
make sinsp
```
> __NOTE:__ Take a break as this will take quite a bit of time (around 15 mins, dependent on the hardware).

### Build userspace using system deps

To build using the system deps instead, first, make sure to have all the needed packages installed. Refer to the [official documentation](https://falco.org/docs/install-operate/source/).

```bash
cmake -DUSE_BUNDLED_DEPS=OFF ../;
make sinsp
```

> __NOTE:__ Using system libraries is useful to cut compile times down, as this way it will only build libs, and not all deps. On the other hand, system deps version may have an impact, and we cannot guarantee everything goes smoothly while using them.

### Build driver - kmod

To build the kmod driver, you need your kernel headers installed. Check out the [official documentation](https://falco.org/docs/install-operate/source/).

```bash
make driver
# Verify the kmod object code was created, uses `.ko` extension.
ls -l driver/src/scap.ko;
```

### Build driver - eBPF probe

To build the eBPF probe, you need `clang` and `llvm` packages and you also need your kernel headers installed. Check out the [official documentation](https://falco.org/docs/install-operate/source/).

```bash
cmake -DBUILD_BPF=ON ../;
make bpf
# Verify the eBPF object code was created, uses `.o` extension.
ls -l driver/bpf/probe.o;
```

>__WARNING__: **clang-7** is the oldest supported version to build our BPF probe.

Initial guidance for CI and building within containers: To build either the kmod or eBPF probe in a container, you will need to make the extracted kernel headers available. The [test/vm](test/vm/) directory contains example [scripts](test/vm/scripts/compile_drivers.sh) demonstrating how to pass them to the `make` command using the argument `KERNELDIR=${EXTRACTED_KERNEL_HEADERS_DIR}`. You can also use the [falcosecurity/driverkit](https://github.com/falcosecurity/driverkit) or explore the scripts within the driverkit repository. The mentioned resources also provide candidate builder containers.

### Build driver - modern eBPF probe

To build the modern eBPF probe, further prerequisites are necessary:

* A recent `clang` version (>=`12`).
* A recent `bpftool` version, typing `bpftool gen` you should see at least these features:
    ```
    Usage: bpftool gen object OUTPUT_FILE INPUT_FILE [INPUT_FILE...]    <---
           bpftool gen skeleton FILE [name OBJECT_NAME]                 <---
           bpftool gen help
    ```
  If you want to use the `bpftool` mirror repo, version [`6.7`](https://github.com/libbpf/bpftool/releases/tag/v6.7.0) should be enough.
  
  If you want to compile it directly from the kernel tree you should pick at least the `5.13` tag.

* BTF exposed by your kernel, you can check it through `ls /sys/kernel/btf/vmlinux`. You should see this line:

    ```
    /sys/kernel/btf/vmlinux
    ```
* A kernel version >=`5.8`.

> __NOTE:__ These are not the requirements to use the modern BPF probe, but rather for building it from source.

Regarding the previously discussed bpf drivers, they create a kernel-specific object code (`driver/bpf/probe.o`) for your machine's kernel release (`uname -r`). This object code is then used as an argument for testing with `scap-open` and `sinsp-example` binaries.

However, the modern BPF driver operates differently. It doesn't require kernel headers, and its build isn't tied to your kernel release. This is enabled by the CO-RE (Compile Once - Run Everywhere) feature of the modern BPF driver. CO-RE allows the driver to work on kernels with backported BTF (BPF Type Format) support or kernel versions >= 5.8.

To comprehend how the driver understands kernel data structures without knowledge of the kernel it runs on, there's no black magic involved. We maintain a [vmlinux.h](driver/modern_bpf/definitions/vmlinux.h) file in our project containing all necessary kernel data structure definitions. Additionally, we sometimes rely on macros or functions typically found in system header files, which we redefine in [struct_flavors.h](driver/modern_bpf/definitions/struct_flavors.h).
 
That being said, the modern BPF driver still produces an object file, which you can create using the target below. Nevertheless, we ultimately include it in `scap` regardless. Hence, when modern BPF is enabled, building `scap` will already cover this step for you.

```bash
cmake \
-DUSE_BUNDLED_DEPS=ON \
-DBUILD_LIBSCAP_MODERN_BPF=ON ../;

make ProbeSkeleton
# Verify the modern eBPF object code / final composed header file including all `.o` modern_bpf files was created, uses `.h` extension.
ls -l skel_dir/bpf_probe.skel.h;
# Now includes skel_dir/bpf_probe.skel.h in `scap` during the linking process.
make scap
```

Initial guidance for CI and building within containers: The Falco Project, for instance, compiles the final Falco userspace binary within older centos7 [falco-builder](https://falco.org/docs/install-operate/source/#build-using-falco-builder-container) containers with bundled dependencies. This ensures compatibility across supported systems, mainly due to GLIBC versions and other intricacies. However, you won't be able to compile the modern BPF driver on such old systems or builder containers. One solution is to build `skel_dir/bpf_probe.skel.h` in a more recent builder container. For example, you can refer to this [container](test/vm/containers/ubuntu2310.Dockerfile) as a guide. Subsequently, you can provide the modern BPF header file as an artifact to `scap` during building in an older builder container. As an illustrative example, we use `/tmp/skel-dir` containing the `bpf_probe.skel.h` file.

```bash
cmake \
-DUSE_BUNDLED_DEPS=ON \
-DBUILD_LIBSCAP_MODERN_BPF=ON \
-DMODERN_BPF_SKEL_DIR="/tmp/skel-dir" ../;
```

### gVisor support

Libscap contains additional library functions to allow integration with system call events coming from [gVisor](https://gvisor.dev).
Compilation of this functionality can be disabled with `-DBUILD_LIBSCAP_GVISOR=OFF`.

</details>

</br>

## Testing

<details>
	<summary>Expand Testing Instructions</summary>

This repository includes convenient test example binaries for both `scap` and `sinsp`:

* `scap-open` -> build a small example binary for `libscap` to test the drivers (dependent on `scap`), checkout the program's [documentation](./userspace/libscap/examples/01-open/README.md)
* `sinsp-example` -> build a small example binary for `libsinsp` to test the drivers and/or `libsinsp` functionality (dependent on `scap` and `sinsp`), checkout the program's [documentation](./userspace/libsinsp/examples/README.md)

When developing new features, you would run either one depending on what you're working on, in order to test and validate your changes.

> __NOTE:__ When you're working on driver development, it can be quite useful to make use of the kernel's built-in `printk` functionality. However, for the traditional bpf driver, you'll need to uncomment a line in the [bpf Makefile](driver/bpf/Makefile) first and use a dedicated build flag `BPF_DEBUG`. For modern BPF, use the build flag `MODERN_BPF_DEBUG_MODE`. Any logs generated by `bpf_printk()` will be written to `/sys/kernel/debug/tracing/trace_pipe`. Just make sure you have the right permissions set up for this.

Here's an example of a `cmake` command that will enable everything you need for all tests and components. By default, the following flags are disabled, with the exception of `USE_BUNDLED_DEPS` and `CREATE_TEST_TARGETS` (they are enabled by default).

```bash
cmake \
-DUSE_BUNDLED_DEPS=ON \
-DBUILD_LIBSCAP_MODERN_BPF=ON \
-DBUILD_LIBSCAP_GVISOR=ON \
-DBUILD_BPF=ON \
-DBUILD_DRIVER=ON \
-DMODERN_BPF_DEBUG_MODE=ON \
-DBPF_DEBUG=ON \
-DCREATE_TEST_TARGETS=ON \
-DENABLE_LIBSCAP_TESTS=ON \
-DENABLE_DRIVERS_TESTS=ON \
-DENABLE_LIBSINSP_E2E_TESTS=ON \
-DENABLE_VM_TESTS=ON ../;
```

> __NOTE:__ The `ENABLE_LIBSINSP_E2E_TESTS` flag enables the new e2e tests for libsinsp. Please keep in mind these tests are currently in heavy development and need some extra steps (see in the section below) to run correctly.

> __TIP:__ Installing and using the package `ccache` can optimize repeated testing, but we don't offer official support or testing for it.

```bash
nproc=$(grep processor /proc/cpuinfo | tail -n 1 | awk '{print $3}');
rm -f driver/bpf/probe.o; make bpf;
rm -f driver/src/scap.ko; make driver;
# scap-open binary
rm -f libscap/examples/01-open/scap-open; make -j$(($nproc-1)) scap-open;
# sinsp-example binary
rm -f libsinsp/examples/sinsp-example; make -j$(($nproc-1)) sinsp-example;
```

These are the conventional unit tests that our CI system enforces:

```bash
# sinsp traditional unit tests
make -j$(($nproc-1)) unit-test-libsinsp; 
# Run
make run-unit-test-libsinsp;

# scap traditional unit tests
make -j$(($nproc-1)) libscap_test; 
# Run
sudo ./test/libscap/libscap_test;
```

Specialized driver tests can be found in [test/drivers](test/drivers), but please be aware that certain limitations might apply, and we're making every effort to ensure compatibility across various distributions. Our CI system also enforces these tests, but do note that currently, the CI system for driver tests is designed exclusively for Ubuntu. Therefore, if you encounter some test failures that aren't related to your changes, don't worry too much.

```bash
make -j$(($nproc-1)) drivers_test; 
# Run each drivers test via changing flags
sudo ./test/drivers/drivers_test -m;
```

The tests mentioned below expand beyond the scope of "unit tests". In this context as well, we are dedicated to making sure they run smoothly on your `localhost` for pre-PR testing, to the best of our ability:

- [test/e2e](test/e2e) - enforced by our CI
- [test/vm](test/vm) - our CI includes comparable tests, but it employs a distinct framework. For current status reports on Falco drivers kernel testing, please visit this [page](https://falcosecurity.github.io/libs/).

As mentioned earlier, The Falco Project's `libs` repository includes numerous CI-powered checks. For the most current information, please refer to the CI definitions under the [workflows](.github/workflows/) directory.

### [EXPERIMENTAL] Run libsinsp e2e tests

To correctly run the new libsinsp e2e tests on x86_64 `gcc-multilib` and `g++-multilib` are needed. To run the tests, use the following commands:

```bash
make -j$(($nproc-1)) libsinsp_e2e_tests;
# Run each drivers test via changing flags
sudo ./test/libsinsp_e2e/libsinsp_e2e_tests -m;
```

</details>

</br>

## How to Contribute

Please refer to the [contributing guide](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md) and the [code of conduct](https://github.com/falcosecurity/evolution/CODE_OF_CONDUCT.md) for more information on how to contribute.

For code contributions to this repository, we kindly ask you to carefully review the [Build](#build) and [Testing](#testing) sections.

## License

This project is licensed to you under the [Apache 2.0](./COPYING) open source license. Some subcomponents might be licensed separately. You can find licensing notices [here](./NOTICES).
