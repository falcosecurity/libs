# falcosecurity/libs

[![CI Build](https://github.com/falcosecurity/libs/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/falcosecurity/libs/actions/workflows/ci.yml)

As per the [OSS Libraries Contribution Plan](https://github.com/falcosecurity/falco/blob/master/proposals/20210119-libraries-contribution.md), this repository has been chosen to be the new home for **libsinsp**, **libscap**, the **kernel module** and the **eBPF probe** sources.  
Refer to https://falco.org/blog/contribution-drivers-kmod-ebpf-libraries/ for more information.  

These components are at the foundation of [Falco](https://github.com/falcosecurity/falco) and other projects that work with the same kind of data.

This component stack mainly operates on a data source: system calls. This data source is collected using either a kernel module or an eBPF probe, which we call *drivers*. On top of the drivers, libscap manages the data capture process, libsinsp enriches the data, and provides a rich set of API to consume the data. Furthermore, these two libraries also implement a [plugin](https://github.com/falcosecurity/plugins) framework that extends this stack to potentially any other data sources.

An image is worth a thousand words, they say:

![diagram](https://falco.org/img/falco-diagram-blog-contribution.png)

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

## Versioning

This project uses two different versioning schemes for the _libs_ and _driver_ components. In particular, the _driver_ versions are suffixed with `+driver` to distinguish them from the _libs_ ones. Both adhere to the [Semantic Versioning 2.0.0](https://semver.org/). You can find more detail about how we version those components in our [release process documentation](./release.md).

If you build this project from a git working directory, the main [CMakeLists.txt](./CMakeLists.txt) will automatically compute the appropriate version for all components. Otherwise, if you use a source code copy with no the git information or pull the sources of the libs or the drivers directly in your project, it's up to you to correctly set the appropriate cmake variables (for example,  `-DFALCOSECURITY_LIBS_VERSION=x.y.z -DDRIVER_VERSION=a.b.c+driver`).

## Drivers officially supported architectures

Right now our drivers officially support the following architectures:

### x86_64
- **Kernel module** requires kernel versions greater or equal than `2.6`
- **eBPF probe** requires kernel versions greater or equal than `4.14`
- **Modern eBPF probe** work in progress...

### ARM64
- **Kernel module** requires kernel versions greater or equal than `3.4`
- **eBPF probe** requires kernel versions greater or equal than `4.17`
- **Modern eBPF probe** work in progress...

### s390x
- **Kernel module** requires kernel versions greater or equal than `2.6`
- **eBPF probe** not supported right now.
- **Modern eBPF probe** not supported right now.

## Build

Libs relies upon `cmake` build system.  
Lots of `make` targets will be available; the most important ones are:
* `driver` -> to build the kmod
* `bpf` -> to build the eBPF probe
* `scap` -> to build libscap
* `sinsp` -> to build libsinsp (depends upon `scap` target)
* `scap-open` -> to build a small libscap example to quickly test drivers (depends upon `scap`)

To start, first create and move inside `build/` folder:
```bash
mkdir build && cd build
```

### Bundled deps

The easiest way to build the project is to use `BUNDLED_DEPS` option, 
meaning that most of the dependencies will be fetched and compiled during the process:
```bash
cmake -DUSE_BUNDLED_DEPS=true -DCREATE_TEST_TARGETS=OFF ../
make sinsp
```
> **NOTE:** take a break as this will take quite a bit of time (around 15 mins, dependent on the hardware obviously).

### System deps

To build using the system deps instead, first, make sure to have all the needed packages installed.  
Refer to https://falco.org/docs/getting-started/source/ for the list of dependencies.  

Then, simply issue:
```bash
cmake ../
make sinsp
```

> **NOTE:** using system libraries is useful to cut compile times down, as this way it will only build libs, and not all deps.  
> On the other hand, system deps version may have an impact, and we cannot guarantee everything goes smoothly while using them.

### Build kmod

To build the kmod driver, you need your kernel headers installed. Again, check out the Falco documentation for this step.  
Then it will be just a matter of running:
```bash
make driver
```

### Build eBPF probe

To build the eBPF probe, you need `clang` and `llvm` packages.  
Then, issue:
```bash
cmake -DBUILD_BPF=true ../
make bpf
```

>__WARNING__: **clang-7** is the oldest supported version to build our BPF probe, since it is the one used by our infrastructure.

### Build modern eBPF probe

To build the modern eBPF probe, you need:

* a recent `clang` version (>=`12`).
* a recent `bpftool` version, typing `bpftool gen` you should see at least these features:
    ```
    Usage: bpftool gen object OUTPUT_FILE INPUT_FILE [INPUT_FILE...]    <---
           bpftool gen skeleton FILE [name OBJECT_NAME]                 <---
           bpftool gen help
    ``` 
* BTF exposed by your kernel, you can check it through `ls /sys/kernel/btf/vmlinux`. You should see this line:

    ```
    /sys/kernel/btf/vmlinux
    ```
* A kernel version >=`5.8`.

Then, issue:
```bash
cmake -DUSE_BUNDLED_DEPS=ON -DUSE_MODERN_BPF=ON -DBUILD_LIBSCAP_GVISOR=OFF .. 
make ProbeSkeleton
```

> __Please note__: these are not the requiremtens to use the BPF probe but to build it from source!

### gVisor support

Libscap contains additional library functions to allow integration with system call events coming from [gVisor](https://gvisor.dev).
Compilation of this functionality can be disabled with `-DBUILD_LIBSCAP_GVISOR=Off`.

## Test drivers

Libscap ships a small example that is quite handy to quickly check that drivers are working fine.
Look at the `scap-open` program [documentation](./userspace/libscap/examples/01-open/README.md).

## Contribute

Any contribution is incredibly helpful and **warmly** accepted; be it code, documentation, or just ideas, please feel free to share it!  
For a contribution guideline, refer to: https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md.

### Adding syscalls

Implementing new syscalls is surely one of the highest frequency requests.  
While it is indeed important for libs to support as many syscalls as possible, most of the time it is not a high priority task.  
But **you** can speed up things by opening a PR for it!  
Luckily enough, a Falco blog post explains the process very thoroughly: https://falco.org/blog/falco-monitoring-new-syscalls/.

## License

This project is licensed to you under the [Apache 2.0](./COPYING) open source license. Some subcomponents might be licensed separately. You can find licensing notices [here](./NOTICES).
