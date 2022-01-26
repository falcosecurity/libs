# falcosecurity/libs

As per the [OSS Libraries Contribution Plan](https://github.com/falcosecurity/falco/blob/master/proposals/20210119-libraries-contribution.md), this repository has been chosen to be the new home for **libsinsp**, **libscap**, the **kernel module** and the **eBPF probe** sources.  
Refer to https://falco.org/blog/contribution-drivers-kmod-ebpf-libraries/ for more informations.  

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

Easiest way to build the project is to use BUNDLED_DEPS option, 
meaning that most of the dependencies will be fetched and compiled during the process:
```bash
cmake -DUSE_BUNDLED_DEPS=true ../
make sinsp
```
> **NOTE:** take a break as this will take quite a bit of time (around 15 mins, dependent on the hardware obviously).

### Use system deps

To install using the system deps, first make sure to have all the needed packages installed.  
Refer to https://falco.org/docs/getting-started/source/ for the list of dependencies.  

Then, simply issue:
```bash
cmake ../
make sinsp
```

> **NOTE:** using system libraries is useful to cut compile times down, as this way it will only build libs, and not all deps.  
> On the other hand, system deps version may have an impact, and we cannot guarantee everything goes smoothly while using them.

### Build kmod

To build the kmod driver, you need your kernel headers installed. Again, checkout the Falco documentation for this step.  
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

## Test drivers

Libscap ships a small example that is quite handy to quickly check that drivers are working fine.  
To build it, issue:
```bash
make scap-open
```

Then, to execute it with the eBPF probe, issue:
```bash
sudo BPF_PROBE=driver/bpf/probe.o ./libscap/examples/01-open/scap-open
```

To execute it with the kmod instead issue:
```bash
sudo insmod driver/scap.ko
sudo ./libscap/examples/01-open/scap-open
sudo rmmod scap
```

As soon as you quit (ctrl-C) the scap-open program, you will be prompted with detailed informations on the capture:
```bash
events captured: 39460
seen by driver: 39912
Number of dropped events: 0
Number of dropped events caused by full buffer: 0
Number of dropped events caused by invalid memory access: 0
Number of dropped events caused by an invalid condition in the kernel instrumentation: 0
Number of preemptions: 0
Number of events skipped due to the tid being in a set of suppressed tids: 0
Number of threads currently being suppressed: 0
```
therefore confirming that the drivers are indeed working fine! 

## Contribute

Any contribution is incredibly helpful and **warmly** accepted; be it code, documentation, or just ideas, please feel free to share it!  
For a contribution guideline, refer to: https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md.

### Adding syscalls

Implementing new syscalls is surely one of the highest frequency request.  
While it is indeed important for libs to support as many syscalls as possible, most of the time it is not a high priority task.  
But **you** can speed up things by opening a PR for it!  
Luckily enough, a Falco blog post explains the process very thoroughly: https://falco.org/blog/falco-monitoring-new-syscalls/.

## License

This project is licensed to you under the [Apache 2.0](./COPYING) open source license. Some subcomponents might be licensed separately. You can find licensing notices [here](./NOTICES).  