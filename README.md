# falcosecurity/libs

As per the [OSS Libraries Contribution Plan](https://github.com/falcosecurity/falco/blob/master/proposals/20210119-libraries-contribution.md), this repository has been chosen to be the new home for **libsinsp**, **libscap**, the **kernel module driver** and the **eBPF driver sources**.

## Project Layout

* _driver/_ folder contains kernel module and eBPF source code.     
* _userspace/_ folder contains libscap and libsinsp libraries code, plus chisels related code and common utilities.
* * **libscap** is the userspace library that directly communicates with the drivers,  
reading syscall events from the ring buffer (where they are placed by drivers), and forwarding them up to libsinsp.  
Moreover, libscap implements OS state collection and supports reading/writing to scap files.  
* * **libsinsp** receives events from libscap and enriches them with machine state;  
moreover, it performs events filtering with rule evaluation through its internal rule engine.  
Finally, it manages outputs.  
* _proposals/_ folder unexpectedly contains the list of proposals
* _cmake/modules_ contains the list of cmake modules used during the build for external dep,  
plus the libscap and libsinsp ones that are used by Falco when building libs.  

## Build

Libs relies upon `cmake` build system.  

### Bundled deps

Easiest way to build the project is to use BUNDLED_DEPS option, ie:
```
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=true ../
make sinsp
```
> **NOTE:** take a break as this will take quite a bit of time (around 15 mins, dependent on the hardware obviously).

### Use system deps

To install using the system deps, first make sure to have all the needed packages installed.  
Refer to https://falco.org/docs/getting-started/source/ for the list of dependencies.  

Then, simply issue:
```
cmake ../
make sinsp
```

> **NOTE:** using system libraries is useful to cut compile times down, as this way it will only build libs, and not all deps.  
> On the other hand, system deps version may have an impact, and we cannot guarantee everything goes smoothly while using them.

### Build kmod

To build the kmod driver, you need your kernel headers installed. Again, checkout the Falco documentation for this step.  
Then it will be just a matter of running:
```
make driver
```

### Build eBPF probe

To build the eBPF probe, you need `clang` and `llvm` packages.  
Then, issue:
```
cmake -DBUILD_BPF=true ../
make bpf
```

## Contribute

Any contribution is incredibly helpful and warmly accepted!  
Be it code, documentation, or just ideas, please feel free to share it!  

### Adding syscalls

Implementing new syscalls is surely one of the highest frequency request.  
While it is indeed important for libs to support as many syscalls as possible, most of the time it is not a high priority task.  
But **you** can speed up things by opening a PR for it!  
Luckily enough, a Falco blog post explains the process very thoroughly: https://falco.org/blog/falco-monitoring-new-syscalls/.

