
# VM - Driver Functionality Test Suites - Kernel Compatibility Tests


![Architectures](https://img.shields.io/badge/ARCHS-x86__64-blueviolet?style=for-the-badge)

Status: **Under development, experimental**


We have developed this framework with the sole intention of providing a convenient and efficient solution for `localhost` testing. It serves a unique purpose that is distinct from our official CI tests or the CI-powered kernel driver artifact build mechanisms. The choice of technology was based on the need for a widely adopted framework that can function effectively on different developer machines. Our aim is to cater to developers who desire to test with various compiler versions across a reasonable kernel grid without having to dedicate excessive hours to testing. Additionally, we understand their preference to conveniently conduct these tests on the same development box. As a result, these considerations have guided the setup of our `localhost` testing infrastructure. If you are considering adopting a CI-powered testing approach, we would like to encourage you to explore the projects' setup designed specifically for that purpose.   

Running these tests is a time-consuming process, typically taking at least one hour from scratch. We kindly request your patience during the execution of these tests.


## Running VM-based Driver Functionality Tests on `localhost`

### System Requirements (Host OS)

It is strongly advised to follow the installation instructions in the official documentation and to run official smoke-tests for every dependency. See [Support Matrix](#support-matrix) for supported host and guest OS / VM specifications.

> If this is your first time using VirtualBox on your machine, you may encounter some minor challenges during the installation process. We recommend following troubleshooting guides or tutorials available on the internet. Additionally, we provide a target called `vm-dependency-check` to assist in confirming the installation and checking other dependencies.

- [Docker](https://www.docker.com/products/docker-desktop/) >= 20.10.9
	- Configure docker to run as non-root user
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) VM provider, latest version
- [Vagrant](https://www.vagrantup.com/), latest version
	- [vagrant virtualbox](https://www.vagrantup.com/docs/providers/virtualbox)
	- `vagrant plugin install vagrant-vbguest`
- [Go](https://go.dev/) >= 1.15
- Ensure that necessary binaries are available on your host machine, such as, `bash`, `time`, `ssh`, `scp`, `tar`.

### CMake Targets

The test suites are integrated with the project's CMake setup but function independently. While you still execute all the cmake and make commands from the usual `libs/build` folder, the primary VM build output is stored in the `libs/test/vm/build` directory to cache results, even if the `libs/build` folder is regenerated. The builds for scap-open and the kernel drivers are performed from scratch in containers, not using the `libs/build` directory. Further information about each step is available in later sections of this document.

As a rule of thumb, test flakiness mostly arises due to failed kernel module (kmod) tests. These tests are best run on a powerful Linux box.


```bash
mkdir -p build; # this is the usual libs/build folder under the libs repo root
cd build;
cmake -DCREATE_TEST_TARGETS=ON -DENABLE_VM_TESTS=ON ../;
```

Create containers, download kernel and header packages, extract kernel headers, and build vagrant VMs.

```bash
# Check dependencies
make vm-dependency-check;

# The initial run of the target vm-init takes longer as we
# create containers and download and extract kernel headers.
# Re-running only re-builds VMs and is faster.
make vm-init;

# Alternatively run each step separately
make vm-container;
make vm-kernel; # If the kernel mirror is unavailable, the URLs need to be changed.
make vm-init;
```

By utilizing compatible containers, build scap-open and each driver artifact for an array of compiler versions. For this step, we also generate a results table that allows us to inspect which compiler version successfully compiled the driver for a given kernel version. We have included kernels 2.6.32 and 3.10 in order to check if they build successfully. However, no VM tests are launched for those kernels.

```bash
# Should not take too long.
make vm-compile;
ls -l libs/test/vm/build/driver_compat_matrix_compiled.md;
```

In a Vagrant VM loop, each downloaded kernel within the `libs/test/vm/build/kernels/` folder is booted, and scap-open is executed for the drivers if they were compiled successfully. Final results tables in the form of markdown documents are generated, where blue indicates that the driver compiled and green indicates functional drivers (successfully compiled and executed). Some historical result tables are preserved [here](https://github.com/falcosecurity/libs/issues/982).

```bash
# make vm-init; # recommended, destroys and re-creates VMs

# Tests take a long time, please be patient as it also depends on your machine.
make vm-centos7;

# Tests take a long time, please be patient as it also depends on your machine.
make vm-ubuntu;

# Explore libs/test/vm/CMakeLists.txt for new distro targets
# (e.g. `make vm-amazonlinux2` as example for an experimental distro) ...

make vm-result;
ls -l libs/test/vm/build/driver_compat_matrix_compiled.md;
ls -l libs/test/vm/build/driver_compat_matrix_success.md;
```

Cleanup. Destroy VMs, untag containers, delete `libs/test/vm/build` folder that cached kernel packages and build artifacts.

```bash
make vm-cleanup;
```

### How To Customize Tests?

You have several options for customizing the VM test grid:

- Modify the kernel grid by changing the URLs in the [kernels.jsonl](kernels.jsonl) file. This allows you to customize the entire test suite. When it comes to Amazon Linux distros, you can refer to [this link](https://github.com/falcosecurity/kernel-crawler/issues/145) to learn how to retrieve the `kernel` and `kernel-devel` RPMs. When downloading new RPMs, it is necessary to delete/remove the existing folders (`libs/test/vm/build/kernels/`, `libs/test/vm/build/headers/`, `libs/test/vm/build/headers_extracted/`) first.
- To limit the VM loop, you can remove kernel packages from the `libs/test/vm/build/kernels/` and `libs/test/vm/build/headers/` as well as `libs/test/vm/build/headers_extracted/` directories. The compile and test loop scripts perform an `ls` operation on these folders.
- If you want different or additional compiler versions, adjust the input arguments to the Go script within the `libs/test/vm/scripts/vm_compile.sh` script.

> Note: Older compiler versions and their builder containers may not be compatible with newer kernels. Similarly, newer compiler versions may not be compatible with older kernels. Currently supported versions are `gcc-5`,`gcc-7`, `gcc-8`, `gcc-9`, `gcc-10`, `gcc-11`, `gcc-12`, `gcc-13` (for kernel module) and `clang-7`, `clang-8`, `clang-9`, `clang-10`, `clang-11`, `clang-12`, `clang-13`, `clang-14`, `clang-15`, `clang-16` (for BPF drivers, modern BPF compiler version support starts with `clang-12`). The GLIBC version of the builder container can also affect the process of building driver artifacts for kernels.

## Support Matrix

The current virtualization framework of choice for the project is [VirtualBox](https://www.virtualbox.org/wiki/) along with [vagrant virtualbox](https://www.vagrantup.com/docs/providers/virtualbox). Note that VirtualBox does not support emulation. An alternative framework that can be used is [libvirt](https://libvirt.org/) along with [vagrant libvirt](https://github.com/vagrant-libvirt/vagrant-libvirt), but it is currently considered less stable. Emulation support is planned for the future, likely using native QEMU VMs. Lastly, options that require a license, such as Parallels or VMware, are not being considered at this time.


|     Host OS Spec            |     Guest OS / VM Spec   |   Emulated Guest OS / VM Spec   |
|-----------------------------|--------------------------|---------------------------------|
|   ✔  Linux (x86_64)         |     ✔  Linux (x86_64)    |   ❌ Linux (aarch64)              |
|   ✔  macOS (x86_64)         |     ✔  Linux (x86_64)    |   ❌ Linux (aarch64)              |
|   ❌ Windows (x86_64)       |     ❌ Linux (x86_64)    |   ❌ Linux (aarch64)              |
|   ❌ Linux (aarch64)          |     ❌ Linux (aarch64)     |   ❌ Linux (x86_64)             |
|   ❌ macOS (Apple silicon)  |     ❌ Linux (aarch64)     |   ❌ Linux (x86_64)             |


This test suite is a best effort and has been tested on:

- ArchLinux (x86_64)
- Linux fedora36 (x86_64)
- Linux ubuntu (x86_64)
- macOS (latest) - Intel x86_64
- Note: This test framework currently does not support Apple silicon, but Falco has published a [blog post](https://falco.org/blog/falco-apple-silicon/) specifically addressing the usage of Falco in a Linux VM on macOS with Apple Silicon made possible by Falco's aarch64 support.


## Motivation

Because of the increasing complexity of libs, drivers, and the nature of kernel development, ad-hoc grid-search compatibility tests are necessary between distro / kernel versions and compiler versions. This project provides a local sanity check option when implementing significant driver changes or when new kernels are released.

The kernel grid is pre-defined in [kernels.jsonl](kernels.jsonl). Subsequently, the drivers are built for every relevant compiler versions for each kernel.

Headless Vagrant VMs running on localhost are rebooted into each kernel, and drivers for each compiler version are tested using the [scap-open](https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open) utility binary. Results are served as table depicting boolean values. A successful test run indicates that the driver functions correctly with the designated kernel and compiler version. For example, in the case of eBPF, a successful test run means that the eBPF probe has loaded, passed the eBPF verifier, and is successfully delivering events to the userspace.

Finally, this project serves as a valuable guide for new developers joining the project, particularly those who may have limited experience or familiarity with kernel development.


## Goals

*End User's and Developers Perspective*

- Guidance on compiler versions suitable for specific kernel versions, and to separate dependencies on GLIBC versions.
- Helpful scripts for building drivers.
- Designed to be self-serve, allowing users to modify and utilize it on their localhost..
- During VM test loops, the entire output of scap-open is displayed, enabling developers to manually inspect issues like eBPF verifier problems.

*Tool Maintainer's Perspective*

- Run pre-push sanity checks to identify possible regressions and issues early on during the development of new features. Checks act as a valuable complement to the existing CI checks.
- The project serves as a valuable resource for end users encountering problems while building drivers from source, providing guidance and assistance.
- The scripted VMs and setup aid in collaborative debugging efforts, helping to isolate differences in developer machine configurations and settings.

*Non-goals*

- Not intended for [driverkit](https://github.com/falcosecurity/driverkit) integration.
- As is not intended for CI.
- Kernel grid does not match official driver builds or kernel versions. It serves as a separate testing environment for compatibility checks.


## More Detailed Explanations of Steps


### Step 1 - Build Containers

> Target `vm-container`. Done as part of `vm-init` target.

To build the userspace binary, the officially supported falco-builder container is pulled. Otherwise, custom containers are built to cater to the specific requirements of the test suites.


### Step 2 - Download Kernel Sources

> Target `vm-kernel`. Done as part of `vm-init` target.

All relevant `.deb` or `.rpm` packages are downloaded and stored in the following folders:

```bash
libs/test/vm/build/kernels/ # actual kernels and other packages needed for VM re-boots
libs/test/vm/build/headers/ # kernel headers needed to build drivers (not applicable for modern_bpf)
```

 If you encounter a situation where kernel mirrors become unavailable, you can adjust the URLs in the `kernels.jsonl` file to point to alternative mirror locations.

### Step 3 - Extract Kernel Headers

> Target `vm-kernel`. Done as part of `vm-init` target.

Extract the kernel headers for each kernel into a new subdirectory. These extracted kernel headers are only required for `bpf` and `kmod`. They are not necessary for `modern_bpf`.

```bash
libs/test/vm/build/headers_extracted/ # extracted kernel headers (not applicable for modern_bpf)
```

For example, the extracted kernel headers directory structure may look like the following:

```bash
├── 5.15.59-051559-generic
│   ├── control.tar.zst
│   ├── data.tar.zst
│   ├── debian-binary
│   └── usr
...
│       └── src
│           └── linux-headers-5.15.59-051559
...
└── kernel-ml-devel-5.19.0-1.el7.elrepo.x86_64
    └── usr
        └── src
            └── kernels
                └── 5.19.0-1.el7.elrepo.x86_64

```

In this structure, the directory names such as `5.15.59-051559-generic` and `5.19.0-1.el7.elrepo.x86_64` correspond to the output of the `uname -r` command, which represents the kernel release. Inside each kernel version directory, you will find the relevant kernel headers and include files needed for building drivers or other components that interface with the kernel.

### Step 4 - Initialize localhost VirtualBox VMs

> Target `vm-init`.

Initialize VirtualBox VMs while pre-installing all kernels, using the Vagrant framework. `ubuntu` and `centos7` are good choices for performing representative kernel compatibility grid-search tests.


### Step 5 - Build scap-open and Driver Artifacts (Big Loop)

> Target `vm-compile`.

Package the current libs source code into the `libs-src.tar.gz` file located at `libs/test/vm/build`. This file is then passed into the containers to build the scap-open binary and each driver.

The drivers are built using a Go launcher script, that allows for simultaneous launching of multiple build containers. This concurrent approach enables the building of the compiler and kernel versions grid in minutes.

Note that the `.o` files represent eBPF object files, while the `.ko` files represent the compiled kernel modules. The eBPF driver uses clang/llvm as the compiler, while the kernel module driver uses gcc.

For this step, we also generate a results table that allows us to inspect which compiler version successfully compiled the driver for a given kernel version. We have included kernels 2.6.32 and 3.10 in order to check if they build successfully. However, no VM tests are launched for those kernels.

```bash
ls -l libs/test/vm/build/driver_compat_matrix_compiled.md;
```

Example resulting driver artifacts:

```bash
libs/test/vm/build/driver/

├── clang-12
│   ├── 4.16.18-041618-generic.o
│   ├── 4.19.262-0419262-generic.o
│   ├── 5.10.16-1.el7.elrepo.x86_64.o
│   ├── 5.14.15-1.el7.elrepo.x86_64.o
│   ├── 5.19.17-051917-generic.o
│   ├── 5.4.215-1.el7.elrepo.x86_64.o
│   ├── 5.9.16-050916-generic.o
│   └── 6.0.0-1.el7.elrepo.x86_64.o
...
├── gcc-8
│   ├── 4.16.18-041618-generic.ko
│   ├── 4.19.262-0419262-generic.ko
│   ├── 5.10.16-1.el7.elrepo.x86_64.ko
│   ├── 5.14.15-1.el7.elrepo.x86_64.ko
│   ├── 5.19.17-051917-generic.ko
│   ├── 5.4.215-1.el7.elrepo.x86_64.ko
│   ├── 5.9.16-050916-generic.ko
│   └── 6.0.0-1.el7.elrepo.x86_64.ko
...
```



### Step 6 - Test Run (Big Loop)

> Targets  `vm-centos7` or `vm-ubuntu` or ... (new future distros)

Iterate through the kernels in the VMs. Each kernel is sequentially booted, and strict kernel change verification checks are performed during the process. Explore `libs/test/vm/CMakeLists.txt` for evolving distro targets (e.g. `vm-amazonlinux2` is still in experimental phase) ...

```bash
...

[STATUS] START 5.14.15-1.el7.elrepo.x86_64

...

[STATUS] IN PROGRESS 6.1.12-1.el7.elrepo.x86_64 -> 5.14.15-1.el7.elrepo.x86_64

...

[STATUS] DONE 5.14.15-1.el7.elrepo.x86_64 grub configuration

Connection to 127.0.0.1 closed by remote host.

...

[STATUS] SUCCESS 5.14.15-1.el7.elrepo.x86_64 kernel change, proceed with unit tests

...

[STATUS] DONE 5.14.15-1.el7.elrepo.x86_64

```


After successfully changing the kernel, we proceed to iterate over each driver and compiler version to execute the scap-open binary and conduct verifications over SSH remote commands. A successful outcome indicates that the driver successfully loaded and delivered events to the userspace.

For the kmod driver, instead of unloading the kernel module after the unit test, we opt to force a reboot of the VM. This approach ensures resilience against any potential issues with buggy kernel modules.


```bash
...

[STATUS] SUCCESS clang-14/5.14.15-1.el7.elrepo.x86_64.o, proceed with next test


[STATUS] START TEST RUN clang-16/5.14.15-1.el7.elrepo.x86_64


[SCAP-OPEN]: Hello!

--------------------------- SCAP SOURCE --------------------------
* BPF probe: '/home/vagrant/driver/clang-16/5.14.15-1.el7.elrepo.x86_64.o'
------------------------------------------------------------------


...

[SCAP-OPEN]: General statistics

Events correctly captured (SCAP_SUCCESS): 1015
Seen by driver (kernel side events): 3483
Time elapsed: 4 s
Rate of userspace events (events/second): 253
Rate of kernel side events (events/second): 870
Number of timeouts: 164
Number of 'next' calls: 1179

[SCAP-OPEN]: Stats v2.


...

```


### Step 7 - Generate Final Result Table

> Target `vm-result`. Done as part of `vm-compile`, `vm-centos7` or `vm-ubuntu` targets.

The results are displayed in a table format, using boolean values to indicate the outcome. This allows for easy inspection and understanding of the results. The initial table indicates whether the drivers compiled, denoted by the blue color. In the subsequent table, the color green signifies that the driver is functioning correctly with the specific compiler version. For instance, in the case of eBPF, it signifies that the eBPF probe successfully loaded, passed the eBPF verifier, and is delivering events to userspace without any issues. Apart from the compiler version, the GLIBC version in the build container can also impact the results. 

Historical results tables are preserved [here](https://github.com/falcosecurity/libs/issues/982).

```bash
ls -l libs/test/vm/build/driver_compat_matrix_compiled.md;
ls -l libs/test/vm/build/driver_compat_matrix_success.md;
```

## Maintenance Overhead Projection

- Periodically update the [kernels.jsonl](kernels.jsonl) kernel test grid as needed to include new kernels or remove outdated ones.
- Introduce new containers to support the latest versions of clang/llvm or gcc compilers for building drivers.
- Keep the project updated in case there are changes to the scap-open utility or the driver build setup.
- Continuously add additional tips and troubleshooting information as new issues or problems arise. 
