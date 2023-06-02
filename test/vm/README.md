
# VM - Driver Sanity Test Suites - Kernel Compatibility Tests


![Architectures](https://img.shields.io/badge/ARCHS-x86__64-blueviolet?style=for-the-badge)

Status: **Under development, experimental**


## Running `vm` VM based tests on `localhost`

### System Requirements (Host OS)

Highly recommended to follow installation instructions in the official docs as well as run official smoke-tests for each dependency. See [Support Matrix](#support-matrix) for supported host and guest OS / VM specs.

- [Docker](https://www.docker.com/products/docker-desktop/) >= 20.10.9
	- Configure docker to run as non-root
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads) VM provider, latest version
- [Vagrant](https://www.vagrantup.com/), latest version
	- [vagrant virtualbox](https://www.vagrantup.com/docs/providers/virtualbox)
	- `vagrant plugin install vagrant-vbguest`
- [Go](https://go.dev/) >= 1.15

### CMake Targets

These test suites integrate with the broader project's CMake setup. However, in a way they are completely separate. For example, the primary vm build output folder resides in the libs src directory under `libs/test/vm/build` in order to take advantage of caching even if the `libs/build` folder is re-created. In addition, all `scap-open` and `kmod` or `bpf` driver builds are done from scratch in containers - not using the `libs/build` dir.

More information around each step is provided in later sections of this document.

```bash
# cmake
git clone https://github.com/falcosecurity/libs.git;
cd libs;
mkdir -p build;
cd build;
cmake -DCREATE_TEST_TARGETS=ON -DENABLE_VM_TESTS=ON ../;
```

Create containers, download kernel and header packages, extract kernel headers, build vagrant VMs.

```bash
# Target vm-init first run can take up to 25 min
# Re-running only re-builds VMs - can take up to 6 min
# Use target vm-cleanup when wanting to start from scratch or delete libs/test/vm/build/ manually
make vm-init;

# Alternatively run each step separately
make vm-container; # about 5 min
make vm-kernel; # about 14 min
make vm-init;
```

Build scap-open and each driver artifact for array of compiler versions.

```bash
# takes about 2 min
make vm-compile;
```

Vagrant VM loop boots into each downloaded kernel within `libs/test/vm/build/kernels/` folder and runs `scap-open` for `kmod` and `bpf` if the driver was successfully compiled for the respective compiler version. As a last step a results table (.png) is generated -> blue means driver works. Re-running the loops can increase confidence in results and reduce test flakiness issues (each re-run keeps old passed tests in the `driver_ok` dir). Re-running tests randomizes the order of kernels to be tested in order to be more resilient against failures.

```bash
# centos7: should be under 7 min, but can take longer depending on number of tests
make vm-centos7;

# ubuntu: can take 10-20 min or longer depending on number of tests
make vm-ubuntu;
# make vm-init; # would destroy and re-create VMs

# Results table preserved in the test build folder, will be generated or updated at the end of each test above (centos7 or ubuntu) -> option to re-create results output manually
# Some historical results tables are preserved in https://github.com/falcosecurity/libs/issues/982
make vm-result;
ls -l libs/test/vm/build/driver_compat_matrix_compiled.png;
ls -l libs/test/vm/build/driver_compat_matrix_success.png;
```

Cleanup. Destroy all VMs, untag containers, delete entire `libs/test/vm/build` folder that caches all kernel packages and build artifacts.

```bash
make vm-cleanup;
```

### How To Customize Tests?

There are a few ways to customize the `vm` test grid:

- The kernel grid is statically defined in [kernels.txt](kernels.txt). However, subsequently everything is auto-discovered based on downloaded kernel packages. This means changing the URLs in [kernels.txt](kernels.txt) allows you to customize the entire test suite.
- In addition, kernel packages are downloaded into `libs/test/vm/build/kernels/` or `libs/test/vm/build/headers/` -> can purge packages to constraint VM loop as vagrant loop script runs `ls` on these folders ...
- Want different or more compiler versions? Currently supported versions are `gcc-7`, `gcc-8`, `gcc-9`, `gcc-10`, `gcc-11`, `gcc-12`, `gcc-13` (for kmod) and `clang-7`, `clang-8`, `clang-9`, `clang-10`, `clang-11`, `clang-12`, `clang-13`, `clang-14`, `clang-15`, `clang-16` (for bpf) -> update input args to Go script within `vm_compile.sh` script. Note however that older clang versions and their builder container are not compatible with newer kernels.
- Recommended to run target `vm-cleanup` or performing parts of the cleanups manually when changing a lot of setups.
- More options and robustness may be added in the future. At the moment changing scripts slightly can result in breaking tests.


## Support Matrix

Current virtualization framework of choice is [VirtualBox](https://www.virtualbox.org/wiki/) + [vagrant virtualbox](https://www.vagrantup.com/docs/providers/virtualbox) which at the time of writing does not support emulation. Possible alternative framework [libvirt](https://libvirt.org/) + [vagrant libvirt](https://github.com/vagrant-libvirt/vagrant-libvirt) appears less stable at the moment. In the future, emulation support is planned, likely native [qemu](https://www.qemu.org/) VMs. Options that require a license e.g. `parallels` or `vmware` are not considered at the moment.


|     Host OS Spec            |     Guest OS / VM Spec   |   Emulated Guest OS / VM Spec   |
|-----------------------------|--------------------------|---------------------------------|
|   ✔  Linux (x86_64)         |     ✔  Linux (x86_64)    |   ❌ Linux (arm64)              |
|   ✔  macOS (x86_64)         |     ✔  Linux (x86_64)    |   ❌ Linux (arm64)              |
|   ❌ Windows (x86_64)       |     ❌ Linux (x86_64)    |   ❌ Linux (arm64)              |
|   ❌ Linux (arm64)          |     ❌ Linux (arm64)     |   ❌ Linux (x86_64)             |
|   ❌ macOS (Apple Silicon)  |     ❌ Linux (arm64)     |   ❌ Linux (x86_64)             |


Driver Sanity Test Suites tested on:

- Linux fedora36 - Intel x86_64  
- Linux ubuntu 22.04 - Intel x86_64  
- macOS (latest) - Intel x86_64
- Note: For macOS on Apple Silicon, Falco published a [blog post](https://falco.org/blog/falco-apple-silicon/), this test framework however does not yet support Apple Silicon.


## Motivation

Because of the increasing complexity of libs and general nature of kernel development there is a need for ad-hoc grid-search like compatibility tests between distro / kernel versions and compiler versions, such as clang/llvm (eBPF) or gcc (kmod) versions. This project serves as sanity check when introducing major driver changes or when new kernels are published. This [issue](https://github.com/falcosecurity/falco/issues/1761) is a great example highlighting several challenges. Sanity checks will remain useful when CORE becomes available in modern_bpf and are a good practice for general regression testing.

The kernel grid is statically defined in [kernels.txt](kernels.txt). Subsequently, eBPF and kernel module drivers are built for all relevant compiler versions for each kernel.

Headless vagrant VMs on localhost are re-booted into each kernel and drivers for each compiler version are test run using the [scap-open](https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open) utility binary. Results are served as table depicting boolean values. A successful test run means that the driver works with this particular compiler version (e.g. in the eBPF case it means the eBPF probe loaded, passed the eBPF verifier and serves events up to userspace).

Finally, this project also serves as guide for new developers joining the project who may be less familiar with kernel development.


## Goals

*End User's and Developers Perspective*

- Knowing which compiler version may generally work for which kernel version based on distros and kernels included in the vm project.
- Disentangle cmake and GLIBC versions dependencies as well.
- Useful scripts for building drivers for custom kernels that are not supported in [driverkit](https://github.com/falcosecurity/driverkit).
- Self-serve project everyone can use and modify on localhost.
- Entire `scap-open` terminal output is printed to the terminal during the VM test loops -> developer can manually scroll through the entire history and inspect issues such as eBPF verifier issues.

*Tool Maintainer's Perspective*

- Run sanity checks to spot possible regressions and issues early on beyond currently supported CI checks for significant kernel driver changes or new kernels.
- Have a resource that can be shared with end users who run into issues when building drivers from source.
- Scripted VMs and setup to collectively debug, disentangling differences in developer's machine settings.

*Non-goals*

- Not intended for [driverkit](https://github.com/falcosecurity/driverkit) integration.
- As is not intended for CI.
- Kernel grid in this project does not reflect officially supported driver builds or kernel versions.

*Don'ts*

- Do not try to install more than 9-10 kernels at a time in a VM.
- If one compiled driver artifact didn't work for one kernel no need to over interpret results. Alarming are only larger consistent gaps in the results table.


## More Detailed Explanations of Steps


### Step 1 - Build Containers

> Target `vm-container`. Done as part of `vm-init` target.

Builds all containers. For building userspace binary we pull the officially supported falco-builder container, else we build custom ubuntu containers. The following compiler versions are supported:

- `gcc-7`, `gcc-8`, `gcc-9`, `gcc-10`, `gcc-11`, `gcc-12`, `gcc-13`
- `clang-7`, `clang-8`, `clang-9`, `clang-10`, `clang-11`, `clang-12`, `clang-13`, `clang-14`, `clang-15`


### Step 2 - Download Kernel Sources

> Target `vm-kernel`. Done as part of `vm-init` target.

All relevant `.deb` or `.rpm` packages are downloaded into the following folders.

```bash
libs/test/vm/build/kernels/ # actual kernels and other packages needed for VM re-boots
libs/test/vm/build/headers/ # kernel headers needed to build drivers (not needed for modern_bpf)
```


### Step 3 - Extract Kernel Headers

> Target `vm-kernel`. Done as part of `vm-init` target.

Extract kernel headers for each kernel into a new sub directory. Extracted kernel headers are only needed for bpf and kmod. They won't be needed for modern_bpf.

```bash
libs/test/vm/build/headers_extracted/ # extracted kernel headers (not needed for modern_bpf)
```

For example extracted kernel headers look like the directory structure below and `5.15.59-051559-generic` and `5.19.0-1.el7.elrepo.x86_64` would be `uname -r`.

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

### Step 4 - Init localhost VBox + vagrant VMs

> Done as part of `vm-init` target.

Init VMs while pre-installing all kernels. `ubuntu` and `centos7` are are a good choice to perform representative enough kernel compatibility grid-search tests.


### Step 5 - Build `scap-open` and `driver` Artifacts (Big Loop)

> Done as part of `vm-compile` target.

Package up current libs source code (`libs/test/vm/build/libs-src.tar.gz` file). `libs-src.tar.gz` is passed into containers to build the scap-open binary and each driver.

Drivers are built over a Go launcher scripts that simultaneously launches multiple build containers for concurrent driver builds in order to build the compiler and kernel versions grid in under 2 min.

Note that `.o` are eBPF object files and `.ko` are the compiled kernel modules. eBPF uses clang/llvm as compiler while the kernel module uses gcc as compiler.

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



### Step 6 - Test Run all Drivers (Big Loop)

> Done as part of `vm-centos7` or `vm-ubuntu` targets.

Loop over kernels in both `centos7` and `ubuntu` VMs. Re-booting into each kernel while performing strict kernel change verification checks.


```bash
...

Next up kernel 5.10.16-1.el7.elrepo.x86_64

...

Current kernel 5.4.215-1.el7.elrepo.x86_64 -> 5.10.16-1.el7.elrepo.x86_64

...

Succesfully configured next kernel 5.10.16-1.el7.elrepo.x86_64 in grub

Connection to 127.0.0.1 closed by remote host.



Sleeping for 45 seconds ...

Kernel updated correctly to 5.10.16-1.el7.elrepo.x86_64, proceed with scap-open unit tests


```


Upon successful kernel change we loop over each driver and compiler version to test run the `scap-open` binary and perform verifications. Success implies that the driver loaded and served events up to userspace. For kmod we do not unload the kernel module after the unit test and rather force reboot the VM to be resilient against possible buggy kernel modules.


```bash
...

Test run for compiler/kernel clang-12/5.10.16-1.el7.elrepo.x86_64

[SCAP-OPEN]: Hello!

---------------------- SCAP SOURCE ----------------------
* BPF probe: '/home/vagrant/driver/clang-12/5.10.16-1.el7.elrepo.x86_64.o'
-----------------------------------------------------------

...

Events correctly captured (SCAP_SUCCESS): 595
Seen by driver: 15523
Time elapsed: 2 s
Number of events/per-second: 297
Number of dropped events: 0

...

```


### Step 7 - Generate Final Results Table

> target `vm-results`. Done as part of `vm-centos7` or `vm-ubuntu` targets as well.

For easy results inspection, results are served as table depicting boolean values. Color blue means that the driver works with this particular compiler version (e.g. in the eBPF case it means the eBPF probe loaded, passed the eBPF verifier and serves events up to userspace - all ok). Note that besides compiler version, GLIBC version in build container can influence results as well. Results are preserved in both build folders.

Some historical results tables are preserved in https://github.com/falcosecurity/libs/issues/982.

```bash
ls -l libs/test/vm/build/driver_compat_matrix_compiled.png;
ls -l libs/test/vm/build/driver_compat_matrix_success.png;
```

## Maintenance Overhead Projection

- Occasionally update [kernels.txt](kernels.txt) kernel test grid.
- Add new containers to support newest clang/llvm or gcc compilers for building drivers.
- Update project if either scap-open or driver build setup changes.
- Add additional tips as issues or problems with building or running Falco drivers come up (re-use this project as troubleshooting guide for both devs and end users).
