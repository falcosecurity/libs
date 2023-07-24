# Falcosecurity drivers

## Home of Falco drivers kernel testing matrixes

Here you can find kernel testing support matrixes for [Falco](https://falco.org/) drivers.  
For more info, make sure to read the [driver kernel testing framework proposal](https://github.com/falcosecurity/libs/blob/master/proposals/20230530-driver-kernel-testing-framework.md).  

Basically, we use Ansible playbooks to spawn Firecracker microvms where we can test:  

* kmod and ebpf drivers build
* scap-open run with {kmod,ebpf,modern-bpf}

The modern-bpf driver-enabled scap-open is built using the exactly same process used by [Falco release pipeline](https://github.com/falcosecurity/falco/blob/master/.github/workflows/reusable_build_packages.yaml#L15):   

* the modern bpf skeleton is built on a Fedora machine
* scap-open with embedded modern-bpf skeleton is built on a centos7 machine to allow largest possible support (old glibc version)
* scap-open binary is copied to each spawned vm

### Supported Archs

For now, supported architectures are:  

* AMD64
* ARM64

### Glossary

* 🟢 -> means that the test was successful
* 🟡 -> means that the test was skipped; you can click the symbol to reach the test section and checkout why the test was skipped.
* ❌ -> means that the test failed; you can click the symbol to reach the test section and checkout why the test failed.

## Syscalls Report

You can also find the list of supported syscalls by our drivers, be it through specific filler or generic.

### Glossary

* 🟢 -> means that the syscall is implemented as a specific event
* 🟡 -> means that the syscall is implemented as a generic event
