# Home of Falco drivers kernel testing matrixes

Basically, we use Ansible playbooks to spawn Firecracker microvms where we can test:  

* kmod and ebpf drivers build
* scap-open run with {kmod,ebpf,modern-bpf}

The modern-bpf driver-enabled scap-open is built using the exactly same process used by [Falco release pipeline](https://github.com/falcosecurity/falco/blob/master/.github/workflows/reusable_build_packages.yaml#L15):   

* the modern bpf skeleton is built on a Fedora machine
* scap-open with embedded modern-bpf skeleton is built on a centos7 machine to allow largest possible support (old glibc version)
* scap-open binary is copied to each spawned vm

## Supported Archs

For now, supported architectures are:  

* AMD64
* ARM64

## Glossary

* 🟢 -> means that the test was successful
* 🟡 -> means that the test was skipped; you can click the symbol to reach the test section and checkout why the test was skipped.
* ❌ -> means that the test failed; you can click the symbol to reach the test section and checkout why the test failed.
