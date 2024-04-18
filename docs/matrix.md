# Home of Falco Drivers Kernel Testing

## Test Procedures

We use Ansible playbooks to spawn Firecracker microVMs where we can test:

* kmod and bpf driver builds.
* `scap-open` runs with {kmod,bpf,modern_bpf}.

Going into more detail, we list kmod and bpf builds separately because these drivers need to be compiled specifically for each kernel release. In the actual microVM, we perform these builds using the corresponding system compiler (gcc for kmod and clang for bpf). That way, we ensure the use of the most appropriate compiler version.

In contrast, modern BPF isn't tied to a particular kernel release. This is because of the CO-RE (Compile Once - Run Everywhere) feature of the modern BPF driver. As a result, we only compile the modern BPF skeleton once and then include it into `scap` during the linking process -- exactly how it's done in the official [Falco release pipeline](https://github.com/falcosecurity/falco/blob/master/.github/workflows/reusable_build_packages.yaml#L15). You can find even more details about modern BPF in the libs [README](https://github.com/falcosecurity/libs/tree/master#build).

Here's some information about the steps in this regard:

* modern BPF skeleton is built on a Fedora machine.
* `scap-open` with embedded modern BPF skeleton is built on a centos7 machine to allow broad support (old GLIBC versions).
* `scap-open` binary is copied to each spawned VM.

## Supported Architectures

For now, supported architectures are:

* AMD64
* ARM64

## Glossary

* 🟢 → test was successful.
* 🟡 → test was skipped; you can click the symbol to reach the test section and checkout why the test was skipped.
* ❌ → test failed; you can click the symbol to reach the test section and checkout why the test failed.

Navigate to the AMD64 and ARM64 links on the left to view the up-to-date results of their respective test matrices or click the links below:

* [AMD64](https://falcosecurity.github.io/libs/matrix_X64/) test matrix results
* [ARM64](https://falcosecurity.github.io/libs/matrix_ARM64/) test matrix results
