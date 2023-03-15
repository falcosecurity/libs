# falcosecurity/libs/test

Home of falcosecurity/libs test suites. Additional more traditional unit tests can be found in the respective module's subfolder of the code base.

- [drivers](drivers/): run unit tests against each driver (kmod, bpf, modern_bpf)
- [driver_sanity](driver_sanity/kernel_compat/): kernel driver (kernel module and eBPF) grid-search scap-open VM based kernel compatibility tests
- [e2e](e2e/): e2e libs sinsp functionality tests
- [modern_bpf](modern_bpf/): modern_bpf unit tests
