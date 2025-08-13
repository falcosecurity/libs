# TOCTOU mitigation programs

eBPF programs in this folder generates enter events providing support to exit events data for TOCTOU mitigation.

For each system call `<syscall>`, two eBPF programs are defined. These programs perform:

- syscall events sampling/filtering
- information gathering
- enter event generation
- enter submission to userspace

The two program classes have the following naming schema and purpose:

- `<syscall>_e` - attached to `tracepoint/syscalls/sys_enter_<syscall>` tracepoint hook; provide support for 64 bit
  system calls
- `ia32_<syscall>_e` - attached to `fentry/__ia32_sys_<syscall>` fentry hook; provide support for ia32 emulated system
  calls