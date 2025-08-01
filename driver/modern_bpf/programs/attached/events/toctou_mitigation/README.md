# TOCTOU mitigation programs

eBPF programs in this folder generates enter events providing support to exit events data for TOCTOU mitigation.

All programs are attached to specific `tracepoint/syscalls/sys_enter_*` hooks.

For each system call `<syscall>`, two eBPF tracepoint programs are defined:
- `ttm_<syscall>_e` - this program is responsible for tail calling the `<syscall>_e` program after having performed
  syscall ID normalization and applied any required sampling/filtering logic
- `<syscall>_e` - this program is responsible for collecting the information needed to generate the proper enter event
  and sending the generated event to userspace
