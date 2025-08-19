# TOCTOU mitigation programs

eBPF programs in this folder generates enter events providing support to exit events data for TOCTOU mitigation.

For each system call `<syscall>`, 3 eBPF programs are defined. These programs perform:

- syscall events sampling/filtering
- information gathering
- enter event generation
- enter event submission to userspace

The three programs have the following naming schema and purpose:

- `<syscall>_e` - tracepoint program attached to `syscalls/sys_enter_<syscall>`; provide support for 64-bit system calls
- `ia32_compat_<syscall>_e`/`ia32_<syscall>_e` - mutually exclusive kprobe programs attached to the
  `__ia32_compat_sys_<syscall>` and `__ia32_sys_<syscall>`, respectively. They provide support for ia-32 emulated system
  calls. Just one of the two programs is attached, based on the availability of the corresponding symbol. The compat
  version attachment attempt takes precedence with respect to the other one.

## FAQ

### Why don't use just a single tracepoint program per system call?

Tracepoint programs are not triggered upon ia-32 emulated system calls.

### Why don't use eBPF fentry programs for ia-32 emulated system calls?

`fentry` support is buggy on some kernel versions for which the modern probe is required to provide support.
Specifically, some kernel versions don't correctly export the `pt_regs` struct BTF type information, making impossible
for the verifier to do correct analysis of the accesses to `struct pt_regs *`. As a result of the latter statement, the
verifier would not allow to do anything useful with those programs.
See [this](https://stackoverflow.com/questions/72824924/invalid-bpf-context-access-when-trying-to-read-regs-parameter)
for more details.

### What about kprobe eBPF programs performance penalty?

This is not a real issue, as this penalty is only introduced for ia-32 emulated system calls, which we don't expect can
generate any relevant overhead on the system, due to their limited (or absent) usage on common systems.
