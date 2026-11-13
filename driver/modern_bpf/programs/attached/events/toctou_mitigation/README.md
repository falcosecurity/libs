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

### Why does libpman open perf events on the tracepoints of the 64-bit programs?

Some kernels run a BPF program on a syscall tracepoint that reads user memory, such as the paths of the `open` family,
only if a perf event of the tracepoint is active on the current CPU. These kernels carry commit 2c2b322acdcc ("tracing:
perf: Fix stale head for perf syscall tracing") without commit 57918341dd19, which runs the BPF programs first. Stable
7.1.y (since 7.1.6) and Ubuntu 7.0 kernels are examples. libbpf attaches a tracepoint program through one perf event on
CPU 0, so on these kernels the `<syscall>_e` programs run only for system calls on CPU 0.

Right after it loads the probe, libpman finds out whether the kernel has the bug. It attaches the `syscall_tp_check`
program to `syscalls/sys_enter_faccessat` and makes one `faccessat` call on each CPU that it can use. The calls pass a
`mode` that the kernel rejects with EINVAL, and the program counts only the calls with that `mode`. If the program
counts fewer calls than libpman made, the kernel has the bug. If libpman can use only one CPU, the check cannot tell
whether that CPU is the one with the perf event of libbpf, and libpman assumes that the kernel has the bug.

On a kernel with the bug, libpman opens one counting perf event of each tracepoint on each CPU, right before it attaches
the program, and closes the events when it detaches the program. Nothing reads the events. The programs return 0, so the
kernel does not record anything for the events. The events take one file descriptor per tracepoint and CPU. If libpman
cannot open an event, the attachment of the program fails. A CPU that comes online after the attachment has no event.
The `connect` tracepoint reads no user memory, so it gets no events.

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
