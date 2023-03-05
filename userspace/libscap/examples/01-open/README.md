# Scap-open 

`scap-open` is a small executable that helps to understand if drivers work correctly.

## CLI options 💻

### Sources

Right now there are 4 `scap` sources:

1. KERNEL_MODULE
2. BPF_PROBE
3. MODERN_BPF_PROBE
4. SCAP_FILE

You can enable them with the following options:

```
'--kmod': enable the kernel module.
'--bpf <probe_path>': enable the BPF probe.
'--modern_bpf': enable modern BPF probe.
'--scap_file <file.scap>': read events from scap file.
```

### Configurations

For each `scap` source you can set additional configurations:

```
'--tp <tp_code>': enable only requested tracepoint. Can be passed multiple times. (dafault: all enabled)
'--ppm_sc <ppm_sc_code>': enable only requested syscall (this is our internal ppm syscall code not the system syscall code). Can be passed multiple times. (dafault: all enabled)
'--num_events <num_events>': number of events to catch before terminating. (default: UINT64_MAX)
'--evt_type <event_type>': every event of this type will be printed to console. (default: -1, no print)
```

### Validation

There are also some options to validate the content of our tables:

```
'--validate_syscalls': validation checks.
```

### Print

Print some information like the supported syscalls or the help menu:

```
'--print_syscalls': print all supported syscalls with different sources and configurations.
'--help': print this menu.
```

## Build 🏗️

From the repository root (`/libs`) type:

```bash
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_GVISOR=OFF -DCREATE_TEST_TARGETS=OFF ..
make scap-open
```

Optional Cmake options:

* `-DBUILD_BPF=ON`: if you want to test the BPF probe.
* `-DBUILD_LIBSCAP_MODERN_BPF=ON`: if you want to test the modern BPF probe.
* `-DMODERN_BPF_DEBUG_MODE=ON`: if you want to test the modern BPF probe in debug mode. (if you use it you need also the previous one `-DBUILD_LIBSCAP_MODERN_BPF=ON`).

You have also to build the driver that you want to use:

* Kernel module

```bash
make driver
```

* BPF probe

```bash
make bpf
```

* Modern BPF probe (if you have already compiled `scap-open` the probe skeleton should be already built)

```bash
make ProbeSkeleton
```

## Run 🏎️

To execute it, you have to pass at least one [source](#Sources). For example in this case we use the `bpf` source.

```bash
sudo ./libscap/examples/01-open/scap-open --bpf driver/bpf/probe.o
```

>__Please note__: to use the BPF probe you have also to pass the path to the `.o` file.


As soon as you quit (`CTRL-C`) the `scap-open` program, you will be prompted with detailed information on the capture:

```
---------------------- STATS -----------------------
Events captured: 20
Seen by driver: 20
Time elapsed: 2 s
Number of events/per-second: 10
Number of dropped events: 0
Number of dropped events caused by full buffer (total / all buffer drops - includes all categories below, likely higher than sum of syscall categories): 0
Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_enter syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_clone_fork_exit syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_execve_enter syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_execve_exit syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_connect_enter syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_connect_exit syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_open_enter syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_open_exit syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_dir_file_enter syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_dir_file_exit syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_other_interest_enter syscall category): 0
Number of dropped events caused by full buffer (n_drops_buffer_other_interest_exit syscall category): 0
Number of dropped events caused by full scratch map: 0
Number of dropped events caused by invalid memory access (page faults): 0
Number of dropped events caused by an invalid condition in the kernel instrumentation (bug): 0
Number of preemptions: 0
Number of events skipped due to the tid being in a set of suppressed tids: 0
Number of threads currently being suppressed: 0
-----------------------------------------------------
```

To run it with the kernel module, you first have to inject the kernel module into the kernel:

```bash
sudo insmod driver/scap.ko
```

Then you can type:

```bash
sudo ./libscap/examples/01-open/scap-open --kmod
```

Remember to remove the kernel module when you have finished:

```bash
sudo rmmod scap
```

To run it with the modern BPF probe, issue:

```bash
sudo ./libscap/examples/01-open/scap-open --modern_bpf
```

### Some examples

You can look at the other available options by using `--help`:

```bash
sudo ./libscap/examples/01-open/scap-open --help
```

Here there are just some examples:

- Read from a `scap-file`:

```bash
sudo ./libscap/examples/01-open/scap-open --scap_file ~/my_scap_file/path
```

- Use BPF probe with only `mkdir` syscall and `sys_enter` tracepoint (on x86_64 architecture)

1. Check the `ppm_code` of `mkdir`, the code is `27` as you can see:

```bash
sudo ./libscap/examples/01-open/scap-open --ppm_sc | grep mkdir
- mkdir                     system_code: (83) ppm_code: (27)
- mkdirat                   system_code: (258) ppm_code: (198)
```

2. Check the code for `sys_enter` tracepoint, the code is `0` as you can see:

```bash
sudo ./libscap/examples/01-open/scap-open --tp | grep sys_enter
- sys_enter                 tp_code: (0)
```

3. Run the command with the obtained configuration:

```bash
sudo ./libscap/examples/01-open/scap-open --bpf driver/bpf/probe.o --ppm_sc 27 --tp 0
```

## Build a docker image for scap-open

### `runner-image` tag

The Dockerfile will use `runner-image` tag to build the final image as you can see here:

```dockerfile
FROM runner-image AS runner
...
```

For example, if I build scap-open locally on a un `ubuntu:22-04` machine I will instruct docker to use `ubuntu:22-04` as a final running image.

```bash
docker tag ubuntu:22.04 runner-image
```

### Build scap-open and drivers

```bash
mkdir build && cd build
cmake -DUSE_BUNDLED_DEPS=On -DBUILD_LIBSCAP_GVISOR=Off -DBUILD_BPF=On -DBUILD_LIBSCAP_MODERN_BPF=On -DCREATE_TEST_TARGETS=Off -DMODERN_BPF_DEBUG_MODE=On ..
make scap-open driver bpf
```

### Build the docker image

From the build directory:

```bash
docker build --tag scap-open-dev -f ./../userspace/libscap/examples/01-open/Dockerfile .
```

### Run it

From the build directory:

```bash
docker run --rm -i -t --privileged \
           -v /dev:/host/dev \
           -v /proc:/host/proc:ro \
           scap-open-dev
```
