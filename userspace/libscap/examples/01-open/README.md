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
'--simple_consumer': enable the simple consumer mode. (default: disabled)
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
events captured: 39460
seen by driver: 39912
Number of dropped events: 0
Number of dropped events caused by full buffer: 0
Number of dropped events caused by invalid memory access: 0
Number of dropped events caused by an invalid condition in the kernel instrumentation: 0
Number of preemptions: 0
Number of events skipped due to the tid being in a set of suppressed tids: 0
Number of threads currently being suppressed: 0
-----------------------------------------------------
```

To run it with the kernel module, you first have to inject the kernel module into the kernel:

```
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

- Use BPF probe in simple consumer mode, print all events with type `80` and catch at most `898898` events.

```bash
sudo ./libscap/examples/01-open/scap-open --bpf driver/bpf/probe.o --simple_consumer --evt_type 80 --num_events 898898 
```

- Print all supported syscall in simple consumer mode by the kernel module.

```bash
sudo ./libscap/examples/01-open/scap-open --kmod --simple_consumer --print_syscalls 
```
