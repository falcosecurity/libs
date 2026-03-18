# BPF iterator programs

eBPF programs in this folder leverage the BPF iterator infrastructure, provided by the kernel, to enable
***synchronous*** fetching of relevant information.

## Implementation details

### Naming schema

Each program is specialized in fetching a specific type of resource, and its name reflects it. The currently followed
naming schema is
`dump_<resource_type>`.

### Event building and delivering

These programs leverage the same `auxmap` abstraction used by syscall programs for event building. They use a dedicated
global `auxmap` instance, which is enough, assuming that information fetching will never happen simultaneously from more
than 1 program at the time.

Events are sent to userspace via the `seq_file` interface, as opposed to the ring buffer one leveraged by syscall
programs. The `seq_file` interface doesn't provide any API that enable taking advantage of the distinction between
variable size and fixed size events (i.e.: the reserve/submit API), so all events are treated as having a variable size:
this means that only `auxmap__store_*()` helpers are used in this context.

### Metrics

Counters are maintained in a global `iter_counters_map` eBPF map. There are counters for accounting both processed and
dropped events.

## Kernel support

Each program has independent requirements on the set of features exposed by the system kernel: as a result, not all
programs will work on all kernels. For example, some programs require to be loaded as "sleepable" in order to be able to
use some sleepable eBPF helpers.

The following list specifies the minimum kernel version required for each program:

- `dump_task` -> 5.18
- `dump_task_file` -> 5.8
