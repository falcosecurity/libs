# Disable support for syscall enter events

## Motivation

This document proposes disabling support for syscall enter events in our codebase. The primary reason behind this proposal is to reduce the throughput of events that our userspace needs to process. As the number of syscalls increases, we are no longer able to support them, and we start dropping events. Since enter events do not provide additional information compared to exit events (TOCTOU attacks will be addressed [in this section](#implement-toctou-mitigation)), the idea is to disable them entirely, thereby halving the number of events generated and processed.

In summary, the main benefits of this proposal are:

* Halving the number of events processed in userspace, thus reducing CPU time consumed by our userspace.
* Reducing the overhead that our probes introduce on running system. Depending on the type of instrumented syscalls, this could almost halve the instrumentation time.
* Simplifying and optimizing the event processing in libsinsp. Currently, we save some enter events in memory to reuse them upon exit, which not only degrades performance but also complicates the entire processing flow.
* Reducing ambiguity about where parameters should be defined, in the enter or exit event. Ideally, we want all parameters in the exit event, as it also includes the syscall return value.

Gathering some concrete data userspace side would be really difficult without implementing this solution first. What we can do is to observe some data kernel side, which is why I conducted an ad hoc benchmark.

## Benchmark on kernel instrumentation time

EC2 instance used:

* AMI ID: ami-0ec7f9846da6b0f61
* AMI name: ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20230325
* Instance type: t2.2xlarge
* Kernel info: 6.5.0-1018-aws #18~22.04.1-Ubuntu
* 32 GB RAM 8 CPUs

These data are collected using the `modern_ebpf` driver but the conclusions can be easily applied to the other drivers.

We run the redis-benchmark on this machine with the following configuration:

```bash
redis-benchmark -t ping_inline,ping_mbulk,set,get,incr,lpush,rpush,lpop,rpop,sadd,hset -q -n 1000000
```

This machine is idle, doing almost nothing apart from the Redis interaction. Below is the machine's syscall fingerprint during the redis-benchmark to better understand which syscalls we need to trace.

```text
Rate of userspace events (events/second): 1065382 # evt/s
- [gettimeofday__enter]: 107109300 # num events
- [gettimeofday__exit]: 107109300
- [epoll_ctl__enter]: 105084000
- [epoll_ctl__exit]: 105084000
- [clock_gettime__enter]: 104064452
- [clock_gettime__exit]: 104064452
- [read__enter]: 21038177
- [read__exit]: 21038174
- [write__exit]: 21011698
- [write__enter]: 21011698
- [sendto__enter]: 21.000.019
- [sendto__exit]: 21.000.019
- [recvfrom__enter]: 21.000.007
- [recvfrom__exit]: 21.000.007
- [epoll_wait__exit]: 11585287
- [epoll_wait__enter]: 11585286
- [sched_switch__enter]: 5549182
- [clock_nanosleep__exit]: 883918
- [clock_nanosleep__enter]: 883917
- [page_fault_user__enter]: 130285
- [setsockopt__enter]: 105232
- [setsockopt__exit]: 105232
- [close__enter]: 51109
- [close__exit]: 51109
- [fcntl__enter]: 42022
- [fcntl__exit]: 42022
- [accept4__enter]: 34361
- [accept4__exit]: 34361
- [socket__enter]: 21090
- [socket__exit]: 21090
- [connect__enter]: 21063
- [connect__exit]: 21063
```

The performance of Redis benchmark without any eBPF instrumentation (baseline):

```bash
redis-benchmark -t ping_inline,ping_mbulk,set,get,incr,lpush,rpush,lpop,rpop,sadd,hset -q -n 1000000

PING_INLINE: 64800.41 requests per second, p50=0.399 msec                
PING_MBULK: 64279.75 requests per second, p50=0.407 msec                
SET: 64106.67 requests per second, p50=0.407 msec                
GET: 64370.78 requests per second, p50=0.399 msec                
INCR: 64628.71 requests per second, p50=0.399 msec                
LPUSH: 64520.29 requests per second, p50=0.407 msec                
RPUSH: 64758.45 requests per second, p50=0.399 msec                
LPOP: 65057.57 requests per second, p50=0.399 msec                
RPOP: 64197.21 requests per second, p50=0.407 msec                
SADD: 64989.93 requests per second, p50=0.399 msec                
HSET: 63889.60 requests per second, p50=0.407 msec
```

The idea is to start with a small instrumentation (0 syscall traced) reach a full instrumentation (almost all syscalls in the above fingerprint) and see what changes in terms of kernel instrumentation time. More in detail we will go throught 3 steps:

1. No instrumented syscalls
2. Small syscall set
3. Big syscall set

For each step we call our `redis-benchmark` command and we use our `scap-open` binary to collect some metrics and filter syscalls with the simple consumer.

### No instrumented syscall

Here, we observe the overhead imposed by tracing a syscall that is not called during the capture, such as the `open_by_handle_at` syscall. The cost we observe here is due to the fact that even if we don’t instrument any called syscall, we always run our `sys_enter`/`sys_exit` BPF programs. We immediately interrupt the flow with the simple consumer logic but there is still a cost.

```text
----------------------------- STATS ------------------------------

Time elapsed: 194 s

------------> Kernel stats
Seen by driver (kernel side events): 0
Rate of kernel side events (events/second): 0
Stats v2: 27 metrics in total
[1] kernel-side counters
[2] libbpf stats (compare to `bpftool prog show` CLI)
[2] sys_enter.run_cnt: 206.512.666
[2] sys_enter.run_time_ns: 13.709.016.483
[2] sys_enter.avg_time_ns: 66
[2] sys_exit.run_cnt: 206.512.710
[2] sys_exit.run_time_ns: 12.806.959.773
[2] sys_exit.avg_time_ns: 62
[2] total_run_cnt: 413.025.376
[2] total_run_time_ns: 26.515.976.256
[2] total_avg_time_ns: 64

------------> Userspace stats
Number of `SCAP_SUCCESS` (events correctly captured): 0
Number of `SCAP_TIMEOUTS`: 6475
Number of `scap_next` calls: 6475
Number of bytes received: 0 bytes
Rate of userspace events (events/second): 0
Syscall stats (userspace-side):
------------------------------------------------------------------

PING_INLINE: 56388.86 requests per second, p50=0.463 msec                
PING_MBULK: 55580.26 requests per second, p50=0.463 msec                
SET: 57323.02 requests per second, p50=0.455 msec                
GET: 56776.24 requests per second, p50=0.455 msec                
INCR: 57025.55 requests per second, p50=0.455 msec                
LPUSH: 56538.70 requests per second, p50=0.463 msec                
RPUSH: 56430.22 requests per second, p50=0.463 msec                
LPOP: 57178.80 requests per second, p50=0.455 msec                
RPOP: 57690.09 requests per second, p50=0.455 msec                
SADD: 56637.97 requests per second, p50=0.463 msec                
HSET: 55816.03 requests per second, p50=0.471 msec
```

* scap-open runs for `194` seconds. This is the time the redis benchmark requires to complete the execution.
* We never send data from the kernel to userspace, we immediately drop the events kernel side with the simple consumer logic.
  * `Seen by driver (kernel side events): 0`
  * `Number of SCAP_SUCCESS (events correctly captured): 0`
* Our kernel instrumentation runs `26` seconds (`total_run_time_ns: 26.515.976.256`) doing nothing. We just call the bpf programs and we interrupt the flow with the simple consumer.
  * Please note that the `sys_enter` prog costs more than the `sys_exit` one. This is not due to our instrumentation but this is probably due to how these tracepoints are called... However this is out of scope for this investigation.
  * **The `sys_enter` tracepoint takes half of the time kernel side.** This is in some way expected, `sys_enter` and `sys_exit` dispatchers do almost the same thing.
* As we can see from Redis Data, we can handle 7000/8000 req/s less than in the "ideal" case (with no instrumentation).

### Small syscall set

We examine the overhead imposed by tracing two system calls frequently called by our redis-benchmark: `sendto`, `recvfrom`.

```text
----------------------------- STATS ------------------------------

Time elapsed: 227 s

------------> Kernel stats
Seen by driver (kernel side events): 44.000.008
Rate of kernel side events (events/second): 193.832
Stats v2: 27 metrics in total
[1] kernel-side counters
[2] libbpf stats (compare to `bpftool prog show` CLI)
[1] n_evts: 44.000.008
[2] sys_enter.run_cnt: 235.481.342
[2] sys_enter.run_time_ns: 27.009.550.840
[2] sys_enter.avg_time_ns: 114
[2] sys_exit.run_cnt: 235.481.390
[2] sys_exit.run_time_ns: 27.793.327.491
[2] sys_exit.avg_time_ns: 118
[2] total_run_cnt: 470.962.732
[2] total_run_time_ns: 54.802.878.331
[2] total_avg_time_ns: 116

------------> Userspace stats
Number of `SCAP_SUCCESS` (events correctly captured): 44.000.008
Number of `SCAP_TIMEOUTS`: 336.373
Number of `scap_next` calls: 44.336.381
Number of bytes received: 2.555.000.598 bytes (2,8 GB)
Average dimension of events: 58 bytes
Rate of userspace events (events/second): 193.832
Syscall stats (userspace-side):
- [sendto__enter]: 11.000.003
- [sendto__exit]: 11.000.003
- [recvfrom__enter]: 11.000.001
- [recvfrom__exit]: 11.000.001


------------------------------------------------------------------

PING_INLINE: 48873.46 requests per second, p50=0.527 msec                
PING_MBULK: 48510.72 requests per second, p50=0.527 msec                
SET: 48435.53 requests per second, p50=0.527 msec                
GET: 48685.49 requests per second, p50=0.527 msec                
INCR: 48206.71 requests per second, p50=0.527 msec                
LPUSH: 48407.39 requests per second, p50=0.527 msec                
RPUSH: 48306.84 requests per second, p50=0.527 msec                
LPOP: 48440.23 requests per second, p50=0.527 msec                
RPOP: 48600.31 requests per second, p50=0.527 msec                
SADD: 48612.12 requests per second, p50=0.527 msec                
HSET: 47684.90 requests per second, p50=0.535 msec
```

* Our ebpf programs run `54` s in the kernel. **`~27 s` in the enter fillers and `~27 s` in the exit one.**
* We see a slowdown both in `scap-open` and in `redis`.
  * scap-open now takes `227 s` instead of `194 s`.
  * we have a decrease of `7000/8000` requests/sec in Redis.
* We send to userspace `2.8` GB in `227` s.

### Big syscall set

Let's see what happens if we decide to trace almost all the syscalls running in the system.

List of traced syscalls:

* `read`
* `write`
* `close`
* `fcntl`
* `gettimeofday`
* `epoll_ctl`
* `epoll_wait`
* `clock_gettime`
* `clock_nanosleep`
* `socket`
* `connect`
* `sendto`
* `recvfrom`
* `setsockopt`
* `accept`

```text
----------------------------- STATS ------------------------------

Time elapsed: 263 s

------------> Kernel stats
Seen by driver (kernel side events): 419.080.075
Rate of kernel side events (events/second): 1.593.460
Stats v2: 27 metrics in total
[1] kernel-side counters
[2] libbpf stats (compare to `bpftool prog show` CLI)
[1] n_evts: 419.080.075
[2] sys_enter.run_cnt: 209.710.116
[2] sys_enter.run_time_ns: 72.137.402.430
[2] sys_enter.avg_time_ns: 343
[2] sys_exit.run_cnt: 209.710.190
[2] sys_exit.run_time_ns: 74.330.638.160
[2] sys_exit.avg_time_ns: 354
[2] total_run_cnt: 419.420.306
[2] total_run_time_ns: 146.468.040.590
[2] total_avg_time_ns: 349

------------> Userspace stats
Number of `SCAP_SUCCESS` (events correctly captured): 419.080.067
Number of `SCAP_TIMEOUTS`: 84.032
Number of `scap_next` calls: 419.164.099
Number of bytes received: 13.509.598.040 bytes (12,6 GB)
Average dimension of events: 32 bytes
Rate of userspace events (events/second): 1.593.460
Syscall stats (userspace-side):
- [epoll_ctl__enter]: 55.002.263
- [epoll_ctl__exit]: 55.002.263
- [gettimeofday__exit]: 54.841.309
- [gettimeofday__enter]: 54.841.309
- [clock_gettime__enter]: 49.684.503
- [clock_gettime__exit]: 49.684.503
- [write__exit]: 11.022.850
- [write__enter]: 11.022.850
- [read__enter]: 11.012.631
- [read__exit]: 11.012.631
- [sendto__enter]: 11.000.016
- [sendto__exit]: 11.000.016
- [recvfrom__enter]: 11.000.015
- [recvfrom__exit]: 11.000.015
- [epoll_wait__exit]: 5.878.219
- [epoll_wait__enter]: 5.878.219
- [clock_nanosleep__exit]: 84.301
- [clock_nanosleep__enter]: 84.300
- [close__exit]: 7696
- [close__enter]: 7696
- [setsockopt__enter]: 2905
- [setsockopt__exit]: 2905
- [fcntl__enter]: 1371
- [fcntl__exit]: 1371
- [accept4__enter]: 749
- [accept4__exit]: 749
- [socket__enter]: 608
- [socket__exit]: 608
- [connect__enter]: 598
- [connect__exit]: 598
------------------------------------------------------------------

PING_INLINE: 42084.00 requests per second, p50=0.615 msec                
PING_MBULK: 41743.20 requests per second, p50=0.623 msec                
SET: 42059.22 requests per second, p50=0.615 msec                
GET: 42060.99 requests per second, p50=0.615 msec                
INCR: 41704.89 requests per second, p50=0.623 msec                
LPUSH: 41557.58 requests per second, p50=0.623 msec                
RPUSH: 41951.59 requests per second, p50=0.623 msec                
LPOP: 42301.18 requests per second, p50=0.615 msec                
RPOP: 41630.24 requests per second, p50=0.623 msec                
SADD: 41785.06 requests per second, p50=0.623 msec                
HSET: 41618.11 requests per second, p50=0.623 msec 
```

* Here we see an instrumentation time of `146,5` s, **more or less splitted equally between `sys_enter` and `sys_exit`.** This is probably a best scenario because some of these syscalls are treated as "generic" by our probe so the instrumentation time of the enter and exit events should be almost the same, but we can easily understand that even in a not ideal scenario the `sys_enter` program has a great impact on our instrumentation overhead.
* We set yet another decrease in Redis performance. This is due to 2 main factors:
  * a greater kernel instrumentation time.
  * a greater CPU request from scap-open that now needs to process 419 million events.
* We send to Userspace `12.6` GB in `263` seconds

## Required steps

This activity involves several steps at different levels:

### Move all the parameters from the enter event into the exit one

The idea is to work without forks, using incremental steps. Each PR will contain the following:

1. Add enter parameters to the exit event without touching anything else. This would be a minor change in the event schema since we are just adding new parameters to the exit one. This must be done for all drivers (kmod, modern ebpf). To give you an example

 ```c
 /////////////////////////// TODAY
   [PPME_SYSCALL_READ_E] = {"read",
         EC_IO_READ | EC_SYSCALL,
         EF_USES_FD | EF_READS_FROM_FD,
         2,
         {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}}},
   [PPME_SYSCALL_READ_X] = {"read",
         EC_IO_READ | EC_SYSCALL,
         EF_USES_FD | EF_READS_FROM_FD,
         2,
         {{"res", PT_ERRNO, PF_DEC},
         {"data", PT_BYTEBUF, PF_NA}}},

 /////////////////////////// TOMORROW
   [PPME_SYSCALL_READ_E] = {"read",
         EC_IO_READ | EC_SYSCALL,
         EF_USES_FD | EF_READS_FROM_FD,
         2,
         {{"fd", PT_FD, PF_DEC}, {"size", PT_UINT32, PF_DEC}}},
   [PPME_SYSCALL_READ_X] = {"read",
         EC_IO_READ | EC_SYSCALL,
         EF_USES_FD | EF_READS_FROM_FD,
         4,
         {{"res", PT_ERRNO, PF_DEC},
         {"data", PT_BYTEBUF, PF_NA},
         {"fd", PT_FD, PF_DEC},
         {"size", PT_UINT32, PF_DEC}}},
 ```

2. Adapt sinsp state to work just with exit events. Enter events can still be generated but they won't populate the state anymore. The idea is to use a feature flag in sinsp to enable/disable enter events. Please note! This means that old driver versions won't work with new libs versions because they cannot correctly populate the sinsp state since it will work only with exit events. The idea is to bump also the minor schema version required by scap <https://github.com/falcosecurity/libs/blob/2e1c5b68380eb00ab79e61f369a8bf95faab4968/userspace/libscap/scap.h#L105>
3. Create a scap-file conversion (in a dedicated scap-file converter) to convert ENTER events into merged EXIT ones. Since we are here we will also handle old event versions in this converter, but each PR will add conversion just for one event pair.
4. Add some tests replaying scap-files and checking that everything is good.

Look at some PRs to have an example:

* <https://github.com/falcosecurity/libs/pull/2187>
* <https://github.com/falcosecurity/libs/pull/2205>
* <https://github.com/falcosecurity/libs/pull/2206>

### Implement TOCTOU mitigation

We currently provide mitigation against TOCTOU attacks for 5 syscalls:

* connect
* open
* creat
* openat
* openat2

The mitigation implemented in this PR (<https://github.com/falcosecurity/libs/pull/235>) uses enter events. How can we achieve the same result without sending these events to userspace?

For the connect syscall, we can use the tuple parameter in the exit event to avoid issues with TOCTOU. So, the mitigation here is to populate the userspace with information directly from the kernel.

For what concerns the other 4 syscalls, the idea is to hook into the specific tracepoints  (e.g., `tracepoint/sys_enter_open`), collect the necessary parameters, and save them in a map indexed by thread ID. So we use a bpf hash map with thread-id as a key and syscall arguments as a value. This is very similar to what we do today when `RAW_TRACEPOINTS` are not enabled:  <https://github.com/falcosecurity/libs/blob/0.19.0/driver/bpf/maps.h#L103> In the exit tracepoint, we can retrieve this information and send only one event to userspace.  This drastically reduces the instrumentation time with respect to using the generic sys_enter tracepoint like today. Moreover, we won't send the enter event to userspace but we will merge the information directly in the kernel.

Long-term mitigation would involve attaching to internal kernel hooks rather than using the syscall enter hooks, but currently, we only support tracepoints as hook points in our drivers.

### Adapt consumers to use only exit events

Some consumers of the libraries still use enter events for their logic. Now exit events should contain all necessary parameters so it’s time to switch the consumers to use exit events. Consumers we need to update:

* Plugins
* Falco
* Sysdig CLI tool

### Adapt rules to use only exit events

Today some rules could use enter events. We need to provide an automatic migration. An idea could be to update our default rulesets and provide a script for users' rulesets' automatic migration.

### Update Documentation

Tell users that by default enter events won’t be generated anymore.

### Make enter event optional in libs

[Preliminary cleanup] During the work, we may have left some todo! to solve at the end of the work. This is probably the right moment to do it and simplify the code. For example, the flag `EF_TMP_CONVERTER_MANAGED` can be removed since we can now mark the enter events as `EF_OLD_VERSION`. We can use `EF_OLD_VERSION` to understand if we need a conversion instead of `EF_TMP_CONVERTER_MANAGED`.

**UPDATE 30/07/2025** - At the time of writing, as some enter events are just old event that must be dropped, they are
not marked as `EF_TMP_CONVERTER_MANAGED` (e.g.: `PPME_SYSCALL_VFORK_E`); conversely, some enter events must be converted
to their new versions leveraging the scap converter, but are not old versions of anything, so they are not marked as
`EF_OLD_VERSION` (e.g.: `PPME_SYSCALL_OPEN_E`). As a result, neither `EF_OLD_VERSION` can be used to always imply
`EF_TMP_CONVERTER_MANAGED`, nor `EF_TMP_CONVERTER_MANAGED` can be used to always imply `EF_OLD_VERSION`: this leads to
the stabilization of `EF_TMP_CONVERTER_MANAGED` as `EF_CONVERTER_MANAGED`.

We need to expose a flag from sinsp to avoid the generation of enter events. The consumer can choose to receive or not enter events.

When we add a new syscall we should remember to add an enter event with 0 parameters like we do today. So events will always be added to the event table in pairs.

## Additional link/resources

* <https://github.com/falcosecurity/falco/issues/2960>
* <https://github.com/falcosecurity/libs/issues/1557>
* <https://github.com/falcosecurity/libs/issues/515#issuecomment-1200811892>
