# Drop support for syscall enter events

## Motivation

This document proposes removing support for syscall enter events in our codebase. The primary reason behind this proposal is to reduce the throughput of events that our userspace needs to process. As the number of syscalls increases, we are no longer able to support them, and we start dropping events. Since enter events do not provide additional information compared to exit events (TOCTOU attacks will be addressed [in this section](#what-about-toctou-attacks)), the idea is to remove them entirely, thereby halving the number of events generated and processed.

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

* Update our three drivers to collect all parameters in the exit fillers and remove the enter ones.
* Update scap-file management to convert all enter events generated over the years into new exit events.
* Update our userspace engines to support only exit events.
* Update the sinsp parsing and extraction logic to use only exit events.
* Update all tests (drivers, libscap, unit, e2e) to use only exit events.
* Update all documentation.

## Bonus point: scap-file management

During this workflow, we need to address the issue of supporting old scap-files with enter and exit events. We definitely need to write a converter to transform enter events into exit events. But can we do better? We know that our events are not "optimized"; for example, we send PID and FD on 64 bits instead of 32 bits and send a 24-byte header for each event, even though 16 bytes could suffice. These changes are currently unthinkable as they would completely break compatibility with older scap-files. However, if we could introduce a versioning mechanism, we could finally clean up our event schema without breaking compatibility.

Since this initiative will involve revising the schema for many events, this seems like the right time to clean up the schema by introducing a versioning mechanism for backward compatibility! The title says "Bonus point" because it is not guaranteed that this work will be carried out during this initiative; it depends on the challenges encountered during the process.

## What about TOCTOU attacks?

We currently provide mitigation against TOCTOU attacks for certain syscalls, specifically:

* `connect`
* `creat`
* `open`
* `openat`
* `openat2`

The mitigation implemented [in this PR](https://github.com/falcosecurity/libs/pull/235) uses enter events. How can we achieve the same result without sending these events to userspace? The idea is to hook into the specific tracepoints for those five syscalls (e.g., `tracepoint/sys_enter_open`), collect the necessary parameters, and save them in a map indexed by thread ID. In the exit event, we can retrieve this information and send only one event to userspace.

Long-term mitigation would involve attaching to internal kernel hooks rather than using the syscall enter hooks, but currently, we only support tracepoints as hook points in our drivers.

## Additional link/resources

* <https://github.com/falcosecurity/falco/issues/2960>
* <https://github.com/falcosecurity/libs/issues/1557>
* <https://github.com/falcosecurity/libs/issues/515#issuecomment-1200811892>
