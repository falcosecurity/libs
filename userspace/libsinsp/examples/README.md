# Example sinsp code

This directory contains a program that demonstrates how to use libsinsp for event capture and filtering.

## Quick Start ##

`sinsp-example` monitors the host and any running containers for system activity. By default, it prints events of all types and is very noisy. 

To use filtering, specify a [Sysdig filter](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide#all-supported-filters) using `-f`.

To use Falco rules, specify a rules directory using `-r`.

### Usage ###

```
$ sudo ./sinsp-example [-f filter] [-r rules_dir]
```

## Sample Output ##

The following output was generated while monitoring a CentOS 8 system currently executing one Docker container with id `915a5fc08d11`.

In an effort to reduce noisiness, we provide a filter with `-f` that informs `sinsp-example` to only monitor the execution of new programs via calls to `execve()`.

In the below output, you can see that `/usr/sbin/useradd` was executed in a container with id `915a5fc08d11`. Also present in the output is evidence of `/usr/sbin/ksmtuned` performing hypervisor-related activity on the host. 

```
$ sudo ./sinsp-example -f "evt.category=process and evt.type=execve"
[2021-04-08T21:12:43.098252119+0000]:[915a5fc08d11]:[CAT=PROCESS]:[PPID=959684]:[PID=961502]:[TYPE=execve]:[EXE=/bin/bash]:[CMD=bash]
[2021-04-08T21:12:43.098741551+0000]:[915a5fc08d11]:[CAT=PROCESS]:[PPID=959684]:[PID=961502]:[TYPE=execve]:[EXE=/usr/sbin/useradd]:[CMD=useradd --help]
[2021-04-08T21:12:54.792161790+0000]:[HOST]:[CAT=PROCESS]:[PPID=961503]:[PID=961504]:[TYPE=execve]:[EXE=/usr/bin/bash]:[CMD=ksmtuned /usr/sbin/ksmtuned]
[2021-04-08T21:12:54.792388363+0000]:[HOST]:[CAT=PROCESS]:[PPID=961503]:[PID=961504]:[TYPE=execve]:[EXE=/usr/bin/awk]:[CMD=awk /^(MemFree|Buffers|Cached):/ {free += $2}; END {print free} /proc/meminfo]
[2021-04-08T21:12:54.797189989+0000]:[HOST]:[CAT=PROCESS]:[PPID=961506]:[PID=961507]:[TYPE=execve]:[EXE=/usr/bin/bash]:[CMD=ksmtuned /usr/sbin/ksmtuned]
[2021-04-08T21:12:54.797344290+0000]:[HOST]:[CAT=PROCESS]:[PPID=961506]:[PID=961507]:[TYPE=execve]:[EXE=/usr/bin/pgrep]:[CMD=pgrep -d   -- ^qemu(-(kvm|system-.+)|:.{1,11})$]
[2021-04-08T21:12:54.812200314+0000]:[HOST]:[CAT=PROCESS]:[PPID=961505]:[PID=961509]:[TYPE=execve]:[EXE=/usr/bin/bash]:[CMD=ksmtuned /usr/sbin/ksmtuned]
[2021-04-08T21:12:54.812479220+0000]:[HOST]:[CAT=PROCESS]:[PPID=961505]:[PID=961509]:[TYPE=execve]:[EXE=/usr/bin/awk]:[CMD=awk { sum += $1 }; END { print 0+sum }]
[2021-04-08T21:12:54.815842710+0000]:[HOST]:[CAT=PROCESS]:[PPID=1013]:[PID=961510]:[TYPE=execve]:[EXE=/usr/bin/bash]:[CMD=ksmtuned /usr/sbin/ksmtuned]
[2021-04-08T21:12:54.816006165+0000]:[HOST]:[CAT=PROCESS]:[PPID=1013]:[PID=961510]:[TYPE=execve]:[EXE=/usr/bin/sleep]:[CMD=sleep 60]
```
