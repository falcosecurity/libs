# kexec_x86

This capture was taken on an x86 Ubuntu machine

```
Linux 5.19.0-1027-aws #28~22.04.1-Ubuntu SMP Wed May 31 18:30:36 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

We used [sysdig tool](https://github.com/draios/sysdig) with the kernel module to dump the scap-file

## Environment

These are the commands we run to set up the environment

```bash
kind create cluster
kubectl apply -f ~/scripts/yaml/ubuntu.yaml
```

where `ubuntu.yaml` is:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ubuntu
spec:
  containers:
  - name: ubuntu
    image: ubuntu:latest
    securityContext:
      privileged: true
    command: ["sleep", "10d"]
    tty: true
```

When the pod is ready:

1. We start the capture with sysdig
2. We run:

```bash
kubectl exec nginx -- sh -c 'tail -f /proc/self/status'
```

3. We stop the capture

## Tests

* `tail_lineage` -> assert the `tail` process lineage in 2 different moments: immediately after the `tail` execve event and after all `runc` threads are dead. See the test comments for more details
* `final_thread_table_dim` -> assert the dimension of the thread table at the end of the capture to ensure that we don't break the removal thread logic with new changes.

### Additional info

These data are collected directly from the running system before stopping the capture, so with `tail` still alive

**Tail lineage after all runc threads are dead**

```plain
📜 Process Lineage for tid: 107370
⬇️ [tail] tid: 107370, pid: 107370, rptid: 107364, rppid: 107364
⬇️ [sh] tid: 107364, pid: 107364, rptid: 107196, rppid: 107196
⬇️ [containerd-shim]💀 tid: 107196, pid: 107196, rptid: 100562, rppid: 100562
⬇️ [systemd] tid: 100562, pid: 100562, rptid: 100542, rppid: 100542
⬇️ [containerd-shim]💀 tid: 100542, pid: 100542, rptid: 1, rppid: 1
⬇️ [systemd] tid: 1, pid: 1, rptid: 0, rppid: 0
```

**Full process tree**

```plain
🌴 Process Tree for tid: 1
[systemd] tid: 1, pid: 1
├─ [systemd-journal] tid: 222, pid: 222
├─ [multipathd] tid: 263, pid: 263
├─ [systemd-udevd] tid: 266, pid: 266
├─ {multipathd} tid: 267, pid: 263
├─ {multipathd} tid: 268, pid: 263
├─ {multipathd} tid: 269, pid: 263
├─ {multipathd} tid: 270, pid: 263
├─ {multipathd} tid: 271, pid: 263
├─ {multipathd} tid: 272, pid: 263
├─ [systemd-network] tid: 470, pid: 470
├─ [systemd-resolve] tid: 472, pid: 472
├─ [acpid] tid: 507, pid: 507
├─ [cron] tid: 513, pid: 513
├─ [dbus-daemon] tid: 514, pid: 514
├─ [irqbalance] tid: 521, pid: 521
├─ [networkd-dispat] tid: 522, pid: 522
├─ [rsyslogd] tid: 523, pid: 523
├─ [amazon-ssm-agen] tid: 524, pid: 524
├─ {gmain} tid: 527, pid: 521
├─ [snapd] tid: 528, pid: 528
├─ [systemd-logind] tid: 529, pid: 529
├─ [containerd] tid: 531, pid: 531
├─ {in:imuxsock} tid: 536, pid: 523
├─ {in:imklog} tid: 537, pid: 523
├─ {rs:main Q:Reg} tid: 538, pid: 523
├─ [chronyd] tid: 587, pid: 587
│  └─ [chronyd] tid: 598, pid: 598
├─ [agetty] tid: 588, pid: 588
├─ {containerd} tid: 639, pid: 531
├─ {containerd} tid: 648, pid: 531
├─ {containerd} tid: 650, pid: 531
├─ {containerd} tid: 651, pid: 531
├─ {containerd} tid: 652, pid: 531
├─ [agetty] tid: 666, pid: 666
├─ [unattended-upgr] tid: 671, pid: 671
├─ [polkitd] tid: 676, pid: 676
├─ {gmain} tid: 682, pid: 676
├─ {gdbus} tid: 685, pid: 676
├─ {containerd} tid: 689, pid: 531
├─ {containerd} tid: 690, pid: 531
├─ {containerd} tid: 691, pid: 531
├─ {gmain} tid: 692, pid: 671
├─ {containerd} tid: 695, pid: 531
├─ {containerd} tid: 696, pid: 531
├─ {containerd} tid: 697, pid: 531
├─ {containerd} tid: 698, pid: 531
├─ [sshd] tid: 699, pid: 699
│  └─ [sshd] tid: 99298, pid: 99298
│     └─ [sshd] tid: 99447, pid: 99447
│        └─ [zsh] tid: 99448, pid: 99448
│           └─ [bash] tid: 99450, pid: 99450
├─ [dockerd] tid: 701, pid: 701
├─ {dockerd} tid: 712, pid: 701
├─ {dockerd} tid: 713, pid: 701
├─ {dockerd} tid: 714, pid: 701
├─ {dockerd} tid: 715, pid: 701
├─ {dockerd} tid: 716, pid: 701
├─ {dockerd} tid: 717, pid: 701
│  ├─ [docker-proxy] tid: 100528, pid: 100528
│  ├─ {docker-proxy} tid: 100529, pid: 100528
│  ├─ {docker-proxy} tid: 100530, pid: 100528
│  ├─ {docker-proxy} tid: 100531, pid: 100528
│  ├─ {docker-proxy} tid: 100532, pid: 100528
│  ├─ {docker-proxy} tid: 100533, pid: 100528
│  ├─ {docker-proxy} tid: 100534, pid: 100528
│  └─ {docker-proxy} tid: 102772, pid: 100528
├─ {dockerd} tid: 718, pid: 701
├─ {dockerd} tid: 719, pid: 701
├─ {snapd} tid: 720, pid: 528
├─ {snapd} tid: 721, pid: 528
├─ {snapd} tid: 722, pid: 528
├─ {snapd} tid: 723, pid: 528
├─ {snapd} tid: 724, pid: 528
├─ {snapd} tid: 729, pid: 528
├─ {dockerd} tid: 747, pid: 701
├─ {dockerd} tid: 748, pid: 701
├─ {snapd} tid: 756, pid: 528
├─ {snapd} tid: 757, pid: 528
├─ {snapd} tid: 758, pid: 528
├─ {snapd} tid: 759, pid: 528
├─ {snapd} tid: 760, pid: 528
├─ {snapd} tid: 794, pid: 528
├─ {amazon-ssm-agen} tid: 825, pid: 524
├─ {amazon-ssm-agen} tid: 826, pid: 524
├─ {amazon-ssm-agen} tid: 827, pid: 524
├─ {amazon-ssm-agen} tid: 828, pid: 524
├─ {amazon-ssm-agen} tid: 829, pid: 524
├─ {snapd} tid: 830, pid: 528
├─ {snapd} tid: 831, pid: 528
├─ {dockerd} tid: 833, pid: 701
├─ {snapd} tid: 837, pid: 528
├─ {snapd} tid: 838, pid: 528
├─ {snapd} tid: 891, pid: 528
├─ {amazon-ssm-agen} tid: 925, pid: 524
│  ├─ [ssm-agent-worke] tid: 1037, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1061, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1062, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1063, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1064, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1065, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1066, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1067, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1068, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1069, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1070, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1071, pid: 1037
│  ├─ {ssm-agent-worke} tid: 1924, pid: 1037
│  └─ {ssm-agent-worke} tid: 1925, pid: 1037
├─ {amazon-ssm-agen} tid: 930, pid: 524
├─ {amazon-ssm-agen} tid: 931, pid: 524
├─ {snapd} tid: 1011, pid: 528
├─ {snapd} tid: 1012, pid: 528
├─ {dockerd} tid: 1013, pid: 701
├─ {amazon-ssm-agen} tid: 1036, pid: 524
├─ {amazon-ssm-agen} tid: 1038, pid: 524
├─ {amazon-ssm-agen} tid: 1039, pid: 524
├─ [systemd]💀 tid: 1146, pid: 1146
│  └─ [(sd-pam)] tid: 1147, pid: 1147
├─ [sh] tid: 1285, pid: 1285
│  ├─ [node] tid: 1295, pid: 1295
│  │  ├─ [node] tid: 1385, pid: 1385
│  │  │  ├─ [zsh] tid: 99621, pid: 99621
│  │  │  │  ├─ [kubectl] tid: 107344, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107345, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107346, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107347, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107348, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107349, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107350, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107351, pid: 107344
│  │  │  │  ├─ {kubectl} tid: 107352, pid: 107344
│  │  │  │  └─ {kubectl} tid: 107353, pid: 107344
│  │  │  ├─ [zsh] tid: 102951, pid: 102951
│  │  │  │  └─ [sudo] tid: 107308, pid: 107308
│  │  │  │     └─ [sudo] tid: 107309, pid: 107309
│  │  │  │        └─ [sysdig] tid: 107310, pid: 107310
│  │  │  ├─ [zsh] tid: 104146, pid: 104146
│  │  │  │  └─ [sudo] tid: 107389, pid: 107389
│  │  │  │     └─ [sudo] tid: 107390, pid: 107390
│  │  │  │        ├─ [bpftree] tid: 107391, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107392, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107393, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107394, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107395, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107396, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107397, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107398, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107399, pid: 107391
│  │  │  │        ├─ {bpftree} tid: 107400, pid: 107391
│  │  │  │        └─ {bpftree} tid: 107401, pid: 107391
│  │  │  └─ [sh] tid: 107406, pid: 107406
│  │  │     └─ [cpuUsage.sh] tid: 107407, pid: 107407
│  │  │        └─ [sleep] tid: 107413, pid: 107413
│  │  ├─ {node} tid: 1386, pid: 1385
│  │  ├─ {node} tid: 1387, pid: 1385
│  │  ├─ {node} tid: 1388, pid: 1385
│  │  ├─ {node} tid: 1389, pid: 1385
│  │  ├─ {node} tid: 1390, pid: 1385
│  │  ├─ {node} tid: 1391, pid: 1385
│  │  ├─ {node} tid: 1392, pid: 1385
│  │  ├─ {node} tid: 1393, pid: 1385
│  │  ├─ {node} tid: 1394, pid: 1385
│  │  ├─ {node} tid: 1395, pid: 1385
│  │  ├─ [node] tid: 99502, pid: 99502
│  │  │  ├─ [cpptools] tid: 99569, pid: 99569
│  │  │  ├─ {cpptools} tid: 99570, pid: 99569
│  │  │  ├─ {cpptools} tid: 99571, pid: 99569
│  │  │  ├─ {cpptools} tid: 99572, pid: 99569
│  │  │  ├─ {cpptools} tid: 99573, pid: 99569
│  │  │  ├─ {cpptools} tid: 99574, pid: 99569
│  │  │  ├─ {cpptools} tid: 99575, pid: 99569
│  │  │  ├─ {cpptools} tid: 99576, pid: 99569
│  │  │  ├─ {cpptools} tid: 99577, pid: 99569
│  │  │  ├─ {cpptools} tid: 99578, pid: 99569
│  │  │  ├─ {cpptools} tid: 99579, pid: 99569
│  │  │  ├─ {cpptools} tid: 99580, pid: 99569
│  │  │  ├─ {cpptools} tid: 99581, pid: 99569
│  │  │  ├─ {cpptools} tid: 99903, pid: 99569
│  │  │  ├─ {cpptools} tid: 99904, pid: 99569
│  │  │  ├─ {cpptools} tid: 99905, pid: 99569
│  │  │  ├─ {cpptools} tid: 99906, pid: 99569
│  │  │  └─ {cpptools} tid: 104718, pid: 99569
│  │  ├─ {node} tid: 99503, pid: 99502
│  │  ├─ {node} tid: 99504, pid: 99502
│  │  ├─ {node} tid: 99505, pid: 99502
│  │  ├─ {node} tid: 99506, pid: 99502
│  │  ├─ {node} tid: 99507, pid: 99502
│  │  ├─ {node} tid: 99508, pid: 99502
│  │  ├─ {node} tid: 99509, pid: 99502
│  │  ├─ {node} tid: 99510, pid: 99502
│  │  ├─ {node} tid: 99511, pid: 99502
│  │  ├─ {node} tid: 99512, pid: 99502
│  │  ├─ [node] tid: 99513, pid: 99513
│  │  ├─ {node} tid: 99514, pid: 99513
│  │  ├─ {node} tid: 99515, pid: 99513
│  │  ├─ {node} tid: 99516, pid: 99513
│  │  ├─ {node} tid: 99517, pid: 99513
│  │  ├─ {node} tid: 99518, pid: 99513
│  │  ├─ {node} tid: 99519, pid: 99513
│  │  ├─ {node} tid: 99520, pid: 99513
│  │  ├─ {node} tid: 99521, pid: 99513
│  │  ├─ {node} tid: 99522, pid: 99513
│  │  ├─ {node} tid: 99523, pid: 99513
│  │  ├─ {node} tid: 99524, pid: 99513
│  │  ├─ {node} tid: 99525, pid: 99513
│  │  ├─ {node} tid: 99526, pid: 99502
│  │  ├─ {node} tid: 99622, pid: 1385
│  │  ├─ {node} tid: 102952, pid: 1385
│  │  └─ {node} tid: 104147, pid: 1385
│  ├─ {node} tid: 1326, pid: 1295
│  ├─ {node} tid: 1327, pid: 1295
│  ├─ {node} tid: 1328, pid: 1295
│  ├─ {node} tid: 1329, pid: 1295
│  ├─ {node} tid: 1330, pid: 1295
│  ├─ {node} tid: 1343, pid: 1295
│  ├─ {node} tid: 1380, pid: 1295
│  ├─ {node} tid: 1381, pid: 1295
│  ├─ {node} tid: 1382, pid: 1295
│  └─ {node} tid: 1383, pid: 1295
├─ {amazon-ssm-agen} tid: 1923, pid: 524
├─ {amazon-ssm-agen} tid: 1940, pid: 524
├─ [packagekitd] tid: 4085, pid: 4085
├─ {gmain} tid: 4086, pid: 4085
├─ {gdbus} tid: 4087, pid: 4085
├─ [zsh] tid: 99630, pid: 99630
│  ├─ [gitstatusd-linu] tid: 99683, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99685, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99686, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99687, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99688, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99689, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99690, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99691, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99692, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99693, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99694, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99695, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99696, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99697, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99698, pid: 99683
│  ├─ {gitstatusd-linu} tid: 99699, pid: 99683
│  └─ {gitstatusd-linu} tid: 99700, pid: 99683
├─ [zsh] tid: 99680, pid: 99680
├─ [zsh] tid: 99681, pid: 99681
├─ {dockerd} tid: 100161, pid: 701
├─ {dockerd} tid: 100191, pid: 701
├─ [containerd-shim]💀 tid: 100542, pid: 100542
│  └─ [systemd] tid: 100562, pid: 100562
│     ├─ [systemd-journal] tid: 100739, pid: 100739
│     ├─ [containerd] tid: 100758, pid: 100758
│     ├─ {containerd} tid: 100759, pid: 100758
│     ├─ {containerd} tid: 100760, pid: 100758
│     ├─ {containerd} tid: 100761, pid: 100758
│     ├─ {containerd} tid: 100763, pid: 100758
│     ├─ {containerd} tid: 100764, pid: 100758
│     ├─ {containerd} tid: 100765, pid: 100758
│     ├─ {containerd} tid: 100766, pid: 100758
│     ├─ {containerd} tid: 100768, pid: 100758
│     ├─ {containerd} tid: 100770, pid: 100758
│     ├─ [containerd-shim]💀 tid: 101089, pid: 101089
│     │  ├─ [pause] tid: 101197, pid: 101197
│     │  ├─ [etcd] tid: 101452, pid: 101452
│     │  ├─ {etcd} tid: 101470, pid: 101452
│     │  ├─ {etcd} tid: 101471, pid: 101452
│     │  ├─ {etcd} tid: 101472, pid: 101452
│     │  ├─ {etcd} tid: 101473, pid: 101452
│     │  ├─ {etcd} tid: 101474, pid: 101452
│     │  ├─ {etcd} tid: 101475, pid: 101452
│     │  ├─ {etcd} tid: 101476, pid: 101452
│     │  ├─ {etcd} tid: 101477, pid: 101452
│     │  ├─ {etcd} tid: 101478, pid: 101452
│     │  ├─ {etcd} tid: 101479, pid: 101452
│     │  ├─ {etcd} tid: 101480, pid: 101452
│     │  ├─ {etcd} tid: 101481, pid: 101452
│     │  └─ {etcd} tid: 107262, pid: 101452
│     ├─ {containerd-shim}💀 tid: 101091, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101092, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101094, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101095, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101104, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101105, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101106, pid: 101089
│     ├─ [containerd-shim]💀 tid: 101107, pid: 101107
│     │  ├─ [pause] tid: 101185, pid: 101185
│     │  ├─ [kube-apiserver] tid: 101359, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101405, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101406, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101407, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101408, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101410, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101411, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101412, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101413, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101414, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101417, pid: 101359
│     │  ├─ {kube-apiserver} tid: 101418, pid: 101359
│     │  └─ {kube-apiserver} tid: 101482, pid: 101359
│     ├─ {containerd-shim}💀 tid: 101108, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101111, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101112, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101113, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101114, pid: 101107
│     ├─ [containerd-shim]💀 tid: 101116, pid: 101116
│     │  ├─ [pause] tid: 101193, pid: 101193
│     │  ├─ [kube-controller] tid: 101328, pid: 101328
│     │  ├─ {kube-controller} tid: 101390, pid: 101328
│     │  ├─ {kube-controller} tid: 101391, pid: 101328
│     │  ├─ {kube-controller} tid: 101392, pid: 101328
│     │  ├─ {kube-controller} tid: 101393, pid: 101328
│     │  ├─ {kube-controller} tid: 101395, pid: 101328
│     │  ├─ {kube-controller} tid: 101396, pid: 101328
│     │  ├─ {kube-controller} tid: 101397, pid: 101328
│     │  ├─ {kube-controller} tid: 101404, pid: 101328
│     │  └─ {kube-controller} tid: 101633, pid: 101328
│     ├─ {containerd-shim}💀 tid: 101118, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101119, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101120, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101121, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101122, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101123, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101124, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101125, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101131, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101132, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101133, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101134, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101135, pid: 101116
│     ├─ [containerd-shim]💀 tid: 101163, pid: 101163
│     │  ├─ [pause] tid: 101209, pid: 101209
│     │  ├─ [kube-scheduler] tid: 101297, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101365, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101366, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101367, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101368, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101371, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101372, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101373, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101374, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101379, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101415, pid: 101297
│     │  ├─ {kube-scheduler} tid: 101416, pid: 101297
│     │  └─ {kube-scheduler} tid: 101419, pid: 101297
│     ├─ {containerd-shim}💀 tid: 101164, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101165, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101166, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101167, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101169, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101170, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101171, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101172, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101173, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101222, pid: 101107
│     ├─ {containerd-shim}💀 tid: 101223, pid: 101089
│     ├─ {containerd-shim}💀 tid: 101242, pid: 101089
│     ├─ {containerd} tid: 101243, pid: 100758
│     ├─ {containerd} tid: 101244, pid: 100758
│     ├─ {containerd} tid: 101245, pid: 100758
│     ├─ {containerd} tid: 101246, pid: 100758
│     ├─ {containerd} tid: 101247, pid: 100758
│     ├─ {containerd} tid: 101248, pid: 100758
│     ├─ {containerd} tid: 101254, pid: 100758
│     ├─ {containerd} tid: 101255, pid: 100758
│     ├─ {containerd} tid: 101256, pid: 100758
│     ├─ {containerd-shim}💀 tid: 101394, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101409, pid: 101107
│     ├─ [kubelet] tid: 101527, pid: 101527
│     ├─ {kubelet} tid: 101528, pid: 101527
│     ├─ {kubelet} tid: 101529, pid: 101527
│     ├─ {kubelet} tid: 101530, pid: 101527
│     ├─ {kubelet} tid: 101531, pid: 101527
│     ├─ {kubelet} tid: 101532, pid: 101527
│     ├─ {kubelet} tid: 101533, pid: 101527
│     ├─ {kubelet} tid: 101534, pid: 101527
│     ├─ {kubelet} tid: 101535, pid: 101527
│     ├─ {kubelet} tid: 101536, pid: 101527
│     ├─ {kubelet} tid: 101537, pid: 101527
│     ├─ {kubelet} tid: 101539, pid: 101527
│     ├─ {kubelet} tid: 101540, pid: 101527
│     ├─ {kubelet} tid: 101555, pid: 101527
│     ├─ {kubelet} tid: 101556, pid: 101527
│     ├─ {containerd-shim}💀 tid: 101564, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101565, pid: 101163
│     ├─ {containerd-shim}💀 tid: 101566, pid: 101116
│     ├─ {containerd-shim}💀 tid: 101569, pid: 101089
│     ├─ {kubelet} tid: 101576, pid: 101527
│     ├─ [containerd-shim]💀 tid: 101931, pid: 101931
│     │  ├─ [pause] tid: 101980, pid: 101980
│     │  ├─ [kube-proxy] tid: 102032, pid: 102032
│     │  ├─ {kube-proxy} tid: 102050, pid: 102032
│     │  ├─ {kube-proxy} tid: 102051, pid: 102032
│     │  ├─ {kube-proxy} tid: 102052, pid: 102032
│     │  ├─ {kube-proxy} tid: 102053, pid: 102032
│     │  ├─ {kube-proxy} tid: 102055, pid: 102032
│     │  ├─ {kube-proxy} tid: 102056, pid: 102032
│     │  ├─ {kube-proxy} tid: 102081, pid: 102032
│     │  ├─ {kube-proxy} tid: 102082, pid: 102032
│     │  └─ {kube-proxy} tid: 102083, pid: 102032
│     ├─ {containerd-shim}💀 tid: 101932, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101933, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101934, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101935, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101941, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101942, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101943, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101944, pid: 101931
│     ├─ {containerd-shim}💀 tid: 101945, pid: 101931
│     ├─ [containerd-shim]💀 tid: 101950, pid: 101950
│     │  ├─ [pause] tid: 101987, pid: 101987
│     │  ├─ [kindnetd] tid: 102203, pid: 102203
│     │  ├─ {kindnetd} tid: 102222, pid: 102203
│     │  ├─ {kindnetd} tid: 102223, pid: 102203
│     │  ├─ {kindnetd} tid: 102224, pid: 102203
│     │  ├─ {kindnetd} tid: 102225, pid: 102203
│     │  ├─ {kindnetd} tid: 102246, pid: 102203
│     │  ├─ {kindnetd} tid: 102247, pid: 102203
│     │  ├─ {kindnetd} tid: 103784, pid: 102203
│     │  └─ {kindnetd} tid: 103785, pid: 102203
│     ├─ {containerd-shim}💀 tid: 101951, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101952, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101953, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101955, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101960, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101961, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101962, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101963, pid: 101950
│     ├─ {containerd-shim}💀 tid: 101999, pid: 101950
│     ├─ {containerd-shim}💀 tid: 102054, pid: 101931
│     ├─ {containerd-shim}💀 tid: 102215, pid: 101950
│     ├─ [containerd-shim]💀 tid: 102340, pid: 102340
│     │  ├─ [pause] tid: 102421, pid: 102421
│     │  ├─ [coredns] tid: 102515, pid: 102515
│     │  ├─ {coredns} tid: 102565, pid: 102515
│     │  ├─ {coredns} tid: 102566, pid: 102515
│     │  ├─ {coredns} tid: 102567, pid: 102515
│     │  ├─ {coredns} tid: 102571, pid: 102515
│     │  ├─ {coredns} tid: 102573, pid: 102515
│     │  ├─ {coredns} tid: 102574, pid: 102515
│     │  ├─ {coredns} tid: 102578, pid: 102515
│     │  ├─ {coredns} tid: 102580, pid: 102515
│     │  ├─ {coredns} tid: 102581, pid: 102515
│     │  └─ {coredns} tid: 102593, pid: 102515
│     ├─ {containerd-shim}💀 tid: 102342, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102344, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102346, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102349, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102352, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102353, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102354, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102355, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102359, pid: 102340
│     ├─ [containerd-shim]💀 tid: 102370, pid: 102370
│     │  ├─ [pause] tid: 102434, pid: 102434
│     │  ├─ [local-path-prov] tid: 102615, pid: 102615
│     │  ├─ {local-path-prov} tid: 102634, pid: 102615
│     │  ├─ {local-path-prov} tid: 102635, pid: 102615
│     │  ├─ {local-path-prov} tid: 102636, pid: 102615
│     │  ├─ {local-path-prov} tid: 102637, pid: 102615
│     │  ├─ {local-path-prov} tid: 102639, pid: 102615
│     │  ├─ {local-path-prov} tid: 102640, pid: 102615
│     │  ├─ {local-path-prov} tid: 102641, pid: 102615
│     │  ├─ {local-path-prov} tid: 102642, pid: 102615
│     │  ├─ {local-path-prov} tid: 102643, pid: 102615
│     │  ├─ {local-path-prov} tid: 102644, pid: 102615
│     │  └─ {local-path-prov} tid: 102645, pid: 102615
│     ├─ {containerd-shim}💀 tid: 102374, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102375, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102376, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102377, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102378, pid: 102370
│     ├─ [containerd-shim]💀 tid: 102379, pid: 102379
│     │  ├─ [pause] tid: 102433, pid: 102433
│     │  ├─ [coredns] tid: 102542, pid: 102542
│     │  ├─ {coredns} tid: 102588, pid: 102542
│     │  ├─ {coredns} tid: 102589, pid: 102542
│     │  ├─ {coredns} tid: 102590, pid: 102542
│     │  ├─ {coredns} tid: 102592, pid: 102542
│     │  ├─ {coredns} tid: 102600, pid: 102542
│     │  ├─ {coredns} tid: 102601, pid: 102542
│     │  ├─ {coredns} tid: 102602, pid: 102542
│     │  ├─ {coredns} tid: 102612, pid: 102542
│     │  ├─ {coredns} tid: 102613, pid: 102542
│     │  ├─ {coredns} tid: 102666, pid: 102542
│     │  └─ {coredns} tid: 102667, pid: 102542
│     ├─ {containerd-shim}💀 tid: 102384, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102386, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102387, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102388, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102389, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102390, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102391, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102392, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102393, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102394, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102396, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102397, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102398, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102402, pid: 102370
│     ├─ {containerd} tid: 102483, pid: 100758
│     ├─ {containerd-shim}💀 tid: 102558, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102651, pid: 101950
│     ├─ {containerd-shim}💀 tid: 102652, pid: 102379
│     ├─ {containerd-shim}💀 tid: 102653, pid: 101931
│     ├─ {containerd-shim}💀 tid: 102654, pid: 102340
│     ├─ {containerd-shim}💀 tid: 102655, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102656, pid: 102370
│     ├─ {containerd-shim}💀 tid: 102911, pid: 101107
│     ├─ {containerd-shim}💀 tid: 103741, pid: 102340
│     ├─ [containerd-shim]💀 tid: 107196, pid: 107196
│     │  ├─ [pause] tid: 107216, pid: 107216
│     │  ├─ [sleep] tid: 107255, pid: 107255
│     │  └─ [sh] tid: 107364, pid: 107364
│     │     └─ [tail] tid: 107370, pid: 107370
│     ├─ {containerd-shim}💀 tid: 107197, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107198, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107199, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107200, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107201, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107202, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107203, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107204, pid: 107196
│     ├─ {containerd-shim}💀 tid: 107205, pid: 107196
│     └─ {containerd-shim}💀 tid: 107268, pid: 107196
├─ {containerd-shim}💀 tid: 100543, pid: 100542
├─ {containerd-shim}💀 tid: 100544, pid: 100542
├─ {containerd-shim}💀 tid: 100545, pid: 100542
├─ {containerd-shim}💀 tid: 100546, pid: 100542
├─ {containerd-shim}💀 tid: 100547, pid: 100542
├─ {containerd-shim}💀 tid: 100548, pid: 100542
├─ {containerd-shim}💀 tid: 100549, pid: 100542
├─ {containerd-shim}💀 tid: 100550, pid: 100542
├─ {containerd-shim}💀 tid: 100635, pid: 100542
├─ {containerd-shim}💀 tid: 100845, pid: 100542
├─ [zsh] tid: 102956, pid: 102956
│  ├─ [gitstatusd-linu] tid: 102987, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102988, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102989, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102990, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102991, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102992, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102993, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102994, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102995, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102996, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102997, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102998, pid: 102987
│  ├─ {gitstatusd-linu} tid: 102999, pid: 102987
│  ├─ {gitstatusd-linu} tid: 103000, pid: 102987
│  ├─ {gitstatusd-linu} tid: 103001, pid: 102987
│  ├─ {gitstatusd-linu} tid: 103002, pid: 102987
│  └─ {gitstatusd-linu} tid: 103003, pid: 102987
├─ [zsh] tid: 102984, pid: 102984
├─ [zsh] tid: 102985, pid: 102985
├─ [zsh] tid: 104151, pid: 104151
│  ├─ [gitstatusd-linu] tid: 104182, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104183, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104184, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104185, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104186, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104187, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104188, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104189, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104190, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104191, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104192, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104193, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104194, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104195, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104196, pid: 104182
│  ├─ {gitstatusd-linu} tid: 104197, pid: 104182
│  └─ {gitstatusd-linu} tid: 104198, pid: 104182
├─ [zsh] tid: 104179, pid: 104179
├─ [zsh] tid: 104180, pid: 104180
└─ {containerd-shim}💀 tid: 104497, pid: 100542
```
