# kexec_arm64

This capture was taken on an arm64 Ubuntu machine

```
Linux 5.19.0-1024-aws #25~22.04.1-Ubuntu SMP Tue Apr 18 23:43:29 UTC 2023 aarch64 aarch64 aarch64 GNU/Linux
```

We used [sysdig tool](https://github.com/draios/sysdig) with the kernel module to dump the scap-file

## Environment

These are the commands we run to set up the environment

```bash
kind create cluster
sudo kubectl apply -f https://k8s.io/examples/pods/simple-pod.yaml
```

When the pod is ready:

1. We start the capture with sysdig
2. We run:

```bash
kubectl exec -it nginx -- env KEY=123 /bin/bash
touch hello
tail -f /proc/self/status
exit
```

3. We stop the capture

## Tests

* `tail_lineage` -> assert the `tail` process lineage in 2 different moments: immediately after the `tail` execve event and after all `runc` threads are dead. See the test comments for more details
* `final_thread_table_dim` -> assert the dimension of the thread table at the end of the capture to ensure that we don't break the removal thread logic with new changes.

### Additional info

These data are collected directly from the running system before stopping the capture, so with `tail` still alive

**Tail lineage after all runc threads are dead**

```plain
📜 Process Lineage for tid: 141546
⬇️ [tail] tid: 141546, pid: 141546, rptid: 141446, rppid: 141446
⬇️ [bash] tid: 141446, pid: 141446, rptid: 141207, rppid: 141207
⬇️ [containerd-shim]💀 tid: 141207, pid: 141207, rptid: 112983, rppid: 112983
⬇️ [systemd] tid: 112983, pid: 112983, rptid: 112962, rppid: 112962
⬇️ [containerd-shim]💀 tid: 112962, pid: 112962, rptid: 1, rppid: 1
⬇️ [systemd] tid: 1, pid: 1, rptid: 0, rppid: 0
```

**Full process tree**

```plain
🌴 Process Tree for tid: 1
[systemd] tid: 1, pid: 1
├─ [systemd-journal] tid: 242, pid: 242
├─ [multipathd] tid: 287, pid: 287
├─ {multipathd} tid: 291, pid: 287
├─ [systemd-udevd] tid: 292, pid: 292
├─ {multipathd} tid: 293, pid: 287
├─ {multipathd} tid: 294, pid: 287
├─ {multipathd} tid: 295, pid: 287
├─ {multipathd} tid: 296, pid: 287
├─ {multipathd} tid: 297, pid: 287
├─ [systemd-network] tid: 491, pid: 491
├─ [systemd-resolve] tid: 493, pid: 493
├─ [cron] tid: 533, pid: 533
├─ [dbus-daemon] tid: 534, pid: 534
├─ [irqbalance] tid: 542, pid: 542
├─ [networkd-dispat] tid: 543, pid: 543
├─ [rsyslogd] tid: 544, pid: 544
├─ [amazon-ssm-agen] tid: 545, pid: 545
├─ [snapd] tid: 549, pid: 549
├─ [systemd-logind] tid: 552, pid: 552
├─ {gmain} tid: 555, pid: 542
├─ [containerd] tid: 557, pid: 557
├─ [chronyd] tid: 561, pid: 561
│  └─ [chronyd] tid: 573, pid: 573
├─ {in:imuxsock} tid: 562, pid: 544
├─ {in:imklog} tid: 563, pid: 544
├─ {rs:main Q:Reg} tid: 564, pid: 544
├─ [agetty] tid: 579, pid: 579
├─ [agetty] tid: 607, pid: 607
├─ {containerd} tid: 609, pid: 557
├─ {containerd} tid: 611, pid: 557
├─ {containerd} tid: 612, pid: 557
├─ {containerd} tid: 613, pid: 557
├─ {containerd} tid: 614, pid: 557
├─ [unattended-upgr] tid: 642, pid: 642
├─ [polkitd] tid: 657, pid: 657
├─ {gmain} tid: 665, pid: 657
├─ {gdbus} tid: 667, pid: 657
├─ {containerd} tid: 718, pid: 557
├─ {containerd} tid: 719, pid: 557
├─ {containerd} tid: 723, pid: 557
├─ {gmain} tid: 729, pid: 642
├─ {containerd} tid: 732, pid: 557
├─ {containerd} tid: 733, pid: 557
├─ {containerd} tid: 735, pid: 557
├─ [dockerd] tid: 738, pid: 738
├─ [sshd] tid: 739, pid: 739
│  ├─ [sshd] tid: 118057, pid: 118057
│  │  └─ [sshd] tid: 118183, pid: 118183
│  │     └─ [zsh] tid: 118184, pid: 118184
│  └─ [sshd] tid: 129189, pid: 129189
│     └─ [sshd] tid: 129339, pid: 129339
│        └─ [zsh] tid: 129340, pid: 129340
│           └─ [bash] tid: 129354, pid: 129354
├─ {dockerd} tid: 740, pid: 738
├─ {dockerd} tid: 741, pid: 738
├─ {dockerd} tid: 742, pid: 738
├─ {dockerd} tid: 743, pid: 738
├─ {dockerd} tid: 744, pid: 738
├─ {dockerd} tid: 745, pid: 738
├─ {dockerd} tid: 746, pid: 738
├─ {dockerd} tid: 747, pid: 738
├─ {dockerd} tid: 748, pid: 738
├─ {snapd} tid: 759, pid: 549
├─ {snapd} tid: 760, pid: 549
├─ {snapd} tid: 761, pid: 549
├─ {snapd} tid: 762, pid: 549
├─ {snapd} tid: 764, pid: 549
├─ {dockerd} tid: 765, pid: 738
├─ {snapd} tid: 782, pid: 549
├─ {snapd} tid: 803, pid: 549
├─ {snapd} tid: 807, pid: 549
├─ {snapd} tid: 821, pid: 549
├─ {snapd} tid: 822, pid: 549
├─ {snapd} tid: 824, pid: 549
├─ {snapd} tid: 825, pid: 549
├─ {snapd} tid: 826, pid: 549
├─ {amazon-ssm-agen} tid: 881, pid: 545
├─ {amazon-ssm-agen} tid: 887, pid: 545
│  ├─ [ssm-agent-worke] tid: 1090, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1092, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1093, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1094, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1095, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1096, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1097, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1098, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1099, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1100, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1101, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1102, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1112, pid: 1090
│  ├─ {ssm-agent-worke} tid: 1113, pid: 1090
│  └─ {ssm-agent-worke} tid: 1255, pid: 1090
├─ {amazon-ssm-agen} tid: 890, pid: 545
├─ {amazon-ssm-agen} tid: 891, pid: 545
├─ {amazon-ssm-agen} tid: 892, pid: 545
├─ {snapd} tid: 930, pid: 549
├─ {snapd} tid: 966, pid: 549
├─ {amazon-ssm-agen} tid: 978, pid: 545
├─ {amazon-ssm-agen} tid: 981, pid: 545
├─ {snapd} tid: 1036, pid: 549
├─ {dockerd} tid: 1055, pid: 738
├─ {snapd} tid: 1061, pid: 549
├─ {snapd} tid: 1062, pid: 549
├─ {snapd} tid: 1063, pid: 549
├─ {amazon-ssm-agen} tid: 1091, pid: 545
├─ {amazon-ssm-agen} tid: 1108, pid: 545
├─ {amazon-ssm-agen} tid: 1109, pid: 545
├─ {amazon-ssm-agen} tid: 1110, pid: 545
├─ {amazon-ssm-agen} tid: 1111, pid: 545
├─ {amazon-ssm-agen} tid: 1115, pid: 545
├─ {amazon-ssm-agen} tid: 1134, pid: 545
├─ [packagekitd] tid: 2333, pid: 2333
├─ {gmain} tid: 2334, pid: 2333
├─ {gdbus} tid: 2335, pid: 2333
├─ {dockerd} tid: 3967, pid: 738
├─ {dockerd} tid: 3968, pid: 738
├─ {dockerd} tid: 3969, pid: 738
│  ├─ [docker-proxy] tid: 112948, pid: 112948
│  ├─ {docker-proxy} tid: 112949, pid: 112948
│  ├─ {docker-proxy} tid: 112950, pid: 112948
│  ├─ {docker-proxy} tid: 112951, pid: 112948
│  ├─ {docker-proxy} tid: 112952, pid: 112948
│  ├─ {docker-proxy} tid: 112953, pid: 112948
│  └─ {docker-proxy} tid: 112954, pid: 112948
├─ {containerd} tid: 4650, pid: 557
├─ [systemd]💀 tid: 109755, pid: 109755
│  └─ [(sd-pam)] tid: 109756, pid: 109756
├─ [containerd-shim]💀 tid: 112962, pid: 112962
│  └─ [systemd] tid: 112983, pid: 112983
│     ├─ [systemd-journal] tid: 113218, pid: 113218
│     ├─ [containerd] tid: 113230, pid: 113230
│     ├─ {containerd} tid: 113231, pid: 113230
│     ├─ {containerd} tid: 113233, pid: 113230
│     ├─ {containerd} tid: 113234, pid: 113230
│     ├─ {containerd} tid: 113235, pid: 113230
│     ├─ {containerd} tid: 113237, pid: 113230
│     ├─ {containerd} tid: 113238, pid: 113230
│     ├─ {containerd} tid: 113241, pid: 113230
│     ├─ {containerd} tid: 113242, pid: 113230
│     ├─ [containerd-shim]💀 tid: 113628, pid: 113628
│     │  ├─ [pause] tid: 113721, pid: 113721
│     │  ├─ [kube-apiserver] tid: 113870, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113920, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113921, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113922, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113923, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113924, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113929, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113930, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113932, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113934, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113995, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113996, pid: 113870
│     │  ├─ {kube-apiserver} tid: 113997, pid: 113870
│     │  └─ {kube-apiserver} tid: 114031, pid: 113870
│     ├─ {containerd-shim}💀 tid: 113632, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113633, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113634, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113635, pid: 113628
│     ├─ [containerd-shim]💀 tid: 113636, pid: 113636
│     │  ├─ [pause] tid: 113733, pid: 113733
│     │  ├─ [etcd] tid: 113967, pid: 113967
│     │  ├─ {etcd} tid: 113986, pid: 113967
│     │  ├─ {etcd} tid: 113987, pid: 113967
│     │  ├─ {etcd} tid: 113988, pid: 113967
│     │  ├─ {etcd} tid: 113989, pid: 113967
│     │  ├─ {etcd} tid: 113990, pid: 113967
│     │  ├─ {etcd} tid: 113991, pid: 113967
│     │  ├─ {etcd} tid: 113992, pid: 113967
│     │  ├─ {etcd} tid: 113993, pid: 113967
│     │  ├─ {etcd} tid: 114011, pid: 113967
│     │  ├─ {etcd} tid: 114012, pid: 113967
│     │  ├─ {etcd} tid: 114013, pid: 113967
│     │  ├─ {etcd} tid: 114032, pid: 113967
│     │  ├─ {etcd} tid: 114033, pid: 113967
│     │  ├─ {etcd} tid: 140503, pid: 113967
│     │  └─ {etcd} tid: 140504, pid: 113967
│     ├─ {containerd-shim}💀 tid: 113637, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113638, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113639, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113640, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113641, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113642, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113643, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113644, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113645, pid: 113628
│     ├─ {containerd-shim}💀 tid: 113646, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113647, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113648, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113649, pid: 113636
│     ├─ [containerd-shim]💀 tid: 113676, pid: 113676
│     │  ├─ [pause] tid: 113741, pid: 113741
│     │  ├─ [kube-controller] tid: 113860, pid: 113860
│     │  ├─ {kube-controller} tid: 113914, pid: 113860
│     │  ├─ {kube-controller} tid: 113915, pid: 113860
│     │  ├─ {kube-controller} tid: 113916, pid: 113860
│     │  ├─ {kube-controller} tid: 113917, pid: 113860
│     │  ├─ {kube-controller} tid: 113918, pid: 113860
│     │  ├─ {kube-controller} tid: 113927, pid: 113860
│     │  ├─ {kube-controller} tid: 113928, pid: 113860
│     │  ├─ {kube-controller} tid: 113933, pid: 113860
│     │  └─ {kube-controller} tid: 114029, pid: 113860
│     ├─ {containerd-shim}💀 tid: 113677, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113678, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113679, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113680, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113685, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113686, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113687, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113688, pid: 113676
│     ├─ {containerd-shim}💀 tid: 113689, pid: 113676
│     ├─ [containerd-shim]💀 tid: 113695, pid: 113695
│     │  ├─ [pause] tid: 113748, pid: 113748
│     │  ├─ [kube-scheduler] tid: 113849, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113901, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113902, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113903, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113904, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113919, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113925, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113926, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113931, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113945, pid: 113849
│     │  ├─ {kube-scheduler} tid: 113946, pid: 113849
│     │  └─ {kube-scheduler} tid: 113947, pid: 113849
│     ├─ {containerd-shim}💀 tid: 113696, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113697, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113698, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113699, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113705, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113706, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113707, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113708, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113709, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113710, pid: 113695
│     ├─ {containerd-shim}💀 tid: 113711, pid: 113695
│     ├─ {containerd} tid: 113778, pid: 113230
│     ├─ {containerd} tid: 113779, pid: 113230
│     ├─ {containerd} tid: 113780, pid: 113230
│     ├─ {containerd} tid: 113782, pid: 113230
│     ├─ {containerd} tid: 113784, pid: 113230
│     ├─ {containerd} tid: 113789, pid: 113230
│     ├─ {containerd} tid: 113791, pid: 113230
│     ├─ {containerd-shim}💀 tid: 113956, pid: 113636
│     ├─ {containerd-shim}💀 tid: 113979, pid: 113636
│     ├─ [kubelet] tid: 114086, pid: 114086
│     ├─ {kubelet} tid: 114087, pid: 114086
│     ├─ {kubelet} tid: 114088, pid: 114086
│     ├─ {kubelet} tid: 114089, pid: 114086
│     ├─ {kubelet} tid: 114090, pid: 114086
│     ├─ {kubelet} tid: 114091, pid: 114086
│     ├─ {kubelet} tid: 114093, pid: 114086
│     ├─ {kubelet} tid: 114094, pid: 114086
│     ├─ {kubelet} tid: 114095, pid: 114086
│     ├─ {kubelet} tid: 114096, pid: 114086
│     ├─ {kubelet} tid: 114098, pid: 114086
│     ├─ {kubelet} tid: 114099, pid: 114086
│     ├─ {kubelet} tid: 114100, pid: 114086
│     ├─ {kubelet} tid: 114107, pid: 114086
│     ├─ {kubelet} tid: 114112, pid: 114086
│     ├─ {containerd-shim}💀 tid: 114147, pid: 113676
│     ├─ {containerd-shim}💀 tid: 114148, pid: 113676
│     ├─ {containerd-shim}💀 tid: 114149, pid: 113676
│     ├─ {containerd-shim}💀 tid: 114155, pid: 113628
│     ├─ {containerd-shim}💀 tid: 114156, pid: 113628
│     ├─ {containerd-shim}💀 tid: 114499, pid: 113636
│     ├─ [containerd-shim]💀 tid: 114510, pid: 114510
│     │  ├─ [pause] tid: 114555, pid: 114555
│     │  ├─ [kube-proxy] tid: 114606, pid: 114606
│     │  ├─ {kube-proxy} tid: 114625, pid: 114606
│     │  ├─ {kube-proxy} tid: 114626, pid: 114606
│     │  ├─ {kube-proxy} tid: 114627, pid: 114606
│     │  ├─ {kube-proxy} tid: 114628, pid: 114606
│     │  ├─ {kube-proxy} tid: 114633, pid: 114606
│     │  ├─ {kube-proxy} tid: 114634, pid: 114606
│     │  ├─ {kube-proxy} tid: 114635, pid: 114606
│     │  ├─ {kube-proxy} tid: 114636, pid: 114606
│     │  └─ {kube-proxy} tid: 114637, pid: 114606
│     ├─ {containerd-shim}💀 tid: 114511, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114512, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114513, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114514, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114515, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114516, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114517, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114518, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114519, pid: 114510
│     ├─ [containerd-shim]💀 tid: 114537, pid: 114537
│     │  ├─ [pause] tid: 114565, pid: 114565
│     │  ├─ [kindnetd] tid: 114749, pid: 114749
│     │  ├─ {kindnetd} tid: 114797, pid: 114749
│     │  ├─ {kindnetd} tid: 114798, pid: 114749
│     │  ├─ {kindnetd} tid: 114799, pid: 114749
│     │  ├─ {kindnetd} tid: 114800, pid: 114749
│     │  ├─ {kindnetd} tid: 114820, pid: 114749
│     │  ├─ {kindnetd} tid: 114821, pid: 114749
│     │  ├─ {kindnetd} tid: 114822, pid: 114749
│     │  ├─ {kindnetd} tid: 114823, pid: 114749
│     │  └─ {kindnetd} tid: 116440, pid: 114749
│     ├─ {containerd-shim}💀 tid: 114538, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114539, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114540, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114541, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114543, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114544, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114545, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114546, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114547, pid: 114537
│     ├─ {containerd-shim}💀 tid: 114618, pid: 114510
│     ├─ {containerd-shim}💀 tid: 114790, pid: 114537
│     ├─ [containerd-shim]💀 tid: 114921, pid: 114921
│     │  ├─ [pause] tid: 115004, pid: 115004
│     │  ├─ [local-path-prov] tid: 115165, pid: 115165
│     │  ├─ {local-path-prov} tid: 115216, pid: 115165
│     │  ├─ {local-path-prov} tid: 115217, pid: 115165
│     │  ├─ {local-path-prov} tid: 115218, pid: 115165
│     │  ├─ {local-path-prov} tid: 115219, pid: 115165
│     │  ├─ {local-path-prov} tid: 115220, pid: 115165
│     │  ├─ {local-path-prov} tid: 115221, pid: 115165
│     │  ├─ {local-path-prov} tid: 115222, pid: 115165
│     │  ├─ {local-path-prov} tid: 115223, pid: 115165
│     │  ├─ {local-path-prov} tid: 115224, pid: 115165
│     │  ├─ {local-path-prov} tid: 115225, pid: 115165
│     │  ├─ {local-path-prov} tid: 115226, pid: 115165
│     │  └─ {local-path-prov} tid: 115227, pid: 115165
│     ├─ {containerd-shim}💀 tid: 114930, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114931, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114932, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114933, pid: 114921
│     ├─ [containerd-shim]💀 tid: 114935, pid: 114935
│     │  ├─ [pause] tid: 114995, pid: 114995
│     │  ├─ [coredns] tid: 115111, pid: 115111
│     │  ├─ {coredns} tid: 115183, pid: 115111
│     │  ├─ {coredns} tid: 115185, pid: 115111
│     │  ├─ {coredns} tid: 115187, pid: 115111
│     │  ├─ {coredns} tid: 115189, pid: 115111
│     │  ├─ {coredns} tid: 115195, pid: 115111
│     │  ├─ {coredns} tid: 115196, pid: 115111
│     │  ├─ {coredns} tid: 115197, pid: 115111
│     │  ├─ {coredns} tid: 115199, pid: 115111
│     │  ├─ {coredns} tid: 115200, pid: 115111
│     │  ├─ {coredns} tid: 115201, pid: 115111
│     │  ├─ {coredns} tid: 115205, pid: 115111
│     │  └─ {coredns} tid: 115857, pid: 115111
│     ├─ {containerd-shim}💀 tid: 114936, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114937, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114938, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114939, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114940, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114941, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114942, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114943, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114944, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114945, pid: 114921
│     ├─ {containerd-shim}💀 tid: 114947, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114948, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114949, pid: 114935
│     ├─ {containerd-shim}💀 tid: 114950, pid: 114935
│     ├─ [containerd-shim]💀 tid: 114971, pid: 114971
│     │  ├─ [pause] tid: 115012, pid: 115012
│     │  ├─ [coredns] tid: 115119, pid: 115119
│     │  ├─ {coredns} tid: 115184, pid: 115119
│     │  ├─ {coredns} tid: 115186, pid: 115119
│     │  ├─ {coredns} tid: 115188, pid: 115119
│     │  ├─ {coredns} tid: 115190, pid: 115119
│     │  ├─ {coredns} tid: 115192, pid: 115119
│     │  ├─ {coredns} tid: 115193, pid: 115119
│     │  ├─ {coredns} tid: 115198, pid: 115119
│     │  ├─ {coredns} tid: 115202, pid: 115119
│     │  ├─ {coredns} tid: 115203, pid: 115119
│     │  ├─ {coredns} tid: 115204, pid: 115119
│     │  ├─ {coredns} tid: 115228, pid: 115119
│     │  └─ {coredns} tid: 115229, pid: 115119
│     ├─ {containerd-shim}💀 tid: 114972, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114973, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114974, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114975, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114980, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114981, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114982, pid: 114971
│     ├─ {containerd-shim}💀 tid: 114983, pid: 114971
│     ├─ {containerd-shim}💀 tid: 115018, pid: 114935
│     ├─ {containerd-shim}💀 tid: 115031, pid: 114971
│     ├─ {containerd} tid: 115051, pid: 113230
│     ├─ {containerd-shim}💀 tid: 115159, pid: 114971
│     ├─ {containerd-shim}💀 tid: 115160, pid: 114935
│     ├─ {containerd-shim}💀 tid: 115235, pid: 114935
│     ├─ {containerd-shim}💀 tid: 115236, pid: 114537
│     ├─ {containerd-shim}💀 tid: 115237, pid: 114921
│     ├─ {containerd-shim}💀 tid: 115238, pid: 114921
│     ├─ {containerd-shim}💀 tid: 115619, pid: 114971
│     ├─ {containerd-shim}💀 tid: 115840, pid: 114510
│     ├─ {kubelet} tid: 115860, pid: 114086
│     ├─ {containerd-shim}💀 tid: 116822, pid: 113628
│     ├─ {containerd-shim}💀 tid: 117967, pid: 114510
│     ├─ {containerd-shim}💀 tid: 132686, pid: 114971
│     ├─ {containerd-shim}💀 tid: 140701, pid: 114537
│     ├─ [containerd-shim]💀 tid: 141207, pid: 141207
│     │  ├─ [pause] tid: 141227, pid: 141227
│     │  ├─ [nginx] tid: 141267, pid: 141267
│     │  │  └─ [nginx] tid: 141286, pid: 141286
│     │  └─ [bash] tid: 141446, pid: 141446
│     │     └─ [tail] tid: 141546, pid: 141546
│     ├─ {containerd-shim}💀 tid: 141208, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141209, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141210, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141211, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141212, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141213, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141214, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141215, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141233, pid: 141207
│     ├─ {containerd-shim}💀 tid: 141279, pid: 141207
│     └─ {containerd-shim}💀 tid: 141291, pid: 141207
├─ {containerd-shim}💀 tid: 112963, pid: 112962
├─ {containerd-shim}💀 tid: 112964, pid: 112962
├─ {containerd-shim}💀 tid: 112965, pid: 112962
├─ {containerd-shim}💀 tid: 112966, pid: 112962
├─ {containerd-shim}💀 tid: 112967, pid: 112962
├─ {containerd-shim}💀 tid: 112968, pid: 112962
├─ {containerd-shim}💀 tid: 112969, pid: 112962
├─ {containerd-shim}💀 tid: 112970, pid: 112962
├─ {containerd-shim}💀 tid: 112971, pid: 112962
├─ {containerd-shim}💀 tid: 113317, pid: 112962
├─ {containerd-shim}💀 tid: 117597, pid: 112962
├─ [zsh] tid: 118188, pid: 118188
│  ├─ [gitstatusd-linu] tid: 118219, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118220, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118221, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118222, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118223, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118224, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118225, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118226, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118227, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118228, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118229, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118230, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118231, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118232, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118233, pid: 118219
│  ├─ {gitstatusd-linu} tid: 118234, pid: 118219
│  └─ {gitstatusd-linu} tid: 118235, pid: 118219
├─ [zsh] tid: 118216, pid: 118216
├─ [zsh] tid: 118217, pid: 118217
├─ [sh] tid: 118506, pid: 118506
│  ├─ [node] tid: 118516, pid: 118516
│  │  ├─ [node] tid: 118552, pid: 118552
│  │  │  ├─ [zsh] tid: 129520, pid: 129520
│  │  │  │  └─ [sudo] tid: 141424, pid: 141424
│  │  │  │     └─ [sudo] tid: 141425, pid: 141425
│  │  │  │        ├─ [kubectl] tid: 141426, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141427, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141428, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141429, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141430, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141431, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141432, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141433, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141434, pid: 141426
│  │  │  │        ├─ {kubectl} tid: 141435, pid: 141426
│  │  │  │        └─ {kubectl} tid: 141436, pid: 141426
│  │  │  ├─ [zsh] tid: 132125, pid: 132125
│  │  │  │  └─ [sudo] tid: 141570, pid: 141570
│  │  │  │     └─ [sudo] tid: 141571, pid: 141571
│  │  │  │        ├─ [bpftree] tid: 141572, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141573, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141574, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141575, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141576, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141577, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141578, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141579, pid: 141572
│  │  │  │        ├─ {bpftree} tid: 141580, pid: 141572
│  │  │  │        └─ {bpftree} tid: 141581, pid: 141572
│  │  │  └─ [zsh] tid: 137822, pid: 137822
│  │  │     └─ [sudo] tid: 141406, pid: 141406
│  │  │        └─ [sudo] tid: 141407, pid: 141407
│  │  │           └─ [sysdig] tid: 141408, pid: 141408
│  │  ├─ {node} tid: 118553, pid: 118552
│  │  ├─ {node} tid: 118554, pid: 118552
│  │  ├─ {node} tid: 118555, pid: 118552
│  │  ├─ {node} tid: 118556, pid: 118552
│  │  ├─ {node} tid: 118557, pid: 118552
│  │  ├─ {node} tid: 118558, pid: 118552
│  │  ├─ {node} tid: 118559, pid: 118552
│  │  ├─ {node} tid: 118560, pid: 118552
│  │  ├─ {node} tid: 118561, pid: 118552
│  │  ├─ {node} tid: 118562, pid: 118552
│  │  ├─ [node] tid: 121001, pid: 121001
│  │  │  ├─ [cpptools] tid: 121080, pid: 121080
│  │  │  ├─ {cpptools} tid: 121081, pid: 121080
│  │  │  ├─ {cpptools} tid: 121082, pid: 121080
│  │  │  ├─ {cpptools} tid: 121083, pid: 121080
│  │  │  ├─ {cpptools} tid: 121084, pid: 121080
│  │  │  ├─ {cpptools} tid: 121085, pid: 121080
│  │  │  ├─ {cpptools} tid: 121086, pid: 121080
│  │  │  ├─ {cpptools} tid: 121087, pid: 121080
│  │  │  ├─ {cpptools} tid: 121088, pid: 121080
│  │  │  ├─ {cpptools} tid: 121089, pid: 121080
│  │  │  ├─ {cpptools} tid: 121090, pid: 121080
│  │  │  ├─ {cpptools} tid: 121091, pid: 121080
│  │  │  ├─ {cpptools} tid: 121092, pid: 121080
│  │  │  ├─ {cpptools} tid: 121219, pid: 121080
│  │  │  ├─ {cpptools} tid: 121220, pid: 121080
│  │  │  ├─ {cpptools} tid: 121221, pid: 121080
│  │  │  ├─ {cpptools} tid: 121222, pid: 121080
│  │  │  └─ {cpptools} tid: 135845, pid: 121080
│  │  ├─ {node} tid: 121002, pid: 121001
│  │  ├─ {node} tid: 121003, pid: 121001
│  │  ├─ {node} tid: 121004, pid: 121001
│  │  ├─ {node} tid: 121005, pid: 121001
│  │  ├─ {node} tid: 121006, pid: 121001
│  │  ├─ {node} tid: 121007, pid: 121001
│  │  ├─ {node} tid: 121008, pid: 121001
│  │  ├─ {node} tid: 121009, pid: 121001
│  │  ├─ {node} tid: 121010, pid: 121001
│  │  ├─ {node} tid: 121011, pid: 121001
│  │  ├─ [node] tid: 121012, pid: 121012
│  │  ├─ {node} tid: 121013, pid: 121012
│  │  ├─ {node} tid: 121014, pid: 121012
│  │  ├─ {node} tid: 121015, pid: 121012
│  │  ├─ {node} tid: 121016, pid: 121012
│  │  ├─ {node} tid: 121017, pid: 121012
│  │  ├─ {node} tid: 121018, pid: 121012
│  │  ├─ {node} tid: 121019, pid: 121012
│  │  ├─ {node} tid: 121020, pid: 121012
│  │  ├─ {node} tid: 121021, pid: 121012
│  │  ├─ {node} tid: 121022, pid: 121012
│  │  ├─ {node} tid: 121023, pid: 121012
│  │  ├─ {node} tid: 121024, pid: 121012
│  │  ├─ {node} tid: 121025, pid: 121001
│  │  ├─ {node} tid: 129521, pid: 118552
│  │  ├─ {node} tid: 132126, pid: 118552
│  │  └─ {node} tid: 137823, pid: 118552
│  ├─ {node} tid: 118517, pid: 118516
│  ├─ {node} tid: 118518, pid: 118516
│  ├─ {node} tid: 118519, pid: 118516
│  ├─ {node} tid: 118520, pid: 118516
│  ├─ {node} tid: 118521, pid: 118516
│  ├─ {node} tid: 118522, pid: 118516
│  ├─ {node} tid: 118538, pid: 118516
│  ├─ {node} tid: 118539, pid: 118516
│  ├─ {node} tid: 118540, pid: 118516
│  └─ {node} tid: 118541, pid: 118516
├─ [zsh] tid: 129554, pid: 129554
├─ [zsh] tid: 129555, pid: 129555
├─ [zsh] tid: 129558, pid: 129558
│  ├─ [gitstatusd-linu] tid: 129563, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129564, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129565, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129566, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129567, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129568, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129569, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129570, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129571, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129572, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129573, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129574, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129575, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129576, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129577, pid: 129563
│  ├─ {gitstatusd-linu} tid: 129578, pid: 129563
│  └─ {gitstatusd-linu} tid: 129579, pid: 129563
├─ [cpptools-srv] tid: 130623, pid: 130623
├─ {cpptools-srv} tid: 130624, pid: 130623
├─ {cpptools-srv} tid: 130625, pid: 130623
├─ {cpptools-srv} tid: 130626, pid: 130623
├─ {cpptools-srv} tid: 130627, pid: 130623
├─ {cpptools-srv} tid: 130628, pid: 130623
├─ {cpptools-srv} tid: 130629, pid: 130623
├─ {cpptools-srv} tid: 130630, pid: 130623
├─ {cpptools-srv} tid: 130631, pid: 130623
├─ {cpptools-srv} tid: 130632, pid: 130623
├─ {cpptools-srv} tid: 130633, pid: 130623
├─ {cpptools-srv} tid: 130634, pid: 130623
├─ {cpptools-srv} tid: 130635, pid: 130623
├─ {cpptools-srv} tid: 130636, pid: 130623
├─ {cpptools-srv} tid: 130637, pid: 130623
├─ {cpptools-srv} tid: 130643, pid: 130623
├─ [zsh] tid: 132130, pid: 132130
│  ├─ [gitstatusd-linu] tid: 132161, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132162, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132163, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132164, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132165, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132166, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132167, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132168, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132169, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132170, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132171, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132172, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132173, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132174, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132175, pid: 132161
│  ├─ {gitstatusd-linu} tid: 132176, pid: 132161
│  └─ {gitstatusd-linu} tid: 132177, pid: 132161
├─ [zsh] tid: 132158, pid: 132158
├─ [zsh] tid: 132159, pid: 132159
├─ [cpptools-srv] tid: 132533, pid: 132533
├─ {cpptools-srv} tid: 132534, pid: 132533
├─ {cpptools-srv} tid: 132535, pid: 132533
├─ {cpptools-srv} tid: 132536, pid: 132533
├─ {cpptools-srv} tid: 132537, pid: 132533
├─ {cpptools-srv} tid: 132538, pid: 132533
├─ {cpptools-srv} tid: 132539, pid: 132533
├─ {cpptools-srv} tid: 132540, pid: 132533
├─ {cpptools-srv} tid: 132541, pid: 132533
├─ {cpptools-srv} tid: 132542, pid: 132533
├─ {cpptools-srv} tid: 132543, pid: 132533
├─ {cpptools-srv} tid: 132544, pid: 132533
├─ {cpptools-srv} tid: 132545, pid: 132533
├─ {cpptools-srv} tid: 132546, pid: 132533
├─ {cpptools-srv} tid: 132547, pid: 132533
├─ {cpptools-srv} tid: 135825, pid: 132533
├─ [zsh] tid: 137827, pid: 137827
│  ├─ [gitstatusd-linu] tid: 137858, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137859, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137860, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137861, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137862, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137863, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137864, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137865, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137866, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137867, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137868, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137869, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137870, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137871, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137872, pid: 137858
│  ├─ {gitstatusd-linu} tid: 137873, pid: 137858
│  └─ {gitstatusd-linu} tid: 137874, pid: 137858
├─ [zsh] tid: 137855, pid: 137855
└─ [zsh] tid: 137856, pid: 137856
```
