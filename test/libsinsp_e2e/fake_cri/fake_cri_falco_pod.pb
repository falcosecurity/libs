status {
metadata {
    name: "falco-9bzbj"
    uid: "893231bb-049a-11e9-9b30-0a583e8b7896"
    namespace: "default",
    attempt: 0
}
state: SANDBOX_READY
created_at: 1545339738831266021
network {
    ip: ""
}
linux {
namespaces {
options {
    network: NODE,
    pid: NODE,
    ipc: POD
}
}
}
labels {
    key: "app"
    value: "falco"
}
labels {
    key: "controller-revision-hash"
    value: "b5944cc84"
}
labels {
    key: "io.kubernetes.pod.name"
    value: "falco-9bzbj"
}
labels {
    key: "io.kubernetes.pod.namespace"
    value: "default"
}
labels {
    key: "io.kubernetes.pod.uid"
    value: "893231bb-049a-11e9-9b30-0a583e8b7896"
}
labels {
    key: "pod-template-generation"
    value: "1"
}
annotations {
    key: "kubernetes.io/config.seen"
    value: "2018-12-20T21:02:18.502551218Z"
}
annotations {
    key: "kubernetes.io/config.source"
    value: "api"
}
}
info {
    key: "info"
    value: "{\"pid\":31353, \"processStatus\":\"running\", \"netNamespaceClosed\":false, \"image\":\"k8s.gcr.io/pause:3.1\", \"snapshotKey\":\"599ad631db94fef0be7722785e299ba128bd3f7f83a27dd00e4f94974eb5acfa\", \"snapshotter\":\"overlayfs\", \"runtime\":{\"runtimeType\":\"io.containerd.runtime.v1.linux\", \"runtimeEngine\":\"\", \"runtimeRoot\":\"\"}, \"config\":{\"metadata\":{\"name\":\"falco-9bzbj\", \"uid\":\"893231bb-049a-11e9-9b30-0a583e8b7896\", \"namespace\":\"default\"}, \"log_directory\":\"/var/log/pods/893231bb-049a-11e9-9b30-0a583e8b7896\", \"dns_config\":{\"servers\":[\"10.96.0.10\"], \"searches\":[\"default.svc.cluster.local\", \"svc.cluster.local\", \"cluster.local\", \"us-east-2.compute.internal\"], \"options\":[\"ndots:5\"]}, \"labels\":{\"app\":\"falco\", \"controller-revision-hash\":\"b5944cc84\", \"io.kubernetes.pod.name\":\"falco-9bzbj\", \"io.kubernetes.pod.namespace\":\"default\", \"io.kubernetes.pod.uid\":\"893231bb-049a-11e9-9b30-0a583e8b7896\", \"pod-template-generation\":\"1\"}, \"annotations\":{\"kubernetes.io/config.seen\":\"2018-12-20T21:02:18.502551218Z\", \"kubernetes.io/config.source\":\"api\"}, \"linux\":{\"cgroup_parent\":\"/kubepods/burstable/pod893231bb-049a-11e9-9b30-0a583e8b7896\", \"security_context\":{\"namespace_options\":{\"network\":2, \"pid\":2}, \"privileged\":true}}}, \"runtimeSpec\":{\"ociVersion\":\"1.0.1\", \"process\":{\"user\":{\"uid\":0, \"gid\":0}, \"args\":[\"/pause\"], \"env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"], \"cwd\":\"/\", \"capabilities\":{\"bounding\":[\"CAP_CHOWN\", \"CAP_DAC_OVERRIDE\", \"CAP_FSETID\", \"CAP_FOWNER\", \"CAP_MKNOD\", \"CAP_NET_RAW\", \"CAP_SETGID\", \"CAP_SETUID\", \"CAP_SETFCAP\", \"CAP_SETPCAP\", \"CAP_NET_BIND_SERVICE\", \"CAP_SYS_CHROOT\", \"CAP_KILL\", \"CAP_AUDIT_WRITE\"], \"effective\":[\"CAP_CHOWN\", \"CAP_DAC_OVERRIDE\", \"CAP_FSETID\", \"CAP_FOWNER\", \"CAP_MKNOD\", \"CAP_NET_RAW\", \"CAP_SETGID\", \"CAP_SETUID\", \"CAP_SETFCAP\", \"CAP_SETPCAP\", \"CAP_NET_BIND_SERVICE\", \"CAP_SYS_CHROOT\", \"CAP_KILL\", \"CAP_AUDIT_WRITE\"], \"inheritable\":[\"CAP_CHOWN\", \"CAP_DAC_OVERRIDE\", \"CAP_FSETID\", \"CAP_FOWNER\", \"CAP_MKNOD\", \"CAP_NET_RAW\", \"CAP_SETGID\", \"CAP_SETUID\", \"CAP_SETFCAP\", \"CAP_SETPCAP\", \"CAP_NET_BIND_SERVICE\", \"CAP_SYS_CHROOT\", \"CAP_KILL\", \"CAP_AUDIT_WRITE\"], \"permitted\":[\"CAP_CHOWN\", \"CAP_DAC_OVERRIDE\", \"CAP_FSETID\", \"CAP_FOWNER\", \"CAP_MKNOD\", \"CAP_NET_RAW\", \"CAP_SETGID\", \"CAP_SETUID\", \"CAP_SETFCAP\", \"CAP_SETPCAP\", \"CAP_NET_BIND_SERVICE\", \"CAP_SYS_CHROOT\", \"CAP_KILL\", \"CAP_AUDIT_WRITE\"]}, \"noNewPrivileges\":true, \"oomScoreAdj\":-998}, \"root\":{\"path\":\"rootfs\", \"readonly\":true}, \"mounts\":[{\"destination\":\"/proc\", \"type\":\"proc\", \"source\":\"proc\"}, {\"destination\":\"/dev\", \"type\":\"tmpfs\", \"source\":\"tmpfs\", \"options\":[\"nosuid\", \"strictatime\", \"mode=755\", \"size=65536k\"]}, {\"destination\":\"/dev/pts\", \"type\":\"devpts\", \"source\":\"devpts\", \"options\":[\"nosuid\", \"noexec\", \"newinstance\", \"ptmxmode=0666\", \"mode=0620\", \"gid=5\"]}, {\"destination\":\"/dev/mqueue\", \"type\":\"mqueue\", \"source\":\"mqueue\", \"options\":[\"nosuid\", \"noexec\", \"nodev\"]}, {\"destination\":\"/sys\", \"type\":\"sysfs\", \"source\":\"sysfs\", \"options\":[\"nosuid\", \"noexec\", \"nodev\", \"ro\"]}, {\"destination\":\"/dev/shm\", \"type\":\"bind\", \"source\":\"/run/containerd/io.containerd.grpc.v1.cri/sandboxes/599ad631db94fef0be7722785e299ba128bd3f7f83a27dd00e4f94974eb5acfa/shm\", \"options\":[\"rbind\", \"ro\"]}], \"annotations\":{\"io.kubernetes.cri.container-type\":\"sandbox\", \"io.kubernetes.cri.sandbox-id\":\"599ad631db94fef0be7722785e299ba128bd3f7f83a27dd00e4f94974eb5acfa\"}, \"linux\":{\"resources\":{\"devices\":[{\"allow\":false, \"access\":\"rwm\"}], \"cpu\":{\"shares\":2}}, \"cgroupsPath\":\"/kubepods/burstable/pod893231bb-049a-11e9-9b30-0a583e8b7896/599ad631db94fef0be7722785e299ba128bd3f7f83a27dd00e4f94974eb5acfa\", \"namespaces\":[{\"type\":\"ipc\"}, {\"type\":\"uts\"}, {\"type\":\"mount\"}], \"maskedPaths\":[\"/proc/acpi\", \"/proc/kcore\", \"/proc/keys\", \"/proc/latency_stats\", \"/proc/timer_list\", \"/proc/timer_stats\", \"/proc/sched_debug\", \"/sys/firmware\", \"/proc/scsi\"], \"readonlyPaths\":[\"/proc/asound\", \"/proc/bus\", \"/proc/fs\", \"/proc/irq\", \"/proc/sys\", \"/proc/sysrq-trigger\"]}}}"
}
