status {
id: "aec4c703604b4504df03108eef12e8256870eca8aabcb251855a35bf4f0337f1"
metadata {
	name: "falco",
	attempt: 0
}
state: CONTAINER_EXITED
created_at: 1549308953419092021
started_at: 1549308953442910382
finished_at: 0
exit_code: 0
image {
	image: "docker.io/falcosecurity/falco:crio"
}
image_ref: "docker.io/falcosecurity/falco@sha256:5241704b37e01f7bbca0ef6a90f5034731eba85320afd2eb9e4bce7ab09165a2"
labels {
	key: "io.kubernetes.container.name"
	value: "falco"
}
labels {
	key: "io.kubernetes.pod.name"
	value: "falco-w5fbj"
}
labels {
	key: "io.kubernetes.pod.namespace"
	value: "default"
}
labels {
	key: "io.kubernetes.pod.uid"
	value: "153b7a61-28b4-11e9-afc4-16bf8ef8d9dc"
}
annotations {
	key: "io.kubernetes.container.hash"
	value: "9435c2ec"
}
annotations {
	key: "io.kubernetes.container.restartCount"
	value: "0"
}
annotations {
	key: "io.kubernetes.container.terminationMessagePath"
	value: "/dev/termination-log"
}
annotations {
	key: "io.kubernetes.container.terminationMessagePolicy"
	value: "File"
}
annotations {
	key: "io.kubernetes.pod.terminationGracePeriod"
	value: "5"
}
mounts {
	container_path: "/dev/shm"
	host_path: "/var/lib/kubelet/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/volumes/kubernetes.io~empty-dir/dshm"
	readonly: false
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/proc"
	host_path: "/proc"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/boot"
	host_path: "/boot"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/etc/hosts"
	host_path: "/var/lib/kubelet/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/etc-hosts"
	readonly: false
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/usr"
	host_path: "/usr"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/run"
	host_path: "/run"
	readonly: false
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/dev"
	host_path: "/dev"
	readonly: false
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/dev/termination-log"
	host_path: "/var/lib/kubelet/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/containers/falco/e01754de"
	readonly: false
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/lib/modules"
	host_path: "/lib/modules"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/host/var/run"
	host_path: "/run"
	readonly: false
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/opt/falco/etc/kubernetes/config"
	host_path: "/var/lib/kubelet/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/volumes/kubernetes.io~configmap/falco-config"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/opt/falco/etc/kubernetes/secrets"
	host_path: "/var/lib/kubelet/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/volumes/kubernetes.io~secret/falco-secrets"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
mounts {
	container_path: "/var/run/secrets/kubernetes.io/serviceaccount"
	host_path: "/var/lib/kubelet/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/volumes/kubernetes.io~secret/falco-token-wl4zl"
	readonly: true
	selinux_relabel: false
	propagation: PROPAGATION_PRIVATE
}
log_path: "/var/log/pods/153b7a61-28b4-11e9-afc4-16bf8ef8d9dc/-falco/0.log"
}
