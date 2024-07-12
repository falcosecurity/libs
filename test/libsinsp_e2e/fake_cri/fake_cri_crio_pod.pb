status {
id: "e16577158fb2003bc4d0a152dd0e2bda888235d0f131ff93390d16138c11c556"
metadata {
	name: "falco-w5fbj"
	uid: "153b7a61-28b4-11e9-afc4-16bf8ef8d9dc"
	namespace: "default"
	attempt: 0
}
state: SANDBOX_READY
created_at: 1549308953113637984
network {
	ip: "172.31.95.87"
}
linux {
namespaces {
options {
	network: NODE
	pid: NODE
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
	value: "56d6c4cf5"
}
labels {
	key: "io.kubernetes.container.name"
	value: "POD"
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
labels {
	key: "pod-template-generation"
	value: "2"
}
annotations {
	key: "kubernetes.io/config.seen"
	value: "2019-02-04T19:35:52.701633172Z"
}
annotations {
	key: "kubernetes.io/config.source"
	value: "api"
}
}
info {
	key: "version"
	value: "{\"version\":\"1.26.0\"}"
}
