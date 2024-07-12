containers {
id: "ea457cc8202bb5684ddd4a2845ad7450ad48fb01448da5172790dcc4641757b9"
pod_sandbox_id: "e16577158fb2003bc4d0a152dd0e2bda888235d0f131ff93390d16138c11c556"
metadata {
    name: "falco"
    attempt: 0
}
state: CONTAINER_RUNNING
created_at: 1545339739712670450
image {
    image: "docker.io/falcosecurity/falco:latest"
}
image_ref: "docker.io/falcosecurity/falco@sha256:8d0619a4da278dfe2772f75aa3cc74df0a250385de56085766035db5c9a062ed"
labels {
    key: "io.kubernetes.container.name"
    value: "falco"
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
annotations {
    key: "io.kubernetes.container.hash"
    value: "decd134"
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
}
