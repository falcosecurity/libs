containers {
id: "593f5b76be2afc23c39aa7eaa29174eac353d32be5e006b710c01aacca4aa05e"
pod_sandbox_id: "599ad631db94fef0be7722785e299ba128bd3f7f83a27dd00e4f94974eb5acfa"
metadata {
    name: "falco-2"
    attempt: 0
}
state: CONTAINER_RUNNING
created_at: 1545339739712670450
image {
    image: "docker.io/falcosecurity/falco:latest"
}
image_ref: "docker.io/falcosecurity/falco@sha256:4df3aba7463d88aefbab4eb9e241468b0475f5e8c2c138d4cd811ca812975612"
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
