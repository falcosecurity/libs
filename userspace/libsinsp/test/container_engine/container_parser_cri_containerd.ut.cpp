// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#if !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__) // MINIMAL_BUILD and emscripten don't support containers at all
#include <gtest/gtest.h>
#include <cri.h>
#include <libsinsp/cri.hpp>
#include <test/helpers/threads_helpers.h>
#include "../sinsp_with_test_input.h"

/*
 * Mock container runtime socket API responses for both container and pod in the containerd CRI scenario,
 * thereby enabling us to test the parser logic.
 * Since we're not querying the socket directly, calling higher-level parsing functions isn't feasible.
 * Instead, we perform targeted step-by-step tests that closely resemble the actual code flow.
 *
 * Note: The container and pod status responses below are mocked and don't come from a real server, so
 * some information might need to be added later. You can use the crictl tool to obtain realistic JSONs
 * by inspecting the container and pod with their truncated IDs:
 *
 * https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md
 *
 * sudo crictl ps
 * sudo crictl inspect ${CONTAINER_ID}
 *
 * sudo crictl pods
 * sudo crictl inspectp ${POD_ID}
 *
 * Many lists in the mock example JSONs were truncated and are not complete
 */

std::string container_info_json = R"({
    "sandboxID": "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
    "pid": 3721416,
    "removing": false,
    "snapshotKey": "3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e",
    "snapshotter": "overlayfs",
    "runtimeType": "io.containerd.runc.v2",
    "runtimeOptions": {},
    "config": {
    "metadata": {
        "name": "busybox"
    },
    "image": {
        "image": "busybox"
    },
    "envs": [
        {
          "key": "HOST_ROOT",
          "value": "/host"
        }
      ],
    "command": [
        "/bin/sh"
    ],
    "args": [
        "-c",
        "while true; do cat /etc/shadow; sleep 1; done"
    ],
    "log_path": "busybox.0.log",
    "linux": {
        "resources": {
        },
        "security_context": {
            "privileged": true,
            "namespace_options": {
                "pid": 1
        },
        "run_as_user": {},
        "masked_paths": [
            "/proc/mocl_masked"
        ],
        "readonly_paths": [
            "/proc/mock-readonly_path"
        ],
        "seccomp": {
            "profile_type": 1
        }
        }
    }
    },
    "runtimeSpec": {
    "ociVersion": "1.0.2-dev",
    "process": {
        "user": {
        "uid": 0,
        "gid": 0,
        "additionalGids": [
            0,
            10
        ]
        },
        "args": [
        "/bin/sh",
        "-c",
        "while true; do cat /etc/shadow; sleep 1; done"
        ],
        "env": [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOSTNAME=fedora"
        ],
        "cwd": "/",
        "capabilities": {
        "bounding": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ],
        "effective": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ],
        "permitted": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ]
        }
    },
    "root": {
        "path": "rootfs"
    },
    "mounts": [
        {
        "destination": "/dev/shm",
        "type": "bind",
        "source": "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a/shm",
        "options": [
            "rbind",
            "rprivate",
            "rw"
        ]
        }
    ],
    "annotations": {
        "io.kubernetes.cri.container-name": "busybox",
        "io.kubernetes.cri.container-type": "container",
        "io.kubernetes.cri.image-name": "docker.io/library/busybox:latest",
        "io.kubernetes.cri.sandbox-id": "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
        "io.kubernetes.cri.sandbox-name": "nginx-sandbox",
        "io.kubernetes.cri.sandbox-namespace": "default",
        "io.kubernetes.cri.sandbox-uid": "hdishddjaidwnduw9a43535366368"
    },
    "linux": {
        "resources": {
            "devices": [
                {
                "allow": false,
                "access": "rwm"
                }
            ],
            "memory": {
                "limit": 1073741824,
                "swap": 1073741824
            },
            "cpu": {
                "shares": 102,
                "quota": 50000,
                "period": 100
            }
        },
        "cgroupsPath": "/k8s.io/3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e",
        "namespaces": [
        {
            "type": "cgroup"
        }
        ]
    }
    }
})";

std::string pod_info_json = R"({
    "pid": 3721379,
    "processStatus": "running",
    "netNamespaceClosed": false,
    "image": "registry.k8s.io/pause:3.8",
    "snapshotKey": "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
    "snapshotter": "overlayfs",
    "runtimeHandler": "",
    "runtimeType": "io.containerd.runc.v2",
    "runtimeOptions": {},
    "config": {
    "metadata": {
        "name": "nginx-sandbox",
        "uid": "hdishddjaidwnduw9a43535366368",
        "namespace": "default",
        "attempt": 1
    },
    "log_directory": "/tmp",
    "linux": {}
    },
    "runtimeSpec": {
    "ociVersion": "1.0.2-dev",
    "process": {
        "user": {
        "uid": 65535,
        "gid": 65535,
        "additionalGids": [
            65535
        ]
        },
        "args": [
        "/pause"
        ],
        "env": [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ],
        "cwd": "/",
        "capabilities": {
        "bounding": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ],
        "effective": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ],
        "permitted": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_MKNOD",
            "CAP_NET_RAW",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETFCAP",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_SYS_CHROOT",
            "CAP_KILL",
            "CAP_AUDIT_WRITE"
        ]
        },
        "noNewPrivileges": true,
        "oomScoreAdj": -998
    },
    "root": {
        "path": "rootfs",
        "readonly": true
    },
    "mounts": [
        {
        "destination": "/etc/resolv.conf",
        "type": "bind",
        "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a/resolv.conf",
        "options": [
            "rbind",
            "ro"
        ]
        }
    ],
    "annotations": {
        "io.kubernetes.cri.container-type": "sandbox",
        "io.kubernetes.cri.sandbox-id": "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
        "io.kubernetes.cri.sandbox-log-directory": "/tmp",
        "io.kubernetes.cri.sandbox-name": "nginx-sandbox",
        "io.kubernetes.cri.sandbox-namespace": "default",
        "io.kubernetes.cri.sandbox-uid": "hdishddjaidwnduw9a43535366368"
    },
    "linux": {
        "resources": {
        "devices": [
            {
            "allow": false,
            "access": "rwm"
            }
        ],
        "cpu": {
            "shares": 2
        }
        },
        "cgroupsPath": "/k8s.io/63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
        "namespaces": [
        {
            "type": "network",
            "path": "/var/run/netns/cni-5ddce098-32ee-e39c-19c2-d6db782f6d20"
        }
        ],
        "maskedPaths": [
        "/proc/acpi"
        ],
        "readonlyPaths": [
        "/proc/bus"
        ]
    }
    },
    "cniResult": {
    "Interfaces": {
        "bridge": {
        "IPConfigs": null,
        "Mac": "ce:64:08:76:88:6a",
        "Sandbox": ""
        },
        "eth0": {
        "IPConfigs": [
            {
            "IP": "10.244.0.2",
            "Gateway": "10.244.0.1"
            }
        ],
        "Mac": "",
        "Sandbox": "/var/run/netns/cni-5ddce098-32ee-e39c-19c2-d6db782f6d20"
        },
        "lo": {
        "IPConfigs": [
            {
            "IP": "127.0.0.1",
            "Gateway": ""
            },
            {
            "IP": "::1",
            "Gateway": ""
            }
        ],
        "Mac": "00:00:00:00:00:00",
        "Sandbox": "/var/run/netns/cni-5ddce098-32ee-e39c-19c2-d6db782f6d20"
        },
        "veth69fb0f20": {
        "IPConfigs": null,
        "Mac": "",
        "Sandbox": ""
        }
    },
    "DNS": [
        {},
        {}
    ],
    "Routes": [
        {
        "dst": "0.0.0.0/0",
        "gw": "10.244.0.1"
        }
    ]
    }
})";

runtime::v1alpha2::ContainerStatusResponse get_default_cri_containerd_container_status_resp()
{

	//     "status": {
	//     "id": "3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e",
	//     "metadata": {
	//       "attempt": 0,
	//       "name": "busybox"
	//     },
	//     "state": "CONTAINER_RUNNING",
	//     "createdAt": "2023-12-12T00:15:15.768416865Z",
	//     "startedAt": "2023-12-12T00:15:15.858420829Z",
	//     "finishedAt": "0001-01-01T00:00:00Z",
	//     "exitCode": 0,
	//     "image": {
	//       "annotations": {},
	//       "image": "docker.io/library/busybox:latest"
	//     },
	//     "imageRef":
	//     "docker.io/library/busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79",
	//     "reason": "",
	//     "message": "",
	//     "labels": {
	//       "io.kubernetes.sandbox.id": "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
	//       "io.kubernetes.pod.uid": "hdishddjaidwnduw9a43535366368",
	//       "io.kubernetes.pod.namespace": "default",
	//       "io.kubernetes.pod.name": "nginx-sandbox"
	//     },
	//     "annotations": {
	//       "io.kubernetes.container.hash": "4689db3",
	//       "io.kubernetes.container.restartCount": "0",
	//       "io.kubernetes.pod.terminationGracePeriod": "30"
	//     },
	//     "mounts": [
	//       {
	//         "containerPath": "/host/boot",
	//         "hostPath": "/boot",
	//         "propagation": "PROPAGATION_PRIVATE",
	//         "readonly": true,
	//         "selinuxRelabel": false,
	//       },
	//       {
	//         "containerPath": "/host/proc",
	//         "hostPath": "/proc",
	//         "propagation": "PROPAGATION_PRIVATE",
	//         "readonly": true,
	//         "selinuxRelabel": false,
	//       }
	//     ],
	//     "logPath": "/tmp/busybox.0.log"
	//   },

	// Mock container runtime socket API responses ContainerStatusResponse
	// Note that some fields are not populated or tested
	runtime::v1alpha2::ContainerStatusResponse resp;

	auto status = resp.mutable_status();
	status->set_id("3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e");
	status->set_state(runtime::v1alpha2::ContainerState::CONTAINER_RUNNING); // "CONTAINER_RUNNING"
	status->set_created_at((uint64_t)1676262698000004577); // dummy
	status->set_started_at((uint64_t)1676262698000004577); // dummy
	status->set_image_ref("docker.io/library/busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79");
	status->mutable_image()->set_image("docker.io/library/busybox:latest");
	auto labels = status->mutable_labels();
	(*labels)["io.kubernetes.container.name"] = "busybox";
	(*labels)["io.kubernetes.pod.uid"] = "hdishddjaidwnduw9a43535366368";
	(*labels)["io.kubernetes.pod.namespace"] = "default";
	(*labels)["io.kubernetes.pod.name"] = "nginx-sandbox";
	auto annotations = status->mutable_annotations();
	(*annotations)["io.kubernetes.container.restartCount"] = "0";
	(*annotations)["io.kubernetes.container.hash"] = "4689db3";
	(*annotations)["io.kubernetes.pod.terminationGracePeriod"] = "30";
	status->mutable_metadata()->set_name("busybox");
	runtime::v1alpha2::Mount mount;
	mount.set_container_path("/host/boot");
	mount.set_host_path("/boot");
	mount.set_readonly(true);
	mount.set_selinux_relabel(false);
	mount.set_propagation(runtime::v1alpha2::MountPropagation::PROPAGATION_PRIVATE);
	status->mutable_mounts()->Add()->CopyFrom(mount);

	resp.mutable_info()->insert({"info", container_info_json});

	return resp;
}

runtime::v1alpha2::PodSandboxStatusResponse get_default_cri_containerd_pod_status_resp()
{

	//     "status": {
	//     "id": "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a",
	//     "metadata": {
	//       "attempt": 1,
	//       "name": "nginx-sandbox",
	//       "namespace": "default",
	//       "uid": "hdishddjaidwnduw9a43535366368"
	//     },
	//     "state": "SANDBOX_READY",
	//     "createdAt": "2023-12-12T00:15:14.434884181Z",
	//     "network": {
	//       "additionalIps": [],
	//       "ip": "10.244.0.2"
	//     },
	//     "linux": {
	//       "namespaces": {
	//         "options": {
	//           "ipc": "POD",
	//           "network": "POD",
	//           "pid": "POD",
	//           "targetId": ""
	//         }
	//       }
	//     },
	//     "labels": {
	//       "app": "myapp",
	//       "example.label": "mylabel",
	//       "io.kubernetes.pod.name": "nginx-sandbox",
	//       "io.kubernetes.pod.namespace": "default"
	//     },
	//     "annotations": {
	//       "ip-annotation-custom": "non-routable-ipv4",
	//       "example.annotation/custom": "myannotation"
	//     },
	//     "runtimeHandler": ""
	//   },

	// Mock container runtime socket API responses PodSandboxStatusResponse
	// Note that some fields are not populated or tested
	runtime::v1alpha2::PodSandboxStatusResponse resp;

	auto status = resp.mutable_status();
	status->set_id("63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a");
	status->set_state(runtime::v1alpha2::PodSandboxState::SANDBOX_READY);
    status->set_created_at((uint64_t)1676262698000004577); // dummy
	status->mutable_metadata()->set_name("nginx-sandbox");
	status->mutable_network()->set_ip("10.244.0.2");
	auto labels = status->mutable_labels();
	(*labels)["app"] = "myapp";
	(*labels)["example-label/custom_one"] = "mylabel";
	(*labels)["io.kubernetes.pod.namespace"] = "default";
	(*labels)["io.kubernetes.pod.name"] = "nginx-sandbox";
	auto annotations = status->mutable_annotations();
	(*annotations)["ip-annotation-custom"] = "non-routable-ipv4";
	(*annotations)["example.annotation/custom"] = "myannotation";
	auto metadata = status->mutable_metadata();
	metadata->set_attempt(0);
	metadata->set_name("nginx-sandbox");
	metadata->set_namespace_("default");
	metadata->set_uid("hdishddjaidwnduw9a43535366368");

	resp.mutable_info()->insert({"info", pod_info_json});

	return resp;
}

TEST_F(sinsp_with_test_input, container_parser_cri_containerd)
{
	std::string cri_path = "/run/containerd/containerd_mock.sock";
	auto cri_api_v1alpha2 = std::make_unique<libsinsp::cri::cri_interface_v1alpha2>(cri_path);
	ASSERT_FALSE(cri_api_v1alpha2->is_ok()); // we are not querying a container runtime socket in this mock test

	// Get mock responses
	runtime::v1alpha2::ContainerStatusResponse resp = get_default_cri_containerd_container_status_resp();
	runtime::v1alpha2::PodSandboxStatusResponse resp_pod = get_default_cri_containerd_pod_status_resp();

	// Step-by-step testing of core parsers given the current unit test limitations
	const auto &resp_container = resp.status();
	const auto &resp_container_info = resp.info();
	const auto &resp_sandbox_container = resp_pod.status();
	std::shared_ptr<sinsp_container_info> container_ptr = std::make_shared<sinsp_container_info>();
	// explicit reference to mimic actual code flow and test sub parser functions
	sinsp_container_info &container = *container_ptr;
	std::shared_ptr<sinsp_container_info> sandbox_container_ptr = std::make_shared<sinsp_container_info>();
	sinsp_container_info &sandbox_container = *sandbox_container_ptr;

	//
	// create and test sinsp_container_info for container
	//

	// Add basic fields manually
	container.m_type = CT_CONTAINERD;
	container.m_id = "3ad7b26ded6d"; // truncated id extracted from cgroups
	container.m_full_id = resp_container.id();
	container.m_name = resp_container.metadata().name();
	for(const auto &pair : resp_container.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			container.m_labels[pair.first] = pair.second;
		}
	}
	// CRI mounts
	auto res = cri_api_v1alpha2->parse_cri_mounts(resp_container, container);
	ASSERT_TRUE(res);
	// CRI image
	res = cri_api_v1alpha2->parse_cri_image(resp_container, resp_container_info, container);
	ASSERT_TRUE(res);
	ASSERT_EQ("3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e", container.m_full_id);
	ASSERT_EQ("docker.io/library/busybox:latest", container.m_image);
	ASSERT_EQ("docker.io/library/busybox", container.m_imagerepo);
	ASSERT_EQ("latest", container.m_imagetag);

	// CRI image, failure resilience test
	auto status = resp.mutable_status();
	status->set_image_ref("sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79");
	status->mutable_image()->set_image("");
	const auto &resp_container_simulate_image_recovery = resp.status();
	res = cri_api_v1alpha2->parse_cri_image(resp_container_simulate_image_recovery, resp_container_info, container);
	ASSERT_TRUE(res);
	ASSERT_EQ("docker.io/library/busybox:latest", container.m_image);
	ASSERT_EQ("docker.io/library/busybox", container.m_imagerepo);
	ASSERT_EQ("latest", container.m_imagetag);

	// network
	container.m_container_ip = ntohl(cri_api_v1alpha2->get_pod_sandbox_ip(resp_pod));
	ASSERT_EQ(183762946, container.m_container_ip); // decimal of "10.244.0.2"
	std::string cniresult = "";
	cri_api_v1alpha2->get_pod_info_cniresult(resp_pod, cniresult);
	ASSERT_EQ("{\"bridge\":{\"IPConfigs\":null},\"eth0\":{\"IPConfigs\":[{\"Gateway\":\"10.244.0.1\",\"IP\":\"10.244.0.2\"}]}}", cniresult);
	container.m_pod_cniresult = cniresult;

	// Extra info such as privileged flag
	const auto &info_it = resp.info().find("info");
	Json::Value root;
	Json::Reader reader;
	if(!reader.parse(info_it->second, root))
	{
		ASSERT(false);
	}
	res = cri_api_v1alpha2->parse_cri_ext_container_info(root, container);
	ASSERT_TRUE(res);
	ASSERT_TRUE(container.m_privileged);
	ASSERT_EQ(1073741824, container.m_memory_limit);
	ASSERT_EQ(50000, container.m_cpu_quota);

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		const auto pod_sandbox_id = root["sandboxID"].asString();
		// Add the pod sandbox id as label to the container.
		// This labels is needed by the filterchecks code to get the pod labels.
		container.m_labels["io.kubernetes.sandbox.id"] = pod_sandbox_id;
	}

	res = cri_api_v1alpha2->parse_cri_json_image(root, container);
	ASSERT_TRUE(res);
	ASSERT_EQ("busybox", container.m_imageid); // info.config.image.image can sometimes be in the format sha256: ...

	//
	// create and test sinsp_container_info for sandbox_container
	//

	// Add basic fields manually
	sandbox_container.m_is_pod_sandbox = true;
	sandbox_container.m_type = CT_CONTAINERD;
	sandbox_container.m_id = "63060edc2d3a"; // truncated id extracted from cgroups, here for the sandbox id / pod
	sandbox_container.m_full_id = resp_sandbox_container.id();
	sandbox_container.m_name = resp_sandbox_container.metadata().name();
	for(const auto &pair : resp_sandbox_container.labels())
	{
		if(pair.second.length() <= sinsp_container_info::m_container_label_max_length)
		{
			sandbox_container.m_labels[pair.first] = pair.second;
		}
	}

	// 
	// Test sinsp filterchecks, similar to spawn_process_container test
	// 

	add_default_init_thread();
	open_inspector();
	sinsp_evt *evt = NULL;

	uint64_t parent_pid = 1, parent_tid = 1, child_pid = 20, child_tid = 20;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	std::vector<std::string> cgroups = {
		"cgroups=cpuset=/k8s.io/3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e",
		"cpu=/k8s.io/3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e", "cpuacct=/",
		"blkio=/k8s.io/3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e",
		"memory=/k8s.io/3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e"};
	std::string cgroupsv = test_utils::to_null_delimited(cgroups);
	std::string container_json = m_inspector.m_container_manager.container_to_json(container);
	std::string sandbox_container_json = m_inspector.m_container_manager.container_to_json(sandbox_container);

	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
	add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, (uint64_t)1, (uint64_t)1, (uint64_t)0, "", (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint32_t)12088, (uint32_t)7208, (uint32_t)0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t)(PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID | PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS), (uint32_t)1000, (uint32_t)1000, (uint64_t)parent_tid, (uint64_t)parent_pid);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, (uint64_t)0, "bash", empty_bytebuf, child_tid, child_pid, (uint64_t)1, "", (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint32_t)12088, (uint32_t)3764, (uint32_t)0, "bash", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t)(PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID | PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS), (uint32_t)1000, (uint32_t)1000, (uint64_t)1, (uint64_t)1);
	add_event_advance_ts(increasing_ts(), -1, PPME_CONTAINER_JSON_2_E, 1, container_json.c_str());
	// todo: don't seem to be able to add the sandbox container via injecting another container event
	// add manually to container cache for now
	m_inspector.m_container_manager.add_container(std::move(sandbox_container_ptr), nullptr);
	add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");
	evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/bin/test-exe", empty_bytebuf, child_tid, child_pid, parent_tid, "", (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, empty_bytebuf, (int32_t)34818, parent_pid, (uint32_t)0, (int32_t)PPM_EXE_UPPER_LAYER, parent_pid, parent_pid, parent_pid, (uint64_t)0, (uint64_t)0, (uint64_t)0, (uint32_t)0);

	// Check containers were added to the container cache
	const sinsp_container_info::ptr_t container_info_check = m_inspector.m_container_manager.get_container(container.m_id);
	ASSERT_TRUE(container_info_check);
	ASSERT_EQ("3ad7b26ded6d", container_info_check->m_id);
	const sinsp_container_info::ptr_t sandbox_container_info_check = m_inspector.m_container_manager.get_container(sandbox_container.m_id);
	ASSERT_TRUE(sandbox_container_info_check);
	ASSERT_EQ("63060edc2d3a", sandbox_container_info_check->m_id);

	// Check container and k8s related filter fields that are retrieved from the container runtime socket
	ASSERT_EQ(get_field_as_string(evt, "container.id"), "3ad7b26ded6d");
	ASSERT_EQ(get_field_as_string(evt, "container.full_id"), "3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e");
	ASSERT_EQ(get_field_as_string(evt, "container.name"), "busybox");
	ASSERT_EQ(get_field_as_string(evt, "container.image"), "docker.io/library/busybox:latest");
	ASSERT_EQ(get_field_as_string(evt, "container.image.id"), "busybox");
	ASSERT_EQ(get_field_as_string(evt, "container.type"), "containerd");
	ASSERT_EQ(get_field_as_string(evt, "container.privileged"), "true");
	ASSERT_EQ(get_field_as_string(evt, "container.mounts"), "/boot:/host/boot::false:private");
	ASSERT_EQ(get_field_as_string(evt, "container.mount.source[0]"), "/boot");
	ASSERT_EQ(get_field_as_string(evt, "container.mount.dest[0]"), "/host/boot");
	ASSERT_EQ(get_field_as_string(evt, "container.mount.propagation[/boot]"), "private");
	ASSERT_EQ(get_field_as_string(evt, "container.image.repository"), "docker.io/library/busybox");
	ASSERT_EQ(get_field_as_string(evt, "container.image.tag"), "latest");
	ASSERT_EQ(get_field_as_string(evt, "container.image.digest"), "sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79");
	ASSERT_EQ(get_field_as_string(evt, "container.ip"), "10.244.0.2");
	ASSERT_EQ(get_field_as_string(evt, "container.cni.json"), "{\"bridge\":{\"IPConfigs\":null},\"eth0\":{\"IPConfigs\":[{\"Gateway\":\"10.244.0.1\",\"IP\":\"10.244.0.2\"}]}}");

	ASSERT_EQ(get_field_as_string(evt, "k8s.ns.name"), "default");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.name"), "nginx-sandbox");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.id"), "hdishddjaidwnduw9a43535366368"); // legacy pod UID
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.uid"), get_field_as_string(evt, "k8s.pod.id")); // new semantically correct pod UID
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.sandbox_id"), "63060edc2d3a");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.full_sandbox_id"), "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label.example-label/custom_one"), "mylabel");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label[example-label/custom_one]"), "mylabel");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.labels"), "app:myapp, example-label/custom_one:mylabel");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.ip"), "10.244.0.2");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.cni.json"), "{\"bridge\":{\"IPConfigs\":null},\"eth0\":{\"IPConfigs\":[{\"Gateway\":\"10.244.0.1\",\"IP\":\"10.244.0.2\"}]}}");
}
#endif // MINIMAL_BUILD
