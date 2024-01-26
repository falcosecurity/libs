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
#include <libsinsp/container_engine/cri.h>
#include <libsinsp/cri.hpp>
#include <test/helpers/threads_helpers.h>
#include "../sinsp_with_test_input.h"

/*
 * Mock container runtime socket API responses for both container and pod in the crio CRI scenario,
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

std::string container_info_json_crio = R"({
"sandboxID": "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca",
    "pid": 1835083,
    "runtimeSpec": {
      "ociVersion": "1.0.2-dev",
      "process": {
        "user": {
          "uid": 0,
          "gid": 0,
          "additionalGids": [
            0
          ]
        },
        "args": [
          "docker-entrypoint.sh",
          "docker-entrypoint.sh",
          "redis-server"
        ],
        "env": [
          "HOSTNAME=crictl_host"
        ],
        "cwd": "/data",
        "capabilities": {
          "bounding": [
            "CAP_SYS_ADMIN",
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ],
          "effective": [
            "CAP_SYS_ADMIN",
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ],
          "inheritable": [
            "CAP_SYS_ADMIN",
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ],
          "permitted": [
            "CAP_SYS_ADMIN",
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ]
        },
        "oomScoreAdj": 30
      },
      "root": {
        "path": "/var/lib/containers/storage/overlay/452374ade3f42caaea412ed8d221100864d3282e29acde3279db72f6d2468a67/merged"
      },
      "hostname": "crictl_host",
      "mounts": [
        {
          "destination": "/dev/pts",
          "type": "devpts",
          "source": "devpts",
          "options": [
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
          ]
        }
      ],
      "annotations": {
        "io.kubernetes.cri-o.ImageName": "quay.io/crio/redis:alpine",
        "io.kubernetes.cri-o.Stdin": "false",
        "io.kubernetes.cri-o.StdinOnce": "false",
        "io.kubernetes.cri-o.Created": "2023-12-12T04:10:25.992573978Z",
        "io.kubernetes.cri-o.Volumes": "[]",
        "io.kubernetes.cri-o.SandboxID": "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca",
        "io.kubernetes.cri-o.ResolvPath": "/run/containers/storage/overlay-containers/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/userdata/resolv.conf",
        "io.container.manager": "cri-o",
        "io.kubernetes.cri-o.LogPath": "/var/log/crio/pods/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.log",
        "pod": "podsandbox1",
        "tier": "backend",
        "org.systemd.property.After": "['crio.service']",
        "io.kubernetes.cri-o.IP.0": "10.244.0.3",
        "org.systemd.property.DefaultDependencies": "true",
        "io.kubernetes.cri-o.Image": "quay.io/crio/redis:alpine",
        "io.kubernetes.cri-o.ImageRef": "98bd7cfc43b8ef0ff130465e3d5427c0771002c2f35a6a9b62cb2d04602bed0a",
        "io.kubernetes.cri-o.MountPoint": "/var/lib/containers/storage/overlay/452374ade3f42caaea412ed8d221100864d3282e29acde3279db72f6d2468a67/merged",
        "io.kubernetes.cri-o.Labels": "{\"tier\":\"backend\"}",
        "io.kubernetes.cri-o.Annotations": "{\"pod\":\"podsandbox1\"}",
        "io.kubernetes.cri-o.Metadata": "{\"name\":\"podsandbox1-redis\"}",
        "com.example.test": "sandbox annotation",
        "security.alpha.kubernetes.io/seccomp/pod": "unconfined",
        "owner": "hmeng",
        "io.kubernetes.cri-o.ContainerID": "49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad",
        "io.kubernetes.cri-o.ContainerType": "container",
        "io.kubernetes.cri-o.Name": "k8s_podsandbox1-redis_podsandbox1_redhat.test.crio_redhat-test-crio_0",
        "io.kubernetes.cri-o.SandboxName": "k8s_podsandbox1_redhat.test.crio_redhat-test-crio_1",
        "io.kubernetes.cri-o.TTY": "false",
        "io.kubernetes.cri-o.SeccompProfilePath": "",
        "org.systemd.property.CollectMode": "'inactive-or-failed'"
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
            "limit": 209715200,
            "swap": 209715200
          },
          "cpu": {
            "shares": 512,
            "quota": 20000,
            "period": 10000,
            "cpus": "0",
            "mems": "0"
          },
          "pids": {
            "limit": 0
          }
        },
        "cgroupsPath": "pod_123-456.slice:crio:49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad",
        "namespaces": [
          {
            "type": "pid"
          }
        ],
        "seccomp": {
          "defaultAction": "SCMP_ACT_ERRNO",
          "defaultErrnoRet": 38,
          "architectures": [
            "SCMP_ARCH_X86_64"
          ],
          "syscalls": [
            {
              "names": [
                "unshare"
              ],
              "action": "SCMP_ACT_ALLOW"
            }
          ]
        },
        "maskedPaths": [
          "/proc/acpi"
        ],
        "readonlyPaths": [
          "/proc/asound"
        ]
      }
    },
    "privileged": true
  }
})";

std::string pod_info_json_crio = R"({
   "runtimeSpec": {
      "ociVersion": "1.0.2-dev",
      "process": {
        "user": {
          "uid": 0,
          "gid": 0
        },
        "args": [
          "/pause"
        ],
        "env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "TERM=xterm"
        ],
        "cwd": "/",
        "capabilities": {
          "bounding": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ],
          "effective": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ],
          "inheritable": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ],
          "permitted": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FSETID",
            "CAP_FOWNER",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_NET_BIND_SERVICE",
            "CAP_KILL"
          ]
        },
        "oomScoreAdj": -998
      },
      "root": {
        "path": "/var/lib/containers/storage/overlay/3d0bdf5559c7bc99637bb455e8612da36bbb082af75467f5aec80a29f2e3a72c/merged",
        "readonly": true
      },
      "hostname": "crictl_host",
      "mounts": [
        {
          "destination": "/proc",
          "type": "proc",
          "source": "proc",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        }
      ],
      "annotations": {
        "io.kubernetes.cri-o.ResolvPath": "/run/containers/storage/overlay-containers/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/userdata/resolv.conf",
        "org.systemd.property.CollectMode": "'inactive-or-failed'",
        "io.kubernetes.cri-o.Name": "k8s_podsandbox1_redhat.test.crio_redhat-test-crio_1",
        "io.kubernetes.cri-o.SandboxID": "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca",
        "io.kubernetes.cri-o.Image": "registry.k8s.io/pause:3.6",
        "io.kubernetes.cri-o.PrivilegedRuntime": "false",
        "io.kubernetes.cri-o.Created": "2023-12-12T04:10:22.504653972Z",
        "io.kubernetes.cri-o.PortMappings": "[]",
        "io.kubernetes.cri-o.IP.0": "10.244.0.3",
        "io.kubernetes.cri-o.Labels": "{\"group\":\"test\",\"io.kubernetes.container.name\":\"POD\"}",
        "io.kubernetes.cri-o.ShmPath": "/run/containers/storage/overlay-containers/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/userdata/shm",
        "io.kubernetes.cri-o.RuntimeHandler": "",
        "io.kubernetes.cri-o.KubeName": "podsandbox1",
        "io.kubernetes.cri-o.HostnamePath": "/run/containers/storage/overlay-containers/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/userdata/hostname",
        "io.kubernetes.cri-o.SeccompProfilePath": "",
        "io.kubernetes.cri-o.Namespace": "redhat.test.crio",
        "io.kubernetes.cri-o.ContainerName": "k8s_POD_podsandbox1_redhat.test.crio_redhat-test-crio_1",
        "security.alpha.kubernetes.io/seccomp/pod": "unconfined",
        "io.kubernetes.container.name": "POD",
        "owner": "hmeng",
        "io.kubernetes.cri-o.LogPath": "/var/log/crio/pods/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca.log",
        "io.kubernetes.cri-o.ImageName": "registry.k8s.io/pause:3.6",
        "io.kubernetes.cri-o.NamespaceOptions": "{\"pid\":1}",
        "io.kubernetes.cri-o.Spoofed": "true",
        "io.kubernetes.cri-o.Annotations": "{\"com.example.test\":\"sandbox annotation\",\"security.alpha.kubernetes.io/seccomp/pod\":\"unconfined\",\"owner\":\"hmeng\"}",
        "io.kubernetes.cri-o.HostName": "crictl_host",
        "io.container.manager": "cri-o",
        "com.example.test": "sandbox annotation",
        "io.kubernetes.cri-o.SandboxName": "k8s_podsandbox1_redhat.test.crio_redhat-test-crio_1",
        "io.kubernetes.cri-o.ContainerID": "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca",
        "io.kubernetes.cri-o.CgroupParent": "pod_123-456.slice",
        "io.kubernetes.cri-o.CNIResult": "{\"cniVersion\":\"1.0.0\",\"interfaces\":[{\"name\":\"bridge\",\"mac\":\"ce:64:08:76:88:6a\"},{\"name\":\"veth71b0e931\",\"mac\":\"72:b7:4f:bc:e4:a4\"},{\"name\":\"eth0\",\"mac\":\"fe:06:00:f8:2f:4d\",\"sandbox\":\"/var/run/netns/dec735d1-0e86-44c1-94e0-a102173334a4\"}],\"ips\":[{\"interface\":2,\"address\":\"10.244.0.3/16\",\"gateway\":\"10.244.0.1\"}],\"routes\":[{\"dst\":\"0.0.0.0/0\",\"gw\":\"10.244.0.1\"}],\"dns\":{}}",
        "io.kubernetes.cri-o.MountPoint": "/var/lib/containers/storage/overlay/3d0bdf5559c7bc99637bb455e8612da36bbb082af75467f5aec80a29f2e3a72c/merged",
        "io.kubernetes.cri-o.Metadata": "{\"name\":\"podsandbox1\",\"uid\":\"redhat-test-crio\",\"namespace\":\"redhat.test.crio\",\"attempt\":1}",
        "io.kubernetes.cri-o.ContainerType": "sandbox",
        "io.kubernetes.cri-o.HostNetwork": "false",
        "group": "test"
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
        "cgroupsPath": "pod_123-456.slice:crio:1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca",
        "namespaces": [
          {
            "type": "pid"
          },
          {
            "type": "network",
            "path": "/var/run/netns/dec735d1-0e86-44c1-94e0-a102173334a4"
          },
          {
            "type": "ipc",
            "path": "/var/run/ipcns/dec735d1-0e86-44c1-94e0-a102173334a4"
          },
          {
            "type": "uts",
            "path": "/var/run/utsns/dec735d1-0e86-44c1-94e0-a102173334a4"
          },
          {
            "type": "mount"
          }
        ],
        "seccomp": {
          "defaultAction": "SCMP_ACT_ERRNO",
          "defaultErrnoRet": 38,
          "architectures": [
            "SCMP_ARCH_X86_64",
            "SCMP_ARCH_X86",
            "SCMP_ARCH_X32"
          ],
          "syscalls": [
            {
              "names": [
                "bdflush"
              ],
              "action": "SCMP_ACT_ERRNO",
              "errnoRet": 1
            }
          ]
        }
      }
    }
  }
})";

runtime::v1alpha2::ContainerStatusResponse get_default_cri_crio_container_status_resp()
{

	// "status": {
	//     "id": "49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad",
	//     "metadata": {
	//       "attempt": 0,
	//       "name": "podsandbox1-redis"
	//     },
	//     "state": "CONTAINER_RUNNING",
	//     "createdAt": "2023-12-12T04:10:26.159883003Z",
	//     "startedAt": "2023-12-12T04:10:26.203875255Z",
	//     "finishedAt": "0001-01-01T00:00:00Z",
	//     "exitCode": 0,
	//     "image": {
	//       "annotations": {},
	//       "image": "quay.io/crio/redis:alpine"
	//     },
	//     "imageRef": "quay.io/crio/redis@sha256:1780b5a5496189974b94eb2595d86731d7a0820e4beb8ea770974298a943ed55",
	//     "reason": "",
	//     "message": "",
	//     "labels": {
	//       "io.kubernetes.sandbox.id": "49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad",
	//       "io.kubernetes.pod.uid": "redhat-test-crio",
	//       "io.kubernetes.pod.namespace": "redhat.test.crio",
	//       "io.kubernetes.pod.name": "podsandbox1"
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
	//     "logPath": "/var/log/crio/pods/1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca/49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.log"
	//   },

	// Mock container runtime socket API responses ContainerStatusResponse
	// Note that some fields are not populated or tested
	runtime::v1alpha2::ContainerStatusResponse resp;

	auto status = resp.mutable_status();
	status->set_id("49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad");
	status->set_state(runtime::v1alpha2::ContainerState::CONTAINER_RUNNING); // "CONTAINER_RUNNING"
	status->set_created_at((uint64_t)1676262698000004577); // dummy
	status->set_started_at((uint64_t)1676262698000004577); // dummy
	status->set_image_ref("quay.io/crio/redis@sha256:1780b5a5496189974b94eb2595d86731d7a0820e4beb8ea770974298a943ed55");
	status->mutable_image()->set_image("quay.io/crio/redis:alpine");
	auto labels = status->mutable_labels();
	(*labels)["io.kubernetes.container.name"] = "redis";
	(*labels)["io.kubernetes.pod.uid"] = "redhat-test-crio";
	(*labels)["io.kubernetes.pod.namespace"] = "redhat.test.crio";
	(*labels)["io.kubernetes.pod.name"] = "podsandbox1";
	auto annotations = status->mutable_annotations();
	(*annotations)["io.kubernetes.container.restartCount"] = "0";
	(*annotations)["io.kubernetes.container.hash"] = "4689db3";
	(*annotations)["io.kubernetes.pod.terminationGracePeriod"] = "30";
	status->mutable_metadata()->set_name("redis");
	runtime::v1alpha2::Mount mount;
	mount.set_container_path("/host/boot");
	mount.set_host_path("/boot");
	mount.set_readonly(true);
	mount.set_selinux_relabel(false);
	mount.set_propagation(runtime::v1alpha2::MountPropagation::PROPAGATION_PRIVATE);
	status->mutable_mounts()->Add()->CopyFrom(mount);

	resp.mutable_info()->insert({"info", container_info_json_crio});

	return resp;
}

runtime::v1alpha2::PodSandboxStatusResponse get_default_cri_crio_pod_status_resp()
{

	//     "status": {
	//     "id": "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca",
	//     "metadata": {
	//       "attempt": 1,
	//       "name": "podsandbox1",
	//       "namespace": "redhat.test.crio",
	//       "uid": "redhat-test-crio"
	//     },
	//     "state": "SANDBOX_READY",
	//     "createdAt": "2023-12-12T00:15:14.434884181Z",
	//     "network": {
	//       "additionalIps": [],
	//       "ip": "10.244.0.3"
	//     },
	//     "linux": {
	//       "namespaces": {
	//         "options": {
	//           "ipc": "POD",
	//           "network": "POD",
	//           "pid": "CONTAINER",
	//           "targetId": ""
	//         }
	//       }
	//     },
	//     "labels": {
	//       "app": "myapp",
	//       "example.label": "mylabel",
	//       "io.kubernetes.pod.name": "podsandbox1",
	//       "io.kubernetes.pod.namespace": "redhat.test.crio"
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
	status->set_id("1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca");
	status->set_state(runtime::v1alpha2::PodSandboxState::SANDBOX_READY);
    status->set_created_at((uint64_t)1676262698000004577); // dummy
	status->mutable_metadata()->set_name("podsandbox1");
	status->mutable_network()->set_ip("10.244.0.3");
	auto labels = status->mutable_labels();
	(*labels)["app"] = "myapp";
	(*labels)["example-label/custom_one"] = "mylabel";
	(*labels)["io.kubernetes.pod.namespace"] = "redhat.test.crio";
	(*labels)["io.kubernetes.pod.name"] = "podsandbox1";
	auto annotations = status->mutable_annotations();
	(*annotations)["ip-annotation-custom"] = "non-routable-ipv4";
	(*annotations)["example.annotation/custom"] = "myannotation";
	auto metadata = status->mutable_metadata();
	metadata->set_attempt(0);
	metadata->set_name("podsandbox1");
	metadata->set_namespace_("redhat.test.crio");
	metadata->set_uid("redhat-test-crio");

	resp.mutable_info()->insert({"info", pod_info_json_crio});

	return resp;
}

TEST_F(sinsp_with_test_input, container_parser_cri_crio)
{
	std::string cri_path = "/run/crio/crio_mock.sock";
	auto cri_api_v1alpha2 = std::make_unique<libsinsp::cri::cri_interface_v1alpha2>(cri_path);
	ASSERT_FALSE(cri_api_v1alpha2->is_ok()); // we are not querying a container runtime socket in this mock test

	// Get mock responses
	runtime::v1alpha2::ContainerStatusResponse resp = get_default_cri_crio_container_status_resp();
	runtime::v1alpha2::PodSandboxStatusResponse resp_pod = get_default_cri_crio_pod_status_resp();

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
	container.m_type = CT_CRIO;
	container.m_id = "49ecc2820215"; // truncated id extracted from cgroups
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
	ASSERT_EQ("49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad", container.m_full_id);
	ASSERT_EQ("quay.io/crio/redis:alpine", container.m_image);
	ASSERT_EQ("quay.io/crio/redis", container.m_imagerepo);
	ASSERT_EQ("alpine", container.m_imagetag);

	// CRI image, failure resilience test
	auto status = resp.mutable_status();
	status->set_image_ref("sha256:49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad");
	status->mutable_image()->set_image("");
	const auto &resp_container_simulate_image_recovery = resp.status();
	res = cri_api_v1alpha2->parse_cri_image(resp_container_simulate_image_recovery, resp_container_info, container);
	ASSERT_TRUE(res);
	ASSERT_EQ("quay.io/crio/redis:alpine", container.m_image);
	ASSERT_EQ("quay.io/crio/redis", container.m_imagerepo);
	ASSERT_EQ("alpine", container.m_imagetag);

	// network
	container.m_container_ip = ntohl(cri_api_v1alpha2->get_pod_sandbox_ip(resp_pod));
	ASSERT_EQ(183762947, container.m_container_ip); // decimal of "10.244.0.3"
	std::string cniresult = "";
	cri_api_v1alpha2->get_pod_info_cniresult(resp_pod, cniresult);
	ASSERT_EQ("{\"cniVersion\":\"1.0.0\",\"interfaces\":[{\"name\":\"bridge\",\"mac\":\"ce:64:08:76:88:6a\"},{\"name\":\"veth71b0e931\",\"mac\":\"72:b7:4f:bc:e4:a4\"},{\"name\":\"eth0\",\"mac\":\"fe:06:00:f8:2f:4d\",\"sandbox\":\"/var/run/netns/dec735d1-0e86-44c1-94e0-a102173334a4\"}],\"ips\":[{\"interface\":2,\"address\":\"10.244.0.3/16\",\"gateway\":\"10.244.0.1\"}],\"routes\":[{\"dst\":\"0.0.0.0/0\",\"gw\":\"10.244.0.1\"}],\"dns\":{}}", cniresult);
	container.m_pod_cniresult = cniresult;

	// Extra info such as privileged flag
	const auto &info_it = resp.info().find("info");
	Json::Value root;
	Json::Reader reader;
	if(!reader.parse(info_it->second, root))
	{\
		ASSERT(false);
	}
	res = cri_api_v1alpha2->parse_cri_ext_container_info(root, container);
	ASSERT_TRUE(res);
	ASSERT_TRUE(container.m_privileged);
	ASSERT_EQ(209715200, container.m_memory_limit);
	ASSERT_EQ(20000, container.m_cpu_quota);

	if(root.isMember("sandboxID") && root["sandboxID"].isString())
	{
		const auto pod_sandbox_id = root["sandboxID"].asString();
		// Add the pod sandbox id as label to the container.
		// This labels is needed by the filterchecks code to get the pod labels.
		container.m_labels["io.kubernetes.sandbox.id"] = pod_sandbox_id;
	}

	//
	// create and test sinsp_container_info for sandbox_container
	//

	// Add basic fields manually
	sandbox_container.m_is_pod_sandbox = true;
	sandbox_container.m_type = CT_CRIO;
	sandbox_container.m_id = "1f04600dc694"; // truncated id extracted from cgroups, here for the sandbox id / pod
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
		"cpuset=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope",
		"cpu=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope",
		"blkio=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope",
		"memory=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope",
		"hugetlb=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope", 
		"pids=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope",
		"misc=/pod_123.slice/pod_123-456.slice/crio-49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad.scope"};
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
	ASSERT_EQ("49ecc2820215", container_info_check->m_id);
	const sinsp_container_info::ptr_t sandbox_container_info_check = m_inspector.m_container_manager.get_container(sandbox_container.m_id);
	ASSERT_TRUE(sandbox_container_info_check);
	ASSERT_EQ("1f04600dc694", sandbox_container_info_check->m_id);

	// Check container and k8s related filter fields that are retrieved from the container runtime socket
	ASSERT_EQ(get_field_as_string(evt, "container.id"), "49ecc2820215");
	ASSERT_EQ(get_field_as_string(evt, "container.full_id"), "49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad");
	ASSERT_EQ(get_field_as_string(evt, "container.name"), "redis");
	ASSERT_EQ(get_field_as_string(evt, "container.image"), "quay.io/crio/redis:alpine");
	// ASSERT_EQ(get_field_as_string(evt, "container.image.id"), "redis"); // TBD unsure how it's parsed in cri.hpp for cri-o
	ASSERT_EQ(get_field_as_string(evt, "container.type"), "cri-o");
	ASSERT_EQ(get_field_as_string(evt, "container.privileged"), "true");
	ASSERT_EQ(get_field_as_string(evt, "container.mounts"), "/boot:/host/boot::false:private");
	ASSERT_EQ(get_field_as_string(evt, "container.mount.source[0]"), "/boot");
	ASSERT_EQ(get_field_as_string(evt, "container.mount.dest[0]"), "/host/boot");
	ASSERT_EQ(get_field_as_string(evt, "container.mount.propagation[/boot]"), "private");
	ASSERT_EQ(get_field_as_string(evt, "container.image.repository"), "quay.io/crio/redis");
	ASSERT_EQ(get_field_as_string(evt, "container.image.tag"), "alpine");
	ASSERT_EQ(get_field_as_string(evt, "container.image.digest"), "sha256:49ecc282021562c567a8159ef424a06cdd8637efdca5953de9794eafe29adcad");
	ASSERT_EQ(get_field_as_string(evt, "container.ip"), "10.244.0.3");
	ASSERT_EQ(get_field_as_string(evt, "container.cni.json"), "{\"cniVersion\":\"1.0.0\",\"interfaces\":[{\"name\":\"bridge\",\"mac\":\"ce:64:08:76:88:6a\"},{\"name\":\"veth71b0e931\",\"mac\":\"72:b7:4f:bc:e4:a4\"},{\"name\":\"eth0\",\"mac\":\"fe:06:00:f8:2f:4d\",\"sandbox\":\"/var/run/netns/dec735d1-0e86-44c1-94e0-a102173334a4\"}],\"ips\":[{\"interface\":2,\"address\":\"10.244.0.3/16\",\"gateway\":\"10.244.0.1\"}],\"routes\":[{\"dst\":\"0.0.0.0/0\",\"gw\":\"10.244.0.1\"}],\"dns\":{}}");

	ASSERT_EQ(get_field_as_string(evt, "k8s.ns.name"), "redhat.test.crio");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.name"), "podsandbox1");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.id"), "redhat-test-crio"); // legacy pod UID
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.uid"), get_field_as_string(evt, "k8s.pod.id")); // new semantically correct pod UID
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.sandbox_id"), "1f04600dc694");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.full_sandbox_id"), "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label.example-label/custom_one"), "mylabel");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label[example-label/custom_one]"), "mylabel");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.labels"), "app:myapp, example-label/custom_one:mylabel");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.ip"), "10.244.0.3");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.cni.json"), "{\"cniVersion\":\"1.0.0\",\"interfaces\":[{\"name\":\"bridge\",\"mac\":\"ce:64:08:76:88:6a\"},{\"name\":\"veth71b0e931\",\"mac\":\"72:b7:4f:bc:e4:a4\"},{\"name\":\"eth0\",\"mac\":\"fe:06:00:f8:2f:4d\",\"sandbox\":\"/var/run/netns/dec735d1-0e86-44c1-94e0-a102173334a4\"}],\"ips\":[{\"interface\":2,\"address\":\"10.244.0.3/16\",\"gateway\":\"10.244.0.1\"}],\"routes\":[{\"dst\":\"0.0.0.0/0\",\"gw\":\"10.244.0.1\"}],\"dns\":{}}");
}
#endif // MINIMAL_BUILD
