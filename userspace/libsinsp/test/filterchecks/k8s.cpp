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

#include <test/helpers/threads_helpers.h>
TEST_F(sinsp_with_test_input, K8S_FILTER_check_fields_presence)
{
	add_default_init_thread();
	open_inspector();
	auto evt = generate_random_event();
	ASSERT_TRUE(field_exists(evt, "k8s.pod.name"));
	ASSERT_TRUE(field_exists(evt, "k8s.pod.id"));
	ASSERT_TRUE(field_exists(evt, "k8s.pod.label.one.second.third"));
	ASSERT_TRUE(field_exists(evt, "k8s.pod.labels"));
	ASSERT_TRUE(field_exists(evt, "k8s.pod.ip"));
	ASSERT_TRUE(field_exists(evt, "k8s.pod.cni.json"));
	ASSERT_TRUE(field_exists(evt, "k8s.ns.name"));

	ASSERT_TRUE(field_exists(evt, "k8s.rc.name"));
	ASSERT_TRUE(field_exists(evt, "k8s.rc.id"));
	ASSERT_TRUE(field_exists(evt, "k8s.rc.label.one"));
	ASSERT_TRUE(field_exists(evt, "k8s.rc.labels"));
	ASSERT_TRUE(field_exists(evt, "k8s.svc.name"));
	ASSERT_TRUE(field_exists(evt, "k8s.svc.id"));
	ASSERT_TRUE(field_exists(evt, "k8s.svc.label.one"));
	ASSERT_TRUE(field_exists(evt, "k8s.svc.labels"));
	ASSERT_TRUE(field_exists(evt, "k8s.ns.id"));
	ASSERT_TRUE(field_exists(evt, "k8s.ns.label.one"));
	ASSERT_TRUE(field_exists(evt, "k8s.ns.labels"));
	ASSERT_TRUE(field_exists(evt, "k8s.rs.name"));
	ASSERT_TRUE(field_exists(evt, "k8s.rs.id"));
	ASSERT_TRUE(field_exists(evt, "k8s.rs.label.one"));
	ASSERT_TRUE(field_exists(evt, "k8s.rs.labels"));
	ASSERT_TRUE(field_exists(evt, "k8s.deployment.name"));
	ASSERT_TRUE(field_exists(evt, "k8s.deployment.id"));
	ASSERT_TRUE(field_exists(evt, "k8s.deployment.label.one"));
	ASSERT_TRUE(field_exists(evt, "k8s.deployment.labels"));

	// There are no containers in the container manager, so there shouldn't be values
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.ip"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.cni.json"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.name"));

	// These fields will always exist but without a value, they are deprecated
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.labels"));
}

TEST_F(sinsp_with_test_input, K8S_FILTER_check_fields_value)
{
	add_default_init_thread();
	open_inspector();

	uint32_t ip = 0xC0A80101; // 192.168.1.1
	std::string ip_string = "192.168.1.1";
	std::string cni_json = "cni.pod";
	std::string container_id = "fce2a82f930f";
	std::string container_full_id = "fce2a82f930fa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6";
	std::string container_name = "kind-control-plane";
	std::string pod_name = "nginx";
	std::string pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
	std::string pod_sandbox_id = "1f04600dc694";
	std::string pod_full_sandbox_id = "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca";
	std::string pod_namespace = "default";
	std::map<std::string, std::string> container_labels = {
						     {"io.kubernetes.sandbox.id", pod_full_sandbox_id},
						     {"io.kubernetes.pod.name", pod_name},
						     {"io.kubernetes.pod.uid", pod_uid},
						     {"io.kubernetes.pod.namespace", pod_namespace}};
	std::map<std::string, std::string> pod_sandbox_labels = {{"io.x-k8s.kind.cluster", "kind"},
						     {"io.x-k8s.kind.role", "control-plane"},
						     {"app.kubernetes-io/name_one", "example"},
						     {"sample", "nginx"}};

	auto init_thread_info = m_inspector.get_thread_ref(INIT_TID).get();
	auto container_info = std::make_shared<sinsp_container_info>();
	container_info->m_id = container_id;
	container_info->m_full_id = container_full_id;
	init_thread_info->m_container_id = container_id;
	container_info->m_name = container_name;
	container_info->m_type = CT_DOCKER;
	container_info->m_lookup.set_status(sinsp_container_lookup::state::SUCCESSFUL);
	container_info->m_labels = container_labels;
	container_info->m_pod_sandbox_labels = pod_sandbox_labels;
	container_info->m_container_ip = ip;
	container_info->m_pod_sandbox_cniresult = cni_json;
	container_info->m_pod_sandbox_id = pod_full_sandbox_id;
	m_inspector.m_container_manager.add_container(std::move(container_info), init_thread_info);

	auto evt = generate_random_event();
	// basic filterchecks
	ASSERT_EQ(get_field_as_string(evt, "container.id"), container_id);
	ASSERT_EQ(get_field_as_string(evt, "container.full_id"), container_full_id);
	ASSERT_EQ(get_field_as_string(evt, "container.name"), container_name);
	ASSERT_EQ(get_field_as_string(evt, "container.ip"), ip_string);
	ASSERT_EQ(get_field_as_string(evt, "container.cni.json"), cni_json);

	// k8s filterchecks, populated because our mock container is in a pod
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.name"), pod_name);
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.id"), pod_uid); // legacy pod UID
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.uid"), get_field_as_string(evt, "k8s.pod.id")); // new semantically correct pod UID
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.sandbox_id"), pod_sandbox_id);
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.full_sandbox_id"), pod_full_sandbox_id);
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label.sample"), "nginx");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label[sample]"), "nginx");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label.app.kubernetes-io/name_one"), "example");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.label[app.kubernetes-io/name_one]"), "example");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.labels"),
		  "app.kubernetes-io/name_one:example, io.x-k8s.kind.cluster:kind, io.x-k8s.kind.role:control-plane, sample:nginx");
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.ip"), ip_string);
	ASSERT_EQ(get_field_as_string(evt, "k8s.pod.cni.json"), cni_json);

	// These fields will always exist but without a value, they are deprecated
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rc.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.svc.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.rs.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.deployment.labels"));
}

TEST_F(sinsp_with_test_input, K8S_FILTER_check_fields_value_with_no_labels)
{
	add_default_init_thread();
	open_inspector();

	uint32_t ip = 0xC0A80101; // 192.168.1.1
	std::string ip_string = "192.168.1.1";
	std::string cni_json = "cni.pod";
	std::string container_id = "fce2a82f930f";
	std::string container_full_id = "fce2a82f930fa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6";
	std::string container_name = "kind-control-plane";
	std::string pod_name = "nginx";
	std::string pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
	std::string pod_sandbox_id = "1f04600dc694";
	std::string pod_full_sandbox_id = "1f04600dc6949359da68eee5fe7c4069706a567c07d1ef89fe3bbfdeac7a6dca";
	std::string pod_namespace = "default";
	std::map<std::string, std::string> container_labels = {{"sample", "nginx"}};
	std::map<std::string, std::string> pod_sandbox_labels = {{"sample", "nginx"}};

	auto init_thread_info = m_inspector.get_thread_ref(INIT_TID).get();
	auto container_info = std::make_shared<sinsp_container_info>();
	container_info->m_id = container_id;
	container_info->m_full_id = container_full_id;
	init_thread_info->m_container_id = container_id;
	container_info->m_name = container_name;
	container_info->m_type = CT_DOCKER;
	container_info->m_lookup.set_status(sinsp_container_lookup::state::SUCCESSFUL);
	container_info->m_labels = container_labels;
	container_info->m_pod_sandbox_labels = pod_sandbox_labels;
	container_info->m_container_ip = ip;
	container_info->m_pod_sandbox_cniresult = cni_json;
	m_inspector.m_container_manager.add_container(std::move(container_info), init_thread_info);

	auto evt = generate_random_event();
	ASSERT_EQ(get_field_as_string(evt, "container.id"), container_id);
	ASSERT_EQ(get_field_as_string(evt, "container.full_id"), container_full_id);
	ASSERT_EQ(get_field_as_string(evt, "container.name"), container_name);
	ASSERT_EQ(get_field_as_string(evt, "container.ip"), ip_string);
	ASSERT_EQ(get_field_as_string(evt, "container.cni.json"), cni_json);

	// If we don't have the `io.kubernetes...` labels on the container we cannot obtain these values
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.uid"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.sandbox_id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.full_sandbox_id"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.label.one"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.labels"));
	ASSERT_FALSE(field_has_value(evt, "k8s.ns.name"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.ip"));
	ASSERT_FALSE(field_has_value(evt, "k8s.pod.cni.json"));
}
