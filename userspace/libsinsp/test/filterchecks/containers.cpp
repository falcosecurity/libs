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

// Containers are supported only without minimal build
#ifndef MINIMAL_BUILD
#include <test/helpers/threads_helpers.h>
TEST_F(sinsp_with_test_input, CONTAINER_FILTER_check_k8s_fields_presence)
{
	add_default_init_thread();
	open_inspector();
	auto evt = generate_random_event();
	ASSERT_TRUE(field_exists(evt, "container.k8s.pod.name"));
	ASSERT_TRUE(field_exists(evt, "container.k8s.pod.id"));
	ASSERT_TRUE(field_exists(evt, "container.k8s.pod.label[one.second.third]"));
	ASSERT_TRUE(field_exists(evt, "container.k8s.pod.labels"));
	ASSERT_TRUE(field_exists(evt, "container.k8s.ns.name"));

	// container.k8s.pod.label requires an argument with the `[ ]` syntax.
	ASSERT_THROW(field_exists(evt, "container.k8s.pod.label.one"), sinsp_exception);
	ASSERT_THROW(field_exists(evt, "container.k8s.pod.label"), sinsp_exception);
	ASSERT_THROW(field_exists(evt, "container.k8s.pod.label."), sinsp_exception);
	ASSERT_THROW(field_exists(evt, "container.k8s.pod.label[["), sinsp_exception);
	ASSERT_THROW(field_exists(evt, "container.k8s.pod.label]]"), sinsp_exception);
	ASSERT_NO_THROW(field_exists(evt, "container.k8s.pod.label[]"));

	// There are no containers in the container manager, so there shouldn't be values
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.name"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.id"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.label[one]"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.labels"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.ns.name"));
}

TEST_F(sinsp_with_test_input, CONTAINER_FILTER_check_k8s_fields_value)
{
	add_default_init_thread();
	open_inspector();

	std::string container_id = "fce2a82f930f";
	std::string container_name = "kind-control-plane";
	std::string pod_name = "nginx";
	std::string pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
	std::string pod_namespace = "default";
	std::map<std::string, std::string> labels = {{"io.x-k8s.kind.cluster", "kind"},
						     {"io.x-k8s.kind.role", "control-plane"},
						     {"io.kubernetes.sandbox.id", container_id},
						     {"io.kubernetes.pod.name", pod_name},
						     {"io.kubernetes.pod.uid", pod_uid},
						     {"io.kubernetes.pod.namespace", pod_namespace},
						     {"sample", "nginx"}};

	auto init_thread_info = m_inspector.get_thread_ref(INIT_TID).get();
	auto container_info = std::make_shared<sinsp_container_info>();
	container_info->m_id = container_id;
	init_thread_info->m_container_id = container_id;
	container_info->m_name = container_name;
	container_info->m_type = CT_DOCKER;
	container_info->m_lookup.set_status(sinsp_container_lookup::state::SUCCESSFUL);
	container_info->m_labels = labels;
	m_inspector.m_container_manager.add_container(container_info, init_thread_info);

	auto evt = generate_random_event();
	// basic filterchecks
	ASSERT_EQ(get_field_as_string(evt, "container.id"), container_id);
	ASSERT_EQ(get_field_as_string(evt, "container.name"), container_name);

	// k8s filterchecks
	ASSERT_EQ(get_field_as_string(evt, "container.k8s.pod.name"), pod_name);
	ASSERT_EQ(get_field_as_string(evt, "container.k8s.pod.id"), pod_uid);
	ASSERT_EQ(get_field_as_string(evt, "container.k8s.pod.label[sample]"), "nginx");
	ASSERT_EQ(get_field_as_string(evt, "container.k8s.pod.labels"),
		  "(io.x-k8s.kind.cluster:kind,io.x-k8s.kind.role:control-plane,sample:nginx)");
	ASSERT_EQ(get_field_as_string(evt, "container.k8s.ns.name"), pod_namespace);
}

TEST_F(sinsp_with_test_input, CONTAINER_FILTER_check_k8s_fields_with_no_labels)
{
	add_default_init_thread();
	open_inspector();

	std::string container_id = "fce2a82f930f";
	std::string container_name = "kind-control-plane";
	std::string pod_name = "nginx";
	std::string pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
	std::string pod_namespace = "default";
	std::map<std::string, std::string> labels = {{"sample", "nginx"}};

	auto init_thread_info = m_inspector.get_thread_ref(INIT_TID).get();
	auto container_info = std::make_shared<sinsp_container_info>();
	container_info->m_id = container_id;
	init_thread_info->m_container_id = container_id;
	container_info->m_name = container_name;
	container_info->m_type = CT_DOCKER;
	container_info->m_lookup.set_status(sinsp_container_lookup::state::SUCCESSFUL);
	container_info->m_labels = labels;
	m_inspector.m_container_manager.add_container(container_info, init_thread_info);

	auto evt = generate_random_event();
	ASSERT_EQ(get_field_as_string(evt, "container.id"), container_id);
	ASSERT_EQ(get_field_as_string(evt, "container.name"), container_name);

	// If we don't have the `io.kubernetes...` labels on the container we cannot obtain these values
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.name"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.id"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.label[one]"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.pod.labels"));
	ASSERT_FALSE(field_has_value(evt, "container.k8s.ns.name"));
}
#endif
