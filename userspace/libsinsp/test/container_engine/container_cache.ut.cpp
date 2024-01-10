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

#include <gtest/gtest.h>

#include "../sinsp_with_test_input.h"
#include <test/helpers/threads_helpers.h>

TEST_F(sinsp_with_test_input, container_manager_cache_threadtable_lifecycle)
{
    std::string test_container_id = "3ad7b26ded6d";
    DEFAULT_TREE;
    ASSERT_EQ(DEFAULT_TREE_NUM_PROCS, m_inspector.m_thread_manager->get_thread_count());
    // Assign the test container id to one thread in the threadtable
    sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(p4_t1_tid, false, true).get();
    ASSERT_TRUE(tinfo);
    tinfo->m_container_id = test_container_id;
    ASSERT_EQ(test_container_id, tinfo->m_container_id);

    // Manually add a mock container to the container engine cache
    std::shared_ptr<sinsp_container_info> container_info = std::make_shared<sinsp_container_info>();
    container_info->m_type = CT_CRI;
	container_info->m_id = test_container_id;
    m_inspector.m_container_manager.add_container(std::move(container_info), nullptr);
    const sinsp_container_info::ptr_t container_info_check = m_inspector.m_container_manager.get_container(test_container_id);
    ASSERT_TRUE(container_info_check);
    ASSERT_EQ(test_container_id, container_info_check->m_id);

    // Arbitrary time travel to invoke removal / flush logic remove_inactive_containers
    m_inspector.m_containers_purging_scan_time_ns = 0;
    m_inspector.m_container_manager.m_last_flush_time_ns = 1;
    m_inspector.m_container_manager.remove_inactive_containers();
    const sinsp_container_info::ptr_t container_info_check_not_removed = m_inspector.m_container_manager.get_container(test_container_id);
    ASSERT_TRUE(container_info_check_not_removed); // container remains cached
    ASSERT_EQ(test_container_id, container_info_check_not_removed->m_id);

    // Mock remove test_container1 container from threadtable
    tinfo = m_inspector.get_thread_ref(p4_t1_tid, false, true).get();
    tinfo->m_container_id = "";
    m_inspector.m_containers_purging_scan_time_ns = 0;
    m_inspector.m_container_manager.m_last_flush_time_ns = 1;
    m_inspector.m_container_manager.remove_inactive_containers();

    const sinsp_container_info::ptr_t container_info_check_removed = m_inspector.m_container_manager.get_container(test_container_id);
    ASSERT_FALSE(container_info_check_removed); // now a nullptr since the container was removed
}
