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

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__)
#include <dns_manager.h>
#include <gtest/gtest.h>

TEST(sinsp_dns_manager, simple_dns_manager_invocation)
{
    // Simple dummy test to assert that sinsp_dns_manager is invocated correctly
    // and not leaking memory
    const char* name = "bogus";
    uint64_t ts = 11111111111111;
    uint32_t addr = 111111;
    bool result = sinsp_dns_manager::get().match(name, AF_INET, &addr, ts);
    ASSERT_FALSE(result);
}
#endif
