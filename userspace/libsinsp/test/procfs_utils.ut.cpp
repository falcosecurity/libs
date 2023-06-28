/*
Copyright (C) 2021 The Falco Authors.

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
#include <procfs_utils.h>
#include <sstream>

using namespace libsinsp::procfs_utils;

TEST(procfs_utils_test, get_userns_uid)
{
	std::string uidmap = "         0      1000         0\n         1   1000000      1000\n";
	std::stringstream s(uidmap);

	ASSERT_EQ(get_userns_root_uid(s), 1000);
}


TEST(procfs_utils_test, get_userns_uid_root)
{
	std::string uidmap = "         0         0         0\n";
	std::stringstream s(uidmap);

	ASSERT_EQ(get_userns_root_uid(s), 0);
}
