
// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.
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

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, QUOTACTL_parse) {
	add_default_init_thread();
	open_inspector();

	constexpr int64_t return_value = 89;
	const std::string special{"special"};
	const std::string quotafilepath{"quotafilepath"};
	constexpr uint64_t dqb_bhardlimit = 50;
	constexpr uint64_t dqb_bsoftlimit = 51;
	constexpr uint64_t dqb_curspace = 52;
	constexpr uint64_t dqb_ihardlimit = 53;
	constexpr uint64_t dqb_isoftlimit = 54;
	constexpr uint64_t dqb_btime = 55;
	constexpr uint64_t dqb_itime = 56;
	constexpr uint64_t dqi_bgrace = 57;
	constexpr uint64_t dqi_igrace = 58;
	constexpr uint8_t dqi_flags = 59;
	constexpr uint8_t quota_fmt_out = 60;
	constexpr uint16_t cmd = 61;
	constexpr uint8_t typ = 62;
	constexpr uint32_t id = 63;
	constexpr uint8_t quota_fmt = 64;
	const auto evt = add_event_advance_ts(increasing_ts(),
	                                      INIT_TID,
	                                      PPME_SYSCALL_QUOTACTL_X,
	                                      18,
	                                      return_value,
	                                      special.c_str(),
	                                      quotafilepath.c_str(),
	                                      dqb_bhardlimit,
	                                      dqb_bsoftlimit,
	                                      dqb_curspace,
	                                      dqb_ihardlimit,
	                                      dqb_isoftlimit,
	                                      dqb_btime,
	                                      dqb_itime,
	                                      dqi_bgrace,
	                                      dqi_igrace,
	                                      dqi_flags,
	                                      quota_fmt_out,
	                                      cmd,
	                                      typ,
	                                      id,
	                                      quota_fmt);

	ASSERT_EQ(evt->get_param_by_name("res")->as<int64_t>(), return_value);
	ASSERT_EQ(evt->get_param_by_name("special")->as<std::string_view>(), special);
	ASSERT_EQ(evt->get_param_by_name("quotafilepath")->as<std::string_view>(), quotafilepath);
	ASSERT_EQ(evt->get_param_by_name("dqb_bhardlimit")->as<uint64_t>(), dqb_bhardlimit);
	ASSERT_EQ(evt->get_param_by_name("dqb_bsoftlimit")->as<uint64_t>(), dqb_bsoftlimit);
	ASSERT_EQ(evt->get_param_by_name("dqb_curspace")->as<uint64_t>(), dqb_curspace);
	ASSERT_EQ(evt->get_param_by_name("dqb_ihardlimit")->as<uint64_t>(), dqb_ihardlimit);
	ASSERT_EQ(evt->get_param_by_name("dqb_isoftlimit")->as<uint64_t>(), dqb_isoftlimit);
	ASSERT_EQ(evt->get_param_by_name("dqb_btime")->as<uint64_t>(), dqb_btime);
	ASSERT_EQ(evt->get_param_by_name("dqb_itime")->as<uint64_t>(), dqb_itime);
	ASSERT_EQ(evt->get_param_by_name("dqi_bgrace")->as<uint64_t>(), dqi_bgrace);
	ASSERT_EQ(evt->get_param_by_name("dqi_igrace")->as<uint64_t>(), dqi_igrace);
	ASSERT_EQ(evt->get_param_by_name("dqi_flags")->as<uint8_t>(), dqi_flags);
	ASSERT_EQ(evt->get_param_by_name("quota_fmt_out")->as<uint8_t>(), quota_fmt_out);
	ASSERT_EQ(evt->get_param_by_name("cmd")->as<uint16_t>(), cmd);
	ASSERT_EQ(evt->get_param_by_name("type")->as<uint8_t>(), typ);
	ASSERT_EQ(evt->get_param_by_name("id")->as<uint32_t>(), id);
	ASSERT_EQ(evt->get_param_by_name("quota_fmt")->as<uint8_t>(), quota_fmt);
}
