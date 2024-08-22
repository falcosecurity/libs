// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <memory>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <libsinsp/gvisor_config.h>
#include <libscap/engine/gvisor/gvisor.h>

TEST(gvisor_config, generate_parse)
{
	std::string socket_path = "/run/falco/gvisor.sock";
	std::string config = gvisor_config::generate(socket_path);

	// check that the output is valid json
	auto root = nlohmann::json::parse(config.c_str(), config.c_str() + config.size(), nullptr, false);
	EXPECT_TRUE(!root.is_discarded()) << "Could not parse configuration file contents.";

	// check that the sink is defined
	// according to https://github.com/google/gvisor/blob/master/tools/tracereplay/README.md#how-to-use-it
	EXPECT_EQ(root["trace_session"]["sinks"][0]["config"]["endpoint"], socket_path);
}
