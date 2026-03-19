// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#pragma once

#include <cxxopts.hpp>
#include <libsinsp/sinsp.h>

/**
 * @brief Adds platform-specific test CLI options to options.
 */
void add_platform_test_options(cxxopts::Options& options);

/**
 * @brief Parses platform-specific test CLI options from result.
 */
void parse_platform_test_options(const cxxopts::ParseResult& result);

#ifdef __linux__
/**
 * @brief Returns true if any linux_platform fetch_* API test option was specified.
 */
bool should_run_linux_platform_fetch_api_tests();

/**
 * @brief Runs the selected linux_platform fetch_* API test against inspector.
 */
int run_linux_platform_fetch_api_tests(sinsp& inspector);
#endif  // __linux__
