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

// SCAP_GTEST_SKIP(message) skips the rest of a test, like GTEST_SKIP() << message.
//
// GTEST_SKIP() arrived in googletest 1.10. The CI jobs that build against the system packages
// run in debian:buster, which has googletest 1.8.1. There, SCAP_GTEST_SKIP prints the message
// and returns, and the test reports as passed.
//
// It returns from the function that calls it, as GTEST_SKIP() does: call it in the test body,
// not in a helper. Do not use testing::Test::IsSkipped(), which 1.8.1 does not have either.

#include <gtest/gtest.h>

#include <iostream>

#ifdef GTEST_SKIP
#define SCAP_GTEST_SKIP(message) GTEST_SKIP() << message
#else
#define SCAP_GTEST_SKIP(message)                     \
	do {                                             \
		std::cerr << "SKIPPED: " << message << '\n'; \
		return;                                      \
	} while(false)
#endif
