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
#include <scap_open_exception.h>
#include <scap.h>
#include <sinsp.h>
#include <scap_engines.h>

#define HOST_ROOT_ENV "HOST_ROOT"

#ifdef HAS_ENGINE_KMOD
TEST(sinsp, wrong_host_root)
{
	ASSERT_EQ(0, setenv(HOST_ROOT_ENV, "fake_hostroot", 1));
	sinsp inspector = {};

	// We cannot scan proc we expect an exception
	ASSERT_THROW(inspector.open_kmod(DEFAULT_DRIVER_BUFFER_BYTES_DIM), scap_open_exception);

	// Clear the env variable
	ASSERT_EQ(0, setenv(HOST_ROOT_ENV, "", 1));

	// Try to close the inspector several times to avoid double frees
	inspector.close();
	inspector.close();
	inspector.close();
}
#endif /* HAS_ENGINE_KMOD */
