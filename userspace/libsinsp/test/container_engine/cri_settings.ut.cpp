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

#if !defined(MINIMAL_BUILD) and !defined(__EMSCRIPTEN__) // MINIMAL_BUILD and emscripten don't support containers at all
#include <gtest/gtest.h>
#include <cri.h>
#include <libsinsp/cri.hpp>
#include "../sinsp_with_test_input.h"


TEST_F(sinsp_with_test_input, default_cri_socket_paths)
{
	libsinsp::cri::cri_settings& cri_settings = libsinsp::cri::cri_settings::get();

	if (!cri_settings.get_cri_unix_socket_paths().empty())
	{
		cri_settings.clear_cri_unix_socket_paths();
	}

	add_default_init_thread();
	open_inspector();

	auto socket_paths = cri_settings.get_cri_unix_socket_paths();

	ASSERT_EQ(socket_paths.size(), 3);
	ASSERT_TRUE("/run/containerd/containerd.sock"==socket_paths[0]);
	ASSERT_TRUE("/run/crio/crio.sock"==socket_paths[1]);
	ASSERT_TRUE("/run/k3s/containerd/containerd.sock"==socket_paths[2]);
}
#endif
