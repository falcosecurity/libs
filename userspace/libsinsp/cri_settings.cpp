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

#include <libsinsp/cri.hpp>

namespace libsinsp
{
namespace cri
{

cri_settings::cri_settings():
	m_cri_unix_socket_paths(),
	m_cri_timeout(1000),
	m_cri_size_timeout(10000),
	m_cri_runtime_type(CT_CRI),
	m_cri_unix_socket_path(),
	m_cri_extra_queries(true)
{ }

cri_settings::~cri_settings()
{ }

std::unique_ptr<cri_settings> cri_settings::s_instance = nullptr;

cri_settings& cri_settings::get()
{
	if(s_instance == nullptr)
	{
		s_instance = std::make_unique<cri_settings>();
	}
	return *s_instance;
}

} // namespace cri
} // namespace libsinsp
