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

#pragma once
#include <libsinsp/fdtable.h>

/*!
  \brief Factory hiding sinsp_fdtable creation details.
*/
class sinsp_fdtable_factory {
	const std::shared_ptr<sinsp_fdtable::ctor_params>& m_params;

public:
	explicit sinsp_fdtable_factory(const std::shared_ptr<sinsp_fdtable::ctor_params>& params):
	        m_params{params} {}

	sinsp_fdtable create() const { return sinsp_fdtable{m_params}; }
};
