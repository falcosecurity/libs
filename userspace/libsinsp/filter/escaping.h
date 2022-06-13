/*
Copyright (C) 2022 The Falco Authors.

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

#include <string>

namespace libsinsp {
namespace filter {

/*!
	\brief Methods to escape/unescape strings
	\note Throws a sinsp_exception in case of parsing errors.
	\return an escaped/unescaped verison of the string
*/
std::string escape_str(const std::string& str);
std::string unescape_str(const std::string& str);


}
}
