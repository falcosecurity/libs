#
# Copyright (C) 2022 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

CLANG_FORMAT_EXE ?= clang-format
CMAKE_FORMAT_EXE ?= cmake-format
PROJECT_ROOT_DIR = $(shell git rev-parse --show-toplevel)

######################
#    Clang-format    #
######################
.PHONY: clang-format-install
clang-format-install:
ifeq (, $(shell ${CLANG_FORMAT_EXE} --version))
	@echo "${CLANG_FORMAT_EXE} is not installed. Please read the 'coding style' doc to get more info."
	@exit 1
endif

.PHONY: format-clang
format-clang: clang-format-install
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cpp|h|c)$$' | xargs ${CLANG_FORMAT_EXE} -Werror --style=file:${PROJECT_ROOT_DIR}/.clang-format -i

.PHONY: check-clang
check-clang: clang-format-install
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cpp|h|c)$$' | xargs ${CLANG_FORMAT_EXE} -Werror --style=file:${PROJECT_ROOT_DIR}/.clang-format -n

######################
#    Cmake-format    #
######################
.PHONY: cmake-format-install
cmake-format-install:
ifeq (, $(shell ${CMAKE_FORMAT_EXE} --version))
	@echo "${CMAKE_FORMAT_EXE} is not installed. Please read the 'coding style' doc to get more info."
	@exit 1
endif

.PHONY: format-cmake
format-cmake: cmake-format-install
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cmake)$$|CMakeLists.txt$$' | xargs ${CMAKE_FORMAT_EXE} --config-files ${PROJECT_ROOT_DIR}/.cmake-format.json -i

.PHONY: check-cmake
check-cmake: cmake-format-install
	git ls-files --directory ${PROJECT_ROOT_DIR} | grep -E '\.(cmake)$$|CMakeLists.txt$$' | xargs ${CMAKE_FORMAT_EXE} --config-files ${PROJECT_ROOT_DIR}/.cmake-format.json --check

# Add new formatters here...

.PHONY: format-all
format-all: format-clang format-cmake

.PHONY: check-all
check-all: check-clang check-cmake

