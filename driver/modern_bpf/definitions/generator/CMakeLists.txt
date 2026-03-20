# SPDX-License-Identifier: GPL-2.0-only OR MIT
#
# Copyright (C) 2026 The Falco Authors.
#
# This file is dual licensed under either the MIT or GPL 2. See MIT.txt or GPL.txt for full copies
# of the license.
#

cmake_minimum_required(VERSION 3.12)
project(events_dimensions_generator LANGUAGES C CXX)

if(NOT DEFINED LIBS_DIR OR "${LIBS_DIR}" STREQUAL "")
	message(FATAL_ERROR "LIBS_DIR must be provided")
endif()

add_executable(
	events_dimensions_generator
	generator.cpp ${LIBS_DIR}/driver/event_table.c ${LIBS_DIR}/driver/flags_table.c
	${LIBS_DIR}/driver/dynamic_params_table.c
)

target_include_directories(events_dimensions_generator PRIVATE ${LIBS_DIR})

set_target_properties(
	events_dimensions_generator PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
