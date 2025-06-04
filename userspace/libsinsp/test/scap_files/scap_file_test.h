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
#pragma once

#include <libscap/scap.h>
#include <gtest/gtest.h>
#include <sinsp.h>
#include <libsinsp_test_var.h>

typedef std::unique_ptr<scap_evt, decltype(free)*> safe_scap_evt_t;

class scap_file_test : public testing::Test {
private:
	safe_scap_evt_t create_safe_scap_evt(scap_evt* evt) { return safe_scap_evt_t{evt, free}; }

protected:
	void open_filename(const std::string file_name) {
		std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + file_name;
		m_inspector = std::make_unique<sinsp>();
		m_inspector->open_savefile(path);
	}

	void assert_num_event_type(ppm_event_code event_type, uint64_t expected_count) {
		sinsp_evt* evt = nullptr;
		int ret = SCAP_SUCCESS;
		uint64_t count = 0;
		uint64_t number_of_evts = 0;
		while(1) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_EOF) {
				break;
			}
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event. scap_code: " + std::to_string(ret) +
				                         ", " + m_inspector->getlasterr());
			}
			if(evt->get_type() == event_type) {
				count++;
			}
			number_of_evts++;
		}
		ASSERT_EQ(count, expected_count);
	}

	void assert_no_event_type(ppm_event_code event_type) {
		sinsp_evt* evt = nullptr;
		int ret = SCAP_SUCCESS;
		while(1) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_EOF) {
				break;
			}
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event. scap_code: " + std::to_string(ret) +
				                         ", " + m_inspector->getlasterr());
			}
			if(evt->get_type() == event_type) {
				FAIL();
			}
		}
	}

	safe_scap_evt_t create_safe_scap_event(uint64_t ts,
	                                       uint64_t tid,
	                                       ppm_event_code event_type,
	                                       uint32_t n,
	                                       ...) {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args;
		va_start(args, n);
		scap_evt* evt = scap_create_event_v(error, ts, tid, event_type, n, args);
		va_end(args);
		if(evt == NULL) {
			throw std::runtime_error("Error creating event: " + std::string(error));
		}
		return create_safe_scap_evt(evt);
	}

	void assert_event_presence(safe_scap_evt_t expected_evt) {
		sinsp_evt* evt = nullptr;
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		int ret = SCAP_SUCCESS;
		while(1) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_EOF) {
				break;
			}
			if(ret != SCAP_SUCCESS) {
				throw std::runtime_error("Error reading event. scap_code: " + std::to_string(ret) +
				                         ", " + m_inspector->getlasterr());
			}
			if(evt->get_scap_evt()->ts == expected_evt->ts &&
			   evt->get_scap_evt()->tid == expected_evt->tid) {
				if(!scap_compare_events(evt->get_scap_evt(), expected_evt.get(), error)) {
					printf("\nExpected event:\n");
					scap_print_event(expected_evt.get(), PRINT_FULL);
					printf("\nConverted event:\n");
					scap_print_event(evt->get_scap_evt(), PRINT_FULL);
					FAIL() << error;
				}
				return;
			}
		}
		FAIL() << "There is no an event with ts: " << expected_evt->ts
		       << " and tid: " << expected_evt->tid;
	}

	sinsp_evt* capture_search_evt_by_type_and_tid(uint64_t type, int64_t tid) {
		sinsp_evt* evt;
		int ret = SCAP_SUCCESS;
		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
			if(ret == SCAP_SUCCESS && evt->get_type() == type && evt->get_tid() == tid) {
				return evt;
			}
		}
		return NULL;
	}

	void read_until_EOF() {
		sinsp_evt* evt;
		int ret = SCAP_SUCCESS;
		while(ret != SCAP_EOF) {
			ret = m_inspector->next(&evt);
		}
	}

	std::unique_ptr<sinsp> m_inspector;
};
