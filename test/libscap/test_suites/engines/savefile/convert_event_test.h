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
#include <cstdarg>
#include <memory>
#include <stdexcept>
#include <libscap/engine/savefile/converter/converter.h>

typedef std::shared_ptr<scap_evt> safe_scap_evt_t;
safe_scap_evt_t new_safe_scap_evt(scap_evt *evt) {
	return safe_scap_evt_t{evt, free};
}
class convert_event_test : public testing::Test {
	static constexpr uint16_t safe_margin = 100;

	static void set_empty_parameters(const safe_scap_evt_t &expected_evt,
	                                 const std::set<uint32_t> &expected_empty_param_indexes) {
		if(expected_empty_param_indexes.empty()) {
			return;
		}

		const auto evt = expected_evt.get();

		uint16_t params_offset = sizeof(scap_evt) + evt->nparams * sizeof(uint16_t);
		constexpr uint64_t zero = 0;
		for(size_t i = 0; i < expected_evt->nparams; i++) {
			const auto len_offset = sizeof(scap_evt) + i * sizeof(uint16_t);
			// Get original length value.
			uint16_t len;
			memcpy(&len, reinterpret_cast<char *>(evt) + len_offset, sizeof(uint16_t));

			if(expected_empty_param_indexes.find(i) == expected_empty_param_indexes.end()) {
				params_offset += len;
				continue;
			}

			// Set the parameter length and value to zero.
			memcpy(reinterpret_cast<char *>(evt) + len_offset, &zero, sizeof(uint16_t));
			memcpy(reinterpret_cast<char *>(evt) + params_offset, &zero, len);
			params_offset += len;
		}
	}

protected:
	// Return an empty value for the type T.
	template<typename T>
	constexpr static T empty_value() {
		return static_cast<T>(0);
	}

	virtual void SetUp() {
		m_converter_buf = scap_convert_alloc_buffer();
		ASSERT_NE(m_converter_buf, nullptr);
	}

	virtual void TearDown() { scap_convert_free_buffer(m_converter_buf); }

	static safe_scap_evt_t create_safe_scap_event(uint64_t ts,
	                                              uint64_t tid,
	                                              ppm_event_code event_type,
	                                              uint32_t n,
	                                              ...) {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		va_list args;
		va_start(args, n);
		scap_evt *evt = scap_create_event_v(error, ts, tid, event_type, n, args);
		va_end(args);
		if(evt == NULL) {
			throw std::runtime_error("Error creating event: " + std::string(error));
		}
		return new_safe_scap_evt(evt);
	}

	// The expected result can be either CONVERSION_CONTINUE or CONVERSION_COMPLETED
	void assert_single_conversion_success(
	        const conversion_result expected_res,
	        const safe_scap_evt_t &evt_to_convert,
	        const safe_scap_evt_t &expected_evt,
	        const std::set<uint32_t> &expected_empty_param_indexes = {}) const {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		// We assume it's okay to create a new event with the same size as the expected event
		auto storage = new_safe_scap_evt((scap_evt *)calloc(1, expected_evt->len));
		// First we check the conversion result matches the expected result
		ASSERT_EQ(scap_convert_event(m_converter_buf, storage.get(), evt_to_convert.get(), error),
		          expected_res)
		        << "Different conversion results: " << error;

		set_empty_parameters(expected_evt, expected_empty_param_indexes);

		if(!scap_compare_events(storage.get(), expected_evt.get(), error)) {
			printf("\nExpected event:\n");
			scap_print_event(expected_evt.get(), PRINT_FULL);
			printf("\nConverted event:\n");
			scap_print_event(storage.get(), PRINT_FULL);
			FAIL() << error;
		}
	}

	void assert_single_conversion_failure(const safe_scap_evt_t &evt_to_convert) const {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		// We assume it's okay to create a new event with the same size as the expected event
		auto storage = new_safe_scap_evt((scap_evt *)calloc(1, evt_to_convert->len));
		// First we check the conversion result matches the expected result
		ASSERT_EQ(scap_convert_event(m_converter_buf, storage.get(), evt_to_convert.get(), error),
		          CONVERSION_ERROR)
		        << "The conversion is not failed: " << error;
	}
	void assert_single_conversion_skip(const safe_scap_evt_t &evt_to_convert) const {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		// We assume it's okay to create a new event with the same size as the expected event
		auto storage = new_safe_scap_evt((scap_evt *)calloc(1, evt_to_convert->len));
		// First we check the conversion result matches the expected result
		ASSERT_EQ(scap_convert_event(m_converter_buf, storage.get(), evt_to_convert.get(), error),
		          CONVERSION_SKIP)
		        << "The conversion is not skipped: " << error;
	}
	void assert_full_conversion(const safe_scap_evt_t &evt_to_convert,
	                            const safe_scap_evt_t &expected_evt,
	                            const std::set<uint32_t> &expected_empty_param_indexes = {}) const {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		// Here we need to allocate more space than the expected event because in the middle we
		// could have larger events. We could also use `MAX_EVENT_SIZE` but probably it will just
		// slowdown tests.
		auto to_convert_evt = new_safe_scap_evt(
		        (scap_evt *)calloc(1, expected_evt->len + convert_event_test::safe_margin));
		auto new_evt = new_safe_scap_evt(
		        (scap_evt *)calloc(1, expected_evt->len + convert_event_test::safe_margin));
		// We copy the event to convert into the new larger storage since during the conversions it
		// could contain larger events than the initial one.
		// We copy it in the new event to match the for loop logic.
		memcpy(new_evt.get(), evt_to_convert.get(), evt_to_convert->len);
		int conv_num = 0;
		conversion_result conv_res = CONVERSION_CONTINUE;
		for(conv_num = 0; conv_num < MAX_CONVERSION_BOUNDARY && conv_res == CONVERSION_CONTINUE;
		    conv_num++) {
			// Copy the new event into the one to convert for the next conversion.
			memcpy(to_convert_evt.get(), new_evt.get(), new_evt->len);
			conv_res = scap_convert_event(m_converter_buf,
			                              (scap_evt *)new_evt.get(),
			                              (scap_evt *)to_convert_evt.get(),
			                              error);
		}
		switch(conv_res) {
		case CONVERSION_ERROR:
			FAIL() << "Unexpected CONVERSION_ERROR: " << error;
		case CONVERSION_SKIP:
			FAIL() << "Unexpected CONVERSION_SKIP";
		case CONVERSION_CONTINUE:
			if(conv_num < MAX_CONVERSION_BOUNDARY) {
				FAIL() << "Unexpected CONVERSION_CONTINUE without reaching max boundary";
			} else {
				FAIL() << "Unexpected CONVERSION_CONTINUE reaching max boundary";
			}
		default:
			break;
		}

		set_empty_parameters(expected_evt, expected_empty_param_indexes);

		if(!scap_compare_events(new_evt.get(), expected_evt.get(), error)) {
			printf("\nExpected event:\n");
			scap_print_event(expected_evt.get(), PRINT_FULL);
			printf("\nConverted event:\n");
			scap_print_event(new_evt.get(), PRINT_FULL);
			FAIL() << error;
		}
	}
	void assert_event_storage_presence(const safe_scap_evt_t &expected_evt) const {
		char error[SCAP_LASTERR_SIZE] = {'\0'};
		int64_t tid = expected_evt.get()->tid;
		auto event = scap_retrieve_evt_from_converter_storage(m_converter_buf, tid);
		if(!event) {
			FAIL() << "Event with tid " << tid << " not found in the storage";
		}
		if(!scap_compare_events(event, expected_evt.get(), error)) {
			FAIL() << "Different events: " << error;
		}
	}

	struct scap_convert_buffer *m_converter_buf = nullptr;
};
