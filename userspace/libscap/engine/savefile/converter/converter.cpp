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

#include <driver/ppm_events_public.h>
#include <converter/table.h>
#include <converter/results.h>
#include <converter/debug_macro.h>
#include <converter/scap_evt_param_reader.h>
#include <stdarg.h>
#include <cstdio>
#include <cassert>
#include <limits>
#include <string>
#include <stdexcept>
#include <memory>
#include <libscap/scap-int.h>
#include <libscap/strerror.h>

typedef std::shared_ptr<scap_evt> safe_scap_evt_t;

static inline safe_scap_evt_t safe_scap_evt(scap_evt *evt) {
	return safe_scap_evt_t{evt, free};
}

struct scap_convert_buffer {
	std::unordered_map<uint64_t, safe_scap_evt_t> evt_storage = {};
};

static const char *get_event_name(ppm_event_code event_type) {
	const struct ppm_event_info *event_info = &g_event_info[event_type];
	return event_info->name;
}

static char get_direction_char(ppm_event_code event_type) {
	if(PPME_IS_ENTER(event_type)) {
		return 'E';
	} else {
		return 'X';
	}
}

static void clear_evt(std::unordered_map<uint64_t, safe_scap_evt_t> &evt_storage, uint64_t tid) {
	if(evt_storage.find(tid) != evt_storage.end()) {
		evt_storage[tid].reset();
	}
}

static void store_evt(std::unordered_map<uint64_t, safe_scap_evt_t> &evt_storage,
                      uint64_t tid,
                      scap_evt *evt) {
	// if there was a previous event for this tid, we can overwrite the pointer because it means we
	// don't need it anymore. We need to keep the enter event until we retrieve it in the
	// corresponding exit event, but if the same thread is doing another enter event it means the
	// previous syscall is already completed.

	clear_evt(evt_storage, tid);

	scap_evt *tmp_evt = (scap_evt *)malloc(evt->len);
	if(!tmp_evt) {
		throw std::runtime_error("Cannot allocate memory for the enter event.");
	}
	memcpy(tmp_evt, evt, evt->len);
	evt_storage[tid] = safe_scap_evt(tmp_evt);
}

static scap_evt *retrieve_evt(std::unordered_map<uint64_t, safe_scap_evt_t> &evt_storage,
                              uint64_t tid) {
	if(evt_storage.find(tid) != evt_storage.end()) {
		return evt_storage[tid].get();
	}
	return nullptr;
}

// Return the number of bytes used to encode parameter lengths in the lengths array of the provided
// event. Currently, it returns 4 or 2, depending on the fact that the provided event has large
// payload or not.
static size_t get_param_len_size(const scap_evt *evt) {
	return g_event_info[evt->type].flags & EF_LARGE_PAYLOAD ? sizeof(uint32_t) : sizeof(uint16_t);
}

static ppm_param_type get_param_type(const scap_evt *evt, const uint8_t param_num) {
	return g_event_info[evt->type].params[param_num].type;
}

static uint32_t get_param_len_unchecked(const scap_evt *evt,
                                        const uint8_t param_num,
                                        const size_t len_size) {
	const size_t len_offset = sizeof(scap_evt) + param_num * len_size;
	auto *const len_ptr = reinterpret_cast<const char *>(evt) + len_offset;
	switch(len_size) {
	case sizeof(uint16_t): {
		uint16_t len;
		memcpy(&len, len_ptr, sizeof(uint16_t));
		return len;
	}
	case sizeof(uint32_t): {
		uint32_t len;
		memcpy(&len, len_ptr, sizeof(uint32_t));
		return len;
	}
	default:
		throw std::runtime_error("Unexpected length size: " + std::to_string(len_size));
	}
}

static void set_param_len_unchecked(scap_evt *evt,
                                    const uint8_t param_num,
                                    const uint32_t len,
                                    const size_t len_size) {
	const size_t len_offset = sizeof(scap_evt) + param_num * len_size;
	auto *const len_ptr = reinterpret_cast<char *>(evt) + len_offset;
	switch(len_size) {
	case sizeof(uint16_t): {
		const auto len_16 = static_cast<uint16_t>(len);
		memcpy(len_ptr, &len_16, sizeof(uint16_t));
		return;
	}
	case sizeof(uint32_t): {
		memcpy(len_ptr, &len, sizeof(uint32_t));
		return;
	}
	default:
		throw std::runtime_error("Unexpected length size: " + std::to_string(len_size));
	}
}

static uint32_t get_param_len(const scap_evt *evt, const uint8_t param_num, const size_t len_size) {
	if(evt->nparams <= param_num) {
		const auto evt_name = get_event_name(static_cast<ppm_event_code>(evt->type));
		const auto evt_dir_char = get_direction_char(static_cast<ppm_event_code>(evt->type));
		const std::string error{"Try to access len of param num '" + std::to_string(param_num) +
		                        "' for event " + evt_name + "_" + evt_dir_char +
		                        " (num parameters: " + std::to_string(evt->nparams) + ")."};
		throw std::runtime_error(error);
	}

	return get_param_len_unchecked(evt, param_num, len_size);
}

static const char *get_param_ptr_unchecked(const scap_evt *evt,
                                           const uint8_t param_num,
                                           const size_t len_size) {
	const size_t params_offset = sizeof(scap_evt) + len_size * evt->nparams;
	const auto *const params_ptr = reinterpret_cast<const char *>(evt) + params_offset;
	size_t param_offset = 0;
	for(auto i = 0; i < param_num; i++) {
		param_offset += get_param_len_unchecked(evt, i, len_size);
	}
	return params_ptr + param_offset;
}

static const char *get_param_ptr(const scap_evt *evt,
                                 const uint8_t param_num,
                                 const size_t len_size) {
	if(evt->nparams <= param_num) {
		const auto evt_name = get_event_name(static_cast<ppm_event_code>(evt->type));
		const auto evt_dir_char = get_direction_char(static_cast<ppm_event_code>(evt->type));
		const std::string error{"Try to access param num '" + std::to_string(param_num) +
		                        "' for event " + evt_name + "_" + evt_dir_char +
		                        " (num parameters: " + std::to_string(evt->nparams) + ")."};
		throw std::runtime_error(error);
	}

	return get_param_ptr_unchecked(evt, param_num, len_size);
}

static uint8_t get_default_value_size_bytes_from_type(const ppm_param_type t) {
	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
	case PT_SOCKADDR:  // Sockaddr default parameter is a single-byte PPM_AF_UNSPEC family value.
		return 1;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
		return 2;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_SIGSET:
		return 4;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		return 8;

	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
		return 0;

	default:
		// We forgot to handle something
		assert(false);
		break;
	}
	assert(false);
	return 0;
}

// `uint64_t` should be enough for all the types considering that types like CHARBUF, BYTEBUF
// have `len==0`. Just remember that the returned value effective content and size should be aligned
// with what is returned by `get_default_value_size_bytes_from_type()`.
static uint64_t get_default_value_from_type(const ppm_param_type t) {
	switch(t) {
	case PT_UID:
	case PT_GID:
		return std::numeric_limits<uint32_t>::max();
	case PT_SOCKADDR:
		return PPM_AF_UNSPEC;
	default:
		return 0;
	}
}

// Writes parameter length and value and update the provided parameter offsets accordingly to the
// written length.
static void push_default_parameter(scap_evt *evt, size_t *params_offset, const uint8_t param_num) {
	// Please ensure that `evt->type` is already the final type you want to obtain.
	// Otherwise, we will access the wrong entry in the event table.
	const auto param_type = get_param_type(evt, param_num);
	const auto len = get_default_value_size_bytes_from_type(param_type);
	const auto len_size = get_param_len_size(evt);

	PRINT_MESSAGE(
	        "push default param (%d, type: %d) with len (%d) at {params_offest (%d), "
	        "lens_offset (%d)}\n",
	        param_num,
	        param_type,
	        len,
	        *params_offset,
	        sizeof(scap_evt) + param_num * len_size);

	const uint64_t val = get_default_value_from_type(param_type);
	memcpy(reinterpret_cast<char *>(evt) + *params_offset, &val, len);
	*params_offset += len;
	set_param_len_unchecked(evt, param_num, len, len_size);
	evt->len += len;
}

static uint32_t get_min_param_len_from_type(const ppm_param_type t) {
	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
		return 1;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
		return 2;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_SIGSET:
		return 4;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		return 8;

	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
	case PT_SOCKADDR:
		return 0;

	default:
		// We forgot to handle something
		assert(false);
		break;
	}
	assert(false);
	return 0;
}

static uint32_t get_max_param_len_from_type(const ppm_param_type t, const size_t len_size) {
	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
		return 1;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
		return 2;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_SIGSET:
		return 4;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		return 8;

	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
	case PT_SOCKADDR:
		switch(len_size) {
		case sizeof(uint16_t): {
			return std::numeric_limits<uint16_t>::max();
		}
		case sizeof(uint32_t): {
			return std::numeric_limits<uint32_t>::max();
		}
		default:
			throw std::runtime_error("Unexpected length size: " + std::to_string(len_size));
		}

	default:
		// We forgot to handle something
		assert(false);
		break;
	}
	return 0;
}

// Writes parameter length and value and update the provided parameter offsets accordingly to the
// written length.
static void push_empty_parameter(scap_evt *evt, const uint8_t param_num) {
	const auto len_size = get_param_len_size(evt);

	PRINT_MESSAGE("push empty param (num: %d, type: %d), lens_offset (%d)}\n",
	              param_num,
	              get_param_type(evt, param_num),
	              sizeof(scap_evt) + param_num * len_size);

	// Just set the parameter length to 0.
	set_param_len_unchecked(evt, param_num, 0, len_size);
}

// Cap the provided parameter length to the maximum value allowed for the event parameter
// corresponding to the provided number. The parameter length size is used to determine the maximum
// value, as it can change depending on how big is the space to store a parameter length.
static uint32_t cap_param_len(const scap_evt *evt,
                              const uint8_t param_num,
                              const uint32_t param_len,
                              const size_t len_size) {
	const ppm_param_type param_type = get_param_type(evt, param_num);
	const auto max_param_len = get_max_param_len_from_type(param_type, len_size);
	return std::min(max_param_len, param_len);
}

// Writes parameter length and value and update the provided parameter offsets accordingly to the
// written length.
static void push_parameter(scap_evt *new_evt,
                           const scap_evt *tmp_evt,
                           size_t *new_evt_params_offset,
                           const uint8_t new_evt_param_num,
                           const uint8_t tmp_evt_param_num) {
	const auto new_evt_len_size = get_param_len_size(new_evt);
	const auto tmp_evt_len_size = get_param_len_size(tmp_evt);
	const auto tmp_evt_param_len = get_param_len(tmp_evt, tmp_evt_param_num, tmp_evt_len_size);
	const auto *const tmp_evt_param_ptr =
	        get_param_ptr(tmp_evt, tmp_evt_param_num, tmp_evt_len_size);
	const auto new_evt_param_len =
	        cap_param_len(new_evt, new_evt_param_num, tmp_evt_param_len, new_evt_len_size);
	auto *const new_evt_param_ptr = reinterpret_cast<char *>(new_evt) + *new_evt_params_offset;

	PRINT_MESSAGE(
	        "push param (%d, type: %d) with len (%d) at {params_offset: %d, "
	        "lens_offset: %d} from event type '%d', param (%d, type: %d) with len (%d)\n",
	        new_evt_param_num,
	        get_param_type(new_evt, new_evt_param_num),
	        new_evt_param_len,
	        *new_evt_params_offset,
	        sizeof(scap_evt) + new_evt_param_num * new_evt_len_size,
	        tmp_evt->type,
	        tmp_evt_param_num,
	        get_param_type(tmp_evt, tmp_evt_param_num),
	        tmp_evt_param_len);

	memcpy(new_evt_param_ptr, tmp_evt_param_ptr, new_evt_param_len);
	*new_evt_params_offset += new_evt_param_len;
	set_param_len_unchecked(new_evt, new_evt_param_num, new_evt_param_len, new_evt_len_size);
	new_evt->len += new_evt_param_len;
}

static size_t copy_old_params(scap_evt *new_evt, const scap_evt *evt_to_convert) {
	auto *const new_evt_ptr = reinterpret_cast<char *>(new_evt);
	const auto *const old_evt_ptr = reinterpret_cast<const char *>(evt_to_convert);
	size_t new_evt_offset = sizeof(scap_evt);
	size_t old_evt_offset = sizeof(scap_evt);
	const auto new_evt_len_size = get_param_len_size(new_evt);
	const auto old_evt_len_size = get_param_len_size(evt_to_convert);

	// Copy the lengths array.
	if(new_evt_len_size == old_evt_len_size) {
		// Optimization for the common case: the new event and the event to convert use both 2 or 4
		// bytes to encode a single length in the lengths array, so we can just copy the lengths
		// array into destination with a single memcpy.
		const auto bytes_to_copy = evt_to_convert->nparams * old_evt_len_size;
		memcpy(new_evt_ptr + new_evt_offset, old_evt_ptr + old_evt_offset, bytes_to_copy);
	} else {
		for(uint32_t i = 0; i < evt_to_convert->nparams; i++) {
			const auto len = get_param_len_unchecked(evt_to_convert, i, old_evt_len_size);
			set_param_len_unchecked(new_evt, i, len, new_evt_len_size);
		}
	}

	PRINT_MESSAGE(
	        "Copy lengths array (size %d) from old event offset '%d' to new event "
	        "offset '%d'\n",
	        evt_to_convert->nparams * old_evt_len_size,
	        old_evt_offset,
	        new_evt_offset);

	// Copy the parameters (we left some space for the missing lengths)
	new_evt_offset += new_evt->nparams * new_evt_len_size;
	old_evt_offset += evt_to_convert->nparams * old_evt_len_size;
	const uint32_t params_len =
	        evt_to_convert->len - (sizeof(scap_evt) + evt_to_convert->nparams * old_evt_len_size);
	memcpy(new_evt_ptr + new_evt_offset, old_evt_ptr + old_evt_offset, params_len);

	PRINT_MESSAGE(
	        "Copy parameters (size %d) from old event offset '%d' to new event "
	        "offset '%d'\n",
	        params_len,
	        old_evt_offset,
	        new_evt_offset);

	return new_evt_offset + params_len;
}

// note: the control flow of this function must always be kept in sync with the converter
// `README.md` content.
extern "C" conversion_result test_event_convertibility(const scap_evt *evt_to_convert,
                                                       char *error) {
	const auto evt_type = evt_to_convert->type;
	assert(evt_type < PPM_EVENT_MAX);
	const auto *evt_info = &g_event_info[evt_type];
	const auto evt_flags = evt_info->flags;

	// If the event is not yet managed by the converter we never need a conversion.
	if(!(evt_flags & EF_TMP_CONVERTER_MANAGED)) {
		// New event versions are allowed to proceed towards upper layers.
		if(!(evt_flags & EF_OLD_VERSION)) {
			return CONVERSION_COMPLETED;
		}

		// Old enter events not managed by converter must be dropped.
		if(PPME_IS_ENTER(evt_type)) {
			return CONVERSION_DROP;
		}

		// Malformed event table: old exit events must be managed by the converter and converted to
		// their new corresponding type.
		scap_errprintf(
		        error,
		        0,
		        "Bug. Old exit event (type: %d) must be flagged as managed by the scap-converter",
		        evt_type);
		assert(false);
		return CONVERSION_ERROR;
	}

	// If it is an enter event, it will always need a conversion.
	if(PPME_IS_ENTER(evt_type)) {
		return CONVERSION_CONTINUE;
	}

	// If it is an exit event it needs a conversion when:
	// - it is an `EF_OLD_VERSION`
	// - the number of parameters is different from the one in the event table

	// If we are a new event type we need to check the number of parameters.
	const uint32_t evt_params_num = evt_to_convert->nparams;
	const uint32_t expected_params_num = evt_info->nparams;
	assert(evt_params_num <= expected_params_num);

	// If the number of parameters is different from the one in the event table we need a
	// conversion.
	if(evt_flags & EF_OLD_VERSION || evt_params_num != expected_params_num) {
		return CONVERSION_CONTINUE;
	}

	return CONVERSION_COMPLETED;
}

extern "C" scap_evt *scap_retrieve_evt_from_converter_storage(
        std::unordered_map<uint64_t, safe_scap_evt_t> &evt_storage,
        uint64_t tid) {
	return retrieve_evt(evt_storage, tid);
}

extern "C" void scap_clear_converter_storage(
        std::unordered_map<uint64_t, safe_scap_evt_t> &evt_storage) {
	evt_storage.clear();
}

scap_evt_param_reader::scap_evt_param_reader(const scap_evt &evt): m_evt{evt} {}

size_t scap_evt_param_reader::read_into(const uint8_t param_num,
                                        void *buffer_ptr,
                                        const size_t buffer_len) const {
	const auto evt_ptr = &m_evt;
	const auto len_size = get_param_len_size(evt_ptr);
	const auto param_len = get_param_len(evt_ptr, param_num, len_size);
	if(buffer_len < param_len) {
		const auto param_type = g_event_info[evt_ptr->type].params[param_num].type;
		const std::string error{"Buffer length '" + std::to_string(buffer_len) +
		                        "' less than param (num '" + std::to_string(param_num) +
		                        "', type '" + std::to_string(param_type) + "')  length '" +
		                        std::to_string(param_len) + "'"};
		throw std::runtime_error(error);
	}
	const auto *param_ptr = get_param_ptr(evt_ptr, param_num, len_size);
	memcpy(buffer_ptr, param_ptr, param_len);
	return param_len;
}

// Writes parameter length and value and update the provided parameter offsets accordingly to the
// written length. If some pre-conditions are not met (e.g.: callback is a null pointer), a negative
// number is returned.
int push_parameter_from_callback(scap_evt *new_evt,
                                 const scap_evt *old_evt,
                                 size_t *new_evt_params_offset,
                                 const uint8_t new_evt_param_num,
                                 const conversion_instruction_callback callback,
                                 char *error) {
	if(callback == nullptr) {
		scap_errprintf(error,
		               0,
		               "We want to set parameter '%d' for event '%d' leveraging a callback "
		               "acting on event `%d`, but we have no callback!",
		               new_evt_param_num,
		               new_evt->type,
		               old_evt->type);
		return -1;
	}

	const auto param_type = get_param_type(new_evt, new_evt_param_num);
	const auto len_size = get_param_len_size(new_evt);
	const auto min_param_len = get_min_param_len_from_type(param_type);
	const auto max_param_len = get_max_param_len_from_type(param_type, len_size);
	const auto buffer = callback(scap_evt_param_reader{*old_evt}, min_param_len, max_param_len);
	const auto *buffer_ptr = std::data(buffer);
	const auto buffer_len = std::size(buffer);
	if(buffer_len < min_param_len || buffer_len > max_param_len) {
		scap_errprintf(error,
		               0,
		               "We want to set parameter '%d' for event '%d' whose length must be in the "
		               "interval '[%d; %d]', but the data returned by the configured callback has "
		               "length equal to '%ld'",
		               new_evt_param_num,
		               new_evt->type,
		               min_param_len,
		               max_param_len,
		               buffer_len);
		return -1;
	}

	PRINT_MESSAGE(
	        "push param (%d, type: %d) with allowed len in interval '[%d; %d]' at {params_offset: "
	        "%d, lens_offset: %d} from callback-generated buffer with len '%d', leveraging event "
	        "'%d'\n",
	        new_evt_param_num,
	        param_type,
	        min_param_len,
	        max_param_len,
	        *new_evt_params_offset,
	        sizeof(scap_evt) + new_evt_param_num * new_evt_len_size,
	        buffer_len,
	        tmp_evt->type);

	memcpy(reinterpret_cast<char *>(new_evt) + *new_evt_params_offset, buffer_ptr, buffer_len);
	*new_evt_params_offset += buffer_len;
	set_param_len_unchecked(new_evt, new_evt_param_num, buffer_len, len_size);
	new_evt->len += buffer_len;
	return 0;
}

static conversion_result convert_event(std::unordered_map<uint64_t, safe_scap_evt_t> &evt_storage,
                                       scap_evt *new_evt,
                                       scap_evt *evt_to_convert,
                                       const conversion_info &ci,
                                       char *error) {
	/////////////////////////////
	// Dispatch the action
	/////////////////////////////

	size_t params_offset = 0;
	int param_to_populate = 0;

	// We copy the entire event in any case so that we are ready to handle `CONVERSION_SKIP` cases
	// without further actions.
	memcpy(new_evt, evt_to_convert, evt_to_convert->len);

	switch(ci.m_action) {
	case C_ACTION_PASS:
		return CONVERSION_SKIP;

	// TODO(ekoops): the current implementation of `C_ACTION_STORE` and `C_ACTION_STORE_AND_PASS` is
	//   identical. However, in the future, `C_ACTION_STORE` will return something to indicate that
	//   the event should be dropped, while `C_ACTION_STORE_AND_PASS` will return `CONVERSION_SKIP`
	//   (or whatever is the name we choose to indicate that the event should proceed... Maybe we
	//   can reuse `CONVERSION_COMPLETE`). Update the implementation once we are ready to change
	//   the `C_ACTION_STORE` logic.
	case C_ACTION_STORE:
	case C_ACTION_STORE_AND_PASS:
		store_evt(evt_storage, evt_to_convert->tid, evt_to_convert);
		return CONVERSION_SKIP;

	case C_ACTION_ADD_PARAMS:
		// The new number of params is the previous one plus the number of conversion instructions.
		new_evt->nparams = evt_to_convert->nparams + ci.m_instrs.size();
		// Initial `new_evt->len` value set in `copy_old_params()`.
		params_offset = copy_old_params(new_evt, evt_to_convert);
		param_to_populate = evt_to_convert->nparams;
		break;

	case C_ACTION_CHANGE_TYPE:
		// The new number of params is the number of conversion instructions.
		new_evt->nparams = ci.m_instrs.size();
		new_evt->type = ci.m_desired_type;
		new_evt->len = 0;
		params_offset = sizeof(scap_evt) + new_evt->nparams * get_param_len_size(new_evt);
		param_to_populate = 0;
		break;

	default:
		scap_errprintf(error, 0, "Unhandled conversion action '%d'.", ci.m_action);
		return CONVERSION_ERROR;
	}

	/////////////////////////////
	// Fill the event to its most recent version
	/////////////////////////////

	PRINT_MESSAGE("New event header (the len is still the old one):\n");
	PRINT_EVENT(new_evt, PRINT_HEADER);

	scap_evt *tmp_evt = nullptr;
	// If this is true at the end of the for loop we will free its memory.
	bool used_enter_event = false;

	// We iterate over the instructions
	for(size_t i = 0; i < ci.m_instrs.size(); i++, param_to_populate++) {
		PRINT_MESSAGE("Instruction n° %d. Param to populate: %d\n", i, param_to_populate);

		auto &instr = ci.m_instrs[i];

		switch(instr.code) {
		case C_INSTR_FROM_EMPTY:
			push_empty_parameter(new_evt, param_to_populate);
			continue;
		case C_INSTR_FROM_DEFAULT:
			push_default_parameter(new_evt, &params_offset, param_to_populate);
			continue;

		case C_INSTR_FROM_ENTER:
			tmp_evt = retrieve_evt(evt_storage, evt_to_convert->tid);
			if(!tmp_evt) {
				// It could be due to different reasons:
				// - we dropped the enter event in the capture
				// - we jump here from a previous conversion. For example, we jump from `BRK_1_X` to
				// `BRK_4_X` but in this case we don't have the enter event BRK_4_E because we don't
				// convert `BRK_1_E` to `BRK_4_E`. It would be meaningless, they would't bring the
				// same info.
				break;
			}

			// todo!: understand if we can pretend this is an error or it is a normal situation.
			if(tmp_evt->type != evt_to_convert->type - 1) {
				scap_errprintf(
				        error,
				        0,
				        "The enter event for '%s_%c' is not the right one! Event found '%s_%c'.",
				        get_event_name((ppm_event_code)evt_to_convert->type),
				        get_direction_char((ppm_event_code)evt_to_convert->type),
				        get_event_name((ppm_event_code)tmp_evt->type),
				        get_direction_char((ppm_event_code)tmp_evt->type));
				return CONVERSION_ERROR;
			}

			if(tmp_evt->nparams <= instr.param_num) {
				scap_errprintf(
				        error,
				        0,
				        "We want to take parameter '%d' from enter event '%d' but this event "
				        "has only '%d' parameters!",
				        instr.param_num,
				        tmp_evt->type,
				        tmp_evt->nparams);
				return CONVERSION_ERROR;
			}

			used_enter_event = true;
			break;

		case C_INSTR_FROM_OLD:
			tmp_evt = evt_to_convert;
			if(tmp_evt->nparams <= instr.param_num) {
				// todo!: this sounds like an error but let's see in the future. At the moment we
				// fail
				scap_errprintf(error,
				               0,
				               "We want to take parameter '%d' from old event '%d' but this event "
				               "has only '%d' parameters!",
				               instr.param_num,
				               tmp_evt->type,
				               tmp_evt->nparams);
				return CONVERSION_ERROR;
			}
			break;

		case C_INSTR_FROM_CALLBACK:
			if(push_parameter_from_callback(new_evt,
			                                evt_to_convert,
			                                &params_offset,
			                                param_to_populate,
			                                instr.callback,
			                                error) != 0) {
				return CONVERSION_ERROR;
			}
			continue;

		default:
			scap_errprintf(error,
			               0,
			               "Unknown instruction (code: %d, param_num: %d).",
			               instr.code,
			               instr.param_num);
			return CONVERSION_ERROR;
		}

		if(!tmp_evt) {
			if(instr.flags & CIF_FALLBACK_TO_EMPTY) {
				push_empty_parameter(new_evt, param_to_populate);
			} else {
				push_default_parameter(new_evt, &params_offset, param_to_populate);
			}
			continue;
		}

		push_parameter(new_evt, tmp_evt, &params_offset, param_to_populate, instr.param_num);
	}

	if(used_enter_event) {
		// We can free the enter event for this thread because we don't need it anymore.
		clear_evt(evt_storage, evt_to_convert->tid);
	}
	new_evt->len = params_offset;

	PRINT_MESSAGE("Final event:\n");
	PRINT_EVENT(new_evt, PRINT_FULL);
	return test_event_convertibility(new_evt, error);
}

extern "C" struct scap_convert_buffer *scap_convert_alloc_buffer() {
	return new scap_convert_buffer();
}

extern "C" conversion_result scap_convert_event(struct scap_convert_buffer *buf,
                                                scap_evt *new_evt,
                                                scap_evt *evt_to_convert,
                                                char *error) {
	// This should be checked by the caller but just double check here.
	switch(const auto conv_res = test_event_convertibility(evt_to_convert, error)) {
	case CONVERSION_CONTINUE:
		break;
	case CONVERSION_ERROR:
		assert(false);
		return conv_res;
	default:
		scap_errprintf(error,
		               0,
		               "Conversion not needed for event (type: %d, nparams: %d), but got "
		               "conversion result '%d'.",
		               evt_to_convert->type,
		               evt_to_convert->nparams,
		               conv_res);
		assert(false);
		return CONVERSION_ERROR;
	}

	// If we need a conversion but we don't have an entry in the table we have an error.
	auto conv_key = conversion_key{evt_to_convert->type, (uint8_t)evt_to_convert->nparams};
	if(g_conversion_table.find(conv_key) == g_conversion_table.end()) {
		scap_errprintf(error,
		               0,
		               "Required conversion for event (type: %d, nparams: %d), but we don't handle "
		               "it in the table.",
		               evt_to_convert->type,
		               evt_to_convert->nparams);
		return CONVERSION_ERROR;
	}

	// If we reached this point we have for sure an entry in the conversion table.
	return convert_event(buf->evt_storage,
	                     new_evt,
	                     evt_to_convert,
	                     g_conversion_table.at(conv_key),
	                     error);
}

extern "C" void scap_convert_free_buffer(struct scap_convert_buffer *buf) {
	delete buf;
}
