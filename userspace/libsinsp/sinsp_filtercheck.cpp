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

#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/utils.h>
#include <libscap/strl.h>
#include <libsinsp/sinsp_filtercheck.h>
#include <libsinsp/value_parser.h>

#include <re2/re2.h>

#define STRPROPERTY_STORAGE_SIZE 1024

std::string std::to_string(boolop b) {
	switch(b) {
	case BO_NONE:
		return "NONE";
	case BO_NOT:
		return "NOT";
	case BO_OR:
		return "OR";
	case BO_AND:
		return "AND";
	case BO_ORNOT:
		return "OR_NOT";
	case BO_ANDNOT:
		return "AND_NOT";
	};
	return "<unset>";
}

void sinsp_filter_check::default_re2_deleter::operator()(re2::RE2* __ptr) const {
	std::default_delete<re2::RE2>{}(__ptr);
}

template<typename Ptr, typename... Params>
static inline void ensure_unique_ptr_allocated(Ptr& p, Params... args) {
	if(!p) {
		p = std::make_unique<typename Ptr::element_type>(args...);
	}
}

template<typename Ptr, typename... Params>
static inline void ensure_unique_ptr_allocated_deleter(Ptr& p, Params... args) {
	if(!p) {
		p.reset(new typename Ptr::element_type(args...));
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_check::sinsp_filter_check() {
	m_boolop = BO_NONE;
	m_cmpop = CO_NONE;
	m_inspector = NULL;
	m_field = NULL;
	m_val_storages_min_size = (std::numeric_limits<uint32_t>::max)();
	m_val_storages_max_size = (std::numeric_limits<uint32_t>::min)();
}

void sinsp_filter_check::set_inspector(sinsp* inspector) {
	m_inspector = inspector;
}

template<class T>
static inline T rawval_cast(uint8_t* rawval) {
	T val;
	memcpy(&val, rawval, sizeof(T));
	return val;
}

Json::Value sinsp_filter_check::rawval_to_json(uint8_t* rawval,
                                               ppm_param_type ptype,
                                               ppm_print_format print_format,
                                               uint32_t len) {
	ASSERT(rawval != NULL);

	switch(ptype) {
	case PT_INT8:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return *(int8_t*)rawval;
		} else if(print_format == PF_OCT || print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}

	case PT_INT16:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return rawval_cast<int16_t>(rawval);
		} else if(print_format == PF_OCT || print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}

	case PT_INT32:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return rawval_cast<int32_t>(rawval);
		} else if(print_format == PF_OCT || print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}
	case PT_DOUBLE:
		if(print_format == PF_DEC) {
			return (Json::Value::Int64)(int64_t)rawval_cast<double>(rawval);
		} else {
			return (Json::Value)rawval_cast<double>(rawval);
		}
	case PT_INT64:
	case PT_PID:
	case PT_FD:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return (Json::Value::Int64)rawval_cast<int64_t>(rawval);
		} else {
			return rawval_to_string(rawval, ptype, print_format, len);
		}

	case PT_L4PROTO:  // This can be resolved in the future
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return *(uint8_t*)rawval;
		} else if(print_format == PF_OCT || print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}

	case PT_PORT:  // This can be resolved in the future
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return *(uint16_t*)rawval;
		} else if(print_format == PF_OCT || print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}

	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return *(uint32_t*)rawval;
		} else if(print_format == PF_OCT || print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}

	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(print_format == PF_DEC || print_format == PF_ID) {
			return (Json::Value::UInt64)rawval_cast<uint64_t>(rawval);
		} else if(print_format == PF_10_PADDED_DEC || print_format == PF_OCT ||
		          print_format == PF_HEX) {
			return rawval_to_string(rawval, ptype, print_format, len);
		} else {
			ASSERT(false);
			return Json::nullValue;
		}

	case PT_SOCKADDR:
	case PT_SOCKFAMILY:
		ASSERT(false);
		return Json::nullValue;

	case PT_BOOL:
		return Json::Value((bool)(rawval_cast<uint32_t>(rawval) != 0));

	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_BYTEBUF:
	case PT_IPV4ADDR:
	case PT_IPV6ADDR:
	case PT_IPADDR:
	case PT_IPNET:
	case PT_FSRELPATH:
		return rawval_to_string(rawval, ptype, print_format, len);
	default:
		ASSERT(false);
		throw sinsp_exception("wrong param type " + std::to_string((long long)ptype));
	}
}

char* sinsp_filter_check::rawval_to_string(uint8_t* rawval,
                                           ppm_param_type ptype,
                                           ppm_print_format print_format,
                                           uint32_t len) {
	char* prfmt;

	ASSERT(rawval != NULL);

	switch(ptype) {
	case PT_INT8:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo8;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRId8;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX8;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         *(int8_t*)rawval);
		return m_getpropertystr_storage.data();
	case PT_INT16:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo16;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRId16;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX16;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         rawval_cast<int16_t>(rawval));
		return m_getpropertystr_storage.data();
	case PT_INT32:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo32;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRId32;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX32;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         rawval_cast<int32_t>(rawval));
		return m_getpropertystr_storage.data();
	case PT_INT64:
	case PT_PID:
	case PT_ERRNO:
	case PT_FD:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo64;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRId64;
		} else if(print_format == PF_10_PADDED_DEC) {
			prfmt = (char*)"%09" PRId64;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX64;
		} else {
			prfmt = (char*)"%" PRId64;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         rawval_cast<int64_t>(rawval));
		return m_getpropertystr_storage.data();
	case PT_L4PROTO:  // This can be resolved in the future
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo8;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRIu8;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX8;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         *(uint8_t*)rawval);
		return m_getpropertystr_storage.data();
	case PT_PORT:  // This can be resolved in the future
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo16;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRIu16;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX16;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         rawval_cast<uint16_t>(rawval));
		return m_getpropertystr_storage.data();
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo32;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRIu32;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX32;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         rawval_cast<uint32_t>(rawval));
		return m_getpropertystr_storage.data();
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		if(print_format == PF_OCT) {
			prfmt = (char*)"%" PRIo64;
		} else if(print_format == PF_DEC || print_format == PF_ID) {
			prfmt = (char*)"%" PRIu64;
		} else if(print_format == PF_10_PADDED_DEC) {
			prfmt = (char*)"%09" PRIu64;
		} else if(print_format == PF_HEX) {
			prfmt = (char*)"%" PRIX64;
		} else {
			ASSERT(false);
			return NULL;
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         prfmt,
		         rawval_cast<uint64_t>(rawval));
		return m_getpropertystr_storage.data();
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		return (char*)rawval;
	case PT_BYTEBUF:
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		binary_buffer_to_string(m_getpropertystr_storage.data(),
		                        (const char*)rawval,
		                        (uint32_t)STRPROPERTY_STORAGE_SIZE - 1,
		                        len,
		                        m_inspector->get_buffer_format());
		return m_getpropertystr_storage.data();
	case PT_SOCKADDR:
		ASSERT(false);
		return NULL;
	case PT_SOCKFAMILY:
		ASSERT(false);
		return NULL;
	case PT_BOOL:
		if(rawval_cast<uint32_t>(rawval) != 0) {
			return (char*)"true";
		} else {
			return (char*)"false";
		}
	case PT_IPV4ADDR:
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
		         rawval[0],
		         rawval[1],
		         rawval[2],
		         rawval[3]);
		return m_getpropertystr_storage.data();
	case PT_IPV6ADDR: {
		char address[INET6_ADDRSTRLEN];

		if(NULL == inet_ntop(AF_INET6, rawval, address, INET6_ADDRSTRLEN)) {
			strlcpy(address, "<NA>", INET6_ADDRSTRLEN);
		}

		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		strlcpy(m_getpropertystr_storage.data(), address, STRPROPERTY_STORAGE_SIZE);

		return m_getpropertystr_storage.data();
	}
	case PT_IPADDR:
		if(len == sizeof(struct in_addr)) {
			return rawval_to_string(rawval, PT_IPV4ADDR, print_format, len);
		} else if(len == sizeof(struct in6_addr)) {
			return rawval_to_string(rawval, PT_IPV6ADDR, print_format, len);
		} else {
			throw sinsp_exception("rawval_to_string called with IP address of incorrect size " +
			                      std::to_string(len));
		}

	case PT_DOUBLE:
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(),
		         STRPROPERTY_STORAGE_SIZE,
		         "%.1lf",
		         rawval_cast<double>(rawval));
		return m_getpropertystr_storage.data();
	case PT_IPNET:
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		snprintf(m_getpropertystr_storage.data(), STRPROPERTY_STORAGE_SIZE, "<IPNET>");
		return m_getpropertystr_storage.data();
	default:
		ASSERT(false);
		throw sinsp_exception("wrong param type " + std::to_string((long long)ptype));
	}
}

char* sinsp_filter_check::tostring(sinsp_evt* evt) {
	m_extracted_values.clear();
	if(!extract(evt, m_extracted_values)) {
		return NULL;
	}

	auto ftype = get_transformed_field_info()->m_type;
	if(get_transformed_field_info()->m_flags & EPF_IS_LIST) {
		std::string res = "(";
		for(auto& val : m_extracted_values) {
			if(res.size() > 1) {
				res += ",";
			}
			res += rawval_to_string(val.ptr, ftype, m_field->m_print_format, val.len);
		}
		res += ")";
		m_getpropertystr_storage.resize(STRPROPERTY_STORAGE_SIZE);
		strlcpy(m_getpropertystr_storage.data(), res.c_str(), STRPROPERTY_STORAGE_SIZE);
		return m_getpropertystr_storage.data();
	}
	return rawval_to_string(m_extracted_values[0].ptr,
	                        ftype,
	                        m_field->m_print_format,
	                        m_extracted_values[0].len);
}

Json::Value sinsp_filter_check::tojson(sinsp_evt* evt) {
	uint32_t len;
	Json::Value jsonval = extract_as_js(evt, &len);

	if(jsonval == Json::nullValue) {
		m_extracted_values.clear();
		if(!extract(evt, m_extracted_values)) {
			return Json::nullValue;
		}

		auto ftype = get_transformed_field_info()->m_type;
		if(get_transformed_field_info()->m_flags & EPF_IS_LIST) {
			for(auto& val : m_extracted_values) {
				jsonval.append(rawval_to_json(val.ptr, ftype, m_field->m_print_format, val.len));
			}
			return jsonval;
		}
		return rawval_to_json(m_extracted_values[0].ptr,
		                      ftype,
		                      m_field->m_print_format,
		                      m_extracted_values[0].len);
	}

	return jsonval;
}

int32_t sinsp_filter_check::parse_field_name(std::string_view str,
                                             bool alloc_state,
                                             bool needed_for_filtering) {
	int32_t max_fldlen = -1;
	uint32_t max_flags = 0;

	ASSERT(m_info != nullptr);
	ASSERT(m_info->m_fields != NULL);
	ASSERT(m_info->m_nfields != -1);

	m_field_id = 0xffffffff;

	for(int32_t j = 0; j != m_info->m_nfields; ++j) {
		auto& fld = m_info->m_fields[j];
		int32_t fldlen = (int32_t)fld.m_name.size();
		if(fldlen <= max_fldlen) {
			continue;
		}

		/* Here we are searching for the longest match */
		if(str.compare(0, fldlen, fld.m_name) == 0) {
			/* we found some info about the required field, we save it in this way
			 * we don't have to loop again through the fields.
			 */
			m_field_id = j;
			m_field = &fld;
			max_fldlen = fldlen;
			max_flags = fld.m_flags;
		}
	}

	if(!needed_for_filtering) {
		if(max_flags & EPF_FILTER_ONLY) {
			throw sinsp_exception(std::string(str) +
			                      " is filter only and cannot be used as a display field");
		}
	}

	return max_fldlen;
}

void sinsp_filter_check::add_filter_value(const char* str, uint32_t len, uint32_t i) {
	if(has_filtercheck_value()) {
		throw sinsp_exception("can't add const field value: field '" +
		                      std::string(get_transformed_field_info()->m_name) +
		                      "' already has another field '" +
		                      m_rhs_filter_check->get_transformed_field_info()->m_name +
		                      "' as right-hand side value");
	}

	// create storage for the value at the given index, if not present
	while(i >= m_val_storages.size()) {
		m_val_storages.push_back(std::vector<uint8_t>(s_min_filter_value_buf_size));
	}

	// attempt parsing the value -- in case errors are found, it may be
	// that they are due to the underlying storage buffer for the value being
	// too short in size, so we retry by resizing it up until a certain max
	// size beyond which we just give up and propagate the errors thrown
	size_t parsed_len = 0;
	while(true) {
		try {
			parsed_len =
			        parse_filter_value(str, len, &(m_val_storages[i][0]), m_val_storages[i].size());
		} catch(sinsp_exception& e) {
			if(m_val_storages[i].size() >= s_max_filter_value_buf_size) {
				throw e;
			}
			m_val_storages[i].resize(m_val_storages[i].size() * 2);
			continue;
		}
		break;
	}

	// store the new value in the state
	filter_value_t item(&(m_val_storages[i][0]), parsed_len);
	m_vals.resize(i + 1);
	m_vals[i] = item;

	// populate operator-specific optimizations
	if(m_cmpop == CO_IN || m_cmpop == CO_INTERSECTS) {
		// If the operator is IN or INTERSECTS, populate the map search
		ensure_unique_ptr_allocated(m_val_storages_members);
		m_val_storages_members->insert(item);

		if(parsed_len < m_val_storages_min_size) {
			m_val_storages_min_size = parsed_len;
		}

		if(parsed_len > m_val_storages_max_size) {
			m_val_storages_max_size = parsed_len;
		}
	} else if(m_cmpop == CO_PMATCH) {
		// If the operator is CO_PMATCH, also add the value to the paths set.
		ensure_unique_ptr_allocated(m_val_storages_paths);
		m_val_storages_paths->add_search_path(item);
	} else if(m_cmpop == CO_REGEX) {
		ensure_unique_ptr_allocated_deleter(m_val_regex,
		                                    re2::StringPiece((const char*)item.first),
		                                    re2::RE2::POSIX);
	}
}

void sinsp_filter_check::add_filter_value(std::unique_ptr<sinsp_filter_check> rhs_chk) {
	if(!get_filter_values().empty()) {
		throw sinsp_exception(
		        "can't add '" + std::string(rhs_chk->get_transformed_field_info()->m_name) +
		        "' as field value: field '" + std::string(get_transformed_field_info()->m_name) +
		        "' is already compared with other const values");
	}

	if(has_filtercheck_value()) {
		throw sinsp_exception(
		        "can't add '" + std::string(rhs_chk->get_transformed_field_info()->m_name) +
		        "' as field value: field '" + std::string(get_transformed_field_info()->m_name) +
		        "' is already compared with right-hand side field '" +
		        std::string(m_rhs_filter_check->get_transformed_field_info()->m_name) + "'");
	}

	if(m_cmpop == CO_PMATCH || m_cmpop == CO_REGEX) {
		throw sinsp_exception("operator '" + std::to_string(m_cmpop) +
		                      "' doesn't support right-hand side fields");
	}

	if(get_transformed_field_info()->m_type == PT_IPNET ||
	   get_transformed_field_info()->m_type == PT_IPV4NET ||
	   get_transformed_field_info()->m_type == PT_IPV6NET) {
		throw sinsp_exception("field type 'IPNET' doesn't support right-hand side fields");
	}

	// For each filter check we need to answer 2 questions:
	// 1. Which filter checks cannot have a rhs filter check?
	// 2. Which filter checks cannot be used as a rhs filter check?
	//
	// There are the involved filter checks:
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. It cannot be used as a rhs filter check because doesn't provide the extraction phase.
	// "fd.ip"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. It cannot be used as a rhs filter check because doesn't provide the extraction phase.
	// "fd.net"
	//
	// 1. It requires a netmask as a rhs value, we don't have filter checks that return a netmask in
	// the extraction phase
	// 2. It cannot be used as a rhs value filter check for other `PT_IPNET` filter checks, becuase
	// they expect a netmask while it returns an address "fd.cnet" "fd.snet" "fd.lnet" "fd.rnet"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. It is a PT_DYN we don't know which is the effective type value.
	// "evt.rawarg"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. It has no real sense to be used as a rhs (we can do if want, let's see)
	// "evt.around"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. It cannot be used as a rhs filter check because doesn't provide the extraction phase.
	// "fd.port"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. It cannot be used as a rhs filter check because doesn't provide the extraction phase.
	// "fd.proto"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. OK! (but not supported for simplicity)
	// "proc.apid"
	// "proc.aname"
	// "proc.aexe"
	// "proc.aexepath"
	// "proc.acmdline"
	// "proc.aenv"
	//
	// 1. It has a custom comparison logic (no base `compare_nocache`) so we cannot use a rhs filter
	// check with this.
	// 2. OK! (but not supported for simplicity)
	// "fd.cip.name"
	// "fd.sip.name"
	// "fd.lip.name"
	// "fd.rip.name"

	if(!get_transformed_field_info()->is_rhs_field_supported()) {
		throw sinsp_exception("field '" + std::string(get_transformed_field_info()->m_name) +
		                      "' doesn't support right-hand side fields");
	}

	if(!rhs_chk->get_transformed_field_info()->is_rhs_field_supported()) {
		throw sinsp_exception("field '" +
		                      std::string(rhs_chk->get_transformed_field_info()->m_name) +
		                      "' can't be used as a right-hand side field");
	}

	m_rhs_filter_check = std::move(rhs_chk);

	check_rhs_field_type_consistency();
}

size_t sinsp_filter_check::parse_filter_value(const char* str,
                                              uint32_t len,
                                              uint8_t* storage,
                                              uint32_t storage_len) {
	size_t parsed_len;

	// byte buffer, no parsing needed
	if(get_transformed_field_info()->m_type == PT_BYTEBUF) {
		if(len >= storage_len) {
			throw sinsp_exception("filter parameter too long (byte buf)");
		}
		memcpy(storage, str, len);
		return len;
	} else {
		parsed_len =
		        sinsp_filter_value_parser::string_to_rawval(str,
		                                                    len,
		                                                    storage,
		                                                    storage_len,
		                                                    get_transformed_field_info()->m_type);
	}

	return parsed_len;
}

bool sinsp_filter_check::compare_rhs(cmpop op,
                                     ppm_param_type type,
                                     std::vector<extract_value_t>& values) {
	if(op == CO_EXISTS) {
		return true;
	}

	if(get_transformed_field_info()->is_list()) {
		// NOTE: using m_val_storages_members.find(item) relies on memcmp to
		// compare filter_value_t values, and not the base-level flt_compare.
		// This has two main consequences. First, this only works for equality
		// comparison, which luckily is what we want for 'in' and 'intersects'.
		// Second, the comparison happens between the value parsed data, which
		// means it may not work for all the supported data types, since
		// flt_compare uses some additional logic for certain data types (e.g. ipv6).
		// None of the libsinsp internal filterchecks use list type fields for now.
		//
		// todo(jasondellaluce): refactor filter_value_t to actually use flt_compare instead of
		// memcmp.
		switch(type) {
		case PT_CHARBUF:
		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
		case PT_BOOL:
		case PT_IPADDR:
		case PT_IPNET:
			break;
		default:
			throw sinsp_exception("list filters are not supported for type " +
			                      std::string(param_type_to_string(type)));
		}
		filter_value_t item(NULL, 0);
		switch(op) {
		case CO_EXISTS:
			// note: sinsp_filter_check_*::compare already discard NULL values
			return true;
		case CO_IN:
			for(const auto& it : values) {
				item.first = it.ptr;
				item.second = it.len;

				// note: PT_IPNET would not work with simple memcmp comparison
				// todo(jasondellaluce): refactor filter_value_t to actually use flt_compare instead
				// of memcmp.
				if(type == PT_IPNET) {
					bool found = false;
					for(const auto& m : m_vals) {
						if(::flt_compare(CO_EQ, type, item.first, m.first, item.second, m.second)) {
							found = true;
							break;
						}
					}
					if(!found) {
						return false;
					}
				} else {
					ensure_unique_ptr_allocated(m_val_storages_members);
					if(it.len < m_val_storages_min_size || it.len > m_val_storages_max_size ||
					   m_val_storages_members->find(item) == m_val_storages_members->end()) {
						return false;
					}
				}
			}
			return true;
		case CO_INTERSECTS:
			for(const auto& it : values) {
				item.first = it.ptr;
				item.second = it.len;

				// note: PT_IPNET would not work with simple memcmp comparison
				// todo(jasondellaluce): refactor filter_value_t to actually use flt_compare instead
				// of memcmp.
				if(type == PT_IPNET) {
					for(const auto& m : m_vals) {
						if(::flt_compare(CO_EQ, type, item.first, m.first, item.second, m.second)) {
							return true;
						}
					}
				} else {
					ensure_unique_ptr_allocated(m_val_storages_members);
					if(it.len >= m_val_storages_min_size && it.len <= m_val_storages_max_size &&
					   m_val_storages_members->find(item) != m_val_storages_members->end()) {
						return true;
					}
				}
			}
			return false;
		default:
			throw sinsp_exception("list filter '" +
			                      std::string(m_info->m_fields[m_field_id].m_name) +
			                      "' only supports operators 'exists', 'in' and 'intersects'");
		}
	} else if(values.size() > 1) {
		ASSERT(false);
		throw sinsp_exception("non-list filter '" +
		                      std::string(m_info->m_fields[m_field_id].m_name) +
		                      "' expected to extract a single value, but " +
		                      std::to_string(values.size()) + " were found");
	}

	return compare_rhs(m_cmpop, type, values[0].ptr, values[0].len);
}

static inline filter_value_t craft_filter_value(ppm_param_type type,
                                                const void* value,
                                                uint32_t len) {
	// For raw strings, the length may not be set. So we do a strlen to find it.
	switch(type) {
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		// set len if missing
		if(len == 0) {
			len = strlen((const char*)value);
		}

		// don't count terminator chars
		while(len > 0 && ((const char*)value)[len - 1] == '\0') {
			len--;
		}
		break;
	default:
		break;
	}
	return filter_value_t{(uint8_t*)value, len};
}

bool sinsp_filter_check::compare_rhs(cmpop op,
                                     ppm_param_type type,
                                     const void* operand1,
                                     uint32_t op1_len) {
	switch(op) {
	case CO_EXISTS:
		return true;
	case CO_IN:
	case CO_PMATCH:
	case CO_INTERSECTS: {
		// Certain filterchecks can't be done as a set
		// membership test/group match. For these, just loop over the
		// values and see if any value is equal.
		switch(type) {
		case PT_IPV4NET:
		case PT_IPV6NET:
		case PT_IPNET:
		case PT_SOCKADDR:
		case PT_SOCKTUPLE:
		case PT_FDLIST:
		case PT_SIGSET:
			for(uint16_t i = 0; i < m_vals.size(); i++) {
				if(::flt_compare(CO_EQ,
				                 type,
				                 operand1,
				                 filter_value_p(i),
				                 op1_len,
				                 filter_value_len(i))) {
					return true;
				}
			}
			return false;
		default:
			auto item = craft_filter_value(type, operand1, op1_len);

			if(op == CO_IN || op == CO_INTERSECTS) {
				// CO_INTERSECTS is really more interesting when a filtercheck can extract
				// multiple values, and you're comparing the set of extracted values
				// against the set of rhs values. sinsp_filter_checks only extract a
				// single value, so CO_INTERSECTS is really the same as CO_IN.
				ensure_unique_ptr_allocated(m_val_storages_members);
				if(item.second >= m_val_storages_min_size &&
				   item.second <= m_val_storages_max_size &&
				   m_val_storages_members->find(item) != m_val_storages_members->end()) {
					return true;
				}
			} else {
				ensure_unique_ptr_allocated(m_val_storages_paths);
				if(m_val_storages_paths->match(item)) {
					return true;
				}
			}

			return false;
		}
		return false;
	}
	case CO_REGEX:
		switch(type) {
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			if(m_val_regex) {
				auto item = craft_filter_value(type, operand1, op1_len);
				re2::StringPiece s((const char*)item.first, item.second);
				return m_val_regex
				        ->Match(s, 0, item.second, re2::RE2::Anchor::ANCHOR_BOTH, nullptr, 0);
			}
			// fallthrough
		default:
			ASSERT(false);
			return false;
		};
	default:
		return (::flt_compare(op, type, operand1, filter_value_p(), op1_len, filter_value_len()));
	}
}

bool sinsp_filter_check::extract_nocache(sinsp_evt* evt,
                                         std::vector<extract_value_t>& values,
                                         bool sanitize_strings) {
	values.clear();
	extract_value_t val;
	val.ptr = extract_single(evt, &val.len, sanitize_strings);
	if(val.ptr != NULL) {
		values.push_back(val);
		return true;
	}
	return false;
}

uint8_t* sinsp_filter_check::extract_single(sinsp_evt* evt, uint32_t* len, bool sanitize_strings) {
	return NULL;
}

bool sinsp_filter_check::extract(sinsp_evt* evt,
                                 std::vector<extract_value_t>& values,
                                 bool sanitize_strings) {
	if(m_cache_metrics != NULL) {
		m_cache_metrics->m_num_extract++;
	}

	// no cache is installed, so just default to non-cached extraction
	if(!m_extract_cache) {
		// extract values and apply transformers on top of them
		return extract_nocache(evt, values, sanitize_strings) && apply_transformers(values);
	}

	// cache is not valid for this event, so we perform a non-cached extraction
	// and update it for the next time. We cache both failed and succeeded extractions
	if(!m_extract_cache->is_valid(evt)) {
		// for now, we support only shallow copies of cached values for performance
		// gains -- we rely on each filtercheck to keep owning the result values
		// across different extractions
		bool deepcopy = false;
		auto res = extract_nocache(evt, values, sanitize_strings) && apply_transformers(values);
		m_extract_cache->update(evt, res, values, deepcopy);
		return res;
	}

	// cache hit, so copy the values, update the metrics, and return
	values = m_extract_cache->values();
	if(m_cache_metrics != NULL) {
		m_cache_metrics->m_num_extract_cache++;
	}
	return m_extract_cache->result();
}

bool sinsp_filter_check::compare(sinsp_evt* evt) {
	if(m_cache_metrics != NULL) {
		m_cache_metrics->m_num_compare++;
	}

	// no cache is installed, so just default to non-cached comparison
	if(!m_compare_cache) {
		return compare_nocache(evt);
	}

	// cache is not valid for this event, so we perform a non-cached comparison
	// and update it for the next time. We cache both failed and succeeded comparison
	if(!m_compare_cache->is_valid(evt)) {
		auto res = compare_nocache(evt);
		m_compare_cache->update(evt, res);
		return res;
	}

	// cache hit, so copy the values, update the metrics, and return
	if(m_cache_metrics != NULL) {
		m_cache_metrics->m_num_compare_cache++;
	}
	return m_compare_cache->result();
}

bool sinsp_filter_check::compare_nocache(sinsp_evt* evt) {
	m_extracted_values.clear();
	if(!extract(evt, m_extracted_values, false)) {
		return false;
	}

	auto lhs_type = get_transformed_field_info()->m_type;
	if(has_filtercheck_value()) {
		check_rhs_field_type_consistency();

		m_rhs_filter_check->m_extracted_values.clear();
		if(!m_rhs_filter_check->extract(evt, m_rhs_filter_check->m_extracted_values, false)) {
			return false;
		}

		populate_filter_values_with_rhs_extracted_values(m_rhs_filter_check->m_extracted_values);
	}

	return compare_rhs(m_cmpop, lhs_type, m_extracted_values);
}

void sinsp_filter_check::add_transformer(filter_transformer_type trtype) {
	auto original_type = get_field_info();
	if(!original_type) {
		throw sinsp_exception("transformer added to non-initialized field info");
	}

	if(!original_type->is_transformer_supported()) {
		throw sinsp_exception("field '" + std::string(get_field_info()->m_name) +
		                      "' does not support transformers");
	}

	// lazily allocate copy of the field's info to add transformations on top of
	// note: we (legitimately) assume that the original type will
	// never change after filtercheck creation, so we create a copy
	// only once and on-demand
	ensure_unique_ptr_allocated(m_transformed_field, *original_type);

	// apply type transformation, both as a feasibility check and
	// as an information to be returned later on
	auto tr = sinsp_filter_transformer::create_transformer(trtype);
	if(!tr->transform_type(m_transformed_field->m_type, m_transformed_field->m_flags)) {
		throw sinsp_exception("can't add field transformer: type '" +
		                      std::string(param_type_to_string(m_transformed_field->m_type)) +
		                      "' is not supported by '" + filter_transformer_type_str(trtype) +
		                      "' transformer applied on " +
		                      (m_transformed_field->is_list() ? "list " : "") + "field '" +
		                      std::string(get_field_info()->m_name) + "'");
	}

	// add transformer to the back of the list, they will be applied at
	// runtime from least-recently-added to most-recently-added. This is also
	// the same order by which type trasformations are applied in the block above
	m_transformers.push_back(std::move(tr));

	check_rhs_field_type_consistency();
}

bool sinsp_filter_check::apply_transformers(std::vector<extract_value_t>& values) {
	const filtercheck_field_info* field_info = get_field_info();
	auto field_type = field_info->m_type;
	auto field_flags = field_info->m_flags;
	for(auto& tr : m_transformers) {
		if(!tr->transform_values(values, field_type, field_flags)) {
			return false;
		}
	}
	return true;
}

void sinsp_filter_check::populate_filter_values_with_rhs_extracted_values(
        const std::vector<extract_value_t>& values) {
	// The storage of the extracted values from the rhs filter check should
	// be handled by the filter check itself during the extraction.

	// Clean the previous comparison.
	m_vals.clear();

	// These are needed for In/Intersects
	if(m_cmpop == CO_IN || m_cmpop == CO_INTERSECTS) {
		ensure_unique_ptr_allocated(m_val_storages_members);
		m_val_storages_members->clear();
		m_val_storages_min_size = (std::numeric_limits<uint32_t>::max)();
		m_val_storages_max_size = (std::numeric_limits<uint32_t>::min)();
	}

	for(const auto& v : values) {
		filter_value_t item(v.ptr, v.len);
		m_vals.push_back(item);

		if(m_cmpop == CO_IN || m_cmpop == CO_INTERSECTS) {
			m_val_storages_members->insert(std::move(item));
			if(v.len < m_val_storages_min_size) {
				m_val_storages_min_size = v.len;
			}

			if(v.len > m_val_storages_max_size) {
				m_val_storages_max_size = v.len;
			}
		}
	}
}

void sinsp_filter_check::check_rhs_field_type_consistency() const {
	if(!has_filtercheck_value()) {
		return;
	}

	auto lhs_type = get_transformed_field_info()->m_type;
	auto lhs_list = get_transformed_field_info()->is_list();

	auto rhs_list = m_rhs_filter_check->get_transformed_field_info()->is_list();
	auto rhs_type = m_rhs_filter_check->get_transformed_field_info()->m_type;

	if(!(lhs_type == rhs_type && lhs_list == rhs_list)) {
		throw sinsp_exception(
		        "field '" + std::string(get_transformed_field_info()->m_name) + "' has type '" +
		        std::string(param_type_to_string(lhs_type)) + (lhs_list ? " (list)" : "") +
		        "' while the right-hand side field '" +
		        std::string(m_rhs_filter_check->get_transformed_field_info()->m_name) +
		        "' has incompatible type '" + std::string(param_type_to_string(rhs_type)) +
		        (rhs_list ? " (list)" : "") + "'");
	}
}
