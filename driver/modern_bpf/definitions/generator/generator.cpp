#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <fstream>
#include <algorithm>

#include "driver/ppm_events_public.h"

extern const struct ppm_event_info g_event_info[];

auto PREFACE = R"(// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2025 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef __EVENT_DIMENSIONS_H__
#define __EVENT_DIMENSIONS_H__

#include "vmlinux.h"

/* Here we have all the dimensions for fixed-size events.
 */

#define PARAM_LEN 2
#define HEADER_LEN sizeof(struct ppm_evt_hdr)

/// TODO: We have to move these in the event_table.c. Right now we don't
/// want to touch scap tables.

/* Syscall events */
)";

auto POSTFACE = R"(
#endif /* __EVENT_DIMENSIONS_H__ */
)";

// Use the following macro to get the stringified version of the C expression retrieving the type
// size (e.g.: SIZE_OF_EXPR(uint8_t) is resolved in "sizeof(uint8_t)").
#define SIZE_OF_EXPR(type) SIZE_OF_EXPR_##type

// Generate the "sizeof" stringified expression for the listed types. New handled types must be
// appended to the list.
#define SIZE_OF_EXPR_DECL_LIST_GEN(FN) \
	FN(int8_t)                         \
	FN(int16_t)                        \
	FN(int32_t)                        \
	FN(int64_t)                        \
	FN(uint8_t)                        \
	FN(uint16_t)                       \
	FN(uint32_t)                       \
	FN(uint64_t)
#define SIZE_OF_EXPR_DECL(type) char SIZE_OF_EXPR(type)[] = "sizeof(" #type ")";
SIZE_OF_EXPR_DECL_LIST_GEN(SIZE_OF_EXPR_DECL)
#undef SIZE_OF_EXPR_DECL
#undef SIZE_OF_EXPR_DECL_LIST_GEN

// Special expressions denoting variable size or unused parameter types.
char SIZE_OF_EXPR_VARIABLE_SIZE[] = "<variable_size>", SIZE_OF_EXPR_UNUSED[] = "<unused>";

// Table containing the mapping between parameter types and the corresponding stringified "sizeof"
// expression.
std::map<long long, char *> type_to_size_expr{
        {PT_NONE, SIZE_OF_EXPR_UNUSED},
        {PT_INT8, SIZE_OF_EXPR(int8_t)},
        {PT_INT16, SIZE_OF_EXPR(int16_t)},
        {PT_INT32, SIZE_OF_EXPR(int32_t)},
        {PT_INT64, SIZE_OF_EXPR(int64_t)},
        {PT_UINT8, SIZE_OF_EXPR(uint8_t)},
        {PT_UINT16, SIZE_OF_EXPR(uint16_t)},
        {PT_UINT32, SIZE_OF_EXPR(uint32_t)},
        {PT_UINT64, SIZE_OF_EXPR(uint64_t)},
        {PT_CHARBUF, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_BYTEBUF, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_ERRNO, SIZE_OF_EXPR(int64_t)},
        {PT_SOCKADDR, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_SOCKTUPLE, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_FD, SIZE_OF_EXPR(int64_t)},
        {PT_PID, SIZE_OF_EXPR(int64_t)},
        {PT_FDLIST, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_FSPATH, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_SYSCALLID, SIZE_OF_EXPR(uint16_t)},
        {PT_SIGTYPE, SIZE_OF_EXPR(uint8_t)},
        {PT_RELTIME, SIZE_OF_EXPR(uint64_t)},
        {PT_ABSTIME, SIZE_OF_EXPR(uint64_t)},
        {PT_PORT, SIZE_OF_EXPR_UNUSED},
        {PT_L4PROTO, SIZE_OF_EXPR_UNUSED},
        {PT_SOCKFAMILY, SIZE_OF_EXPR_UNUSED},
        {PT_BOOL, SIZE_OF_EXPR_UNUSED},
        {PT_IPV4ADDR, SIZE_OF_EXPR_UNUSED},
        {PT_DYN, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_FLAGS8, SIZE_OF_EXPR(uint8_t)},
        {PT_FLAGS16, SIZE_OF_EXPR(uint16_t)},
        {PT_FLAGS32, SIZE_OF_EXPR(uint32_t)},
        {PT_UID, SIZE_OF_EXPR(uint32_t)},
        {PT_GID, SIZE_OF_EXPR(uint32_t)},
        {PT_DOUBLE, SIZE_OF_EXPR_UNUSED},
        {PT_SIGSET, SIZE_OF_EXPR(uint32_t)},
        {PT_CHARBUFARRAY, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_CHARBUF_PAIR_ARRAY, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_IPV4NET, SIZE_OF_EXPR_UNUSED},
        {PT_IPV6ADDR, SIZE_OF_EXPR_UNUSED},
        {PT_IPV6NET, SIZE_OF_EXPR_UNUSED},
        {PT_IPADDR, SIZE_OF_EXPR_UNUSED},
        {PT_IPNET, SIZE_OF_EXPR_UNUSED},
        {PT_MODE, SIZE_OF_EXPR(uint32_t)},
        {PT_FSRELPATH, SIZE_OF_EXPR_VARIABLE_SIZE},
        {PT_ENUMFLAGS8, SIZE_OF_EXPR(uint8_t)},
        {PT_ENUMFLAGS16, SIZE_OF_EXPR(uint16_t)},
        {PT_ENUMFLAGS32, SIZE_OF_EXPR(uint32_t)},
};

// is_fixed_size_event determines if the provided event has a fixed size or not.
bool is_fixed_size_event(struct ppm_event_info const *const evt) {
	for(uint32_t i = 0; i < evt->nparams; i++) {
		auto &param = evt->params[i];
		auto const param_type = param.type;

		auto it = type_to_size_expr.find(param_type);
		if(it == type_to_size_expr.end()) {
			throw std::runtime_error("Unknown event parameter type: " + std::to_string(param_type));
		}

		auto const size_expr = it->second;
		// Just compare pointers is enough.
		if(size_expr == SIZE_OF_EXPR_UNUSED) {
			throw std::runtime_error("Unexpected unused event parameter type: " +
			                         std::to_string(param_type));
		}
		if(size_expr == SIZE_OF_EXPR_VARIABLE_SIZE) {
			return false;
		}
	}
	return true;
}

// get_vent_size_expr_counts returns, given the provided event and the resulting size expression of
// its parameters, a map containing, for each size expression, the number of occurrences.
std::map<std::string, size_t> get_event_size_expr_counts(struct ppm_event_info const *const evt) {
	std::map<std::string, size_t> size_expr_counts;
	for(uint32_t i = 0; i < evt->nparams; i++) {
		auto const &param = evt->params[i];
		auto const param_type = param.type;
		auto const it = type_to_size_expr.find(param_type);
		if(it == type_to_size_expr.end()) {
			throw std::runtime_error("Unknown event parameter type: " + std::to_string(param_type));
		}
		auto const size_expr = it->second;
		size_expr_counts[size_expr]++;
	}
	return size_expr_counts;
}

// output_event_size outputs the event size macro for the provided event into the provided output
// stream.
void output_event_size(std::ostream &os,
                       struct ppm_event_info const *const evt,
                       bool const is_enter_evt) {
	// Exclude old versions.
	if(evt->flags & EF_OLD_VERSION) {
		return;
	}

	std::string name{evt->name};
	// Ignore events without name.
	if(name == "NA") {
		return;
	}

	// Exclude events not having a fixed size.
	if(!is_fixed_size_event(evt)) {
		return;
	}

	// Generate the complete event size macro name.
	std::transform(name.cbegin(), name.cend(), name.begin(), toupper);
	if((evt->category & EC_TRACEPOINT) == 0) {
		name += is_enter_evt ? "_E" : "_X";
	}
	name += "_SIZE";

	// The event contains at least the header.
	os << "#define " << name << " HEADER_LEN";

	auto const params_num = evt->nparams;

	// Count the number of occurrences for each size expression.
	auto size_expr_counts = get_event_size_expr_counts(evt);

	// Output "size expression" * "number of occurrences of size expression", for each size
	// expression.
	for(auto const &[size_expr, count] : size_expr_counts) {
		os << " + " << size_expr;
		if(count != 1) {
			os << " * " << count;
		}
	}

	// Add "number of parameters" * PARAM_LEN, to account the size of each parameter length.
	if(params_num != 0) {
		os << " + PARAM_LEN";
		if(params_num != 1) {
			os << " * " << params_num;
		}
	}
	os << '\n';
}

int main(int argc, char *argv[]) {
	if(argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <filepath>\n";
		std::exit(EXIT_FAILURE);
	}

	std::string filepath{argv[1]};

	// Build file content.
	std::ostringstream oss;
	oss << PREFACE;
	for(int i = 0; i < PPM_EVENT_MAX; i++) {
		output_event_size(oss, &g_event_info[i], i % 2 == 0);
	}
	oss << POSTFACE;

	// Write content to file.
	std::ofstream f{filepath, std::fstream::out | std::fstream::trunc};
	f << oss.str();
	f.close();

	return 0;
}
