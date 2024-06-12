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

#include <libsinsp/filter_compare.h>
#include <libsinsp/sinsp_exception.h>
#include <libsinsp/utils.h>

#ifdef _WIN32
#define NOMINMAX
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include "arpa/inet.h"
#include <netdb.h>
#endif

//
// Fallback implementation of memmem
//
#if !defined(_GNU_SOURCE) && !defined(__APPLE__)
#include <string.h>

static inline void *memmem(const void *haystack, size_t haystacklen,
	const void *needle, size_t needlelen)
{
	const unsigned char *ptr;
	const unsigned char *end;

	if(needlelen == 0)
	{
		return (void *)haystack;
	}

	if(haystacklen < needlelen)
	{
		return NULL;
	}

	end = (const unsigned char *)haystack + haystacklen - needlelen;
	for(ptr = (const unsigned char *)haystack; ptr <= end; ptr++)
	{
		if(!memcmp(ptr, needle, needlelen))
		{
			return (void *)ptr;
		}
	}

	return NULL;
}
#endif

cmpop str_to_cmpop(std::string_view str)
{
	if(str == "=" || str == "==")
	{
		return CO_EQ;
	}
	else if(str == "!=")
	{
		return CO_NE;
	}
	else if(str == "<=")
	{
		return CO_LE;
	}
	else if(str == "<")
	{
		return CO_LT;
	}
	else if(str == ">=")
	{
		return CO_GE;
	}
	else if(str == ">")
	{
		return CO_GT;
	}
	else if(str == "contains")
	{
		return CO_CONTAINS;
	}
	else if(str == "icontains")
	{
		return CO_ICONTAINS;
	}
	else if(str == "bcontains")
	{
		return CO_BCONTAINS;
	}
	else if(str == "startswith")
	{
		return CO_STARTSWITH;
	}
	else if(str == "bstartswith")
	{
		return CO_BSTARTSWITH;
	}
	else if(str == "endswith")
	{
		return CO_ENDSWITH;
	}
	else if(str == "in")
	{
		return CO_IN;
	}
	else if(str == "intersects")
	{
		return CO_INTERSECTS;
	}
	else if(str == "pmatch")
	{
		return CO_PMATCH;
	}
	else if(str == "exists")
	{
		return CO_EXISTS;
	}
	else if(str == "glob")
	{
		return CO_GLOB;
	}
	else if(str == "iglob")
	{
		return CO_IGLOB;
	}

	throw sinsp_exception("unrecognized filter comparison operator '" + std::string(str) + "'");
}

bool cmpop_to_str(cmpop op, std::string& out)
{
	switch (op)
	{
	case CO_NONE: { out = "none"; return true; }
	case CO_EQ: { out = "="; return true; }
	case CO_NE: { out = "!="; return true; }
	case CO_LT: { out = "<"; return true; }
	case CO_LE: { out = "<="; return true; }
	case CO_GT: { out = ">"; return true; }
	case CO_GE: { out = ">="; return true; }
	case CO_CONTAINS: { out = "contains"; return true; }
	case CO_IN: { out = "in"; return true; }
	case CO_EXISTS: { out = "exists"; return true; }
	case CO_ICONTAINS: { out = "icontains"; return true; }
	case CO_STARTSWITH: { out = "startswith"; return true; }
	case CO_GLOB: { out = "glob"; return true; }
	case CO_IGLOB: { out = "iglob"; return true; }
	case CO_PMATCH: { out = "pmatch"; return true; }
	case CO_ENDSWITH: { out = "endswith"; return true; }
	case CO_INTERSECTS: { out = "intersects"; return true; }
	case CO_BCONTAINS: { out = "bcontains"; return true; }
	case CO_BSTARTSWITH: { out = "bstartswith"; return true; }
	default:
		ASSERT(false);
		out = "unknown";
		return false;
	}
};

std::string std::to_string(cmpop c)
{
	switch (c)
	{
	case CO_NONE: return "NONE";
	case CO_EQ: return "EQ";
	case CO_NE: return "NE";
	case CO_LT: return "LT";
	case CO_LE: return "LE";
	case CO_GT: return "GT";
	case CO_GE: return "GE";
	case CO_CONTAINS: return "CONTAINS";
	case CO_IN: return "IN";
	case CO_EXISTS: return "EXISTS";
	case CO_ICONTAINS: return "ICONTAINS";
	case CO_STARTSWITH: return "STARTSWITH";
	case CO_GLOB: return "GLOB";
	case CO_IGLOB: return "IGLOB";
	case CO_PMATCH: return "PMATCH";
	case CO_ENDSWITH: return "ENDSWITH";
	case CO_INTERSECTS: return "INTERSECTS";
	case CO_BCONTAINS: return "BCONTAINS";
	case CO_BSTARTSWITH: return "BSTARTSWITH";
	default:
		ASSERT(false);
		return "<unset>";
	}
};

static inline bool flt_is_comparable_numeric(cmpop op, std::string& err)
{
	switch(op)
	{
	case CO_EQ:
	case CO_NE:
	case CO_LT:
	case CO_LE:
	case CO_GT:
	case CO_GE:
	case CO_IN:
	case CO_INTERSECTS:
	case CO_EXISTS:
		return true;
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported for numeric filters";
		return false;
	}
}

static inline bool flt_is_comparable_bool(cmpop op, std::string& err)
{
	switch(op)
	{
	case CO_EQ:
	case CO_NE:
	case CO_IN:
	case CO_INTERSECTS:
	case CO_EXISTS:
		return true;
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported for numeric filters";
		return false;
	}
}

static inline bool flt_is_comparable_string(cmpop op, std::string& err)
{
	switch(op)
	{
	case CO_EQ:
	case CO_NE:
	case CO_LT:
	case CO_LE:
	case CO_GT:
	case CO_GE:
	case CO_CONTAINS:
	case CO_IN:
	case CO_EXISTS:
    case CO_ICONTAINS:
	case CO_STARTSWITH:
	case CO_GLOB:
	case CO_PMATCH:
	case CO_ENDSWITH:
	case CO_INTERSECTS:
	case CO_IGLOB:
		return true;
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported for string filters";
		return false;
	}
}

static inline bool flt_is_comparable_buffer(cmpop op, std::string& err)
{
	switch(op)
	{
	case CO_EQ:
	case CO_NE:
	case CO_CONTAINS:
	case CO_IN:
	case CO_EXISTS:
	case CO_STARTSWITH:
	case CO_ENDSWITH:
	case CO_INTERSECTS:
	case CO_BCONTAINS:
	case CO_BSTARTSWITH:
		return true;
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported for buffer filters";
		return false;
	}
}

static inline bool flt_is_comparable_ip_or_net(cmpop op, std::string& err)
{
	switch(op)
	{
	case CO_EQ:
	case CO_NE:
	case CO_IN:
	case CO_EXISTS:
	case CO_INTERSECTS:
		return true;
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported for ip address and network filters";
		return false;
	}
}

static inline bool flt_is_comparable_any_list(cmpop op, std::string& err)
{
	switch(op)
	{
	case CO_IN:
	case CO_EXISTS:
	case CO_INTERSECTS:
		return true;
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported list filters";
		return false;
	}
}

bool flt_is_comparable(cmpop op, ppm_param_type t, bool is_list, std::string& err)
{
	if(op == CO_EXISTS)
	{
		return true;
	}

	if (is_list)
	{
		switch (t)
		{
		case PT_CHARBUF:
		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
		case PT_BOOL:
		case PT_IPADDR:
		case PT_IPNET:
			return flt_is_comparable_any_list(op, err);
		default:
			err = "list filters are not supported for type '" + std::string(param_type_to_string(t)) + "'";
			return false;
		}
	}

	switch(t)
	{
	case PT_INT8:
	case PT_INT16:
	case PT_INT32:
	case PT_INT64:
	case PT_UINT8:
	case PT_UINT16:
	case PT_UINT32:
	case PT_UINT64:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
	case PT_SYSCALLID:
	case PT_SIGTYPE:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_PORT:
	case PT_FLAGS8:
	case PT_FLAGS16:
	case PT_FLAGS32:
	case PT_DOUBLE:
	case PT_MODE:
	case PT_ENUMFLAGS8:
	case PT_ENUMFLAGS16:
	case PT_ENUMFLAGS32:
		return flt_is_comparable_numeric(op, err);
	case PT_BOOL:
		return flt_is_comparable_bool(op, err);
	case PT_IPV4ADDR:
	case PT_IPV4NET:
	case PT_IPV6ADDR:
	case PT_IPV6NET:
	case PT_IPADDR:
	case PT_IPNET:
		return flt_is_comparable_ip_or_net(op, err);
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		return flt_is_comparable_string(op, err);
	case PT_BYTEBUF:
		return flt_is_comparable_buffer(op, err);
	default:
		std::string opname;
		cmpop_to_str(op, opname);
		err = "'" + opname + "' operator not supported for type '" + std::string(param_type_to_string(t)) + "'";
		return false;
	}
}

// little helper for functions below
template <typename Check>
static inline void _throw_if_not_comparable(cmpop op, Check c)
{
	std::string err;
	if (!c(op, err))
	{
		throw sinsp_exception(err);
	}
}

template<typename T>
static inline bool flt_compare_numeric(cmpop op, T operand1, T operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return (operand1 == operand2);
	case CO_NE:
		return (operand1 != operand2);
	case CO_LT:
		return (operand1 < operand2);
	case CO_LE:
		return (operand1 <= operand2);
	case CO_GT:
		return (operand1 > operand2);
	case CO_GE:
		return (operand1 >= operand2);
	default:
		_throw_if_not_comparable(op, flt_is_comparable_numeric);
		return false;
	}
}

static inline bool flt_compare_string(cmpop op, char* operand1, char* operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return (strcmp(operand1, operand2) == 0);
	case CO_NE:
		return (strcmp(operand1, operand2) != 0);
	case CO_CONTAINS:
		return (strstr(operand1, operand2) != NULL);
    case CO_ICONTAINS:
#ifdef _WIN32
	{
		std::string s1(operand1);
		std::string s2(operand2);
		std::transform(s1.begin(), s1.end(), s1.begin(), [](unsigned char c){ return std::tolower(c); });
		std::transform(s2.begin(), s2.end(), s2.begin(), [](unsigned char c){ return std::tolower(c); });
		return (strstr(s1.c_str(), s2.c_str()) != NULL);
	}
#else
		return (strcasestr(operand1, operand2) != NULL);
#endif
	case CO_STARTSWITH:
		return (strncmp(operand1, operand2, strlen(operand2)) == 0);
	case CO_ENDSWITH:
		return (sinsp_utils::endswith(operand1, operand2, strlen(operand1), strlen(operand2)));
	case CO_GLOB:
		return sinsp_utils::glob_match(operand2, operand1);
	case CO_IGLOB:
		return sinsp_utils::glob_match(operand2, operand1, true);
	case CO_LT:
		return (strcmp(operand1, operand2) < 0);
	case CO_LE:
		return (strcmp(operand1, operand2) <= 0);
	case CO_GT:
		return (strcmp(operand1, operand2) > 0);
	case CO_GE:
		return (strcmp(operand1, operand2) >= 0);
	case CO_PMATCH:
		// note: pmatch is not handled here
		return false;
	default:
		_throw_if_not_comparable(op, flt_is_comparable_string);
		return false;
	}
}

static inline bool flt_compare_buffer(cmpop op, char* operand1, char* operand2, uint32_t op1_len, uint32_t op2_len)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return op1_len == op2_len && (memcmp(operand1, operand2, op1_len) == 0);
	case CO_NE:
		return op1_len != op2_len || (memcmp(operand1, operand2, op1_len) != 0);
	case CO_CONTAINS:
		return (memmem(operand1, op1_len, operand2, op2_len) != NULL);
	case CO_BCONTAINS:
		return (memmem(operand1, op1_len, operand2, op2_len) != NULL);
	case CO_STARTSWITH:
		return op2_len <= op1_len && (memcmp(operand1, operand2, op2_len) == 0);
	case CO_BSTARTSWITH:
		return op2_len <= op1_len && (memcmp(operand1, operand2, op2_len) == 0);
	case CO_ENDSWITH:
		return (sinsp_utils::endswith(operand1, operand2, op1_len, op2_len));
	default:
		_throw_if_not_comparable(op, flt_is_comparable_buffer);
		return false;
	}
}

static inline bool flt_compare_bool(cmpop op, uint64_t operand1, uint64_t operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return (operand1 == operand2);
	case CO_NE:
		return (operand1 != operand2);
	default:
		_throw_if_not_comparable(op, flt_is_comparable_numeric);
		return false;
	}
}

static inline bool flt_compare_ipv4addr(cmpop op, uint64_t operand1, uint64_t operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return operand1 == operand2;
	case CO_NE:
		return operand1 != operand2;
	default:
		_throw_if_not_comparable(op, flt_is_comparable_ip_or_net);
		return false;
	}
}

static inline bool flt_compare_ipv6addr(cmpop op, ipv6addr* operand1, ipv6addr* operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return *operand1 == *operand2;
	case CO_NE:
		return *operand1 != *operand2;
	default:
		_throw_if_not_comparable(op, flt_is_comparable_ip_or_net);
		return false;
	}
}

bool flt_compare_ipv4net(cmpop op, uint64_t operand1, const ipv4net* operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return ((operand1 & operand2->m_netmask) == (operand2->m_ip & operand2->m_netmask));
	case CO_NE:
		return ((operand1 & operand2->m_netmask) != (operand2->m_ip & operand2->m_netmask));
	default:
		_throw_if_not_comparable(op, flt_is_comparable_ip_or_net);
		return false;
	}
}

bool flt_compare_ipv6net(cmpop op, const ipv6addr *operand1, const ipv6net *operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	case CO_INTERSECTS:
		return operand2->in_cidr(*operand1);
	case CO_NE:
		return !operand2->in_cidr(*operand1);
	default:
		_throw_if_not_comparable(op, flt_is_comparable_ip_or_net);
		return false;
	}
}

// flt_cast takes a pointer to memory, dereferences it as fromT type and casts it
// to a compatible toT type
template<class fromT, class toT>
static inline toT flt_cast(const void* ptr)
{
	fromT val;
	memcpy(&val, ptr, sizeof(fromT));

	return static_cast<toT>(val);
}

bool flt_compare(cmpop op, ppm_param_type type, const void* operand1, const void* operand2, uint32_t op1_len, uint32_t op2_len)
{
	//
	// sinsp_filter_check_*::compare
	// already discard NULL values
	//
	if(op == CO_EXISTS)
	{
		return true;
	}

	switch(type)
	{
	case PT_INT8:
		return flt_compare_numeric<int64_t>(op, flt_cast<int8_t, int64_t>(operand1), flt_cast<int8_t, int64_t>(operand2));
	case PT_INT16:
		return flt_compare_numeric<int64_t>(op, flt_cast<int16_t, int64_t>(operand1), flt_cast<int16_t, int64_t>(operand2));
	case PT_INT32:
		return flt_compare_numeric<int64_t>(op, flt_cast<int32_t, int64_t>(operand1), flt_cast<int32_t, int64_t>(operand2));
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		return flt_compare_numeric<int64_t>(op, flt_cast<int64_t, int64_t>(operand1), flt_cast<int64_t, int64_t>(operand2));
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		return flt_compare_numeric<uint64_t>(op, flt_cast<uint8_t, uint64_t>(operand1), flt_cast<uint8_t, uint64_t>(operand2));
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_ENUMFLAGS16:
	case PT_PORT:
	case PT_SYSCALLID:
		return flt_compare_numeric<uint64_t>(op, flt_cast<uint16_t, uint64_t>(operand1), flt_cast<uint16_t, uint64_t>(operand2));
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_MODE:
		return flt_compare_numeric<uint64_t>(op, flt_cast<uint32_t, uint64_t>(operand1), flt_cast<uint32_t, uint64_t>(operand2));
	case PT_BOOL:
		return flt_compare_bool(op, flt_cast<uint32_t, uint64_t>(operand1), flt_cast<uint32_t, uint64_t>(operand2));
	case PT_IPV4ADDR:
		if (op2_len != sizeof(struct in_addr))
		{
			return false;
		}
		return flt_compare_ipv4addr(op, flt_cast<uint32_t, uint64_t>(operand1), flt_cast<uint32_t, uint64_t>(operand2));
	case PT_IPV4NET:
		if (op2_len != sizeof(ipv4net))
		{
			return false;
		}
		return flt_compare_ipv4net(op, (uint64_t)*(uint32_t*)operand1, (ipv4net*)operand2);
	case PT_IPV6ADDR:
		if (op2_len != sizeof(ipv6addr))
		{
			return false;
		}
		return flt_compare_ipv6addr(op, (ipv6addr *)operand1, (ipv6addr *)operand2);
	case PT_IPV6NET:
		if (op2_len != sizeof(ipv6net))
		{
			return false;
		}
		return flt_compare_ipv6net(op, (ipv6addr *)operand1, (ipv6net*)operand2);
	case PT_IPADDR:
		if(op1_len == sizeof(struct in_addr))
		{
			if (op2_len != sizeof(struct in_addr))
			{
				return false;
			}
			return flt_compare(op, PT_IPV4ADDR, operand1, operand2, op1_len, op2_len);
		}
		else if(op1_len == sizeof(struct in6_addr))
		{
			if (op2_len != sizeof(ipv6addr))
			{
				return false;
			}
			return flt_compare(op, PT_IPV6ADDR, operand1, operand2, op1_len, op2_len);
		}
		else
		{
			throw sinsp_exception("rawval_to_string called with IP address of incorrect size " + std::to_string(op1_len));
		}
	case PT_IPNET:
		if(op1_len == sizeof(struct in_addr))
		{
			if (op2_len != sizeof(ipv4net))
			{
				return false;
			}
			return flt_compare(op, PT_IPV4NET, operand1, operand2, op1_len, op2_len);
		}
		else if(op1_len == sizeof(struct in6_addr))
		{
			if (op2_len != sizeof(ipv6net))
			{
				return false;
			}
			return flt_compare(op, PT_IPV6NET, operand1, operand2, op1_len, op2_len);
		}
		else
		{
			throw sinsp_exception("rawval_to_string called with IP network of incorrect size " + std::to_string(op1_len));
		}
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		return flt_compare_numeric<uint64_t>(op, flt_cast<uint64_t, uint64_t>(operand1), flt_cast<uint64_t, uint64_t>(operand2));
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		return flt_compare_string(op, (char*)operand1, (char*)operand2);
	case PT_BYTEBUF:
		return flt_compare_buffer(op, (char*)operand1, (char*)operand2, op1_len, op2_len);
	case PT_DOUBLE:
		return flt_compare_numeric<double>(op, flt_cast<double, double>(operand1), flt_cast<double, double>(operand2));
	default:
		ASSERT(false);
		return false;
	}
}

bool flt_compare_avg(cmpop op,
					 ppm_param_type type,
					 const void* operand1,
					 const void* operand2,
					 uint32_t op1_len,
					 uint32_t op2_len,
					 uint32_t cnt1,
					 uint32_t cnt2)
{
	int64_t i641, i642;
	uint64_t u641, u642;
	double d1, d2;

	//
	// If count = 0 we assume that the value is zero too (there are assertions to
	// check that, and we just divide by 1
	//
	if(cnt1 == 0)
	{
		cnt1 = 1;
	}

	if(cnt2 == 0)
	{
		cnt2 = 1;
	}

	switch(type)
	{
	case PT_INT8:
		i641 = ((int64_t)*(int8_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int8_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_numeric<int64_t>(op, i641, i642);
	case PT_INT16:
		i641 = ((int64_t)*(int16_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int16_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_numeric<int64_t>(op, i641, i642);
	case PT_INT32:
		i641 = ((int64_t)*(int32_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int32_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_numeric<int64_t>(op, i641, i642);
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		i641 = ((int64_t)*(int64_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int64_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_numeric<int64_t>(op, i641, i642);
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
		u641 = ((uint64_t)*(uint8_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint8_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_numeric<uint64_t>(op, u641, u642);
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_ENUMFLAGS16:
	case PT_PORT:
	case PT_SYSCALLID:
		u641 = ((uint64_t)*(uint16_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint16_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_numeric<uint64_t>(op, u641, u642);
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_MODE:
	case PT_BOOL:
	case PT_IPV4ADDR:
	case PT_IPV6ADDR:
		// What does an average mean for ip addresses anyway?
		u641 = ((uint64_t)*(uint32_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint32_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_numeric<uint64_t>(op, u641, u642);
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		u641 = (*(uint64_t*)operand1) / cnt1;
		u642 = (*(uint64_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_numeric<uint64_t>(op, u641, u642);
	case PT_DOUBLE:
		d1 = (*(double*)operand1) / cnt1;
		d2 = (*(double*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || d1 == 0);
		ASSERT(cnt2 != 0 || d2 == 0);
		return flt_compare_numeric<double>(op, d1, d2);
	default:
		ASSERT(false);
		return false;
	}
}
