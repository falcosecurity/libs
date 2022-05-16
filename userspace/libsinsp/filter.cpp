/*
Copyright (C) 2021 The Falco Authors.

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

//
// Why isn't this parser written using antlr or some other parser generator?
// Essentially, after dealing with that stuff multiple times in the past, and fighting for a day
// to configure everything with crappy documentation and code that doesn't compile,
// I decided that I agree with this http://mortoray.com/2012/07/20/why-i-dont-use-a-parser-generator/
// and that I'm going with a manually written parser. The grammar is simple enough that it's not
// going to take more time. On the other hand I will avoid a crappy dependency that breaks my
// code at every new release, and I will have a cleaner and easier to understand code base.
//

#ifdef _WIN32
#define NOMINMAX
#endif

#include <regex>
#include <algorithm>

#include "sinsp.h"
#include "sinsp_int.h"
#include "utils.h"

#include "filter.h"
#include "filterchecks.h"
#include "value_parser.h"
#include "filter/parser.h"
#ifndef _WIN32
#include "arpa/inet.h"
#endif

#ifndef _GNU_SOURCE
//
// Fallback implementation of memmem
//
void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
#endif

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
#else
#include <netdb.h>
#endif


///////////////////////////////////////////////////////////////////////////////
// type-based comparison functions
///////////////////////////////////////////////////////////////////////////////
bool flt_compare_uint64(cmpop op, uint64_t operand1, uint64_t operand2)
{
	switch(op)
	{
	case CO_EQ:
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
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for numeric filters");
		return false;
	case CO_ENDSWITH:
		throw sinsp_exception("'endswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("'unknown' not supported for numeric filters");
		return false;
	}
}

bool flt_compare_int64(cmpop op, int64_t operand1, int64_t operand2)
{
	switch(op)
	{
	case CO_EQ:
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
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for numeric filters");
		return false;
	case CO_ENDSWITH:
		throw sinsp_exception("'endswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("'unknown' not supported for numeric filters");
		return false;
	}
}

bool flt_compare_string(cmpop op, char* operand1, char* operand2)
{
	switch(op)
	{
	case CO_EQ:
		return (strcmp(operand1, operand2) == 0);
	case CO_NE:
		return (strcmp(operand1, operand2) != 0);
	case CO_CONTAINS:
		return (strstr(operand1, operand2) != NULL);
    case CO_ICONTAINS:
#ifdef _WIN32
	{
		string s1(operand1);
		string s2(operand2);
		std::transform(s1.begin(), s1.end(), s1.begin(), [](unsigned char c){ return std::tolower(c); });
		std::transform(s2.begin(), s2.end(), s2.begin(), [](unsigned char c){ return std::tolower(c); });
		return (strstr(s1.c_str(), s2.c_str()) != NULL);
	}
#else
		return (strcasestr(operand1, operand2) != NULL);
#endif
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for string filters");
	case CO_STARTSWITH:
		return (strncmp(operand1, operand2, strlen(operand2)) == 0);
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for string filters");
	case CO_ENDSWITH: 
		return (sinsp_utils::endswith(operand1, operand2));
	case CO_GLOB:
		return sinsp_utils::glob_match(operand2, operand1);
	case CO_LT:
		return (strcmp(operand1, operand2) < 0);
	case CO_LE:
		return (strcmp(operand1, operand2) <= 0);
	case CO_GT:
		return (strcmp(operand1, operand2) > 0);
	case CO_GE:
		return (strcmp(operand1, operand2) >= 0);
	default:
		ASSERT(false);
		throw sinsp_exception("invalid filter operator " + std::to_string((long long) op));
		return false;
	}
}

bool flt_compare_buffer(cmpop op, char* operand1, char* operand2, uint32_t op1_len, uint32_t op2_len)
{
	switch(op)
	{
	case CO_EQ:
		return op1_len == op2_len && (memcmp(operand1, operand2, op1_len) == 0);
	case CO_NE:
		return op1_len != op2_len || (memcmp(operand1, operand2, op1_len) != 0);
	case CO_CONTAINS:
		return (memmem(operand1, op1_len, operand2, op2_len) != NULL);
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for buffer filters");
	case CO_BCONTAINS:
	{
		std::vector<char> hex_chars(operand2, operand2 + op2_len);
		std::vector<char> hex_bytes;
		if(!sinsp_utils::unhex(hex_chars, hex_bytes))
		{
			throw sinsp_exception("filter error: bcontains operator supports hex strings only");
		}
		return (memmem(operand1, op1_len, &hex_bytes[0], hex_bytes.size()) != NULL);
	}
	case CO_STARTSWITH:
		return op2_len <= op1_len && (memcmp(operand1, operand2, op2_len) == 0);
	case CO_BSTARTSWITH:
	{
		std::vector<char> hex_chars(operand2, operand2 + op2_len);
		std::vector<char> hex_bytes;
		if(!sinsp_utils::unhex(hex_chars, hex_bytes))
		{
			throw sinsp_exception("filter error: bstartswith operator supports hex strings only");
		}
		return hex_bytes.size() <= op1_len && (memcmp(operand1, &hex_bytes[0], hex_bytes.size()) == 0);
	}
	case CO_ENDSWITH: 
		return (sinsp_utils::endswith(operand1, operand2, op1_len, op2_len));
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for buffer filters");
	case CO_LT:
		throw sinsp_exception("'<' not supported for buffer filters");
	case CO_LE:
		throw sinsp_exception("'<=' not supported for buffer filters");
	case CO_GT:
		throw sinsp_exception("'>' not supported for buffer filters");
	case CO_GE:
		throw sinsp_exception("'>=' not supported for buffer filters");
	default:
		ASSERT(false);
		throw sinsp_exception("invalid filter operator " + std::to_string((long long) op));
		return false;
	}
}

bool flt_compare_double(cmpop op, double operand1, double operand2)
{
	switch(op)
	{
	case CO_EQ:
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
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for numeric filters");
		return false;
	case CO_ENDSWITH:
		throw sinsp_exception("'endswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("'unknown' not supported for numeric filters");
		return false;
	}
}

bool flt_compare_ipv4net(cmpop op, uint64_t operand1, const ipv4net* operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
	{
		return ((operand1 & operand2->m_netmask) == (operand2->m_ip & operand2->m_netmask));
	}
	case CO_NE:
		return ((operand1 & operand2->m_netmask) != (operand2->m_ip & operand2->m_netmask));
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for numeric filters");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for numeric filters");
		return false;
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for numeric filters");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for numeric filters");
		return false;
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for numeric filters");
		return false;
	case CO_ENDSWITH:
		throw sinsp_exception("'endswith' not supported for numeric filters");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for numeric filters");
		return false;
	default:
		throw sinsp_exception("comparison operator not supported for ipv4 networks");
	}
}

bool flt_compare_ipv6addr(cmpop op, ipv6addr *operand1, ipv6addr *operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
		return *operand1 == *operand2;
	case CO_NE:
		return *operand1 != *operand2;
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for ipv6 addresses");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for ipv6 addresses");
		return false;
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for ipv6 addresses");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for ipv6 addresses");
		return false;
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for ipv6 addresses");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for ipv6 addresses");
		return false;
	default:
		throw sinsp_exception("comparison operator not supported for ipv6 addresses");
	}
}

bool flt_compare_ipv6net(cmpop op, const ipv6addr *operand1, const ipv6net *operand2)
{
	switch(op)
	{
	case CO_EQ:
	case CO_IN:
		return operand2->in_cidr(*operand1);
	case CO_NE:
		return !operand2->in_cidr(*operand1);
	case CO_CONTAINS:
		throw sinsp_exception("'contains' not supported for ipv6 networks");
		return false;
	case CO_ICONTAINS:
		throw sinsp_exception("'icontains' not supported for ipv6 networks");
		return false;
	case CO_BCONTAINS:
		throw sinsp_exception("'bcontains' not supported for ipv6 networks");
		return false;
	case CO_STARTSWITH:
		throw sinsp_exception("'startswith' not supported for ipv6 networks");
		return false;
	case CO_BSTARTSWITH:
		throw sinsp_exception("'bstartswith' not supported for ipv6 networks");
		return false;
	case CO_GLOB:
		throw sinsp_exception("'glob' not supported for ipv6 networks");
		return false;
	default:
		throw sinsp_exception("comparison operator not supported for ipv6 networks");
	}
}

bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len)
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
		return flt_compare_int64(op, (int64_t)*(int8_t*)operand1, (int64_t)*(int8_t*)operand2);
	case PT_INT16:
		return flt_compare_int64(op, (int64_t)*(int16_t*)operand1, (int64_t)*(int16_t*)operand2);
	case PT_INT32:
		return flt_compare_int64(op, (int64_t)*(int32_t*)operand1, (int64_t)*(int32_t*)operand2);
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		return flt_compare_int64(op, *(int64_t*)operand1, *(int64_t*)operand2);
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		return flt_compare_uint64(op, (uint64_t)*(uint8_t*)operand1, (uint64_t)*(uint8_t*)operand2);
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_ENUMFLAGS16:
	case PT_PORT:
	case PT_SYSCALLID:
		return flt_compare_uint64(op, (uint64_t)*(uint16_t*)operand1, (uint64_t)*(uint16_t*)operand2);
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_MODE:
	case PT_BOOL:
	case PT_IPV4ADDR:
		return flt_compare_uint64(op, (uint64_t)*(uint32_t*)operand1, (uint64_t)*(uint32_t*)operand2);
	case PT_IPV4NET:
		return flt_compare_ipv4net(op, (uint64_t)*(uint32_t*)operand1, (ipv4net*)operand2);
	case PT_IPV6ADDR:
		return flt_compare_ipv6addr(op, (ipv6addr *)operand1, (ipv6addr *)operand2);
	case PT_IPV6NET:
		return flt_compare_ipv6net(op, (ipv6addr *)operand1, (ipv6net*)operand2);
	case PT_IPADDR:
		if(op1_len == sizeof(struct in_addr))
		{
			return flt_compare(op, PT_IPV4ADDR, operand1, operand2, op1_len, op2_len);
		}
		else if(op1_len == sizeof(struct in6_addr))
		{
			return flt_compare(op, PT_IPV6ADDR, operand1, operand2, op1_len, op2_len);
		}
		else
		{
			throw sinsp_exception("rawval_to_string called with IP address of incorrect size " + to_string(op1_len));
		}
	case PT_IPNET:
		if(op1_len == sizeof(struct in_addr))
		{
			return flt_compare(op, PT_IPV4NET, operand1, operand2, op1_len, op2_len);
		}
		else if(op1_len == sizeof(struct in6_addr))
		{
			return flt_compare(op, PT_IPV6NET, operand1, operand2, op1_len, op2_len);
		}
		else
		{
			throw sinsp_exception("rawval_to_string called with IP network of incorrect size " + to_string(op1_len));
		}
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		return flt_compare_uint64(op, *(uint64_t*)operand1, *(uint64_t*)operand2);
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		return flt_compare_string(op, (char*)operand1, (char*)operand2);
	case PT_BYTEBUF:
		return flt_compare_buffer(op, (char*)operand1, (char*)operand2, op1_len, op2_len);
	case PT_DOUBLE:
		return flt_compare_double(op, *(double*)operand1, *(double*)operand2);
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_SIGSET:
	default:
		ASSERT(false);
		return false;
	}
}

bool flt_compare_avg(cmpop op,
					 ppm_param_type type,
					 void* operand1,
					 void* operand2,
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
		return flt_compare_int64(op, i641, i642);
	case PT_INT16:
		i641 = ((int64_t)*(int16_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int16_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_INT32:
		i641 = ((int64_t)*(int32_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int32_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_INT64:
	case PT_FD:
	case PT_PID:
	case PT_ERRNO:
		i641 = ((int64_t)*(int64_t*)operand1) / cnt1;
		i642 = ((int64_t)*(int64_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || i641 == 0);
		ASSERT(cnt2 != 0 || i642 == 0);
		return flt_compare_int64(op, i641, i642);
	case PT_FLAGS8:
	case PT_UINT8:
	case PT_ENUMFLAGS8:
	case PT_SIGTYPE:
		u641 = ((uint64_t)*(uint8_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint8_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
	case PT_FLAGS16:
	case PT_UINT16:
	case PT_ENUMFLAGS16:
	case PT_PORT:
	case PT_SYSCALLID:
		u641 = ((uint64_t)*(uint16_t*)operand1) / cnt1;
		u642 = ((uint64_t)*(uint16_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
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
		return flt_compare_uint64(op, u641, u642);
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		u641 = (*(uint64_t*)operand1) / cnt1;
		u642 = (*(uint64_t*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || u641 == 0);
		ASSERT(cnt2 != 0 || u642 == 0);
		return flt_compare_uint64(op, u641, u642);
	case PT_DOUBLE:
		d1 = (*(double*)operand1) / cnt1;
		d2 = (*(double*)operand2) / cnt2;
		ASSERT(cnt1 != 0 || d1 == 0);
		ASSERT(cnt2 != 0 || d2 == 0);
		return flt_compare_double(op, d1, d2);
	default:
		ASSERT(false);
		return false;
	}
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_check::sinsp_filter_check()
{
	m_boolop = BO_NONE;
	m_cmpop = CO_NONE;
	m_inspector = NULL;
	m_field = NULL;
	m_info.m_fields = NULL;
	m_info.m_nfields = -1;
	m_val_storage_len = 0;
	m_aggregation = A_NONE;
	m_merge_aggregation = A_NONE;
	m_val_storages = vector<vector<uint8_t>> (1, vector<uint8_t>(256));
	m_val_storages_min_size = (numeric_limits<uint32_t>::max)();
	m_val_storages_max_size = (numeric_limits<uint32_t>::min)();
}

void sinsp_filter_check::set_inspector(sinsp* inspector)
{
	m_inspector = inspector;
}

Json::Value sinsp_filter_check::rawval_to_json(uint8_t* rawval,
					       ppm_param_type ptype,
					       ppm_print_format print_format,
					       uint32_t len)
{
	ASSERT(rawval != NULL);

	switch(ptype)
	{
		case PT_INT8:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return *(int8_t *)rawval;
			}
			else if(print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_INT16:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return *(int16_t *)rawval;
			}
			else if(print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_INT32:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return *(int32_t *)rawval;
			}
			else if(print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_INT64:
		case PT_PID:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
		 		return (Json::Value::Int64)*(int64_t *)rawval;
			}
			else
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}

		case PT_L4PROTO: // This can be resolved in the future
		case PT_UINT8:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return *(uint8_t *)rawval;
			}
			else if(print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_PORT: // This can be resolved in the future
		case PT_UINT16:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return *(uint16_t *)rawval;
			}
			else if(print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_UINT32:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return *(uint32_t *)rawval;
			}
			else if(print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
			if(print_format == PF_DEC ||
			   print_format == PF_ID)
			{
				return (Json::Value::UInt64)*(uint64_t *)rawval;
			}
			else if(
				print_format == PF_10_PADDED_DEC ||
				print_format == PF_OCT ||
				print_format == PF_HEX)
			{
				return rawval_to_string(rawval, ptype, print_format, len);
			}
			else
			{
				ASSERT(false);
				return Json::nullValue;
			}

		case PT_SOCKADDR:
		case PT_SOCKFAMILY:
			ASSERT(false);
			return Json::nullValue;

		case PT_BOOL:
			return Json::Value((bool)(*(uint32_t*)rawval != 0));

		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_BYTEBUF:
		case PT_IPV4ADDR:
		case PT_IPV6ADDR:
		case PT_IPADDR:
		case PT_FSRELPATH:
			return rawval_to_string(rawval, ptype, print_format, len);
		default:
			ASSERT(false);
			throw sinsp_exception("wrong event type " + to_string((long long) ptype));
	}
}

char* sinsp_filter_check::rawval_to_string(uint8_t* rawval,
					   ppm_param_type ptype,
					   ppm_print_format print_format,
					   uint32_t len)
{
	char* prfmt;

	ASSERT(rawval != NULL);

	switch(ptype)
	{
		case PT_INT8:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo8;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId8;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX8;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int8_t *)rawval);
			return m_getpropertystr_storage;
		case PT_INT16:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo16;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId16;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX16;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int16_t *)rawval);
			return m_getpropertystr_storage;
		case PT_INT32:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo32;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId32;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX32;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int32_t *)rawval);
			return m_getpropertystr_storage;
		case PT_INT64:
		case PT_PID:
		case PT_ERRNO:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo64;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRId64;
			}
			else if(print_format == PF_10_PADDED_DEC)
			{
				prfmt = (char*)"%09" PRId64;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX64;
			}
			else
			{
				prfmt = (char*)"%" PRId64;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(int64_t *)rawval);
			return m_getpropertystr_storage;
		case PT_L4PROTO: // This can be resolved in the future
		case PT_UINT8:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo8;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu8;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIu8;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint8_t *)rawval);
			return m_getpropertystr_storage;
		case PT_PORT: // This can be resolved in the future
		case PT_UINT16:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo16;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu16;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIu16;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint16_t *)rawval);
			return m_getpropertystr_storage;
		case PT_UINT32:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo32;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu32;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIu32;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint32_t *)rawval);
			return m_getpropertystr_storage;
		case PT_UINT64:
		case PT_RELTIME:
		case PT_ABSTIME:
			if(print_format == PF_OCT)
			{
				prfmt = (char*)"%" PRIo64;
			}
			else if(print_format == PF_DEC ||
				print_format == PF_ID)
			{
				prfmt = (char*)"%" PRIu64;
			}
			else if(print_format == PF_10_PADDED_DEC)
			{
				prfmt = (char*)"%09" PRIu64;
			}
			else if(print_format == PF_HEX)
			{
				prfmt = (char*)"%" PRIX64;
			}
			else
			{
				ASSERT(false);
				return NULL;
			}

			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 prfmt, *(uint64_t *)rawval);
			return m_getpropertystr_storage;
		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			return (char*)rawval;
		case PT_BYTEBUF:
			if(rawval[len] == 0)
			{
				return (char*)rawval;
			}
			else
			{
				ASSERT(len < 1024 * 1024);

				if(len >= filter_value()->size())
				{
					filter_value()->resize(len + 1);
				}

				memcpy(filter_value_p(), rawval, len);
				filter_value_p()[len] = 0;
				return (char*)filter_value_p();
			}
		case PT_SOCKADDR:
			ASSERT(false);
			return NULL;
		case PT_SOCKFAMILY:
			ASSERT(false);
			return NULL;
		case PT_BOOL:
			if(*(uint32_t*)rawval != 0)
			{
				return (char*)"true";
			}
			else
			{
				return (char*)"false";
			}
		case PT_IPV4ADDR:
			snprintf(m_getpropertystr_storage,
						sizeof(m_getpropertystr_storage),
						"%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
						rawval[0],
						rawval[1],
						rawval[2],
						rawval[3]);
			return m_getpropertystr_storage;
		case PT_IPV6ADDR:
		{
			char address[INET6_ADDRSTRLEN];

			if(NULL == inet_ntop(AF_INET6, rawval, address, INET6_ADDRSTRLEN))
			{
				strcpy(address, "<NA>");
			}

			strlcpy(m_getpropertystr_storage, address, sizeof(m_getpropertystr_storage));

			return m_getpropertystr_storage;
		}
	        case PT_IPADDR:
			if(len == sizeof(struct in_addr))
			{
				return rawval_to_string(rawval, PT_IPV4ADDR, print_format, len);
			}
			else if(len == sizeof(struct in6_addr))
			{
				return rawval_to_string(rawval, PT_IPV6ADDR, print_format, len);
			}
			else
			{
				throw sinsp_exception("rawval_to_string called with IP address of incorrect size " + to_string(len));
			}

		case PT_DOUBLE:
			snprintf(m_getpropertystr_storage,
					 sizeof(m_getpropertystr_storage),
					 "%.1lf", *(double*)rawval);
			return m_getpropertystr_storage;
		default:
			ASSERT(false);
			throw sinsp_exception("wrong event type " + to_string((long long) ptype));
	}
}

char* sinsp_filter_check::tostring(sinsp_evt* evt)
{
	vector<extract_value_t> raw_values;
	if(!extract_cached(evt, raw_values))
	{
		return NULL;
	}

	if (m_field->m_flags & EPF_IS_LIST)
	{
		std::string res = "(";
		for (auto &val : raw_values)
		{
			if (res.size() > 1)
			{
				res += ",";
			}
			res += rawval_to_string(val.ptr, m_field->m_type, m_field->m_print_format, val.len);
		}
		res += ")";
		strncpy(m_getpropertystr_storage, res.c_str(), sizeof(m_getpropertystr_storage) - 1);
		return m_getpropertystr_storage;
	}
	return rawval_to_string(raw_values[0].ptr, m_field->m_type, m_field->m_print_format, raw_values[0].len);
}

Json::Value sinsp_filter_check::tojson(sinsp_evt* evt)
{
	uint32_t len;
	Json::Value jsonval = extract_as_js(evt, &len);

	if(jsonval == Json::nullValue)
	{
		vector<extract_value_t> raw_values;
		if(!extract_cached(evt, raw_values))
		{
			return Json::nullValue;
		}

		if (m_field->m_flags & EPF_IS_LIST)
		{
			for (auto &val : raw_values)
			{
				jsonval.append(rawval_to_json(val.ptr, m_field->m_type, m_field->m_print_format, val.len));
			}
			return jsonval;
		}
		return rawval_to_json(raw_values[0].ptr, m_field->m_type, m_field->m_print_format, raw_values[0].len);
	}

	return jsonval;
}

int32_t sinsp_filter_check::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	int32_t j;
	int32_t max_fldlen = -1;
	uint32_t max_flags = 0;

	ASSERT(m_info.m_fields != NULL);
	ASSERT(m_info.m_nfields != -1);

	string val(str);

	m_field_id = 0xffffffff;

	for(j = 0; j < m_info.m_nfields; j++)
	{
		string fldname = m_info.m_fields[j].m_name;
		int32_t fldlen = (uint32_t)fldname.length();

		if(val.compare(0, fldlen, fldname) == 0)
		{
			if(fldlen > max_fldlen)
			{
				m_field_id = j;
				m_field = &m_info.m_fields[j];
				max_fldlen = fldlen;
				max_flags = (m_info.m_fields[j]).m_flags;
			}
		}
	}

	if(!needed_for_filtering)
	{
		if(max_flags & EPF_FILTER_ONLY)
		{
			throw sinsp_exception(string(str) + " is filter only and cannot be used as a display field");
		}
	}

	return max_fldlen;
}

void sinsp_filter_check::add_filter_value(const char* str, uint32_t len, uint32_t i)
{
	size_t parsed_len;

	if (i >= m_val_storages.size())
	{
		m_val_storages.push_back(vector<uint8_t>(256));
	}

	parsed_len = parse_filter_value(str, len, filter_value_p(i), filter_value(i)->size());

	// XXX/mstemm this doesn't work if someone called
	// add_filter_value more than once for a given index.
	filter_value_t item(filter_value_p(i), parsed_len);
	m_val_storages_members.insert(item);

	if(parsed_len < m_val_storages_min_size)
	{
		m_val_storages_min_size = parsed_len;
	}

	if(parsed_len > m_val_storages_max_size)
	{
		m_val_storages_max_size = parsed_len;
	}

	// If the operator is CO_PMATCH, also add the value to the paths set.
	if (m_cmpop == CO_PMATCH)
	{
		m_val_storages_paths.add_search_path(item);
	}
}

size_t sinsp_filter_check::parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len)
{
	size_t parsed_len;

	// byte buffer, no parsing needed
	if (m_field->m_type == PT_BYTEBUF)
	{
		if(len >= storage_len)
		{
			throw sinsp_exception("filter parameter too long:" + string(str));
		}
		memcpy(storage, str, len);
		m_val_storage_len = len;
		return len;
	}
	else
	{
		parsed_len = sinsp_filter_value_parser::string_to_rawval(str, len, storage, storage_len, m_field->m_type);
	}
	validate_filter_value(str, len);

	return parsed_len;
}

const filtercheck_field_info* sinsp_filter_check::get_field_info()
{
	return &m_info.m_fields[m_field_id];
}

bool sinsp_filter_check::flt_compare(cmpop op, ppm_param_type type, vector<extract_value_t>& values, uint32_t op2_len)
{
	if (m_info.m_fields[m_field_id].m_flags & EPF_IS_LIST)
	{
		// NOTE: using m_val_storages_members.find(item) relies on memcmp to
		// compare filter_value_t values, and not the base-level flt_compare.
		// This has two main consequences. First, this only works for equality
		// comparison, which luckily is what we want for 'in' and 'intersects'.
		// Second, the comparison happens between the value parsed data, which
		// means it may not work for all the supported data types, since
		// flt_compare uses some additional logic for certain data types (e.g. ipv6).
		// However, for now we only support lists of types PT_CHARBUF and
		// PT_UINT64, that is what the plugin system is able to use. None of the
		// libsinsp internal filterchecks use list type fields for now.
		//
		// todo(jasondellaluce): once we support list fields for more types,
		// refactor filter_value_t to actually use flt_compare instead of memcmp.
		if (type != PT_CHARBUF && type != PT_UINT64)
		{
			throw sinsp_exception("list filters are only supported for CHARBUF and UINT64 types");
		}
		filter_value_t item(NULL, 0);
		switch (op)
		{
			case CO_IN:
				for (auto it = values.begin(); it != values.end(); ++it)
				{
					item.first = (*it).ptr;
					item.second = (*it).len;
					if((*it).len < m_val_storages_min_size ||
						(*it).len > m_val_storages_max_size ||
						m_val_storages_members.find(item) == m_val_storages_members.end())
					{
						return false;
					}
				}
				return true;
			case CO_INTERSECTS:
				for (auto it = values.begin(); it != values.end(); ++it)
				{
					item.first = (*it).ptr;
					item.second = (*it).len;
					if((*it).len >= m_val_storages_min_size &&
						(*it).len <= m_val_storages_max_size &&
						m_val_storages_members.find(item) != m_val_storages_members.end())
					{
						return true;
					}
				}
				return false;
			default:
				ASSERT(false);
				throw sinsp_exception("list filter '"
					+ string(m_info.m_fields[m_field_id].m_name)
					+ "' only supports operators 'in' and 'intersects'");
		}
	}
	else if (values.size() > 1)
	{
		ASSERT(false);
		throw sinsp_exception("non-list filter '"
			+ string(m_info.m_fields[m_field_id].m_name)
			+ "' expected to extract a single value, but "
			+ to_string(values.size()) + " were found");
	}

	return flt_compare(m_cmpop,
		m_info.m_fields[m_field_id].m_type,
		values[0].ptr,
		values[0].len,
		op2_len);
}

bool sinsp_filter_check::flt_compare(cmpop op, ppm_param_type type, void* operand1, uint32_t op1_len, uint32_t op2_len)
{
	if (op == CO_IN || op == CO_PMATCH || op == CO_INTERSECTS)
	{
		// Certain filterchecks can't be done as a set
		// membership test/group match. For these, just loop over the
		// values and see if any value is equal.
		switch(type)
		{
		case PT_IPV4NET:
		case PT_IPV6NET:
		case PT_IPNET:
		case PT_SOCKADDR:
		case PT_SOCKTUPLE:
		case PT_FDLIST:
		case PT_FSPATH:
		case PT_SIGSET:
		case PT_FSRELPATH:
			for (uint16_t i=0; i < m_val_storages.size(); i++)
			{
				if (::flt_compare(CO_EQ,
						  type,
						  operand1,
						  filter_value_p(i),
						  op1_len,
						  filter_value(i)->size()))
				{
					return true;
				}
			}
			return false;
		default:
			// For raw strings, the length may not be set. So we do a strlen to find it.
			if(type == PT_CHARBUF && op1_len == 0)
			{
				op1_len = strlen((char *) operand1);
			}

			filter_value_t item((uint8_t *) operand1, op1_len);

			if (op == CO_IN || op == CO_INTERSECTS)
			{
				// CO_INTERSECTS is really more interesting when a filtercheck can extract
				// multiple values, and you're comparing the set of extracted values
				// against the set of rhs values. sinsp_filter_checks only extract a
				// single value, so CO_INTERSECTS is really the same as CO_IN.

				if(op1_len >= m_val_storages_min_size &&
				   op1_len <= m_val_storages_max_size &&
				   m_val_storages_members.find(item) != m_val_storages_members.end())
				{
					return true;
				}
			}
			else
			{
				if (m_val_storages_paths.match(item))
				{
					return true;
				}
			}

			return false;
			break;
		}
	}
	else
	{
		return (::flt_compare(op,
				      type,
				      operand1,
				      filter_value_p(),
				      op1_len,
				      op2_len)
			);
	}
}

bool sinsp_filter_check::extract(gen_event *evt, OUT vector<extract_value_t>& values, bool sanitize_strings)
{
	return extract((sinsp_evt *) evt, values, sanitize_strings);
}

bool sinsp_filter_check::extract(sinsp_evt *evt, OUT vector<extract_value_t>& values, bool sanitize_strings)
{
	values.clear();
	extract_value_t val;
	val.ptr = extract(evt, &val.len, sanitize_string);
	if (val.ptr != NULL)
	{
		values.push_back(val);
		return true;
	}
	return false;
}

uint8_t* sinsp_filter_check::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	return NULL;
}

bool sinsp_filter_check::extract_cached(sinsp_evt *evt, OUT vector<extract_value_t>& values, bool sanitize_strings)
{
	if(m_extraction_cache_entry != NULL)
	{
		uint64_t en = ((sinsp_evt *)evt)->get_num();

		if(en != m_extraction_cache_entry->m_evtnum)
		{
			m_extraction_cache_entry->m_evtnum = en;
			extract(evt, m_extraction_cache_entry->m_res, sanitize_strings);
		}

		// Shallow-copy the cached values to values
		values = m_extraction_cache_entry->m_res;

		return !m_extraction_cache_entry->m_res.empty();
	}
	else
	{
		return extract(evt, values, sanitize_strings);
	}
}

bool sinsp_filter_check::compare(gen_event *evt)
{
	if(m_eval_cache_entry != NULL)
	{
		uint64_t en = ((sinsp_evt *)evt)->get_num();

		if(en != m_eval_cache_entry->m_evtnum)
		{
			m_eval_cache_entry->m_evtnum = en;
			m_eval_cache_entry->m_res = compare((sinsp_evt *) evt);
		}

		return m_eval_cache_entry->m_res;
	}
	else
	{
		return compare((sinsp_evt *) evt);
	}
}

bool sinsp_filter_check::compare(sinsp_evt *evt)
{
	bool sanitize_strings = false;
	vector<extract_value_t> extracted_values;
	if(!extract_cached(evt, extracted_values, sanitize_strings))
	{
		return false;
	}

	return flt_compare(m_cmpop,
		m_info.m_fields[m_field_id].m_type,
		extracted_values);
}

sinsp_filter::sinsp_filter(sinsp *inspector)
{
	m_inspector = inspector;
}

sinsp_filter::~sinsp_filter()
{
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_compiler implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_compiler::sinsp_filter_compiler(
		sinsp* inspector,
		const string& fltstr,
		bool ttable_only)
{
	m_factory.reset(new sinsp_filter_factory(inspector));
	m_filter = NULL;
	m_flt_str = fltstr;
	m_flt_ast = NULL;
	m_ttable_only = ttable_only;
	m_internal_parsing = true;
	m_check_id = 0;
}

sinsp_filter_compiler::sinsp_filter_compiler(
		std::shared_ptr<gen_event_filter_factory> factory,
		const string& fltstr,
		bool ttable_only)
{
	m_factory = factory;
	m_filter = NULL;
	m_flt_str = fltstr;
	m_flt_ast = NULL;
	m_ttable_only = ttable_only;
	m_internal_parsing = true;
	m_check_id = 0;
}

sinsp_filter_compiler::sinsp_filter_compiler(
		std::shared_ptr<gen_event_filter_factory> factory,
		libsinsp::filter::ast::expr* fltast,
		bool ttable_only)
{
	m_factory = factory;
	m_filter = NULL;
	m_flt_ast = fltast;
	m_ttable_only = ttable_only;
	m_internal_parsing = false;
	m_check_id = 0;
}

sinsp_filter_compiler::~sinsp_filter_compiler()
{
	// we delete the AST only if it was parsed internally
	if (m_internal_parsing && m_flt_ast != NULL)
	{
		delete m_flt_ast;
	}
}

void sinsp_filter_compiler::set_check_id(int32_t id)
{
	m_check_id = id;
}

sinsp_filter* sinsp_filter_compiler::compile()
{
	// parse filter string on-the-fly if not pre-parsed AST is provided
	if (m_internal_parsing && m_flt_ast == NULL)
	{
		libsinsp::filter::parser parser(m_flt_str);
		try
		{
			m_flt_ast = parser.parse();
		}
		catch (const sinsp_exception& e)
		{
			throw sinsp_exception("filter error at " 
				+ parser.get_pos().as_string() + ": " + e.what());
		}
	}

	// create new filter using factory
	auto new_filter = m_factory->new_filter();
	auto new_sinsp_filter = dynamic_cast<sinsp_filter*>(new_filter);
	if (new_sinsp_filter == nullptr)
	{
		ASSERT(false);
		delete new_filter;
		throw sinsp_exception("filter error: factory did not create a sinsp_filter");
	}

	// setup compiler state and start compilation
	m_filter = new_sinsp_filter;
	m_last_boolop = BO_NONE;
	m_expect_values = false;
	try 
	{
		m_flt_ast->accept(this);
	}
	catch (const sinsp_exception& e)
	{
		delete new_sinsp_filter;
		m_filter = NULL;
		throw e;
	}

	// return compiled filter
	m_filter = NULL;
	return new_sinsp_filter;
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::and_expr* e)
{
	bool nested = m_last_boolop != BO_AND;
	if (nested)
	{
		m_filter->push_expression(m_last_boolop);
		m_last_boolop = BO_NONE;
	}
	for (auto &c : e->children)
	{
		c->accept(this);
		m_last_boolop = BO_AND;
	}
	if (nested)
	{
		m_filter->pop_expression();
	}
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::or_expr* e)
{
	bool nested = m_last_boolop != BO_OR;
	if (nested)
	{
		m_filter->push_expression(m_last_boolop);
		m_last_boolop = BO_NONE;
	}
	for (auto &c : e->children)
	{
		c->accept(this);
		m_last_boolop = BO_OR;
	}
	if (nested)
	{
		m_filter->pop_expression();
	}
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::not_expr* e)
{
	m_last_boolop = (boolop)((uint32_t)m_last_boolop | BO_NOT);
	m_filter->push_expression(m_last_boolop);
	m_last_boolop = BO_NONE;
	e->child->accept(this);
	m_filter->pop_expression();
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::unary_check_expr* e)
{
	string field = create_filtercheck_name(e->field, e->arg);
	gen_event_filter_check *check = create_filtercheck(field);
	m_filter->add_check(check);
	check_ttable_only(field, check);
	check->m_cmpop = str_to_cmpop(e->op);
	check->m_boolop = m_last_boolop;
	check->parse_field_name(field.c_str(), true, true);
	check->set_check_id(m_check_id);
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::binary_check_expr* e)
{
	string field = create_filtercheck_name(e->field, e->arg);
	gen_event_filter_check *check = create_filtercheck(field);
	m_filter->add_check(check);
	check_ttable_only(field, check);
	check->m_cmpop = str_to_cmpop(e->op);
	check->m_boolop = m_last_boolop;
	check->parse_field_name(field.c_str(), true, true);
	check->set_check_id(m_check_id);

	// Read the the the right-hand values of the filtercheck. 
	// For list-related operators ('in', 'intersects', 'pmatch'), the vector
	// can be filled with more than 1 value, whereas in all other cases we
	// expect the vector to only have 1 value. We don't check this here, as
	// the parser is trusted to apply proper grammar checks on this constraint.
	m_expect_values = true;
	e->value->accept(this);
	m_expect_values = false;
	for (size_t i = 0; i < m_field_values.size(); i++)
	{
		check_op_value_compatibility(check->m_cmpop, m_field_values[i]);
		check->add_filter_value(m_field_values[i].c_str(), m_field_values[i].size(), i);
	}
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::value_expr* e)
{
	if (!m_expect_values)
	{
		// this ensures that identifiers, such as Falco macros, are not left
		// unresolved at filter compilation time
		throw sinsp_exception("filter error: unexpected identifier '" + e->value + "'");
	}
	m_field_values.clear();
	m_field_values.push_back(e->value);
}

void sinsp_filter_compiler::visit(libsinsp::filter::ast::list_expr* e)
{
	if (!m_expect_values)
	{
		ASSERT(false);
		// this is not expected, as it should not be allowed by the parser
		throw sinsp_exception("filter error: unexpected value list");
	}
	m_field_values.clear();
	m_field_values = e->values;
}

void sinsp_filter_compiler::check_op_value_compatibility(cmpop op, std::string& value)
{
	std::vector<char> hex_chars(value.c_str(), value.c_str() + value.size());
	std::vector<char> hex_bytes;
	switch(op)
	{
		case CO_BCONTAINS:
		case CO_BSTARTSWITH:
			if(!sinsp_utils::unhex(hex_chars, hex_bytes))
			{
				throw sinsp_exception("filter error: bcontains and bstartswith operator support hex strings only");
			}
			break;
		default:
			break;
	}
}

string sinsp_filter_compiler::create_filtercheck_name(string& name, string& arg)
{
	// The filtercheck factories parse the name + arg as a whole.
	// We keep this for now, but we may want to change this in the future.
	// todo(jasondellaluce): handle field arg parsing at compilation time
	string fld = name;
	if (arg.size() > 0)
	{
		fld += "[" + arg + "]";
	}
	return fld;
}

gen_event_filter_check* sinsp_filter_compiler::create_filtercheck(string& field)
{
	gen_event_filter_check *chk = m_factory->new_filtercheck(field.c_str());
	if(chk == NULL)
	{
		throw sinsp_exception("filter_check called with nonexistent field " + field);
	}
	return chk;
}

void sinsp_filter_compiler::check_ttable_only(string& field, gen_event_filter_check *check)
{
	if(m_ttable_only)
	{
		sinsp_filter_check* sinsp_check = dynamic_cast<sinsp_filter_check*>(check);
		if (sinsp_check != nullptr
			&& !(sinsp_check->get_fields()->m_flags & filter_check_info::FL_WORKS_ON_THREAD_TABLE))
		{
			if(field != "evt.rawtime" &&
				field != "evt.rawtime.s" &&
				field != "evt.rawtime.ns" &&
				field != "evt.time" &&
				field != "evt.time.s" &&
				field != "evt.datetime" &&
				field != "evt.reltime")
			{
				throw sinsp_exception("filter error: '" + field + "' is not supported for thread table filtering");
			}
		}
	}
}

cmpop sinsp_filter_compiler::str_to_cmpop(string& str)
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
	// we are not supposed to get here, as the parser pre-checks this
	ASSERT(false);
	throw sinsp_exception("filter error: unrecognized comparison operator '" + string(str) + "'");
}


sinsp_filter_factory::sinsp_filter_factory(sinsp *inspector,
					   filter_check_list &available_checks)
	: m_inspector(inspector), m_available_checks(available_checks)
{
}

sinsp_filter_factory::~sinsp_filter_factory()
{
}

gen_event_filter *sinsp_filter_factory::new_filter()
{
	return new sinsp_filter(m_inspector);
}


gen_event_filter_check *sinsp_filter_factory::new_filtercheck(const char *fldname)
{
	return m_available_checks.new_filter_check_from_fldname(fldname,
								m_inspector,
								true);
}

std::list<gen_event_filter_factory::filter_fieldclass_info> sinsp_filter_factory::get_fields()
{
	vector<const filter_check_info*> fc_plugins;
	m_available_checks.get_all_fields(fc_plugins);

	return check_infos_to_fieldclass_infos(fc_plugins);
}

std::list<gen_event_filter_factory::filter_fieldclass_info> sinsp_filter_factory::check_infos_to_fieldclass_infos(
	const vector<const filter_check_info*> &fc_plugins)
{
	std::list<gen_event_filter_factory::filter_fieldclass_info> ret;

	for(auto &fci : fc_plugins)
	{
		if(fci->m_flags & filter_check_info::FL_HIDDEN)
		{
			continue;
		}

		gen_event_filter_factory::filter_fieldclass_info cinfo;
		cinfo.name = fci->m_name;
		cinfo.desc = fci->m_desc;
		cinfo.shortdesc = fci->m_shortdesc;

		for(int32_t k = 0; k < fci->m_nfields; k++)
		{
			const filtercheck_field_info* fld = &fci->m_fields[k];

			// If a field is only used for stuff like
			// chisels to organize events, we don't want
			// to print it and don't return it here.
			if(fld->m_flags & EPF_PRINT_ONLY)
			{
				continue;
			}

			gen_event_filter_factory::filter_field_info info;
			info.name = fld->m_name;
			info.desc = fld->m_description;
			info.data_type =  param_type_to_string(fld->m_type);

			if(fld->m_flags & EPF_FILTER_ONLY)
			{
				info.tags.insert("FILTER_ONLY");
			}

			if(fld->m_flags & EPF_TABLE_ONLY)
			{
				info.tags.insert("EPF_TABLE_ONLY");
			}

			if(fld->m_flags & EPF_ARG_REQUIRED)
			{
				info.tags.insert("ARG_REQUIRED");
			}
			else if(fld->m_flags & EPF_ARG_ALLOWED)
			{
				info.tags.insert("ARG_ALLOWED");
			}

			cinfo.fields.emplace_back(std::move(info));
		}

		ret.emplace_back(std::move(cinfo));
	}

	return ret;
}

