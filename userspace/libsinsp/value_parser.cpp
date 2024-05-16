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
#include <libsinsp/value_parser.h>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#include <WinSock2.h>
#else
#include <netdb.h>
#endif

static inline void check_storage_size(
	const char* str, std::string::size_type storage_len, std::string::size_type used_len)
{
	if (used_len > storage_len) {
		throw sinsp_exception(
			+ "filter parameter too long (used="
			+ std::to_string(used_len)
			+ ", available="
			+ std::to_string(storage_len)
			+ "):"
			+ std::string(str));
	}
}

size_t sinsp_filter_value_parser::string_to_rawval(const char* str, uint32_t len, uint8_t *storage, std::string::size_type max_len, ppm_param_type ptype)
{
	size_t parsed_len;

	switch(ptype)
	{
		case PT_INT8:
			check_storage_size(str, max_len, sizeof(int8_t));
			*(int8_t*)storage = sinsp_numparser::parsed8(str);
			parsed_len = sizeof(int8_t);
			break;
		case PT_INT16:
			check_storage_size(str, max_len, sizeof(int16_t));
			*(int16_t*)storage = sinsp_numparser::parsed16(str);
			parsed_len = sizeof(int16_t);
			break;
		case PT_INT32:
			check_storage_size(str, max_len, sizeof(int32_t));
			*(int32_t*)storage = sinsp_numparser::parsed32(str);
			parsed_len = sizeof(int32_t);
			break;
		case PT_INT64:
		case PT_FD:
		case PT_ERRNO:
			check_storage_size(str, max_len, sizeof(int64_t));
			*(int64_t*)storage = sinsp_numparser::parsed64(str);
			parsed_len = sizeof(int64_t);
			break;
		case PT_L4PROTO: // This can be resolved in the future
		case PT_FLAGS8:
		case PT_UINT8:
		case PT_ENUMFLAGS8:
			check_storage_size(str, max_len, sizeof(uint8_t));
			*(uint8_t*)storage = sinsp_numparser::parseu8(str);
			parsed_len = sizeof(int8_t);
			break;
		case PT_PORT:
		{
			check_storage_size(str, max_len, sizeof(uint16_t));
			std::string in(str);

			if(in.empty())
			{
				*(uint16_t*)storage = 0;
			}
			else
			{
				// if the string is made only of numbers
				if(strspn(in.c_str(), "0123456789") == in.size())
				{
					*(uint16_t*)storage = stoi(in);
				}
				else
				{
					struct servent* se = getservbyname(in.c_str(), NULL);

					if(se == NULL)
					{
						throw sinsp_exception("unrecognized protocol " + in);
					}
					else
					{
						*(uint16_t*)storage = ntohs(getservbyname(in.c_str(), NULL)->s_port);
					}
				}
			}

			parsed_len = sizeof(int16_t);
			break;
		}
		case PT_FLAGS16:
		case PT_UINT16:
		case PT_ENUMFLAGS16:
			check_storage_size(str, max_len, sizeof(uint16_t));
			*(uint16_t*)storage = sinsp_numparser::parseu16(str);
			parsed_len = sizeof(uint16_t);
			break;
		case PT_FLAGS32:
		case PT_UINT32:
		case PT_MODE:
		case PT_ENUMFLAGS32:
			check_storage_size(str, max_len, sizeof(uint32_t));
			*(uint32_t*)storage = sinsp_numparser::parseu32(str);
			parsed_len = sizeof(uint32_t);
			break;
		case PT_UINT64:
			check_storage_size(str, max_len, sizeof(uint64_t));
			*(uint64_t*)storage = sinsp_numparser::parseu64(str);
			parsed_len = sizeof(uint64_t);
			break;
		case PT_RELTIME:
		case PT_ABSTIME:
			check_storage_size(str, max_len, sizeof(uint64_t));
			*(uint64_t*)storage = sinsp_numparser::parseu64(str);
			parsed_len = sizeof(uint64_t);
			break;
		case PT_CHARBUF:
		case PT_SOCKADDR:
		case PT_SOCKFAMILY:
		case PT_FSPATH:
		case PT_FSRELPATH:
			{
				len = (uint32_t)strlen(str);
				check_storage_size(str, max_len, len + 1);

				memcpy(storage, str, len);
				*(uint8_t*)(&storage[len]) = 0;
				parsed_len = len;
			}
			break;
		case PT_BOOL:
			check_storage_size(str, max_len, sizeof(uint32_t));
			parsed_len = sizeof(uint32_t);
			if(std::string(str) == "true")
			{
				*(uint32_t*)storage = 1;
			}
			else if(std::string(str) == "false")
			{
				*(uint32_t*)storage = 0;
			}
			else
			{
				throw sinsp_exception("filter error: unrecognized boolean value " + std::string(str));
			}

			break;
		case PT_DOUBLE:
		{
			check_storage_size(str, max_len, sizeof(double));
			// note(jasondellaluce): we historically never supported parsing
			// floating point number values, so as a starter we just stick to
			// integer numberd
			// todo(jasondellaluce): support floating point (double) value parsing
			*(double*)storage = (double)sinsp_numparser::parsed32(str);
			parsed_len = sizeof(double);
			break;
		}
		case PT_IPADDR:
			if(memchr(str, '.', len) != NULL)
			{
				return string_to_rawval(str, len, storage, max_len, PT_IPV4ADDR);
			}
			else
			{
				return string_to_rawval(str, len, storage, max_len, PT_IPV6ADDR);
			}

			break;
	    case PT_IPV4ADDR:
			check_storage_size(str, max_len, sizeof(struct in_addr));
			if(inet_pton(AF_INET, str, storage) != 1)
			{
				throw sinsp_exception("unrecognized IPv4 address " + std::string(str));
			}
			parsed_len = sizeof(struct in_addr);
			break;
	    case PT_IPV6ADDR:
		{
			check_storage_size(str, max_len, sizeof(ipv6addr));
			new (storage) ipv6addr(str);
			parsed_len = sizeof(ipv6addr);
			break;
		}
		case PT_IPNET:
			if(memchr(str, '.', len) != NULL)
			{
				return string_to_rawval(str, len, storage, max_len, PT_IPV4NET);
			}
			else
			{
				return string_to_rawval(str, len, storage, max_len, PT_IPV6NET);
			}
			break;
		case PT_IPV4NET:
		{
			check_storage_size(str, max_len, sizeof(ipv4net));
			std::stringstream ss(str);
			std::string ip, mask;
			ipv4net* net = (ipv4net*)storage;

			if (strchr(str, '/') == NULL)
			{
				throw sinsp_exception("unrecognized IP network " + std::string(str));
			}

			getline(ss, ip, '/');
			getline(ss, mask);

			if(inet_pton(AF_INET, ip.c_str(), &net->m_ip) != 1)
			{
				throw sinsp_exception("unrecognized IP address " + std::string(str));
			}

			uint32_t cidrlen = sinsp_numparser::parseu8(mask);

			if (cidrlen > 32)
			{
				throw sinsp_exception("invalid netmask " + mask);
			}

			uint32_t j;
			net->m_netmask = 0;

			for(j = 0; j < cidrlen; j++)
			{
				net->m_netmask |= 1<<(31-j);
			}

			net->m_netmask = htonl(net->m_netmask);

			parsed_len = sizeof(ipv4net);
			break;
		}
		case PT_IPV6NET:
		{
			check_storage_size(str, max_len, sizeof(ipv6net));
			new (storage) ipv6net(str);
			parsed_len = sizeof(ipv6net);
			break;
		}
		default:
			ASSERT(false);
			throw sinsp_exception("wrong parameter type " + std::to_string((long long) ptype));
	}

	return parsed_len;
}

