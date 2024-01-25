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
#include <libsinsp/sinsp_errno.h>
#include <libsinsp/sinsp_signal.h>
#include <libsinsp/filter.h>
#include <libsinsp/filter_check_list.h>
#include <libsinsp/filterchecks.h>
#include <libscap/strl.h>

#if !defined(_WIN32) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
#include <curl/curl.h>
#endif

#ifndef _WIN32
	#include <climits>
	#include <cstdlib>
	#include <cstring>
	#ifdef __GLIBC__
	#include <execinfo.h>
	#endif
	#include <fnmatch.h>
	#include <netdb.h>
	#include <string>
	#include <sys/ioctl.h>
	#include <sys/time.h>
	#include <unistd.h>
#else
	#pragma comment(lib, "Ws2_32.lib")
	#include <WinSock2.h>
	#include "Shlwapi.h"
	#pragma comment(lib,"shlwapi.lib")
#endif

#include <algorithm>
#include <cerrno>
#include <functional>
#include <sys/stat.h>
#include <filesystem>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

///////////////////////////////////////////////////////////////////////////////
// sinsp_initializer implementation
///////////////////////////////////////////////////////////////////////////////

//
// These are the libsinsp globals
//
sinsp_evttables g_infotables;
sinsp_initializer g_initializer;

//
// loading time initializations
//
sinsp_initializer::sinsp_initializer()
{
	//
	// Init the event tables
	//
	g_infotables.m_event_info = scap_get_event_info_table();

	//
	// Init the logger
	//
	libsinsp_logger()->set_severity(sinsp_logger::SEV_INFO);

	//
	// Sockets initialization on windows
	//
#ifdef _WIN32
	WSADATA wsaData;
	WORD version = MAKEWORD( 2, 0 );
	WSAStartup( version, &wsaData );
#endif
}

///////////////////////////////////////////////////////////////////////////////
// Various helper functions
///////////////////////////////////////////////////////////////////////////////

//
// errno to string conversion.
//
const char* sinsp_utils::errno_to_str(int32_t code)
{
	switch(-code)
	{
	case SE_EPERM:
		return "EPERM";
	case SE_ENOENT:
		return "ENOENT";
	case SE_ESRCH:
		return "ESRCH";
	case SE_EINTR:
		return "EINTR";
	case SE_EIO:
		return "EIO";
	case SE_ENXIO:
		return "ENXIO";
	case SE_E2BIG:
		return "E2BIG";
	case SE_ENOEXEC:
		return "ENOEXEC";
	case SE_EBADF:
		return "EBADF";
	case SE_ECHILD:
		return "ECHILD";
	case SE_EAGAIN:
		return "EAGAIN";
	case SE_ENOMEM:
		return "ENOMEM";
	case SE_EACCES:
		return "EACCES";
	case SE_EFAULT:
		return "EFAULT";
	case SE_ENOTBLK:
		return "ENOTBLK";
	case SE_EBUSY:
		return "EBUSY";
	case SE_EEXIST:
		return "EEXIST";
	case SE_EXDEV:
		return "EXDEV";
	case SE_ENODEV:
		return "ENODEV";
	case SE_ENOTDIR:
		return "ENOTDIR";
	case SE_EISDIR:
		return "EISDIR";
	case SE_EINVAL:
		return "EINVAL";
	case SE_ENFILE:
		return "ENFILE";
	case SE_EMFILE:
		return "EMFILE";
	case SE_ENOTTY:
		return "ENOTTY";
	case SE_ETXTBSY:
		return "ETXTBSY";
	case SE_EFBIG:
		return "EFBIG";
	case SE_ENOSPC:
		return "ENOSPC";
	case SE_ESPIPE:
		return "ESPIPE";
	case SE_EROFS:
		return "EROFS";
	case SE_EMLINK:
		return "EMLINK";
	case SE_EPIPE:
		return "EPIPE";
	case SE_EDOM:
		return "EDOM";
	case SE_ERANGE:
		return "ERANGE";
	case SE_EDEADLK:
		return "EDEADLK";
	case SE_ENAMETOOLONG:
		return "ENAMETOOLONG";
	case SE_ENOLCK:
		return "ENOLCK";
	case SE_ENOSYS:
		return "ENOSYS";
	case SE_ENOTEMPTY:
		return "ENOTEMPTY";
	case SE_ELOOP:
		return "ELOOP";
	case SE_ENOMSG:
		return "ENOMSG";
	case SE_EIDRM:
		return "EIDRM";
	case SE_ECHRNG:
		return "ECHRNG";
	case SE_EL2NSYNC:
		return "EL2NSYNC";
	case SE_EL3HLT:
		return "EL3HLT";
	case SE_EL3RST:
		return "EL3RST";
	case SE_ELNRNG:
		return "ELNRNG";
	case SE_EUNATCH:
		return "EUNATCH";
	case SE_ENOCSI:
		return "ENOCSI";
	case SE_EL2HLT:
		return "EL2HLT";
	case SE_EBADE:
		return "EBADE";
	case SE_EBADR:
		return "EBADR";
	case SE_EXFULL:
		return "EXFULL";
	case SE_ENOANO:
		return "ENOANO";
	case SE_EBADRQC:
		return "EBADRQC";
	case SE_EBADSLT:
		return "EBADSLT";
	case SE_EBFONT:
		return "EBFONT";
	case SE_ENOSTR:
		return "ENOSTR";
	case SE_ENODATA:
		return "ENODATA";
	case SE_ETIME:
		return "ETIME";
	case SE_ENOSR:
		return "ENOSR";
	case SE_ENONET:
		return "ENONET";
	case SE_ENOPKG:
		return "ENOPKG";
	case SE_EREMOTE:
		return "EREMOTE";
	case SE_ENOLINK:
		return "ENOLINK";
	case SE_EADV:
		return "EADV";
	case SE_ESRMNT:
		return "ESRMNT";
	case SE_ECOMM:
		return "ECOMM";
	case SE_EPROTO:
		return "EPROTO";
	case SE_EMULTIHOP:
		return "EMULTIHOP";
	case SE_EDOTDOT:
		return "EDOTDOT";
	case SE_EBADMSG:
		return "EBADMSG";
	case SE_EOVERFLOW:
		return "EOVERFLOW";
	case SE_ENOTUNIQ:
		return "ENOTUNIQ";
	case SE_EBADFD:
		return "EBADFD";
	case SE_EREMCHG:
		return "EREMCHG";
	case SE_ELIBACC:
		return "ELIBACC";
	case SE_ELIBBAD:
		return "ELIBBAD";
	case SE_ELIBSCN:
		return "ELIBSCN";
	case SE_ELIBMAX:
		return "ELIBMAX";
	case SE_ELIBEXEC:
		return "ELIBEXEC";
	case SE_EILSEQ:
		return "EILSEQ";
	case SE_ERESTART:
		return "ERESTART";
	case SE_ESTRPIPE:
		return "ESTRPIPE";
	case SE_EUSERS:
		return "EUSERS";
	case SE_ENOTSOCK:
		return "ENOTSOCK";
	case SE_EDESTADDRREQ:
		return "EDESTADDRREQ";
	case SE_EMSGSIZE:
		return "EMSGSIZE";
	case SE_EPROTOTYPE:
		return "EPROTOTYPE";
	case SE_ENOPROTOOPT:
		return "ENOPROTOOPT";
	case SE_EPROTONOSUPPORT:
		return "EPROTONOSUPPORT";
	case SE_ESOCKTNOSUPPORT:
		return "ESOCKTNOSUPPORT";
	case SE_EOPNOTSUPP:
		return "EOPNOTSUPP";
	case SE_EPFNOSUPPORT:
		return "EPFNOSUPPORT";
	case SE_EAFNOSUPPORT:
		return "EAFNOSUPPORT";
	case SE_EADDRINUSE:
		return "EADDRINUSE";
	case SE_EADDRNOTAVAIL:
		return "EADDRNOTAVAIL";
	case SE_ENETDOWN:
		return "ENETDOWN";
	case SE_ENETUNREACH:
		return "ENETUNREACH";
	case SE_ENETRESET:
		return "ENETRESET";
	case SE_ECONNABORTED:
		return "ECONNABORTED";
	case SE_ECONNRESET:
		return "ECONNRESET";
	case SE_ENOBUFS:
		return "ENOBUFS";
	case SE_EISCONN:
		return "EISCONN";
	case SE_ENOTCONN:
		return "ENOTCONN";
	case SE_ESHUTDOWN:
		return "ESHUTDOWN";
	case SE_ETOOMANYREFS:
		return "ETOOMANYREFS";
	case SE_ETIMEDOUT:
		return "ETIMEDOUT";
	case SE_ECONNREFUSED:
		return "ECONNREFUSED";
	case SE_EHOSTDOWN:
		return "EHOSTDOWN";
	case SE_EHOSTUNREACH:
		return "EHOSTUNREACH";
	case SE_EALREADY:
		return "EALREADY";
	case SE_EINPROGRESS:
		return "EINPROGRESS";
	case SE_ESTALE:
		return "ESTALE";
	case SE_EUCLEAN:
		return "EUCLEAN";
	case SE_ENOTNAM:
		return "ENOTNAM";
	case SE_ENAVAIL:
		return "ENAVAIL";
	case SE_EISNAM:
		return "EISNAM";
	case SE_EREMOTEIO:
		return "EREMOTEIO";
	case SE_EDQUOT:
		return "EDQUOT";
	case SE_ENOMEDIUM:
		return "ENOMEDIUM";
	case SE_EMEDIUMTYPE:
		return "EMEDIUMTYPE";
	case SE_ECANCELED:
		return "ECANCELED";
	case SE_ERESTARTSYS:
		return "ERESTARTSYS";
	case SE_ERESTARTNOINTR:
		return "ERESTARTNOINTR";
	case SE_ERESTARTNOHAND:
		return "ERESTARTNOHAND";
	case SE_ENOIOCTLCMD:
		return "ENOIOCTLCMD";
	case SE_ERESTART_RESTARTBLOCK:
		return "ERESTART_RESTARTBLOCK";
	case SE_EBADHANDLE:
		return "EBADHANDLE";
	case SE_ENOTSYNC:
		return "ENOTSYNC";
	case SE_EBADCOOKIE:
		return "EBADCOOKIE";
	case SE_ENOTSUPP:
		return "ENOTSUPP";
	case SE_ETOOSMALL:
		return "ETOOSMALL";
	case SE_ESERVERFAULT:
		return "ESERVERFAULT";
	case SE_EBADTYPE:
		return "EBADTYPE";
	case SE_EJUKEBOX:
		return "EJUKEBOX";
	case SE_EIOCBQUEUED:
		return "EIOCBQUEUED";
	case SE_EIOCBRETRY:
		return "EIOCBRETRY";
	default:
		ASSERT(false);
		return "";
	}
}

//
// signal to string conversion.
// Only non-extremely-obscure signals are implemented
//
const char* sinsp_utils::signal_to_str(uint8_t code)
{
	switch(code)
	{
	case SE_SIGHUP:
		return "SIGHUP";
	case SE_SIGINT:
		return "SIGINT";
	case SE_SIGQUIT:
		return "SIGQUIT";
	case SE_SIGILL:
		return "SIGILL";
	case SE_SIGTRAP:
		return "SIGTRAP";
	case SE_SIGABRT:
		return "SIGABRT";
	case SE_SIGBUS:
		return "SIGBUS";
	case SE_SIGFPE:
		return "SIGFPE";
	case SE_SIGKILL:
		return "SIGKILL";
	case SE_SIGUSR1:
		return "SIGUSR1";
	case SE_SIGSEGV:
		return "SIGSEGV";
	case SE_SIGUSR2:
		return "SIGUSR2";
	case SE_SIGPIPE:
		return "SIGPIPE";
	case SE_SIGALRM:
		return "SIGALRM";
	case SE_SIGTERM:
		return "SIGTERM";
	case SE_SIGSTKFLT:
		return "SIGSTKFLT";
	case SE_SIGCHLD:
		return "SIGCHLD";
	case SE_SIGCONT:
		return "SIGCONT";
	case SE_SIGSTOP:
		return "SIGSTOP";
	case SE_SIGTSTP:
		return "SIGTSTP";
	case SE_SIGTTIN:
		return "SIGTTIN";
	case SE_SIGTTOU:
		return "SIGTTOU";
	case SE_SIGURG:
		return "SIGURG";
	case SE_SIGXCPU:
		return "SIGXCPU";
	case SE_SIGXFSZ:
		return "SIGXFSZ";
	case SE_SIGVTALRM:
		return "SIGVTALRM";
	case SE_SIGPROF:
		return "SIGPROF";
	case SE_SIGWINCH:
		return "SIGWINCH";
	case SE_SIGIO:
		return "SIGIO";
	case SE_SIGPWR:
		return "SIGPWR";
	case SE_SIGSYS:
		return "SIGSYS";
	default:
		return NULL;
	}
}

bool sinsp_utils::sockinfo_to_str(sinsp_sockinfo* sinfo, scap_fd_type stype, char* targetbuf, uint32_t targetbuf_size, bool resolve)
{
	if(stype == SCAP_FD_IPV4_SOCK)
	{
		uint8_t* sb = (uint8_t*)&sinfo->m_ipv4info.m_fields.m_sip;
		uint8_t* db = (uint8_t*)&sinfo->m_ipv4info.m_fields.m_dip;

		if(sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_TCP ||
			sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			ipv4tuple addr;
			addr.m_fields.m_sip = sinfo->m_ipv4info.m_fields.m_sip;
			addr.m_fields.m_sport = sinfo->m_ipv4info.m_fields.m_sport;
			addr.m_fields.m_dip = sinfo->m_ipv4info.m_fields.m_dip;
			addr.m_fields.m_dport = sinfo->m_ipv4info.m_fields.m_dport;
			addr.m_fields.m_l4proto = sinfo->m_ipv4info.m_fields.m_l4proto;
			std::string straddr = ipv4tuple_to_string(&addr, resolve);
			snprintf(targetbuf,
					 targetbuf_size,
					 "%s",
					 straddr.c_str());
		}
		else if(sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_ICMP ||
			sinfo->m_ipv4info.m_fields.m_l4proto == SCAP_L4_RAW)
		{
			snprintf(targetbuf,
				targetbuf_size,
				"%u.%u.%u.%u->%u.%u.%u.%u",
				(unsigned int)(uint8_t)sb[0],
				(unsigned int)(uint8_t)sb[1],
				(unsigned int)(uint8_t)sb[2],
				(unsigned int)(uint8_t)sb[3],
				(unsigned int)(uint8_t)db[0],
				(unsigned int)(uint8_t)db[1],
				(unsigned int)(uint8_t)db[2],
				(unsigned int)(uint8_t)db[3]);
		}
		else
		{
			snprintf(targetbuf,
				targetbuf_size,
				"<unknown>");
		}
	}
	else if(stype == SCAP_FD_IPV6_SOCK)
	{
		uint8_t* sip6 = (uint8_t*)sinfo->m_ipv6info.m_fields.m_sip.m_b;
		uint8_t* dip6 = (uint8_t*)sinfo->m_ipv6info.m_fields.m_dip.m_b;
		uint8_t* sip = ((uint8_t*)(sinfo->m_ipv6info.m_fields.m_sip.m_b)) + 12;
		uint8_t* dip = ((uint8_t*)(sinfo->m_ipv6info.m_fields.m_dip.m_b)) + 12;

		if(sinfo->m_ipv6info.m_fields.m_l4proto == SCAP_L4_TCP ||
			sinfo->m_ipv6info.m_fields.m_l4proto == SCAP_L4_UDP)
		{
			if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
			{
				ipv4tuple addr;
				memcpy(&addr.m_fields.m_sip, sip, sizeof(uint32_t));
				addr.m_fields.m_sport = sinfo->m_ipv4info.m_fields.m_sport;
				memcpy(&addr.m_fields.m_dip, dip, sizeof(uint32_t));
				addr.m_fields.m_dport = sinfo->m_ipv4info.m_fields.m_dport;
				addr.m_fields.m_l4proto = sinfo->m_ipv4info.m_fields.m_l4proto;
				std::string straddr = ipv4tuple_to_string(&addr, resolve);
				snprintf(targetbuf,
						 targetbuf_size,
						 "%s",
						 straddr.c_str());
				return true;
			}
			else
			{
				char srcstr[INET6_ADDRSTRLEN];
				char dststr[INET6_ADDRSTRLEN];
				if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) &&
					inet_ntop(AF_INET6, dip6, dststr, sizeof(dststr)))
				{
					snprintf(targetbuf,
								targetbuf_size,
								"%s:%s->%s:%s",
								srcstr,
								port_to_string(sinfo->m_ipv6info.m_fields.m_sport, sinfo->m_ipv6info.m_fields.m_l4proto, resolve).c_str(),
								dststr,
								port_to_string(sinfo->m_ipv6info.m_fields.m_dport, sinfo->m_ipv6info.m_fields.m_l4proto, resolve).c_str());
					return true;
				}
			}
		}
		else if(sinfo->m_ipv6info.m_fields.m_l4proto == SCAP_L4_ICMP)
		{
			if(sinsp_utils::is_ipv4_mapped_ipv6(sip6) && sinsp_utils::is_ipv4_mapped_ipv6(dip6))
			{
				snprintf(targetbuf,
					targetbuf_size,
					"%u.%u.%u.%u->%u.%u.%u.%u",
					(unsigned int)sip[0],
					(unsigned int)sip[1],
					(unsigned int)sip[2],
					(unsigned int)sip[3],
					(unsigned int)dip[0],
					(unsigned int)dip[1],
					(unsigned int)dip[2],
					(unsigned int)dip[3]);

				return true;
			}
			else
			{
				char srcstr[INET6_ADDRSTRLEN];
				char dststr[INET6_ADDRSTRLEN];
				if(inet_ntop(AF_INET6, sip6, srcstr, sizeof(srcstr)) &&
					inet_ntop(AF_INET6, dip6, dststr, sizeof(dststr)))
				{
					snprintf(targetbuf,
						targetbuf_size,
						"%s->%s",
						srcstr,
						dststr);

					return true;
				}
			}
		}
		else
		{
			snprintf(targetbuf,
				targetbuf_size,
				"<unknown>");
		}
	}

	return true;
}

std::filesystem::path workaround_win_root_name(std::filesystem::path p)
{
	if (!p.has_root_name())
	{
		return p;
	}

	if (p.root_name().string().rfind("//", 0) == 0)
	{
		// this is something like //dir/hello. Add a leading slash to identify an absolute path rooted at /
		return std::filesystem::path("/" + p.string());
	}

	// last case: this is a relative path, like c:/dir/hello. Add a leading ./ to identify a relative path
	return std::filesystem::path("./" + p.string());
}

//
// Helper function to move a directory up in a path string
//
static inline void rewind_to_parent_path(const char* targetbase, char** tc, const char** pc, uint32_t delta)
{
	if(*tc <= targetbase + 1)
	{
		(*pc) += delta;
		return;
	}

	(*tc)--;

	while((*tc) >= targetbase + 1 && *((*tc) - 1) != '/')
	{
		(*tc)--;
	}

	(*pc) += delta;
}

//
// Args:
//  - target: the string where we are supposed to start copying
//  - targetbase: the base of the path, i.e. the furthest we can go back when
//                following parent directories
//  - path: the path to copy
//
static inline void copy_and_sanitize_path(char* target, char* targetbase, const char *path, char separator)
{
	char* tc = target;
	const char* pc = path;
	g_invalidchar ic;
	const bool empty_base = target == targetbase;

	while(true)
	{
		if(*pc == 0)
		{
			*tc = 0;

			//
			// If the path ends with a separator, remove it, as the OS does.
			// Properly manage case where path is just "/".
			//
			if((tc > (targetbase + 1)) && (*(tc - 1) == separator))
			{
				*(tc - 1) = 0;
			}

			return;
		}

		if(ic(*pc))
		{
			//
			// Invalid char, substitute with a '.'
			//
			*tc = '.';
			tc++;
			pc++;
		}
		else
		{
			//
			// If path begins with '.' or '.' is the first char after a '/'
			//
			if(*pc == '.' && (tc == targetbase || *(tc - 1) == separator))
			{
				//
				// '../', rewind to the previous separator
				//
				if(*(pc + 1) == '.' && *(pc + 2) == separator)
				{
					rewind_to_parent_path(targetbase, &tc, &pc, 3);
				}
				//
				// '..', with no separator.
				// This is valid if we are at the end of the string, and in that case we rewind.
				//
				else if(*(pc + 1) == '.' && *(pc + 2) == 0)
				{
					rewind_to_parent_path(targetbase, &tc, &pc, 2);
				}
				//
				// './', just skip it
				//
				else if(*(pc + 1) == separator)
				{
					pc += 2;
				}
				//
				// '.', with no separator.
				// This is valid if we are at the end of the string, and in that case we rewind.
				//
				else if(*(pc + 1) == 0)
				{
					pc++;
				}
				//
				// Otherwise, we leave the string intact.
				//
				else
				{
					*tc = *pc;
					pc++;
					tc++;
				}
			}
			else if(*pc == separator)
			{
				//
				// separator:
				// * if the last char is already a separator, skip it
				// * if we are back at targetbase but targetbase was not empty before, it means we
				//   fully rewinded back to targetbase and the string is now empty. Skip separator.
				//   Example: "/foo/../a" -> "/a" BUT "foo/../a" -> "a"
				//   -> Otherwise: "foo/../a" -> "/a"
				//
				if((tc > targetbase && *(tc - 1) == separator) || (tc == targetbase && !empty_base))
				{
					pc++;
				}
				else
				{
					*tc = *pc;
					tc++;
					pc++;
				}
			}
			else
			{
				//
				// Normal char, copy it
				//
				*tc = *pc;
				tc++;
				pc++;
			}
		}
	}
}

/*
 * Return false if path2 is an absolute path.
 * path1 MUST be '/' terminated.
 * path1 is not sanitized.
 * If path2 is absolute, we only account for it.
 */
static inline bool concatenate_paths_(char* target, uint32_t targetlen, const char* path1, uint32_t len1,
				      const char* path2, uint32_t len2)
{
	if(targetlen < (len1 + len2 + 1))
	{
		strlcpy(target, "/PATH_TOO_LONG", targetlen);
		return false;
	}

	if(len2 != 0 && path2[0] != '/')
	{
		memcpy(target, path1, len1);
		copy_and_sanitize_path(target + len1, target, path2, '/');
		return true;
	}
	else
	{
		target[0] = 0;
		copy_and_sanitize_path(target, target, path2, '/');
		return false;
	}
}

std::string sinsp_utils::concatenate_paths(std::string_view path1, std::string_view path2)
{
	char fullpath[SCAP_MAX_PATH_SIZE];
	concatenate_paths_(fullpath, SCAP_MAX_PATH_SIZE, path1.data(), (uint32_t)path1.length(), path2.data(),
				  path2.size());
	return std::string(fullpath);
}


bool sinsp_utils::is_ipv4_mapped_ipv6(uint8_t* paddr)
{
	if(paddr[0] == 0 && paddr[1] == 0 && paddr[2] == 0 && paddr[3] == 0 && paddr[4] == 0 &&
		paddr[5] == 0 && paddr[6] == 0 && paddr[7] == 0 && paddr[8] == 0 && paddr[9] == 0 &&
			(
					( paddr[10] == 0xff && paddr[11] == 0xff) || // A real IPv4 address
					(paddr[10] == 0 && paddr[11] == 0 && paddr[12] == 0 && paddr[13] == 0 && paddr[14] == 0 && paddr[15] == 0) // all zero address, assume IPv4 as well
			)
		)
	{
		return true;
	}
	else
	{
		return false;
	}
}

const ppm_param_info* sinsp_utils::find_longest_matching_evt_param(std::string name)
{
	uint32_t maxlen = 0;
	const ppm_param_info* res = nullptr;
	const auto name_len = name.size();

	for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
	{
		const ppm_event_info* ei = &g_infotables.m_event_info[j];

		for(uint32_t k = 0; k < ei->nparams; k++)
		{
			const ppm_param_info* pi = &ei->params[k];
			const char* an = pi->name;
			const auto alen = strlen(an);

			if (alen > name_len || alen <= maxlen)
			{
				continue;
			}

			if (name.compare(0, alen, pi->name) == 0)
			{
				res = pi;
				maxlen = alen;
			}
		}
	}

	return res;
}

uint64_t sinsp_utils::get_current_time_ns()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return tv.tv_sec * (uint64_t) 1000000000 + tv.tv_usec * 1000;
}

bool sinsp_utils::glob_match(const char *pattern, const char *string, const bool& case_insensitive)
{
#ifdef _WIN32
	return PathMatchSpec(string, pattern) == TRUE;
#else
	int flags = case_insensitive ? FNM_CASEFOLD : 0;
	return fnmatch(pattern, string, flags) == 0;
#endif
}

#ifndef CYGWING_AGENT
#ifndef _WIN32
#ifdef __GLIBC__
void sinsp_utils::bt(void)
{
	static const char start[] = "BACKTRACE ------------";
	static const char end[] = "----------------------";

	void *bt[1024];
	int bt_size;
	char **bt_syms;
	int i;

	bt_size = backtrace(bt, 1024);
	bt_syms = backtrace_symbols(bt, bt_size);
	libsinsp_logger()->format("%s", start);
	for (i = 1; i < bt_size; i++)
	{
		libsinsp_logger()->format("%s", bt_syms[i]);
	}
	libsinsp_logger()->format("%s", end);

	free(bt_syms);
}
#endif // __GLIBC__
#endif // _WIN32
#endif // CYGWING_AGENT

bool sinsp_utils::find_first_env(std::string &out, const std::vector<std::string> &env, const std::vector<std::string> &keys)
{
	for (const auto& key : keys)
	{
		for(const auto& env_var : env)
		{
			if((env_var.size() > key.size()) && !env_var.compare(0, key.size(), key) && (env_var[key.size()] == '='))
			{
				out = env_var.substr(key.size()+1);
				return true;
			}
		}
	}
	return false;
}

bool sinsp_utils::find_env(std::string &out, const std::vector<std::string> &env, const std::string &key)
{
	const std::vector<std::string> keys = { key };
	return find_first_env(out, env, keys);
}

void sinsp_utils::split_container_image(const std::string &image,
					std::string &hostname,
					std::string &port,
					std::string &name,
					std::string &tag,
					std::string &digest,
					bool split_repo)
{
	auto split = [](const std::string &src, std::string &part1, std::string &part2, const std::string sep)
	{
		size_t pos = src.find(sep);
		if(pos != std::string::npos)
		{
			part1 = src.substr(0, pos);
			part2 = src.substr(pos+1);
			return true;
		}
		return false;
	};

	std::string hostport, rem, rem2, repo;

	hostname = port = name = tag = digest = "";

	if(split(image, hostport, rem, "/"))
	{
		repo = hostport + "/";
		if(!split(hostport, hostname, port, ":"))
		{
			hostname = hostport;
			port = "";
		}
	}
	else
	{
		hostname = "";
		port = "";
		rem = image;
	}

	if(split(rem, rem2, digest, "@"))
	{
		if(!split(rem2, name, tag, ":"))
		{
			name = rem2;
			tag = "";
		}
	}
	else
	{
		digest = "";
		if(!split(rem, name, tag, ":"))
		{
			name = rem;
			tag = "";
		}
	}

	if(!split_repo)
	{
		name = repo + name;
	}
}

void sinsp_utils::parse_suppressed_types(const std::vector<std::string>& supp_strs,
					 std::vector<ppm_event_code>* supp_ids)
{
	for (auto ii = 0; ii < PPM_EVENT_MAX; ii++)
	{
		auto iter = std::find(supp_strs.begin(), supp_strs.end(),
				      event_name_by_id(ii));
		if (iter != supp_strs.end())
		{
			supp_ids->push_back(static_cast<ppm_event_code>(ii));
		}
	}
}

const char* sinsp_utils::event_name_by_id(uint16_t id)
{
	if (id >= PPM_EVENT_MAX)
	{
		ASSERT(false);
		return "NA";
	}
	return g_infotables.m_event_info[id].name;
}

static int32_t gmt2local(time_t t)
{
	int dt, dir;
	struct tm *gmt, *tmp_gmt, *loc;
	struct tm sgmt;

	if(t == 0)
	{
		t = time(NULL);
	}

	gmt = &sgmt;
	tmp_gmt = gmtime(&t);
	if (tmp_gmt == NULL)
	{
		throw sinsp_exception("cannot get gmtime");
	}
	*gmt = *tmp_gmt;
	loc = localtime(&t);
	if(loc == NULL)
	{
		throw sinsp_exception("cannot get localtime");
	}

	dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + (loc->tm_min - gmt->tm_min) * 60;

	dir = loc->tm_year - gmt->tm_year;
	if(dir == 0)
	{
		dir = loc->tm_yday - gmt->tm_yday;
	}

	dt += dir * 24 * 60 * 60;

	return dt;
}

void sinsp_utils::ts_to_string(uint64_t ts, OUT std::string* res, bool date, bool ns)
{
	struct tm *tm;
	time_t Time;
	uint64_t sec = ts / ONE_SECOND_IN_NS;
	uint64_t nsec = ts % ONE_SECOND_IN_NS;
	int32_t thiszone = gmt2local(0);
	int32_t s = (sec + thiszone) % 86400;
	int32_t bufsize = 0;
	char buf[256];

	if(date)
	{
		Time = (sec + thiszone) - s;
		tm = gmtime (&Time);
		if(!tm)
		{
			bufsize = sprintf(buf, "<date error> ");
		}
		else
		{
			bufsize = sprintf(buf, "%04d-%02d-%02d ",
				   tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday);
		}
	}

	if(ns)
	{
		sprintf(buf + bufsize, "%02d:%02d:%02d.%09u",
				s / 3600, (s % 3600) / 60, s % 60, (unsigned)nsec);
	}
	else
	{
		sprintf(buf + bufsize, "%02d:%02d:%02d",
				s / 3600, (s % 3600) / 60, s % 60);
	}

	*res = buf;
}

#define TS_STR_FMT "YYYY-MM-DDTHH:MM:SS-0000"
void sinsp_utils::ts_to_iso_8601(uint64_t ts, OUT std::string* res)
{
	static const char *fmt = TS_STR_FMT;
	char buf[sizeof(TS_STR_FMT)];
	uint64_t ns = ts % ONE_SECOND_IN_NS;
	time_t sec = ts / ONE_SECOND_IN_NS;

	if(strftime(buf, sizeof(buf), "%FT%T", gmtime(&sec)) == 0)
	{
		*res = fmt;
		return;
	}

	*res = buf;
	if(sprintf(buf, ".%09u", (unsigned) ns) < 0)
	{
		*res = fmt;
		return;
	}
	*res += buf;
	if(strftime(buf, sizeof(buf), "%z", gmtime(&sec)) == 0)
	{
		*res = fmt;
		return;
	}
	*res += buf;
}

///////////////////////////////////////////////////////////////////////////////
// Time utility functions.
///////////////////////////////////////////////////////////////////////////////

bool sinsp_utils::parse_iso_8601_utc_string(const std::string& time_str, uint64_t &ns)
{
#ifndef _WIN32
	tm tm_time{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	char* rem = strptime(time_str.c_str(), "%Y-%m-%dT%H:%M:", &tm_time);
	if(rem == NULL || *rem == '\0')
	{
		return false;
	}
	tm_time.tm_isdst = -1; // strptime does not set this, signal timegm to determine DST
	ns = timegm(&tm_time) * ONE_SECOND_IN_NS;

	// Handle the possibly fractional seconds now. Also verify
	// that the string ends with Z.
	double fractional_secs;
	if(sscanf(rem, "%lfZ", &fractional_secs) != 1)
	{
		return false;
	}

	ns += (fractional_secs * ONE_SECOND_IN_NS);

	return true;
#else
	throw sinsp_exception("parse_iso_8601_utc_string() not implemented on Windows");
#endif
}

time_t get_epoch_utc_seconds(const std::string& time_str, const std::string& fmt)
{
#ifndef _WIN32
	if(time_str.empty() || fmt.empty())
	{
		throw sinsp_exception("get_epoch_utc_seconds(): empty time or format string.");
	}
	tm tm_time{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	strptime(time_str.c_str(), fmt.c_str(), &tm_time);
	tm_time.tm_isdst = -1; // strptime does not set this, signal timegm to determine DST
	return timegm(&tm_time);
#else
	throw sinsp_exception("get_epoch_utc_seconds() not implemented on Windows");
#endif // _WIN32
}

time_t get_epoch_utc_seconds_now()
{
#ifndef _WIN32
	time_t rawtime;
	time(&rawtime);
	return timegm(gmtime(&rawtime));
#else
	throw sinsp_exception("get_now_seconds() not implemented on Windows");
#endif // _WIN32
}

// gettimeofday() windows implementation
#ifdef _WIN32

#include <time.h>
#include <windows.h>

const __int64 DELTA_EPOCH_IN_MICROSECS = 11644473600000000;

int gettimeofday(struct timeval *tv, struct timezone2 *tz)
{
	FILETIME ft;
	__int64 tmpres = 0;
	TIME_ZONE_INFORMATION tz_winapi;
	int rez=0;

	ZeroMemory(&ft,sizeof(ft));
	ZeroMemory(&tz_winapi,sizeof(tz_winapi));

	GetSystemTimeAsFileTime(&ft);

	tmpres = ft.dwHighDateTime;
	tmpres <<= 32;
	tmpres |= ft.dwLowDateTime;

	//
	// converting file time to unix epoch
	//
	tmpres /= 10;  // convert into microseconds
	tmpres -= DELTA_EPOCH_IN_MICROSECS;
	tv->tv_sec = (__int32)(tmpres*0.000001);
	tv->tv_usec =(tmpres%1000000);

	//
	// _tzset(),don't work properly, so we use GetTimeZoneInformation
	//
	if(tz)
	{
		rez=GetTimeZoneInformation(&tz_winapi);
		tz->tz_dsttime=(rez==2)?true:false;
		tz->tz_minuteswest = tz_winapi.Bias + ((rez==2)?tz_winapi.DaylightBias:0);
	}

	return 0;
}
#endif // _WIN32

///////////////////////////////////////////////////////////////////////////////
// gethostname wrapper
///////////////////////////////////////////////////////////////////////////////
std::string sinsp_gethostname()
{
	char hname[256];
	int res = gethostname(hname, sizeof(hname) / sizeof(hname[0]));

	if(res == 0)
	{
		return hname;
	}
	else
	{
		ASSERT(false);
		return "";
	}
}

///////////////////////////////////////////////////////////////////////////////
// tuples to string
///////////////////////////////////////////////////////////////////////////////
std::string port_to_string(uint16_t port, uint8_t l4proto, bool resolve)
{
	std::string ret = "";
	if(resolve)
	{
		std::string proto = "";
		if(l4proto == SCAP_L4_TCP)
		{
			proto = "tcp";
		}
		else if(l4proto == SCAP_L4_UDP)
		{
			proto = "udp";
		}

		// `port` is saved with network byte order
		struct servent * res;
		res = getservbyport(ntohs(port), (proto != "") ? proto.c_str() : NULL);	// best effort!
		if (res)
		{
			ret = res->s_name;
		}
		else
		{
			ret = std::to_string(port);
		}
	}
	else
	{
		ret = std::to_string(port);
	}

	return ret;
}

std::string ipv4serveraddr_to_string(ipv4serverinfo* addr, bool resolve)
{
	char buf[50];
	uint8_t *ip = (uint8_t *)&addr->m_ip;

	// IP address is in network byte order regardless of host endianness
	snprintf(buf,
		sizeof(buf),
		"%d.%d.%d.%d:%s", ip[0], ip[1], ip[2], ip[3],
		port_to_string(addr->m_port, addr->m_l4proto, resolve).c_str());

	return std::string(buf);
}

std::string ipv4tuple_to_string(ipv4tuple* tuple, bool resolve)
{
	char buf[100];

	ipv4serverinfo info;

	info.m_ip = tuple->m_fields.m_sip;
	info.m_port = tuple->m_fields.m_sport;
	info.m_l4proto = tuple->m_fields.m_l4proto;
	std::string source = ipv4serveraddr_to_string(&info, resolve);

	info.m_ip = tuple->m_fields.m_dip;
	info.m_port = tuple->m_fields.m_dport;
	info.m_l4proto = tuple->m_fields.m_l4proto;
	std::string dest = ipv4serveraddr_to_string(&info, resolve);

	snprintf(buf, sizeof(buf), "%s->%s", source.c_str(), dest.c_str());

	return std::string(buf);
}

std::string ipv6serveraddr_to_string(ipv6serverinfo* addr, bool resolve)
{
	char address[100];
	char buf[200];

	if(NULL == inet_ntop(AF_INET6, addr->m_ip.m_b, address, 100))
	{
		return std::string();
	}

	snprintf(buf,200,"%s:%s",
		address,
		port_to_string(addr->m_port, addr->m_l4proto, resolve).c_str());

	return std::string(buf);
}

std::string ipv6tuple_to_string(ipv6tuple* tuple, bool resolve)
{
	char source_address[INET6_ADDRSTRLEN];
	if(NULL == inet_ntop(AF_INET6, tuple->m_fields.m_sip.m_b, source_address, 100))
	{
		return std::string();
	}

	char destination_address[INET6_ADDRSTRLEN];
	if(NULL == inet_ntop(AF_INET6, tuple->m_fields.m_dip.m_b, destination_address, 100))
	{
		return std::string();
	}

	char buf[200];
	snprintf(buf, sizeof(buf), "%s:%s->%s:%s",
		source_address,
		port_to_string(tuple->m_fields.m_sport, tuple->m_fields.m_l4proto, resolve).c_str(),
		destination_address,
		port_to_string(tuple->m_fields.m_dport, tuple->m_fields.m_l4proto, resolve).c_str());

	return std::string(buf);
}

const char* param_type_to_string(ppm_param_type pt)
{
	switch(pt)
	{
	case PT_NONE:
		return "NONE";
	case PT_INT8:
		return "INT8";
	case PT_INT16:
		return "INT16";
	case PT_INT32:
		return "INT32";
	case PT_INT64:
		return "INT64";
	case PT_UINT8:
		return "UINT8";
	case PT_UINT16:
		return "UINT16";
	case PT_UINT32:
		return "UINT32";
	case PT_UINT64:
		return "UINT64";
	case PT_CHARBUF:
		return "CHARBUF";
	case PT_BYTEBUF:
		return "BYTEBUF";
	case PT_ERRNO:
		return "ERRNO";
	case PT_SOCKADDR:
		return "SOCKADDR";
	case PT_SOCKTUPLE:
		return "SOCKTUPLE";
	case PT_FD:
		return "FD";
	case PT_PID:
		return "PID";
	case PT_FDLIST:
		return "FDLIST";
	case PT_FSPATH:
		return "FSPATH";
	case PT_SYSCALLID:
		return "SYSCALLID";
	case PT_SIGTYPE:
		return "SIGTYPE";
	case PT_RELTIME:
		return "RELTIME";
	case PT_ABSTIME:
		return "ABSTIME";
	case PT_PORT:
		return "PORT";
	case PT_L4PROTO:
		return "L4PROTO";
	case PT_SOCKFAMILY:
		return "SOCKFAMILY";
	case PT_BOOL:
		return "BOOL";
	case PT_IPV4ADDR:
		return "IPV4ADDR";
	case PT_IPADDR:
		return "IPADDR";
	case PT_IPNET:
		return "IPNET";
	case PT_DYN:
		return "DYNAMIC";
	case PT_FLAGS8:
		return "FLAGS8";
	case PT_FLAGS16:
		return "FLAGS16";
	case PT_FLAGS32:
		return "FLAGS32";
	case PT_ENUMFLAGS8:
		return "ENUMFLAGS8";
	case PT_ENUMFLAGS16:
		return "ENUMFLAGS16";
	case PT_ENUMFLAGS32:
		return "ENUMFLAGS32";
	case PT_MODE:
		return "MODE";
	case PT_UID:
		return "UID";
	case PT_GID:
		return "GID";
	case PT_SIGSET:
		return "SIGSET";
	case PT_IPV4NET:
		return "IPV4NET";
	case PT_DOUBLE:
		return "DOUBLE";
	case PT_CHARBUFARRAY:
		return "CHARBUFARRAY";
	case PT_CHARBUF_PAIR_ARRAY:
		return "CHARBUF_PAIR_ARRAY";
	case PT_FSRELPATH:
		return "FSRELPATH";
	default:
		ASSERT(false);
		return "<NA>";
	}
}

const char* print_format_to_string(ppm_print_format fmt)
{
	switch(fmt)
	{
	case PF_DEC:
		return "DEC";
	case PF_HEX:
		return "HEX";
	case PF_10_PADDED_DEC:
		return "10_PADDED_DEC";
	case PF_ID:
		return "ID";
	case PF_DIR:
		return "DIR";
	case PF_OCT:
		return "OCT";
	case PF_NA:
		return "NA";
	default:
		ASSERT(false);
		return "NA";
	}
}

///////////////////////////////////////////////////////////////////////////////
// String helpers
///////////////////////////////////////////////////////////////////////////////
//
// String split
//
std::vector<std::string> sinsp_split(const std::string &s, char delim)
{
	std::vector<std::string> res;
	std::istringstream f(s);
	std::string ts;

	while(getline(f, ts, delim))
	{
		res.push_back(ts);
	}

	return res;
}

//
// trim from start
//
std::string& ltrim(std::string &s)
{
	s.erase(s.begin(), find_if(s.begin(), s.end(), [](int c) {return !std::isspace(c);}));
	return s;
}

//
// trim from end
//
std::string& rtrim(std::string &s)
{
	s.erase(find_if(s.rbegin(), s.rend(), [](int c) {return !std::isspace(c);}).base(), s.end());
	return s;
}

//
// trim from both ends
//
std::string& trim(std::string &s)
{
	return ltrim(rtrim(s));
}

std::string& replace_in_place(std::string& str, const std::string& search, const std::string& replacement)
{
	std::string::size_type ssz = search.length();
	std::string::size_type rsz = replacement.length();
	std::string::size_type pos = 0;
	while((pos = str.find(search, pos)) != std::string::npos)
	{
		str.replace(pos, ssz, replacement);
		pos += rsz;
		ASSERT(pos <= str.length());
	}
	return str;
}

std::string replace(const std::string& str, const std::string& search, const std::string& replacement)
{
	std::string s(str);
	replace_in_place(s, search, replacement);
	return s;
}


bool sinsp_utils::endswith(const std::string& str, const std::string& ending)
{
	if (ending.size() <= str.size())
	{
		return (0 == str.compare(str.length() - ending.length(), ending.length(), ending));
	}
	return false;
}


bool sinsp_utils::endswith(const char *str, const char *ending, uint32_t lstr, uint32_t lend)
{
	if (lstr >= lend)
	{
		return (0 == memcmp(ending, str + (lstr - lend), lend));
	}
	return 0;
}

bool sinsp_utils::startswith(const std::string& s, const std::string& prefix)
{
	if(prefix.empty())
	{
		return false;
	}

	size_t prefix_len = prefix.length();
	if(s.length() < prefix_len)
	{
		return false;
	}

	return strncmp(s.c_str(), prefix.c_str(), prefix_len) == 0;
}

bool sinsp_utils::unhex(const std::vector<char> &hex_chars, std::vector<char> &hex_bytes)
{
	if(hex_chars.size() % 2 != 0 ||
		!std::all_of(hex_chars.begin(), hex_chars.end(), [](unsigned char c){ return std::isxdigit(c); }))
	{
		return false;
	}

	std::stringstream ss;
	for(size_t i = 0; i < hex_chars.size(); i += 2)
	{
		int byte;
		ss << std::hex << hex_chars.at(i) << hex_chars.at(i + 1);
		ss >> byte;
		hex_bytes.push_back(byte & 0xff);
		ss.str(std::string());
		ss.clear();
	}

	return true;
}

const std::vector<std::string> capabilities {
	{"CAP_CHOWN"},
	{"CAP_DAC_OVERRIDE"},
	{"CAP_DAC_READ_SEARCH"},
	{"CAP_FOWNER"},
	{"CAP_FSETID"},
	{"CAP_KILL"},
	{"CAP_SETGID"},
	{"CAP_SETUID"},
	{"CAP_SETPCAP"},
	{"CAP_LINUX_IMMUTABLE"},
	{"CAP_NET_BIND_SERVICE"},
	{"CAP_NET_BROADCAST"},
	{"CAP_NET_ADMIN"},
	{"CAP_NET_RAW"},
	{"CAP_IPC_LOCK"},
	{"CAP_IPC_OWNER"},
	{"CAP_SYS_MODULE"},
	{"CAP_SYS_RAWIO"},
	{"CAP_SYS_CHROOT"},
	{"CAP_SYS_PTRACE"},
	{"CAP_SYS_PACCT"},
	{"CAP_SYS_ADMIN"},
	{"CAP_SYS_BOOT"},
	{"CAP_SYS_NICE"},
	{"CAP_SYS_RESOURCE"},
	{"CAP_SYS_TIME"},
	{"CAP_SYS_TTY_CONFIG"},
	{"CAP_MKNOD"},
	{"CAP_LEASE"},
	{"CAP_AUDIT_WRITE"},
	{"CAP_AUDIT_CONTROL"},
	{"CAP_SETFCAP"},
	{"CAP_MAC_OVERRIDE"},
	{"CAP_MAC_ADMIN"},
	{"CAP_SYSLOG"},
	{"CAP_WAKE_ALARM"},
	{"CAP_BLOCK_SUSPEND"},
	{"CAP_AUDIT_READ"},
	{"CAP_PERFMON"},
	{"CAP_BPF"},
	{"CAP_CHECKPOINT_RESTORE"},
};

std::string sinsp_utils::caps_to_string(const uint64_t caps)
{
	std::string res;

	for(size_t i = 0; i < capabilities.size(); ++i)
	{
		uint64_t current_cap = (uint64_t)1 << i;
		if(caps & current_cap)
		{
			res += capabilities[i];
			res += " ";
		}
	}

	if(res.length() > 0)
	{
		res = res.substr(0, res.length() - 1);
	}

	return res;
}

uint64_t sinsp_utils::get_max_caps()
{
	return ((uint64_t)1 << capabilities.size()) - 1;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_numparser implementation
///////////////////////////////////////////////////////////////////////////////
uint8_t sinsp_numparser::parseu8(const std::string& str)
{
	uint32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return (uint8_t)res;
}

int8_t sinsp_numparser::parsed8(const std::string& str)
{
	int32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return (int8_t)res;
}

uint16_t sinsp_numparser::parseu16(const std::string& str)
{
	uint32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return (uint16_t)res;
}

int16_t sinsp_numparser::parsed16(const std::string& str)
{
	int32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return (int16_t)res;
}

uint32_t sinsp_numparser::parseu32(const std::string& str)
{
	uint32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

int32_t sinsp_numparser::parsed32(const std::string& str)
{
	int32_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId32 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

uint64_t sinsp_numparser::parseu64(const std::string& str)
{
	uint64_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu64 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

int64_t sinsp_numparser::parsed64(const std::string& str)
{
	int64_t res;
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId64 "%c", &res, &temp) != 1)
	{
		throw sinsp_exception(str + " is not a valid number");
	}

	return res;
}

bool sinsp_numparser::tryparseu32(const std::string& str, uint32_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu32 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparsed32(const std::string& str, int32_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId32 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparseu64(const std::string& str, uint64_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRIu64 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparsed64(const std::string& str, int64_t* res)
{
	char temp;

	if(std::sscanf(str.c_str(), "%" PRId64 "%c", res, &temp) != 1)
	{
		return false;
	}

	return true;
}

bool sinsp_numparser::tryparseu32_fast(const char* str, uint32_t strlen, uint32_t* res)
{
	const char* p = str;
	const char* end = str + strlen;

	*res = 0;

	while(p < end)
	{
		if(*p >= '0' && *p <= '9')
		{
			*res = (*res) * 10 + (*p - '0');
		}
		else
		{
			return false;
		}

		p++;
	}

	return true;
}

bool sinsp_numparser::tryparsed32_fast(const char* str, uint32_t strlen, int32_t* res)
{
	const char* p = str;
	const char* end = str + strlen;

	*res = 0;

	while(p < end)
	{
		if(*p >= '0' && *p <= '9')
		{
			*res = (*res) * 10 + (*p - '0');
		}
		else
		{
			return false;
		}

		p++;
	}

	return true;
}

///////////////////////////////////////////////////////////////////////////////
// JSON helpers
///////////////////////////////////////////////////////////////////////////////

std::string get_json_string(const Json::Value& obj, const std::string& name)
{
	std::string ret;
	const Json::Value& json_val = obj[name];
	if(!json_val.isNull() && json_val.isConvertibleTo(Json::stringValue))
	{
		ret = json_val.asString();
	}
	return ret;
}

///////////////////////////////////////////////////////////////////////////////
// socket helpers
///////////////////////////////////////////////////////////////////////////////

bool set_socket_blocking(int sock, bool block)
{
#ifndef _WIN32
	int arg = block ? 0 : 1;
	if(ioctl(sock, FIONBIO, &arg) == -1)
#else
	u_long arg = block ? 0 : 1;
	if(ioctlsocket(sock, FIONBIO, &arg) == -1)
#endif // _WIN32
	{
		return false;
	}
	return true;
}

unsigned int read_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;

	fp = fopen(fcpu, "r");
	if (!fp) {
		return possible_cpus;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "%u-%u", &start, &end) == 2) {
			possible_cpus = start == 0 ? end + 1 : 0;
			break;
		}
	}

	fclose(fp);

	return possible_cpus;
}

///////////////////////////////////////////////////////////////////////////////
// Log helper
///////////////////////////////////////////////////////////////////////////////
void sinsp_scap_log_fn(const char* component, const char* msg, falcosecurity_log_severity sev)
{
	std::string prefix = (component == NULL) ? "" : std::string(component) + ": ";
	libsinsp_logger()->log(prefix + msg, (sinsp_logger::severity)sev);
}

///////////////////////////////////////////////////////////////////////////////
// Set operation functions.
///////////////////////////////////////////////////////////////////////////////

// unordered_set_to_ordered
template<typename T>
std::set<T> unordered_set_to_ordered(const std::unordered_set<T>& unordered_set)
{
	std::set<T> s;
	for(const auto& val : unordered_set)
	{
		s.insert(val);
	}
	return s;
}
template std::set<uint32_t> unordered_set_to_ordered(const std::unordered_set<uint32_t>& unordered_set);
template std::set<std::string> unordered_set_to_ordered(const std::unordered_set<std::string>& unordered_set);

// unordered_set_difference, equivalent to SQL left_anti join operation
template<typename T>
std::unordered_set<T> unordered_set_difference(const std::unordered_set<T>& a, const std::unordered_set<T>& b)
{
	std::unordered_set<T> s;
	for(const auto& val : a)
	{
		if (b.find(val) == b.end())
		{
			s.insert(val);
		}
	}
	return s;
}
template std::unordered_set<std::string> unordered_set_difference(const std::unordered_set<std::string>& a, const std::unordered_set<std::string>& b);
template std::unordered_set<uint32_t> unordered_set_difference(const std::unordered_set<uint32_t>& a, const std::unordered_set<uint32_t>& b);

// set_difference, equivalent to SQL left_anti join operation
template<typename T>
std::set<T> set_difference(const std::set<T>& a, const std::set<T>& b)
{
	std::set<T> out;
	std::set_difference(a.begin(), a.end(), b.begin(), b.end(), std::inserter(out, out.begin()));
	return out;
}
template std::set<std::string> set_difference(const std::set<std::string>& a, const std::set<std::string>& b);
template std::set<uint32_t> set_difference(const std::set<uint32_t>& a, const std::set<uint32_t>& b);

// unordered_set_union
template<typename T>
std::unordered_set<T> unordered_set_union(const std::unordered_set<T>& a, const std::unordered_set<T>& b)
{
	std::unordered_set<T> s = a;
	for(const auto& val : b)
	{
		s.insert(val);
	}
	return s;
}
template std::unordered_set<std::string> unordered_set_union(const std::unordered_set<std::string>& a, const std::unordered_set<std::string>& b);
template std::unordered_set<uint32_t> unordered_set_union(const std::unordered_set<uint32_t>& a, const std::unordered_set<uint32_t>& b);

// set_union
template<typename T>
std::set<T> set_union(const std::set<T>& a, const std::set<T>& b)
{
	std::set<T> out;
	std::set_union(a.begin(), a.end(), b.begin(), b.end(), std::inserter(out, out.begin()));
	return out;
}
template std::set<std::string> set_union(const std::set<std::string>& a, const std::set<std::string>& b);
template std::set<uint32_t> set_union(const std::set<uint32_t>& a, const std::set<uint32_t>& b);

// unordered_set_intersection
template<typename T>
std::unordered_set<T> unordered_set_intersection(const std::unordered_set<T>& a, const std::unordered_set<T>& b)
{
	std::unordered_set<T> s;
	for(const auto& val : a)
	{
		if (b.find(val) != b.end())
		{
			s.insert(val);
		}
	}
	return s;
}
template std::unordered_set<std::string> unordered_set_intersection(const std::unordered_set<std::string>& a, const std::unordered_set<std::string>& b);
template std::unordered_set<uint32_t> unordered_set_intersection(const std::unordered_set<uint32_t>& a, const std::unordered_set<uint32_t>& b);

// set_intersection
template<typename T>
std::set<T> set_intersection(const std::set<T>& a, const std::set<T>& b)
{
	std::set<T> out;
	std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::inserter(out, out.begin()));
	return out;
}
template std::set<std::string> set_intersection(const std::set<std::string>& a, const std::set<std::string>& b);
template std::set<uint32_t> set_intersection(const std::set<uint32_t>& a, const std::set<uint32_t>& b);

std::string concat_set_in_order(const std::unordered_set<std::string>& s, const std::string& delim)
{
	if (s.empty())
	{
		return "";
	}
	std::set<std::string> s_ordered = unordered_set_to_ordered(s);
	std::stringstream ss;
	std::copy(s_ordered.begin(), s_ordered.end(),
	std::ostream_iterator<std::string>(ss, delim.c_str()));
	std::string s_str = ss.str();
	return s_str.substr(0, s_str.size() - delim.size());
}

std::string concat_set_in_order(const std::set<std::string>& s, const std::string& delim)
{
	if (s.empty())
	{
		return "";
	}
	std::stringstream ss;
	std::copy(s.begin(), s.end(),
	std::ostream_iterator<std::string>(ss, delim.c_str()));
	std::string s_str = ss.str();
	return s_str.substr(0, s_str.size() - delim.size());
}
