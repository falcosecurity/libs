/*
Copyright (C) 2022 The Falco Authors.

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

#include "sinsp_events.h"
#include "../utils.h"

libsinsp::events::set<ppm_sc_code> libsinsp::events::sinsp_state_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		std::vector<uint8_t> sc_vec(PPM_SC_MAX);
		/* Should never happen but just to be sure. */
		if(scap_get_modifies_state_ppm_sc(sc_vec.data()) != SCAP_SUCCESS)
		{
			throw sinsp_exception("'ppm_sc_set' is an unexpected NULL vector!");
		}
		for (int i = 0; i < PPM_SC_MAX; i++)
		{
			if (sc_vec[i])
			{
				ppm_sc_set.insert((ppm_sc_code)i);
			}
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_simple_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	static libsinsp::events::set<ppm_sc_code> simple_set = {
		PPM_SC_ACCEPT,
		PPM_SC_ACCEPT4,
		PPM_SC_BIND,
		PPM_SC_BPF,
		PPM_SC_CAPSET,
		PPM_SC_CHDIR,
		PPM_SC_CHMOD,
		PPM_SC_CHROOT,
		PPM_SC_CLONE,
		PPM_SC_CLONE3,
		PPM_SC_CLOSE,
		PPM_SC_CONNECT,
		PPM_SC_CREAT,
		PPM_SC_DUP,
		PPM_SC_DUP2,
		PPM_SC_DUP3,
		PPM_SC_EVENTFD,
		PPM_SC_EVENTFD2,
		PPM_SC_EXECVE,
		PPM_SC_EXECVEAT,
		PPM_SC_FCHDIR,
		PPM_SC_FCHMOD,
		PPM_SC_FCHMODAT,
		PPM_SC_FCNTL,
		PPM_SC_FCNTL64,
		PPM_SC_FLOCK,
		PPM_SC_FORK,
		PPM_SC_GETSOCKOPT,
		PPM_SC_INOTIFY_INIT,
		PPM_SC_INOTIFY_INIT1,
		PPM_SC_IOCTL,
		PPM_SC_IO_URING_SETUP,
		PPM_SC_KILL,
		PPM_SC_LINK,
		PPM_SC_LINKAT,
		PPM_SC_LISTEN,
		PPM_SC_MKDIR,
		PPM_SC_MKDIRAT,
		PPM_SC_MOUNT,
		PPM_SC_OPEN,
		PPM_SC_OPEN_BY_HANDLE_AT,
		PPM_SC_OPENAT,
		PPM_SC_OPENAT2,
		PPM_SC_PIPE,
		PPM_SC_PIPE2,
		PPM_SC_PRLIMIT64,
		PPM_SC_PTRACE,
		PPM_SC_QUOTACTL,
		PPM_SC_RECVFROM,
		PPM_SC_RECVMSG,
		PPM_SC_RENAME,
		PPM_SC_RENAMEAT,
		PPM_SC_RENAMEAT2,
		PPM_SC_RMDIR,
		PPM_SC_SECCOMP,
		PPM_SC_SENDMSG,
		PPM_SC_SENDTO,
		PPM_SC_SETGID,
		PPM_SC_SETGID32,
		PPM_SC_SETNS,
		PPM_SC_SETPGID,
		PPM_SC_SETRESGID,
		PPM_SC_SETRESGID32,
		PPM_SC_SETRESUID,
		PPM_SC_SETRESUID32,
		PPM_SC_SETRLIMIT,
		PPM_SC_SETSID,
		PPM_SC_SETUID,
		PPM_SC_SETUID32,
		PPM_SC_SHUTDOWN,
		PPM_SC_SIGNALFD,
		PPM_SC_SIGNALFD4,
		PPM_SC_SOCKET,
		PPM_SC_SOCKETPAIR,
		PPM_SC_SYMLINK,
		PPM_SC_SYMLINKAT,
		PPM_SC_TGKILL,
		PPM_SC_TIMERFD_CREATE,
		PPM_SC_TKILL,
		PPM_SC_UMOUNT,
		PPM_SC_UMOUNT2,
		PPM_SC_UNLINK,
		PPM_SC_UNLINKAT,
		PPM_SC_UNSHARE,
		PPM_SC_USERFAULTFD,
		PPM_SC_VFORK,
	};
	static auto sinsp_state_ppm_sc = sinsp_state_sc_set();
	static auto final_set = simple_set.merge(sinsp_state_ppm_sc);
	return ppm_sc_set.merge(final_set);
}

static inline void get_sc_set_from_cat(libsinsp::events::set<ppm_sc_code> &ppm_sc_set, const std::function<bool(ppm_event_category)>& filter)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		auto cat = scap_get_syscall_info_table()[ppm_sc].category & bitmask;
		if (filter((ppm_event_category)cat))
		{
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::io_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		get_sc_set_from_cat(ppm_sc_set, [](ppm_event_category cat)
		{
		   if (cat == EC_IO_READ || cat == EC_IO_WRITE)
		   {
			   return true;
		   }
		   return false;
		});
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::io_other_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		get_sc_set_from_cat(ppm_sc_set, [](ppm_event_category cat)
		{
			return cat == EC_IO_OTHER;
		});
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::file_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		get_sc_set_from_cat(ppm_sc_set, [](ppm_event_category cat)
		{
			return cat == EC_FILE;
		});
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::net_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		get_sc_set_from_cat(ppm_sc_set, [](ppm_event_category cat)
		{
			return cat == EC_NET;
		});
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::proc_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		get_sc_set_from_cat(ppm_sc_set, [](ppm_event_category cat)
		{
		        return cat == EC_PROCESS;
		});
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::sys_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		get_sc_set_from_cat(ppm_sc_set, [](ppm_event_category cat)
		{
		    if (cat == EC_SYSTEM || cat == EC_MEMORY || cat == EC_SIGNAL)
		    {
			    return true;
		    }
		    return false;
		});
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::names_to_sc_set(const std::unordered_set<std::string>& syscalls)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	for (const auto &syscall_name : syscalls)
	{
		auto ppm_sc = scap_ppm_sc_from_name(syscall_name.c_str());
		if(ppm_sc != -1)
		{
			ppm_sc_set.insert(ppm_sc);
		}
	}
	/* Extra back and forth mapping to resolve overloaded event <-> sc names, e.g. accept -> accept, accept4
	 * Plus account for variants that share event codes, e.g. eventfd, eventfd2 share PPME_SYSCALL_EVENTFD_E, PPME_SYSCALL_EVENTFD_X
	 * Plus handle special snowflakes, e.g. "umount" event string maps to PPME_SYSCALL_UMOUNT_E, PPME_SYSCALL_UMOUNT_X, but
	 * in actuality applies for "umount2" syscall as "umount" syscall is a generic event -> end result is activating both umount, umount2
	 *
	 * Since names_to_event_set would resolve generic sc events, we only apply these extra lookups for non generic sc event codes
	 *
	 * note: todo @jasondellaluce, @incertum once we refactor tables and/or introduce a paradigm change of not supporting shared event names across syscall variants
	 * we can remove this extra logic again. Timing can be relaxed as these extra lookups won't break anything, at worst they are redundant.
	*/
	auto all_non_generic_sc_event_set = libsinsp::events::all_event_set().filter([&](ppm_event_code e) { return libsinsp::events::is_syscall_event(e); })\
	.diff(libsinsp::events::set<ppm_event_code>{PPME_GENERIC_E, PPME_GENERIC_X});
	auto tmp_event_set = all_non_generic_sc_event_set.intersect(libsinsp::events::names_to_event_set(syscalls));
	auto tmp_sc_set = libsinsp::events::event_set_to_sc_set(tmp_event_set);
	return ppm_sc_set.merge(tmp_sc_set);
}

libsinsp::events::set<ppm_event_code> libsinsp::events::sc_set_to_event_set(const libsinsp::events::set<ppm_sc_code> &ppm_sc_set)
{
	libsinsp::events::set<ppm_event_code> events_set;
	std::vector<uint8_t> event_vec(PPM_EVENT_MAX);
	if(scap_get_events_from_ppm_sc(ppm_sc_set.data(), event_vec.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("`ppm_sc_array` or `events_set` is an unexpected NULL vector!");
	}
	for (int i = 0; i < PPM_EVENT_MAX; i++)
	{
		if (event_vec[i])
		{
			events_set.insert((ppm_event_code)i);
		}
	}
	return events_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::all_sc_set()
{
	static libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	if (ppm_sc_set.empty())
	{
		for(uint32_t ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
		{
			if (scap_get_syscall_info_table()[ppm_sc].name[0] != '\0')
			{
				// Skip non-existent
				ppm_sc_set.insert((ppm_sc_code)ppm_sc);
			}
		}
	}
	return ppm_sc_set;
}

std::unordered_set<std::string> libsinsp::events::sc_set_to_names(const libsinsp::events::set<ppm_sc_code>& ppm_sc_set)
{
	std::unordered_set<std::string> ppm_sc_names_set;
	for (const auto& val : ppm_sc_set)
	{
		std::string ppm_sc_name = scap_get_syscall_info_table()[val].name;
		if (ppm_sc_name != "")
		{
			// Skip non-existent
			ppm_sc_names_set.insert(ppm_sc_name);
		}
	}
	return ppm_sc_names_set;
}
