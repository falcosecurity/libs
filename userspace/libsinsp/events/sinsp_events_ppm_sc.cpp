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

#include <libsinsp/events/sinsp_events.h>
#include <libsinsp/utils.h>

/*
 * Repair base syscalls flags.
 */
#define PPM_REPAIR_STATE_SC_NETWORK_BASE (1 << 0)
#define PPM_REPAIR_STATE_SC_NETWORK_BIND (1 << 1)
#define PPM_REPAIR_STATE_SC_FD_CLOSE (1 << 2)


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

/* The filter should contain only conditions on the syscall category (lower bits)*/
static inline libsinsp::events::set<ppm_sc_code> get_sc_set_from_cat(const std::function<bool(ppm_event_category)>& filter)
{
	std::vector<uint8_t> ev_vec(PPM_EVENT_MAX, 0);
	std::vector<uint8_t> sc_vec(PPM_SC_MAX, 0);

	/* Find all the events involved in that category */
	for(int ev = 0; ev < PPM_EVENT_MAX; ev++)
	{
		auto cat = scap_get_syscall_category_from_event((ppm_event_code)ev);
		if(filter((ppm_event_category)cat))
		{
			ev_vec[ev] = 1;
		}
	}

	/* Obtain all sc associated with those events */
	if(scap_get_ppm_sc_from_events(ev_vec.data(), sc_vec.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("'sc_vec' or 'ev_vec' is unexpected NULL vector!");
	}

	libsinsp::events::set<ppm_sc_code> sc_set;

	for(int sc = 0; sc < PPM_SC_MAX; sc++)
	{
		if(sc_vec[sc])
		{
			sc_set.insert((ppm_sc_code)sc);
		}
	}
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::io_sc_set()
{
	static auto sc_set = get_sc_set_from_cat([](ppm_event_category cat)
		{
			return cat == EC_IO_READ || cat == EC_IO_WRITE;
		});
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::io_other_sc_set()
{
	static auto sc_set = get_sc_set_from_cat([](ppm_event_category cat)
		{
			return cat == EC_IO_OTHER;
		});
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::file_sc_set()
{
	static auto sc_set = get_sc_set_from_cat([](ppm_event_category cat)
		{
			return cat == EC_FILE;
		});
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::net_sc_set()
{
	static auto sc_set = get_sc_set_from_cat([](ppm_event_category cat)
		{
			return cat == EC_NET;
		});
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::proc_sc_set()
{
	static auto sc_set = get_sc_set_from_cat([](ppm_event_category cat)
		{
			return cat == EC_PROCESS;
		});
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::sys_sc_set()
{
	static auto sc_set = get_sc_set_from_cat([](ppm_event_category cat)
		{
			return cat == EC_SYSTEM || cat == EC_MEMORY || cat == EC_SIGNAL;
		});
	return sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::event_names_to_sc_set(const std::unordered_set<std::string>& events)
{
	/* Convert event names into an event set, and then convert that into a
	 * syscall set. We exclude generics due to the potential information loss
	 * (e.g. one generic event will include all generic syscalls in the
	 * conversion). Generics are handled below using their actuall syscall name.
	 * Note: this is the same logic with which the "evt.type" filter field
	 * is extracted. */
	auto gen_event_set = libsinsp::events::set<ppm_event_code>(
		{ PPME_GENERIC_E, PPME_GENERIC_X });
	auto event_set = libsinsp::events::names_to_event_set(events);
	bool has_gen_event = !event_set.intersect(gen_event_set).empty();
	event_set = event_set.diff(gen_event_set);

	auto ppm_sc_set = libsinsp::events::event_set_to_sc_set(event_set);
	if (has_gen_event)
	{
		std::string name;
		auto gen_sc_set = libsinsp::events::event_set_to_sc_set(gen_event_set);
		for (const auto &sc : gen_sc_set)
		{
			name.assign(scap_get_ppm_sc_name(sc));
			if (events.find(name) != events.end())
			{
				ppm_sc_set.insert(sc);
			}
		}
	}

	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::sc_names_to_sc_set(const std::unordered_set<std::string>& syscalls)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	for (const auto &name : syscalls)
	{
		auto ppm_sc = scap_ppm_sc_from_name(name.c_str());
		if(static_cast<int>(ppm_sc) != -1)
		{
			ppm_sc_set.insert(ppm_sc);
		}
	}
	return ppm_sc_set;
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
		// Skip UNKNOWN
		for(uint32_t ppm_sc = 1; ppm_sc < PPM_SC_MAX; ppm_sc++)
		{
			if (scap_get_ppm_sc_name((ppm_sc_code)ppm_sc)[0] != '\0')
			{
				// Skip non-existent
				ppm_sc_set.insert((ppm_sc_code)ppm_sc);
			}
		}
	}
	return ppm_sc_set;
}

std::unordered_set<std::string> libsinsp::events::sc_set_to_sc_names(const libsinsp::events::set<ppm_sc_code>& ppm_sc_set)
{
	std::unordered_set<std::string> ppm_sc_names_set;
	for (const auto& val : ppm_sc_set)
	{
		std::string ppm_sc_name = scap_get_ppm_sc_name(val);
		if (ppm_sc_name != "")
		{
			// Skip non-existent
			ppm_sc_names_set.insert(ppm_sc_name);
		}
	}
	return ppm_sc_names_set;
}

std::unordered_set<std::string> libsinsp::events::sc_set_to_event_names(const libsinsp::events::set<ppm_sc_code>& ppm_sc_set)
{
	// convert all sc code to their event codes mappings, generic event excluded
	auto event_set = sc_set_to_event_set(ppm_sc_set);
	event_set.remove(ppm_event_code::PPME_GENERIC_E);
	event_set.remove(ppm_event_code::PPME_GENERIC_X);

	// obtain the names set from the event code set
	auto event_names_set = event_set_to_names(event_set);

	// collect the remaining sc codes in the set that don't have an
	// event code mapping. This is only expected to happen for generic events.
	auto remaining_sc_set = ppm_sc_set.diff(event_set_to_sc_set(event_set));
	auto remaining_sc_names_set = sc_set_to_sc_names(remaining_sc_set);

	return unordered_set_union(event_names_set, remaining_sc_names_set);
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::sinsp_repair_state_sc_set(const libsinsp::events::set<ppm_sc_code>& ppm_sc_set)
{
	uint32_t flags = 0;
	if (!libsinsp::events::net_sc_set().intersect(ppm_sc_set).empty())
	{
		flags |= PPM_REPAIR_STATE_SC_NETWORK_BASE;
		flags |= PPM_REPAIR_STATE_SC_FD_CLOSE;
	}

	static libsinsp::events::set<ppm_sc_code> accept_listen_sc_set = {PPM_SC_ACCEPT, PPM_SC_ACCEPT4, PPM_SC_LISTEN};
	if (!accept_listen_sc_set.intersect(ppm_sc_set).empty())
	{
		flags |= PPM_REPAIR_STATE_SC_NETWORK_BIND;
	}

	if (!libsinsp::events::file_sc_set().intersect(ppm_sc_set).empty() ||
		!libsinsp::events::io_sc_set().intersect(ppm_sc_set).empty() ||
		!libsinsp::events::io_other_sc_set().intersect(ppm_sc_set).empty())
	{
		flags |= PPM_REPAIR_STATE_SC_FD_CLOSE;
	}

	/* These syscalls are used to build up or modify info of the basic process (tinfo) struct.
	 * Consistent enforcement regardless of the input ppm_sc_set.
	 */
	libsinsp::events::set<ppm_sc_code> repaired_sinsp_state_sc_set = {
		PPM_SC_CLONE,
		PPM_SC_CLONE3,
		PPM_SC_FORK,
		PPM_SC_VFORK,
		PPM_SC_EXECVE,
		PPM_SC_EXECVEAT,
		PPM_SC_FCHDIR,
		PPM_SC_CHDIR,
		PPM_SC_CHROOT,
		PPM_SC_CAPSET,
		PPM_SC_SETGID,
		PPM_SC_SETGID32,
		PPM_SC_SETPGID,
		PPM_SC_SETRESGID,
		PPM_SC_SETRESGID32,
		PPM_SC_SETRESUID,
		PPM_SC_SETRESUID32,
		PPM_SC_SETSID,
		PPM_SC_SETUID,
		PPM_SC_SETUID32,
		PPM_SC_PRCTL,
	};

	if ((flags & PPM_REPAIR_STATE_SC_NETWORK_BASE))
	{
		repaired_sinsp_state_sc_set.insert(PPM_SC_SOCKET);
		repaired_sinsp_state_sc_set.insert(PPM_SC_GETSOCKOPT);
	}
	if ((flags & PPM_REPAIR_STATE_SC_NETWORK_BIND))
	{
		repaired_sinsp_state_sc_set.insert(PPM_SC_BIND);
	}
	if ((flags & PPM_REPAIR_STATE_SC_FD_CLOSE))
	{
		repaired_sinsp_state_sc_set.insert(PPM_SC_CLOSE);
	}

	/* Enforce proc exit tp as safety even if enforced elsewhere. */
	repaired_sinsp_state_sc_set.insert(PPM_SC_SCHED_PROCESS_EXIT);

	/* Merge input sc set with sinsp_state_sc_set and return a complete "repaired" set. */
	return repaired_sinsp_state_sc_set.merge(ppm_sc_set);
}
