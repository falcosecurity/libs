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

#include <sinsp_events.h>

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_sinsp_state_ppm_sc(libsinsp::events::set<ppm_sc_code> ppm_sc_of_interest)
{
	std::vector<uint32_t> minimum_syscalls(PPM_SC_MAX, 0);

	/* Should never happen but just to be sure. */
	if(scap_get_modifies_state_ppm_sc(minimum_syscalls.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("'minimum_syscalls' is an unexpected NULL vector!");
	}

	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		if(minimum_syscalls[ppm_sc])
		{
			ppm_sc_of_interest.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_of_interest;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_simple_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	auto simple_set = enforce_sinsp_state_ppm_sc(
		libsinsp::events::set<ppm_sc_code>(std::unordered_set<ppm_sc_code>{
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
		PPM_SC_UMOUNT2,
		PPM_SC_UNLINK,
		PPM_SC_UNLINKAT,
		PPM_SC_UNSHARE,
		PPM_SC_USERFAULTFD,
		PPM_SC_VFORK,
	}));
	ppm_sc_set.merge(simple_set);
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_io_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc].category & bitmask)
		{
		case EC_IO_READ:
		case EC_IO_WRITE:
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_io_other_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc].category & bitmask)
		{
		case EC_IO_OTHER:
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_file_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc].category & bitmask)
		{
		case EC_FILE:
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_net_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc].category & bitmask)
		{
		case EC_NET:
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_proc_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc].category & bitmask)
		{
		case EC_PROCESS:
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::enforce_sys_ppm_sc_set(libsinsp::events::set<ppm_sc_code> ppm_sc_set)
{
	const int bitmask = EC_SYSCALL - 1;
	for(int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		switch(g_infotables.m_syscall_info_table[ppm_sc].category & bitmask)
		{
		case EC_SYSTEM:
		case EC_MEMORY:
		case EC_SIGNAL:
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_event_code> libsinsp::events::enforce_sinsp_state_ppme(libsinsp::events::set<ppm_event_code> ppm_event_info_of_interest)
{
	/* Fill-up the set of event infos of interest. This is needed to ensure critical non syscall PPME events are activated, e.g. container or proc exit events. */
	for (uint32_t ev = 2; ev < PPM_EVENT_MAX; ev++)
	{
		if (!libsinsp::events::is_old_version_event((ppm_event_code)ev)
				&& !libsinsp::events::is_unused_event((ppm_event_code)ev)
				&& !libsinsp::events::is_unknown_event((ppm_event_code)ev))
		{
			/* So far we only covered syscalls, so we add other kinds of
			interesting events. In this case, we are also interested in
			metaevents and in the procexit tracepoint event. */
			if (libsinsp::events::is_metaevent((ppm_event_code)ev) || ev == PPME_PROCEXIT_1_E)
			{
				ppm_event_info_of_interest.insert((ppm_event_code)ev);
			}
		}
	}
	return ppm_event_info_of_interest;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::get_ppm_sc_set_from_syscalls_name(const std::unordered_set<std::string>& syscalls)
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;
	for (int ppm_sc = 0; ppm_sc < PPM_SC_MAX; ++ppm_sc)
	{
		std::string ppm_sc_name = g_infotables.m_syscall_info_table[ppm_sc].name;
		if (syscalls.find(ppm_sc_name) != syscalls.end())
		{
			ppm_sc_set.insert((ppm_sc_code)ppm_sc);
		}
	}
	return ppm_sc_set;
}

libsinsp::events::set<ppm_event_code> libsinsp::events::get_event_set_from_ppm_sc_set(const libsinsp::events::set<ppm_sc_code> &ppm_sc_set)
{
	std::vector<uint32_t> events_array(PPM_EVENT_MAX, 0);
	std::vector<uint32_t> ppm_sc_array(PPM_SC_MAX, 0);
	libsinsp::events::set<ppm_event_code> events_set;

	/* Fill the `ppm_sc_array` with the syscalls we are interested in. */
	ppm_sc_set.for_each([&ppm_sc_array](ppm_sc_code val)
	{
		ppm_sc_array[val] = 1;
		return true;
	});

	if(scap_get_events_from_ppm_sc(ppm_sc_array.data(), events_array.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("`ppm_sc_array` or `events_array` is an unexpected NULL vector!");
	}

	for(uint32_t event_num = 0; event_num < PPM_EVENT_MAX; event_num++)
	{
		/* True means it is associated with a `ppm_sc` */
		if(events_array[event_num])
		{
			events_set.insert((ppm_event_code)event_num);
		}
	}

	return events_set;
}

libsinsp::events::set<ppm_sc_code> libsinsp::events::get_all_ppm_sc()
{
	libsinsp::events::set<ppm_sc_code> ppm_sc_set;

	for(uint32_t ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		ppm_sc_set.insert((ppm_sc_code)ppm_sc);
	}

	return ppm_sc_set;
}

std::unordered_set<std::string> libsinsp::events::get_ppm_sc_names(const libsinsp::events::set<ppm_sc_code>& ppm_sc_set)
{
	std::unordered_set<std::string> ppm_sc_names_set;
	ppm_sc_set.for_each([&ppm_sc_names_set](ppm_sc_code val)
        {
	        std::string ppm_sc_name = g_infotables.m_syscall_info_table[val].name;
	        ppm_sc_names_set.insert(ppm_sc_name);
	        return true;
        });
	return ppm_sc_names_set;
}