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

#include <sinsp.h>

void sinsp::fill_ppm_sc_of_interest(scap_open_args *oargs, const std::unordered_set<uint32_t> &ppm_sc_of_interest)
{
	for (int i = 0; i < PPM_SC_MAX; i++)
	{
		/* If the set is empty, fallback to all interesting syscalls */
		if (ppm_sc_of_interest.empty())
		{
			oargs->ppm_sc_of_interest.ppm_sc[i] = true;
		}
		else
		{
			oargs->ppm_sc_of_interest.ppm_sc[i] = ppm_sc_of_interest.find(i) != ppm_sc_of_interest.end();
		}
	}
}

void sinsp::mark_ppm_sc_of_interest(uint32_t ppm_sc, bool enable)
{
	/* This API must be used only after the initialization phase. */
	if (!m_inited)
	{
		throw sinsp_exception("you cannot use this method before opening the inspector!");
	}
	if (ppm_sc >= PPM_SC_MAX)
	{
		throw sinsp_exception("inexistent ppm_sc code: " + std::to_string(ppm_sc));
	}
	int ret = scap_set_ppm_sc(m_h, ppm_sc, enable);
	if (ret != SCAP_SUCCESS)
	{
		throw sinsp_exception(scap_getlasterr(m_h));
	}
}

std::unordered_set<uint32_t> sinsp::enforce_sinsp_state_ppm_sc(std::unordered_set<uint32_t> ppm_sc_of_interest)
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
			ppm_sc_of_interest.insert(ppm_sc);
		}
	}
	return ppm_sc_of_interest;
}

std::unordered_set<uint32_t> sinsp::enforce_simple_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set)
{
	auto simple_set = enforce_sinsp_state_ppm_sc(std::unordered_set<uint32_t>{
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
	});
	ppm_sc_set.insert(simple_set.begin(), simple_set.end());
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::enforce_io_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set)
{
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_IO_READ ||
		   g_infotables.m_syscall_info_table[i].category == EC_IO_WRITE ||
		   g_infotables.m_syscall_info_table[i].category == EC_IO_OTHER ||
		   g_infotables.m_syscall_info_table[i].category == EC_FILE)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::enforce_net_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set)
{
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_NET)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::enforce_proc_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set)
{
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_PROCESS)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::enforce_sys_ppm_sc_set(std::unordered_set<uint32_t> ppm_sc_set)
{
	for(int i = 0; i < PPM_SC_MAX; i++)
	{
		if(g_infotables.m_syscall_info_table[i].category == EC_SYSTEM ||
		   g_infotables.m_syscall_info_table[i].category == EC_MEMORY ||
		   g_infotables.m_syscall_info_table[i].category == EC_SIGNAL)
		{
			ppm_sc_set.insert(i);
		}
	}
	return ppm_sc_set;
}

std::unordered_set<uint32_t> sinsp::get_event_set_from_ppm_sc_set(const std::unordered_set<uint32_t> &ppm_sc_set)
{
	std::vector<uint32_t> events_array(PPM_EVENT_MAX, 0);
	std::vector<uint32_t> ppm_sc_array(PPM_SC_MAX, 0);
	std::unordered_set<uint32_t> events_set;

	/* Fill the `ppm_sc_array` with the syscalls we are interested in. */
	for (auto itr = ppm_sc_set.begin(); itr != ppm_sc_set.end(); itr++)
	{
		ppm_sc_array[*itr] = 1;
	}

	if(scap_get_events_from_ppm_sc(ppm_sc_array.data(), events_array.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("`ppm_sc_array` or `events_array` is an unexpected NULL vector!");
	}

	for(uint32_t event_num = 0; event_num < PPM_EVENT_MAX; event_num++)
	{
		/* True means it is associated with a `ppm_sc` */
		if(events_array[event_num])
		{
			events_set.insert(event_num);
		}
	}

	return events_set;
}

std::unordered_set<uint32_t> sinsp::get_all_ppm_sc()
{
	std::unordered_set<uint32_t> ppm_sc_set;

	for(uint32_t ppm_sc = 0; ppm_sc < PPM_SC_MAX; ppm_sc++)
	{
		ppm_sc_set.insert(ppm_sc);
	}

	return ppm_sc_set;
}

std::unordered_set<std::string> sinsp::get_syscalls_names(const std::unordered_set<uint32_t>& ppm_sc_set)
{
	std::unordered_set<std::string> ppm_sc_names_set;
	for(const auto& it : ppm_sc_set)
	{
		std::string ppm_sc_name = g_infotables.m_syscall_info_table[it].name;
		ppm_sc_names_set.insert(ppm_sc_name);
	}
	return ppm_sc_names_set;
}

std::unordered_set<std::string> sinsp::get_events_names(const std::unordered_set<uint32_t>& events_set)
{
	std::unordered_set<std::string> events_names_set;
	for(const auto& it : events_set)
	{
		if (it > PPME_GENERIC_X)
		{
			events_names_set.insert(g_infotables.m_event_info[it].name);
		}
		else
		{
			for (uint32_t i = 1; i < PPM_SC_MAX; i++)
			{
				const auto evts = get_event_set_from_ppm_sc_set({i});
				if (evts.find(it) != evts.end())
				{
					events_names_set.insert(g_infotables.m_syscall_info_table[i].name);
				}
			}
		}
	}
	return events_names_set;
}
