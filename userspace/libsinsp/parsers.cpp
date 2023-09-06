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

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif // _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits>

#include "container_engine/mesos.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "tracers.h"
#include "parsers.h"
#include "sinsp_errno.h"
#include "filter.h"
#include "filterchecks.h"
#include "protodecoder.h"
#include "strl.h"
#include "plugin_manager.h"
#include "sinsp_observer.h"

#ifdef SIMULATE_DROP_MODE
bool should_drop(sinsp_evt *evt);
#endif
#include "sinsp_int.h"

#if !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
#include "container_engine/docker/async_source.h"
#endif

extern sinsp_protodecoder_list g_decoderlist;
extern sinsp_evttables g_infotables;

sinsp_parser::sinsp_parser(sinsp *inspector) :
	m_inspector(inspector),
	m_tmp_evt(m_inspector),
	m_syscall_event_source_idx(sinsp_no_event_source_idx)
{
	m_fake_userevt = (scap_evt*)m_fake_userevt_storage;

	//
	// Note: allocated here instead of in the sinsp constructor because sinsp_partial_tracer
	//       is not defined in sinsp.cpp
	//
	m_inspector->m_partial_tracers_pool = new simple_lifo_queue<sinsp_partial_tracer>(128);

	init_metaevt(m_k8s_metaevents_state, PPME_K8S_E, SP_EVT_BUF_SIZE);
	init_metaevt(m_mesos_metaevents_state, PPME_MESOS_E, SP_EVT_BUF_SIZE);
}

sinsp_parser::~sinsp_parser()
{
	for(uint32_t j = 0; j < m_protodecoders.size(); j++)
	{
		delete m_protodecoders[j];
	}

	while(!m_tmp_events_buffer.empty())
	{
		auto ptr = m_tmp_events_buffer.top();
		free(ptr);
		m_tmp_events_buffer.pop();
	}
	m_protodecoders.clear();

	free(m_k8s_metaevents_state.m_piscapevt);
	free(m_mesos_metaevents_state.m_piscapevt);

	if(m_inspector->m_partial_tracers_pool != NULL)
	{
		delete m_inspector->m_partial_tracers_pool;
	}
}

void sinsp_parser::init_scapevt(metaevents_state& evt_state, uint16_t evt_type, uint16_t buf_size)
{
	scap_evt *new_piscapevt = (scap_evt*) realloc(evt_state.m_piscapevt, buf_size);
	if(new_piscapevt == NULL)
	{
		throw sinsp_exception("memory reallocation error in sinsp_parser::init_scapevt.");
	}
	evt_state.m_piscapevt = new_piscapevt;
	evt_state.m_scap_buf_size = buf_size;
	evt_state.m_piscapevt->type = evt_type;
	evt_state.m_metaevt.m_pevt = evt_state.m_piscapevt;
}

void sinsp_parser::init_metaevt(metaevents_state& evt_state, uint16_t evt_type, uint16_t buf_size)
{
	evt_state.m_piscapevt = 0;
	init_scapevt(evt_state, evt_type, buf_size);
	evt_state.m_metaevt.m_inspector = m_inspector;
	evt_state.m_metaevt.m_info = &(g_infotables.m_event_info[PPME_SCAPEVENT_X]);
	evt_state.m_metaevt.m_cpuid = 0;
	evt_state.m_metaevt.m_evtnum = 0;
	evt_state.m_metaevt.m_fdinfo = NULL;
}

void sinsp_parser::set_track_connection_status(bool enabled)
{
	m_track_connection_status = enabled;
}

///////////////////////////////////////////////////////////////////////////////
// PROCESSING ENTRY POINT
///////////////////////////////////////////////////////////////////////////////
void sinsp_parser::process_event(sinsp_evt *evt)
{
	uint16_t etype = evt->m_pevt->type;
	bool is_live = m_inspector->is_live() || m_inspector->is_syscall_plugin();

	//
	// Cleanup the event-related state
	//
	reset(evt);

	//
	// When debug mode is not enabled, filter out events about itself
	//
#if defined(HAS_CAPTURE)
	if(is_live && !m_inspector->is_debug_enabled())
	{
		if(evt->get_tid() == m_inspector->m_self_pid &&
		   etype != PPME_SCHEDSWITCH_1_E &&
		   etype != PPME_SCHEDSWITCH_6_E &&
		   etype != PPME_DROP_E &&
		   etype != PPME_DROP_X &&
		   etype != PPME_SCAPEVENT_E &&
		   etype != PPME_PROCINFO_E &&
		   etype != PPME_CPU_HOTPLUG_E &&
		   m_inspector->m_self_pid)
		{
			evt->m_filtered_out = true;
			return;
		}
	}
#endif

	//
	// Filtering
	//
	bool do_filter_later = false;

	if(m_inspector->m_filter)
	{
		ppm_event_flags eflags = evt->get_info_flags();

		if(etype == PPME_SYSCALL_WRITE_X)
		{
			//
			// Check if this is a tracer
			//
			sinsp_fdinfo_t* fdinfo = evt->m_fdinfo;

			if(fdinfo == NULL && evt->m_tinfo != nullptr)
			{
				fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
				evt->m_fdinfo = fdinfo;
			}

			if(fdinfo && (fdinfo->m_flags & (sinsp_fdinfo_t::FLAGS_IS_TRACER_FD | sinsp_fdinfo_t::FLAGS_IS_TRACER_FILE)))
			{
				eflags = (ppm_event_flags)(((uint64_t)eflags) | EF_MODIFIES_STATE);
			}
			else
			{
				if(m_inspector->is_capture())
				{
					if((evt->get_dump_flags() & SCAP_DF_TRACER) != 0)
					{
						evt->m_fdinfo = NULL;
						eflags = (ppm_event_flags)(((uint64_t)eflags) | EF_MODIFIES_STATE);
					}
				}
			}
		}

		if(eflags & EF_MODIFIES_STATE)
		{
			do_filter_later = true;
		}
		else
		{
			if(m_inspector->run_filters_on_evt(evt) == false)
			{
				if(evt->m_tinfo != NULL)
				{
					if(!(eflags & EF_SKIPPARSERESET || etype == PPME_SCHEDSWITCH_6_E))
					{
						evt->m_tinfo->m_lastevent_type = PPM_EVENT_MAX;
					}
				}

				evt->m_filtered_out = true;
				return;
			}
		}
	}

	evt->m_filtered_out = false;

	//
	// Route the event to the proper function
	//
	switch(etype)
	{
	case PPME_SOCKET_SENDTO_E:
		if((evt->m_fdinfo == nullptr) && (evt->m_tinfo != nullptr))
		{
			infer_sendto_fdinfo(evt);
		}

		// FALLTHRU
	case PPME_SYSCALL_OPEN_E:
	case PPME_SYSCALL_CREAT_E:
	case PPME_SYSCALL_OPENAT_E:
	case PPME_SYSCALL_OPENAT_2_E:
	case PPME_SYSCALL_OPENAT2_E:
	case PPME_SOCKET_SOCKET_E:
	case PPME_SYSCALL_EVENTFD_E:
	case PPME_SYSCALL_EVENTFD2_E:
	case PPME_SYSCALL_CHDIR_E:
	case PPME_SYSCALL_FCHDIR_E:
	case PPME_SYSCALL_LINK_E:
	case PPME_SYSCALL_LINKAT_E:
	case PPME_SYSCALL_MKDIR_E:
	case PPME_SYSCALL_RMDIR_E:
	case PPME_SOCKET_SHUTDOWN_E:
	case PPME_SYSCALL_GETRLIMIT_E:
	case PPME_SYSCALL_SETRLIMIT_E:
	case PPME_SYSCALL_PRLIMIT_E:
	case PPME_SOCKET_SENDMSG_E:
	case PPME_SYSCALL_SENDFILE_E:
	case PPME_SYSCALL_SETRESUID_E:
	case PPME_SYSCALL_SETRESGID_E:
	case PPME_SYSCALL_SETUID_E:
	case PPME_SYSCALL_SETGID_E:
	case PPME_SYSCALL_SETPGID_E:
	case PPME_SYSCALL_UNLINK_E:
	case PPME_SYSCALL_UNLINKAT_E:
	case PPME_SYSCALL_EXECVE_18_E:
	case PPME_SYSCALL_EXECVE_19_E:
	case PPME_SYSCALL_EXECVEAT_E:
		store_event(evt);
		break;
	case PPME_SYSCALL_WRITE_E:
		if(!m_inspector->m_is_dumping && evt->m_tinfo != nullptr)
		{
			evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
			if(evt->m_fdinfo)
			{
				if(evt->m_fdinfo->m_flags & sinsp_fdinfo_t::FLAGS_IS_TRACER_FD)
				{
					evt->m_filtered_out = true;
					return;
				}
			}
		}
		break;
	case PPME_SYSCALL_MKDIR_X:
	case PPME_SYSCALL_RMDIR_X:
	case PPME_SYSCALL_LINK_X:
	case PPME_SYSCALL_LINKAT_X:
	case PPME_SYSCALL_UNLINK_X:
	case PPME_SYSCALL_UNLINKAT_X:
		parse_fspath_related_exit(evt);
		break;
	case PPME_SYSCALL_READ_X:
	case PPME_SYSCALL_WRITE_X:
	case PPME_SOCKET_RECV_X:
	case PPME_SOCKET_SEND_X:
	case PPME_SOCKET_RECVFROM_X:
	case PPME_SOCKET_RECVMSG_X:
	case PPME_SOCKET_SENDTO_X:
	case PPME_SOCKET_SENDMSG_X:
	case PPME_SYSCALL_READV_X:
	case PPME_SYSCALL_WRITEV_X:
	case PPME_SYSCALL_PREAD_X:
	case PPME_SYSCALL_PWRITE_X:
	case PPME_SYSCALL_PREADV_X:
	case PPME_SYSCALL_PWRITEV_X:
		parse_rw_exit(evt);
		break;
	case PPME_SYSCALL_SENDFILE_X:
		parse_sendfile_exit(evt);
		break;
	case PPME_SYSCALL_OPEN_X:
	case PPME_SYSCALL_CREAT_X:
	case PPME_SYSCALL_OPENAT_2_X:
	case PPME_SYSCALL_OPENAT2_X:
	case PPME_SYSCALL_OPEN_BY_HANDLE_AT_X:
		parse_open_openat_creat_exit(evt);
		break;
	case PPME_SYSCALL_FCHMOD_X:
	case PPME_SYSCALL_FCHOWN_X:
		parse_fchmod_fchown_exit(evt);
		break;
	case PPME_SYSCALL_OPENAT_X:
		parse_fspath_related_exit(evt);
		parse_open_openat_creat_exit(evt);
		break;
	case PPME_SYSCALL_SELECT_E:
	case PPME_SYSCALL_POLL_E:
	case PPME_SYSCALL_PPOLL_E:
	case PPME_SYSCALL_EPOLLWAIT_E:
		parse_select_poll_epollwait_enter(evt);
		break;
	case PPME_SYSCALL_UNSHARE_E:
	case PPME_SYSCALL_SETNS_E:
		store_event(evt);
		break;
	case PPME_SYSCALL_UNSHARE_X:
	case PPME_SYSCALL_SETNS_X:
		parse_unshare_setns_exit(evt);
		break;
	case PPME_SYSCALL_MEMFD_CREATE_X:
		parse_memfd_create_exit(evt, SCAP_FD_MEMFD);
		break;
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parse_clone_exit(evt);
		break;
	case PPME_SYSCALL_PIDFD_OPEN_X:
		parse_pidfd_open_exit(evt);
		break;
	case PPME_SYSCALL_PIDFD_GETFD_X:
		parse_pidfd_getfd_exit(evt);
		break;
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
    case PPME_SYSCALL_EXECVEAT_X:
		parse_execve_exit(evt);
		break;
	case PPME_PROCEXIT_E:
	case PPME_PROCEXIT_1_E:
		parse_thread_exit(evt);
		break;
	case PPME_SYSCALL_PIPE_X:
	case PPME_SYSCALL_PIPE2_X:
		parse_pipe_exit(evt);
		break;

	case PPME_SOCKET_SOCKET_X:
		parse_socket_exit(evt);
		break;
	case PPME_SOCKET_BIND_X:
		parse_bind_exit(evt);
		break;
	case PPME_SOCKET_CONNECT_E:
		parse_connect_enter(evt);
		break;
	case PPME_SOCKET_CONNECT_X:
		parse_connect_exit(evt);
		break;
	case PPME_SOCKET_ACCEPT_X:
	case PPME_SOCKET_ACCEPT_5_X:
	case PPME_SOCKET_ACCEPT4_X:
	case PPME_SOCKET_ACCEPT4_5_X:
	case PPME_SOCKET_ACCEPT4_6_X:
		parse_accept_exit(evt);
		break;
	case PPME_SYSCALL_CLOSE_E:
		parse_close_enter(evt);
		break;
	case PPME_SYSCALL_CLOSE_X:
		parse_close_exit(evt);
		break;
	case PPME_SYSCALL_FCNTL_E:
		parse_fcntl_enter(evt);
		break;
	case PPME_SYSCALL_FCNTL_X:
		parse_fcntl_exit(evt);
		break;
	case PPME_SYSCALL_EVENTFD_X:
	case PPME_SYSCALL_EVENTFD2_X:
		parse_eventfd_exit(evt);
		break;
	case PPME_SYSCALL_CHDIR_X:
		parse_chdir_exit(evt);
		break;
	case PPME_SYSCALL_FCHDIR_X:
		parse_fchdir_exit(evt);
		break;
	case PPME_SYSCALL_GETCWD_X:
		parse_getcwd_exit(evt);
		break;
	case PPME_SOCKET_SHUTDOWN_X:
		parse_shutdown_exit(evt);
		break;
	case PPME_SYSCALL_DUP_X:
	case PPME_SYSCALL_DUP_1_X:
	case PPME_SYSCALL_DUP2_X:
	case PPME_SYSCALL_DUP3_X:
		parse_dup_exit(evt);
		break;
	case PPME_SYSCALL_SIGNALFD_X:
	case PPME_SYSCALL_SIGNALFD4_X:
		parse_single_param_fd_exit(evt, SCAP_FD_SIGNALFD);
		break;
	case PPME_SYSCALL_TIMERFD_CREATE_X:
		parse_single_param_fd_exit(evt, SCAP_FD_TIMERFD);
		break;
	case PPME_SYSCALL_INOTIFY_INIT_X:
	case PPME_SYSCALL_INOTIFY_INIT1_X:
		parse_single_param_fd_exit(evt, SCAP_FD_INOTIFY);
		break;
	case PPME_SYSCALL_BPF_2_X:
		parse_single_param_fd_exit(evt, SCAP_FD_BPF);
		break;
	case PPME_SYSCALL_USERFAULTFD_X:
		parse_single_param_fd_exit(evt, SCAP_FD_USERFAULTFD);
		break;
	case PPME_SYSCALL_IO_URING_SETUP_X:
		parse_single_param_fd_exit(evt, SCAP_FD_IOURING);
		break;
	case PPME_SYSCALL_EPOLL_CREATE_X:
	case PPME_SYSCALL_EPOLL_CREATE1_X:
		parse_single_param_fd_exit(evt, SCAP_FD_EVENTPOLL);
		break;
	case PPME_SYSCALL_GETRLIMIT_X:
	case PPME_SYSCALL_SETRLIMIT_X:
		parse_getrlimit_setrlimit_exit(evt);
		break;
	case PPME_SYSCALL_PRLIMIT_X:
		parse_prlimit_exit(evt);
		break;
	case PPME_SOCKET_SOCKETPAIR_X:
		parse_socketpair_exit(evt);
		break;
	case PPME_SCHEDSWITCH_1_E:
	case PPME_SCHEDSWITCH_6_E:
		parse_context_switch(evt);
		break;
	case PPME_SYSCALL_BRK_4_X:
	case PPME_SYSCALL_MMAP_X:
	case PPME_SYSCALL_MMAP2_X:
	case PPME_SYSCALL_MUNMAP_X:
		parse_brk_munmap_mmap_exit(evt);
		break;
	case PPME_SYSCALL_SETRESUID_X:
		parse_setresuid_exit(evt);
		break;
	case PPME_SYSCALL_SETRESGID_X:
		parse_setresgid_exit(evt);
		break;
	case PPME_SYSCALL_SETUID_X:
		parse_setuid_exit(evt);
		break;
	case PPME_SYSCALL_SETGID_X:
		parse_setgid_exit(evt);
		break;
	case PPME_CONTAINER_E:
		parse_container_evt(evt); // deprecated, only here for backwards compatibility
		break;
	case PPME_CONTAINER_JSON_E:
	case PPME_CONTAINER_JSON_2_E:
		parse_container_json_evt(evt);
		break;
	case PPME_CPU_HOTPLUG_E:
		parse_cpu_hotplug_enter(evt);
		break;
#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
	case PPME_K8S_E:
		if(m_inspector->is_capture())
		{
			parse_k8s_evt(evt);
		}
		break;
	case PPME_MESOS_E:
		if(m_inspector->is_capture())
		{
			parse_mesos_evt(evt);
		}
		break;
#endif // #if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
	case PPME_SYSCALL_CHROOT_X:
		parse_chroot_exit(evt);
		break;
	case PPME_SYSCALL_SETSID_X:
		parse_setsid_exit(evt);
		break;
	case PPME_SOCKET_GETSOCKOPT_X:
		if(evt->get_num_params() > 0)
		{
			parse_getsockopt_exit(evt);
		}
		break;
	case PPME_SYSCALL_CAPSET_X:
		parse_capset_exit(evt);
		break;
	case PPME_USER_ADDED_E:
	case PPME_USER_DELETED_E:
		parse_user_evt(evt);
		break;
	case PPME_GROUP_ADDED_E:
	case PPME_GROUP_DELETED_E:
		parse_group_evt(evt);
		break;
	case PPME_SYSCALL_PRCTL_X:
		parse_prctl_exit_event(evt);
		break;		
	default:
		break;
	}

	//
	// With some state-changing events like clone, execve and open, we do the
	// filtering after having updated the state
	//
	if(do_filter_later)
	{
		if(m_inspector->run_filters_on_evt(evt) == false)
		{
			evt->m_filtered_out = true;
			return;
		}
		evt->m_filtered_out = false;
	}
	//
	// Offline captures can produce events with the SCAP_DF_STATE_ONLY. They are
	// supposed to go through the engine, but they must be filtered out before
	// reaching the user.
	//
	if(m_inspector->is_capture())
	{
		if(evt->get_dump_flags() & SCAP_DF_STATE_ONLY)
		{
			evt->m_filtered_out = true;
		}
	}

	// Check to see if the name changed as a side-effect of
	// parsing this event. Try to avoid the overhead of a string
	// compare for every event.
	if(evt->m_fdinfo)
	{
		evt->set_fdinfo_name_changed(evt->m_fdinfo->m_name != evt->m_fdinfo->m_oldname);
	}
}

void sinsp_parser::event_cleanup(sinsp_evt *evt)
{
	if(evt->get_direction() == SCAP_ED_OUT &&
	   evt->m_tinfo && evt->m_tinfo->m_lastevent_data)
	{
		free_event_buffer(evt->m_tinfo->m_lastevent_data);
		evt->m_tinfo->m_lastevent_data = NULL;
		evt->m_tinfo->set_lastevent_data_validity(false);
	}
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS
///////////////////////////////////////////////////////////////////////////////

//
// Called before starting the parsing.
// Returns false in case of issues resetting the state.
//
bool sinsp_parser::reset(sinsp_evt *evt)
{
	uint16_t etype = evt->get_type();
	//
	// Before anything can happen, the event needs to be
	// initialized.
	//
	// For events created by the container resolvers and pushed
	// onto the inspector's pending_container_events queue, the
	// event has a threadinfo pointer that points to the process
	// that created the container.
	//
	// However, for container events that are at the beginning of
	// trace files and only describe the set of current
	// containers, the threadinfo pointer is junk and must be
	// cleared in init(). So only keep the threadinfo for "live"
	// containers.
	//
	bool keep_threadinfo = false;
	if (!m_inspector->is_capture() && (etype == PPME_CONTAINER_JSON_E || etype == PPME_CONTAINER_JSON_2_E) && evt->m_tinfo_ref != nullptr)
	{
		// this is a synthetic event generated by the container manager
		// the threadinfo should already be set properly
		evt->init_keep_threadinfo();
		keep_threadinfo = true;
	}
	else
	{
		evt->init();
	}

	uint32_t plugin_id = 0;
	if (evt->get_type() == PPME_PLUGINEVENT_E || evt->get_type() == PPME_ASYNCEVENT_E)
	{
		// note: async events can potentially encode a non-zero plugin ID
		// to indicate that they've been produced by a plugin with
		// a specific event source. If an async event has a zero plugin ID, then
		// we can assume it being of the "syscall" source. On the other hand,
		// plugin events are not allowed to have a zero plugin ID, so we should
		// be ok on that front.
		auto parinfo = evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		plugin_id = *(uint32_t *) parinfo->m_val;
	}

	if (plugin_id != 0)
	{
		bool pfound = false;
		auto srcidx = m_inspector->get_plugin_manager()->source_idx_by_plugin_id(plugin_id, pfound);
		if (!pfound)
		{
			evt->m_source_idx = sinsp_no_event_source_idx;
			evt->m_source_name = sinsp_no_event_source_name;
		}
		else
		{
			evt->m_source_idx = srcidx;
			evt->m_source_name = m_inspector->event_sources()[srcidx].c_str();
		}
	}
	else
	{
		// every other event falls under the "syscall" event source umbrella
		// cache index of "syscall" event source in case we haven't already
		if (m_syscall_event_source_idx == sinsp_no_event_source_idx)
		{
			// note: the current inspector's implementation guarantees
			// that the "syscall" event source is always at index 0, being
			// the first one in the list. However we don't want to leak
			// that knowledge down to this level, so we search for it
			// in order to be resilient to future changes.
			// The search happens only once.
			for (size_t i = 0; i < m_inspector->event_sources().size(); i++)
			{
				if (m_inspector->event_sources()[i] == sinsp_syscall_event_source_name)
				{
					m_syscall_event_source_idx = i;
					break;
				}
			}
		}
		evt->m_source_idx = m_syscall_event_source_idx;
		evt->m_source_name = (m_syscall_event_source_idx != sinsp_no_event_source_idx)
			? sinsp_syscall_event_source_name : sinsp_no_event_source_name;
	}

	if (keep_threadinfo)
	{
		return true;
	}

	ppm_event_flags eflags = evt->get_info_flags();

	evt->m_fdinfo = NULL;
	evt->m_errorcode = 0;

	//
	// Ignore scheduler events
	//
	if(eflags & EF_SKIPPARSERESET)
	{
		if(etype == PPME_PROCINFO_E)
		{
			evt->m_tinfo = m_inspector->get_thread_ref(evt->m_pevt->tid, false, false).get();
		}
		else
		{
			evt->m_tinfo = NULL;
		}

		return false;
	}

	//
	// Find the thread info
	//

	//
	// If we're exiting a clone or if we have a scheduler event
	// (many kernel thread), we don't look for /proc
	//
	bool query_os;
	if(etype == PPME_SYSCALL_CLONE_11_X ||
		etype == PPME_SYSCALL_CLONE_16_X ||
		etype == PPME_SYSCALL_CLONE_17_X ||
		etype == PPME_SYSCALL_CLONE_20_X ||
		etype == PPME_SYSCALL_FORK_X ||
		etype == PPME_SYSCALL_FORK_17_X ||
		etype == PPME_SYSCALL_FORK_20_X ||
		etype == PPME_SYSCALL_VFORK_X ||
		etype == PPME_SYSCALL_VFORK_17_X ||
		etype == PPME_SYSCALL_VFORK_20_X ||
		etype == PPME_SYSCALL_CLONE3_X ||
		etype == PPME_SCHEDSWITCH_6_E ||
		/* If we received a `procexit` event it means that the process
		 * is dead in the kernel, `query_os==true` would just generate fake entries.
		 */
		etype == PPME_PROCEXIT_E ||
		etype == PPME_PROCEXIT_1_E)
	{
		query_os = false;
	}
	else
	{
		query_os = true;
	}

	// todo(jasondellaluce): should we do this for all meta-events in general? (mesos and k8s too?)
	if(etype == PPME_CONTAINER_JSON_E ||
	   etype == PPME_CONTAINER_JSON_2_E ||
	   etype == PPME_USER_ADDED_E ||
	   etype == PPME_USER_DELETED_E ||
	   etype == PPME_GROUP_ADDED_E ||
	   etype == PPME_GROUP_DELETED_E ||
	   etype == PPME_PLUGINEVENT_E ||
	   etype == PPME_ASYNCEVENT_E)
	{
		evt->m_tinfo = nullptr;
		return true;
	}
	else
	{
		evt->m_tinfo = m_inspector->get_thread_ref(evt->m_pevt->tid, query_os, false).get();
	}

	if(etype == PPME_SCHEDSWITCH_6_E)
	{
		return false;
	}

	if(!evt->m_tinfo)
	{
		if(etype == PPME_SYSCALL_CLONE_11_X ||
			etype == PPME_SYSCALL_CLONE_16_X ||
			etype == PPME_SYSCALL_CLONE_17_X ||
			etype == PPME_SYSCALL_CLONE_20_X ||
			etype == PPME_SYSCALL_FORK_X ||
			etype == PPME_SYSCALL_FORK_17_X ||
			etype == PPME_SYSCALL_FORK_20_X ||
			etype == PPME_SYSCALL_VFORK_X ||
			etype == PPME_SYSCALL_VFORK_17_X ||
			etype == PPME_SYSCALL_VFORK_20_X ||
			etype == PPME_SYSCALL_CLONE3_X)
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_thread_manager->m_failed_lookups->decrement();
#endif
		}
		return false;
	}

	if(query_os)
	{
		evt->m_tinfo->m_flags |= PPM_CL_ACTIVE;
	}

	if(PPME_IS_ENTER(etype))
	{
		evt->m_tinfo->m_lastevent_fd = -1;
		evt->m_tinfo->m_lastevent_type = etype;

		if(eflags & EF_USES_FD)
		{
			sinsp_evt_param *parinfo;

			//
			// Get the fd.
			// The fd is always the first parameter of the enter event.
			//
			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			ASSERT(evt->get_param_info(0)->type == PT_FD);

			evt->m_tinfo->m_lastevent_fd = *(int64_t *)parinfo->m_val;
			evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
		}

		evt->m_tinfo->m_latency = 0;
		evt->m_tinfo->m_last_latency_entertime = evt->get_ts();
	}
	else
	{
		sinsp_threadinfo* tinfo = evt->m_tinfo;

		//
		// event latency
		//
		if(tinfo->m_last_latency_entertime != 0)
		{
			tinfo->m_latency = evt->get_ts() - tinfo->m_last_latency_entertime;
			ASSERT((int64_t)tinfo->m_latency >= 0);
		}

		if((etype==PPME_SYSCALL_EXECVE_18_X ||
		   etype==PPME_SYSCALL_EXECVE_19_X)
		   &&
		   tinfo->m_lastevent_type == PPME_SYSCALL_EXECVEAT_E)
		{
			tinfo->set_lastevent_data_validity(true);
		}
		else if(etype == tinfo->m_lastevent_type + 1)
		{
			tinfo->set_lastevent_data_validity(true);
		}
		else
		{
			tinfo->set_lastevent_data_validity(false);

			if(tinfo->m_lastevent_type != PPME_TRACER_E)
			{
				return false;
			}
		}

		//
		// Error detection logic
		//
		if(evt->get_num_params() != 0 &&
			((evt->m_info->params[0].name[0] == 'r' &&
			  evt->m_info->params[0].name[1] == 'e' &&
			  evt->m_info->params[0].name[2] == 's' &&
			  evt->m_info->params[0].name[3] == '\0') ||
			 (evt->m_info->params[0].name[0] == 'f' &&
			  evt->m_info->params[0].name[1] == 'd' &&
			  evt->m_info->params[0].name[2] == '\0')))
		{
			sinsp_evt_param *parinfo;

			parinfo = evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			int64_t res = *(int64_t *)parinfo->m_val;

			if(res < 0)
			{
				evt->m_errorcode = -(int32_t)res;
			}
		}

		//
		// Retrieve the fd
		//
		if(eflags & EF_USES_FD)
		{
			//
			// The copy_file_range syscall has the peculiarity of using two fds
			// Set as m_lastevent_fd the output fd
			//
			if(etype == PPME_SYSCALL_COPY_FILE_RANGE_X)
			{
				sinsp_evt_param *parinfo;

				parinfo = evt->get_param(1);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				tinfo->m_lastevent_fd = *(int64_t *)parinfo->m_val;
			}

			evt->m_fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);

			if(evt->m_fdinfo == NULL)
			{
				return false;
			}

			if(evt->m_errorcode != 0 && m_inspector->get_observer())
			{
				m_inspector->get_observer()->on_error(evt);
			}

			if(evt->m_fdinfo->m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED)
			{
				//
				// A close gets canceled when the same fd is created successfully between
				// close enter and close exit.
				// If that happens
				//
				erase_fd_params eparams;

				evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;
				eparams.m_fd = CANCELED_FD_NUMBER;
				eparams.m_fdinfo = tinfo->get_fd(CANCELED_FD_NUMBER);

				//
				// Remove the fd from the different tables
				//
				eparams.m_remove_from_table = true;
				eparams.m_tinfo = tinfo;
				eparams.m_ts = evt->get_ts();

				erase_fd(&eparams);
			}
		}
	}

	return true;
}

void sinsp_parser::store_event(sinsp_evt *evt)
{
	if(evt->m_tinfo == nullptr)
	{
		//
		// No thread in the table. We won't store this event, which mean that
		// we won't be able to parse the corresponding exit event and we'll have
		// to drop the information it carries.
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats->m_n_store_drops++;
#endif
		return;
	}

	uint32_t elen;

	//
	// Make sure the event data is going to fit
	//
	elen = scap_event_getlen(evt->m_pevt);

	if(elen > SP_EVT_BUF_SIZE)
	{
		ASSERT(false);
		return;
	}

	//
	// Copy the data
	//
	auto tinfo = evt->m_tinfo;
	if(tinfo->m_lastevent_data == NULL)
	{
		tinfo->m_lastevent_data = reserve_event_buffer();
		if(tinfo->m_lastevent_data == NULL)
		{
			throw sinsp_exception("cannot reserve event buffer in sinsp_parser::store_event.");
			return;
		}
	}
	memcpy(tinfo->m_lastevent_data, evt->m_pevt, elen);
	tinfo->m_lastevent_cpuid = evt->get_cpuid();

#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats->m_n_stored_evts++;
#endif
}

bool sinsp_parser::retrieve_enter_event(sinsp_evt *enter_evt, sinsp_evt *exit_evt)
{
	//
	// Make sure there's a valid thread info
	//
	if(!exit_evt->m_tinfo)
	{
		return false;
	}

	//
	// Retrieve the copy of the enter event and initialize it
	//
	if(!(exit_evt->m_tinfo->is_lastevent_data_valid() && exit_evt->m_tinfo->m_lastevent_data))
	{
		//
		// This happen especially at the beginning of trace files, where events
		// can be truncated
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats->m_n_retrieve_drops++;
#endif
		return false;
	}

	enter_evt->init(exit_evt->m_tinfo->m_lastevent_data, exit_evt->m_tinfo->m_lastevent_cpuid);

	/* The `execveat` syscall is a wrapper of `execve`, when the call
	 * succeeds the event returned is simply an `execve` exit event.
	 * So if an `execveat` is correctly executed we will have, a
	 * `PPME_SYSCALL_EXECVEAT_E` as enter event and a
	 * `PPME_SYSCALL_EXECVE_..._X` as exit one. So when we retrieve
	 * the enter event in the `parse_execve_exit` method  we cannot
	 * only check for the same syscall event, so `PPME_SYSCALL_EXECVE_..._E`,
	 * we have also to check for the `PPME_SYSCALL_EXECVEAT_E`.
	 */
	if((exit_evt->get_type() == PPME_SYSCALL_EXECVE_18_X ||
		exit_evt->get_type() == PPME_SYSCALL_EXECVE_19_X)
		&&
		enter_evt->get_type() == PPME_SYSCALL_EXECVEAT_E)
	{
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats->m_n_retrieved_evts++;
#endif
		return true;
	}

	//
	// Make sure that we're using the right enter event, to prevent inconsistencies when events
	// are dropped
	//
	if(enter_evt->get_type() != (exit_evt->get_type() - 1))
	{
		//ASSERT(false);
		exit_evt->m_tinfo->set_lastevent_data_validity(false);
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats->m_n_retrieve_drops++;
#endif
		return false;
	}

#ifdef GATHER_INTERNAL_STATS
	m_inspector->m_stats->m_n_retrieved_evts++;
#endif
	return true;
}

sinsp_protodecoder* sinsp_parser::add_protodecoder(std::string decoder_name)
{
	//
	// Make sure this decoder is not present yet
	//
	std::vector<sinsp_protodecoder*>::iterator it;
	for(it = m_protodecoders.begin(); it != m_protodecoders.end(); ++it)
	{
		if((*it)->get_name() == decoder_name)
		{
			return (*it);
		}
	}

	sinsp_protodecoder* nd = g_decoderlist.new_protodecoder_from_name(decoder_name,
		m_inspector);

	nd->init();

	m_protodecoders.push_back(nd);

	return nd;
}

void sinsp_parser::register_event_callback(sinsp_pd_callback_type etype, sinsp_protodecoder* dec)
{
	switch(etype)
	{
	case CT_OPEN:
		m_open_callbacks.push_back(dec);
		break;
	case CT_CONNECT:
		m_connect_callbacks.push_back(dec);
		break;
	default:
		ASSERT(false);
		break;
	}

	return;
}

///////////////////////////////////////////////////////////////////////////////
// PARSERS
///////////////////////////////////////////////////////////////////////////////

void sinsp_parser::parse_clone_exit_caller(sinsp_evt *evt, int64_t child_tid)
{
	sinsp_evt_param* parinfo = nullptr;
	uint16_t etype = evt->get_type();
	int64_t caller_tid = evt->get_tid();

	/* We have a collision when we force a removal in the thread table because
	 * we have 2 entries with the same tid.
	 */
	int64_t tid_collision = -1;

	/* By default we have a valid caller. `valid_caller==true` means that we can
	 * use the caller info to fill some fields of the child, `valid_caller==false`
	 * means that we will use some info about the child to fill the caller thread info.
	 * We need the caller because it is the most reliable source of info for the child.
	 */
	bool valid_caller = true;

	/* The clone caller exit event has 2 main purposes:
	 * 1. enrich the caller thread info with fresh info or create a new one if it was not there.
	 * 2. create a new thread info for the child if necessary. (resilience to event drops)
	 */

	/*=============================== ENRICH/CREATE ESSENTIAL CALLER STATE ===========================*/
	
	/* Let's see if we have some info regarding the caller */
	auto caller_tinfo = m_inspector->get_thread_ref(caller_tid, true);
	
	/* This happens only if we reach the max entries in our table otherwise we should obtain a new fresh empty
	 * thread info to populate even if we are not able to recover any information!
	 * If `caller_tinfo == nullptr` we return, we won't have enough space for the child in the table!
	 */
	if(caller_tinfo == nullptr)
	{
		/* Invalidate the thread info associated with this event */
		ASSERT(false);
		evt->m_tinfo = nullptr;
		return;
	}

	/* We have an invalid thread:
	 * 1. The process is dead and we are not able to find it in /proc.
	 * 2. We have done too much /proc scan and we cannot recover it.
	 */	
	if(caller_tinfo->is_invalid())
	{
		/* In case of invalid thread we enrich it with fresh info and we obtain a sort of valid thread info */
		valid_caller = false;

		/* pid. */
		parinfo = evt->get_param(4);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		caller_tinfo->m_pid = *(int64_t *)parinfo->m_val;

		/* ptid */
		parinfo = evt->get_param(5);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		caller_tinfo->m_ptid = *(int64_t *)parinfo->m_val;

		/* vtid & vpid */
		/* We preset them for old scap-files compatibility. */
		caller_tinfo->m_vtid = caller_tid;
		caller_tinfo->m_vpid = -1;
		switch(etype)
		{
		case PPME_SYSCALL_CLONE_11_X:
		case PPME_SYSCALL_CLONE_16_X:
		case PPME_SYSCALL_CLONE_17_X:
		case PPME_SYSCALL_FORK_X:
		case PPME_SYSCALL_FORK_17_X:
		case PPME_SYSCALL_VFORK_X:
		case PPME_SYSCALL_VFORK_17_X:
			break;
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE3_X:
			parinfo = evt->get_param(18);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			caller_tinfo->m_vtid = *(int64_t *)parinfo->m_val;

			parinfo = evt->get_param(19);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			caller_tinfo->m_vpid = *(int64_t *)parinfo->m_val;		
			break;
		default:
			ASSERT(false);
		}

		/* Create thread groups and parenting relationships */
		m_inspector->m_thread_manager->create_thread_dependencies(caller_tinfo);
	}

	/* Update the evt->m_tinfo of the caller. */
	evt->m_tinfo = caller_tinfo.get();

	/// todo(@Andreagit97): here we could update `comm` `exe` and `args` with fresh info from the event

	/*=============================== ENRICH/CREATE ESSENTIAL CALLER STATE ===========================*/

	/*=============================== CHILD IN CONTAINER CASE ===========================*/

	/* Get `flags` to check if we are in a container.
	 * We should never assign these flags to the caller otherwise if the child is a thread
	 * also the caller will be marked as a thread with the `PPM_CL_CLONE_THREAD` flag.
	 */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(8);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(13);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(15);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	uint32_t flags = *(uint32_t *)parinfo->m_val;

	/* PPM_CL_CHILD_IN_PIDNS is true when:
	 * - the caller is running into a container and so the child
	 * Please note: if only the child is running into a container
	 * (so when the child is the init process of the new namespace)
	 * this flag is not set
	 * 
	 * PPM_CL_CLONE_NEWPID is true when:
	 * - the child is the init process of a new namespace
	 * 
	 * PPM_CL_CLONE_PARENT is set by `runc:[0:PARENT]` when it creates
	 * the first process in the new pid namespace. In new sinsp versions
	 * `PPM_CL_CHILD_IN_PIDNS` is enough but in old scap-files where we don't have
	 * this custom flag, we leave the event to the child parser when `PPM_CL_CLONE_PARENT`
	 * is set since we don't know if the new child is in a pid namespace or not.
	 * Moreover when `PPM_CL_CLONE_PARENT` is set `PPM_CL_CLONE_NEWPID` cannot
	 * be set according to the clone manual.
	 * 
	 * When `caller_tid != caller_tinfo->m_vtid` is true we are for
	 * sure in a container, and so is the child.
	 * This is not a strict requirement (leave it here for compatibility with old
	 * scap-files)
	 */
	if(flags & PPM_CL_CHILD_IN_PIDNS || 
		flags & PPM_CL_CLONE_NEWPID ||
		flags & PPM_CL_CLONE_PARENT ||
		caller_tid != caller_tinfo->m_vtid)
	{
		return;
	}

	/*=============================== CHILD IN CONTAINER CASE ===========================*/

	/*=============================== CHILD ALREADY THERE ===========================*/

	/* See if the child is already there, if yes and it is valid we return immediately */
	sinsp_threadinfo* child_tinfo = m_inspector->get_thread_ref(child_tid, false, true).get();
	if(child_tinfo != nullptr)
	{
		/* If this was an inverted clone, all is fine, we've already taken care
		 * of adding the thread table entry in the child.
		 * Otherwise, we assume that the entry is there because we missed the proc exit event
		 * for a previous thread and we replace the tinfo.
		 */
		if(child_tinfo->m_flags & PPM_CL_CLONE_INVERTED)
		{
			return;
		}
		else
		{
			m_inspector->remove_thread(child_tid);
			tid_collision = child_tid;
		}
	}

	/*=============================== CHILD ALREADY THERE ===========================*/

	/* If we come here it means that we need to create the child thread info */

	/*=============================== CREATE CHILD ===========================*/

	/* Allocate the new thread info and initialize it.
	 * We avoid `malloc` here and get the item from a preallocated list.
	 */
	child_tinfo = m_inspector->build_threadinfo();

	/* Initialise last exec time to zero (can be overridden in the case of a
	 * thread clone)
	 */
	child_tinfo->m_lastexec_ts = 0;

	/* flags */
	child_tinfo->m_flags = flags;

	/* tid */
	child_tinfo->m_tid = child_tid;

	/* Thread-leader case */
	if(!(child_tinfo->m_flags & PPM_CL_CLONE_THREAD))
	{
		/* We populate fdtable, cwd and env only if we are
		 * a new leader thread, all not leader threads will use the same information
		 * of the main thread.
		 */
		if(valid_caller)
		{
			/* Copy the fd list:
			* XXX this is a gross oversimplification that will need to be fixed.
			* What we do is: if the child is NOT a thread, we copy all the parent fds.
			* The right thing to do is looking at PPM_CL_CLONE_FILES, but there are
			* syscalls like open and pipe2 that can override PPM_CL_CLONE_FILES with the O_CLOEXEC flag
			*/
			sinsp_fdtable* fd_table_ptr = caller_tinfo->get_fd_table();
			if(fd_table_ptr != NULL)
			{
				child_tinfo->m_fdtable = *(fd_table_ptr);

				/* Track down that those are cloned fds */
				for(auto fdit = child_tinfo->m_fdtable.m_table.begin(); fdit != child_tinfo->m_fdtable.m_table.end(); ++fdit)
				{
					fdit->second.set_is_cloned();
				}

				/* It's important to reset the cache of the child thread, to prevent it from
				* referring to an element in the parent's table.
				*/
				child_tinfo->m_fdtable.reset_cache();
			}
			else
			{
				/* This should never happen */
				g_logger.format(sinsp_logger::SEV_DEBUG, "cannot get fd table in sinsp_parser::parse_clone_exit.");
				ASSERT(false);
			}

			/* Not a thread, copy cwd */
			child_tinfo->m_cwd = caller_tinfo->get_cwd();

			/* Not a thread, copy env */
			child_tinfo->m_env = caller_tinfo->m_env;
		}

		/* Create info about the thread group */

		/* pid */
		child_tinfo->m_pid = child_tinfo->m_tid;

		/* The child parent is the calling process */
		child_tinfo->m_ptid = caller_tinfo->m_tid;
	}
	else /* Simple thread case */
	{
		/* pid */
		child_tinfo->m_pid = caller_tinfo->m_pid;
		
		/* ptid */
		/* The parent is the parent of the calling process */
		child_tinfo->m_ptid = caller_tinfo->m_ptid;

		/* Please note this is not the right behavior, it is something we do to be compliant with `/proc` scan.
		 *
		 * In our approximation threads will never have their `fdtable` they will use the main thread one, for
		 * this reason, we keep the main thread alive until we have some threads in the group.
		 */
		child_tinfo->m_flags |= PPM_CL_CLONE_FILES;

		/* If we are a new thread we keep the same lastexec time of the main thread 
		 * If the caller is invalid we are re-initializing this value to 0 again.
		 */
		child_tinfo->m_lastexec_ts = caller_tinfo->m_lastexec_ts;
	}

	/* We are not in a container otherwise we should never reach this point.
	 * We have a previous check in this parser!
	 */

	/* vtid */
	child_tinfo->m_vtid = child_tinfo->m_tid;
	
	/* vpid */
	child_tinfo->m_vpid = child_tinfo->m_pid;	

	/* exe */
	parinfo = evt->get_param(1);
	child_tinfo->m_exe = (char*)parinfo->m_val;

	/* args */
	parinfo = evt->get_param(2);
	child_tinfo->set_args(parinfo->m_val, parinfo->m_len);

	/* comm */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		child_tinfo->m_comm = child_tinfo->m_exe;
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(13);
		child_tinfo->m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}
	
	/* fdlimit */
	parinfo = evt->get_param(7);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	child_tinfo->m_fdlimit = *(int64_t *)parinfo->m_val;

	/* Generic memory info */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		/* pgflt_maj */
		parinfo = evt->get_param(8);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		child_tinfo->m_pfmajor = *(uint64_t *)parinfo->m_val;

		/* pgflt_min */
		parinfo = evt->get_param(9);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		child_tinfo->m_pfminor = *(uint64_t *)parinfo->m_val;

		/* vm_size */
		parinfo = evt->get_param(10);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		child_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;

		/* vm_rss */
		parinfo = evt->get_param(11);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		child_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;

		/* vm_swap */
		parinfo = evt->get_param(12);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		child_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	/* uid */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(9);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(16);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	child_tinfo->set_user(*(int32_t *)parinfo->m_val);

	/* gid */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(10);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(16);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(17);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	child_tinfo->set_group(*(int32_t *)parinfo->m_val);

	/* Set cgroups and heuristically detect container id */
	switch(etype)
	{
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_CLONE3_X:
			parinfo = evt->get_param(14);
			child_tinfo->set_cgroups(parinfo->m_val, parinfo->m_len);
			m_inspector->m_container_manager.resolve_container(child_tinfo, m_inspector->is_live() || m_inspector->is_syscall_plugin());
			break;
	}

	/* Initialize the thread clone time */
	child_tinfo->m_clone_ts = evt->get_ts();

	/* Get pid namespace start ts - convert monotonic time in ns to epoch ts */
	child_tinfo->m_pidns_init_start_ts = m_inspector->m_machine_info->boot_ts_epoch;

	/* Take some further info from the caller */
	if(valid_caller)
	{
		/* We should trust the info we obtain from the caller, if it is valid */
		child_tinfo->m_exepath = caller_tinfo->m_exepath;

		child_tinfo->m_exe_writable = caller_tinfo->m_exe_writable;

		child_tinfo->m_exe_upper_layer = caller_tinfo->m_exe_upper_layer;

		child_tinfo->m_exe_from_memfd = caller_tinfo->m_exe_from_memfd;

		child_tinfo->m_root = caller_tinfo->m_root;

		child_tinfo->m_sid = caller_tinfo->m_sid;

		child_tinfo->m_vpgid = caller_tinfo->m_vpgid;

		child_tinfo->m_tty = caller_tinfo->m_tty;

		child_tinfo->m_loginuser = caller_tinfo->m_loginuser;

		child_tinfo->m_cap_permitted = caller_tinfo->m_cap_permitted;

		child_tinfo->m_cap_inheritable = caller_tinfo->m_cap_inheritable;

		child_tinfo->m_cap_effective = caller_tinfo->m_cap_effective;

		child_tinfo->m_exe_ino = caller_tinfo->m_exe_ino;

		child_tinfo->m_exe_ino_ctime = caller_tinfo->m_exe_ino_ctime;

		child_tinfo->m_exe_ino_mtime = caller_tinfo->m_exe_ino_mtime;

		child_tinfo->m_exe_ino_ctime_duration_clone_ts = caller_tinfo->m_exe_ino_ctime_duration_clone_ts;
	}
	else
	{
		/* exe */
		caller_tinfo->m_exe = child_tinfo->m_exe;

		/* comm */
		caller_tinfo->m_comm = child_tinfo->m_comm;

		/* args */
		parinfo = evt->get_param(2);
		caller_tinfo->set_args(parinfo->m_val, parinfo->m_len);
	}

	/*=============================== CREATE CHILD ===========================*/

	/*=============================== ADD THREAD TO THE TABLE ===========================*/

	/* Until we use the shared pointer we need it here, after we can move it at the end */
	bool thread_added = m_inspector->add_thread(child_tinfo);

	/* Refresh user / loginuser / group */
	if(child_tinfo->m_container_id.empty() == false)
	{
		child_tinfo->set_user(child_tinfo->m_user.uid);
		child_tinfo->set_loginuser(child_tinfo->m_loginuser.uid);
		child_tinfo->set_group(child_tinfo->m_group.gid);
	}

	/* If there's a listener, invoke it */
	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_clone(evt, child_tinfo);
	}

	/* If we had to erase a previous entry for this tid and rebalance the table,
	 * make sure we reinitialize the tinfo pointer for this event, as the thread
	 * generating it might have gone away.
	 */
	if(tid_collision != -1)
	{
		reset(evt);
#ifdef HAS_ANALYZER
		m_inspector->m_tid_collisions.push_back(tid_collision);
#endif
		DBG_SINSP_INFO("tid collision for %" PRIu64 "(%s)",
		               tid_collision,
		               child_tinfo->m_comm.c_str());
	}

	if(!thread_added)
	{
		delete child_tinfo;
	}

	/*=============================== ADD THREAD TO THE TABLE ===========================*/

	return;
}

void sinsp_parser::parse_clone_exit_child(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo = nullptr;
	uint16_t etype = evt->get_type();
	int64_t child_tid = evt->get_tid();

	int64_t tid_collision = -1;
	bool valid_lookup_thread = true;

	/*=============================== CHILD ALREADY THERE ===========================*/

	/* Before embarking on parsing the event, check if there's already
	 * an entry in the thread table for this process. If there is one, make sure
	 * it was created recently. Otherwise, assume it's an old thread for which
	 * we lost the exit event and remove it from the table.
	 * Please note that the thread info is associated with the event
	 * in `sinsp_parser::reset` method.
	 */
	if(evt->m_tinfo != nullptr && evt->m_tinfo->m_clone_ts != 0)
	{
		if(evt->get_ts() - evt->m_tinfo->m_clone_ts < CLONE_STALE_TIME_NS)
		{
			/* This is a valid thread-info, the caller populated it so we
			 * have nothing to do here. Note that if we are in a container the caller
			 * will never generate the child thread-info because it doesn't have
			 * enough info. In all other cases the thread info created by the caller
			 * should be already valid.
			 */
			return;
		}

		/* The info is too old, we remove it and create a new one */
		m_inspector->remove_thread(child_tid);
		tid_collision = child_tid;
		evt->m_tinfo = nullptr;
	}

	/*=============================== CHILD ALREADY THERE ===========================*/

	/*=============================== CREATE NEW THREAD-INFO ===========================*/

	/* We take this flow in the following situations:
	 * - clone() returns in the child before then in the caller.
	 *   This usually happens when we use the CAPTURE_SCHED_PROC_FORK logic
	 *   because the child event is generated by the `sched_proc_fork`
	 *   tracepoint. (Default behavior on arm64 and s390x)
	 * - We dropped the clone exit event in the caller.
	 * - The new process lives in a container.
	 */

	/* Allocate the new thread info and initialize it.
	 * We must avoid `malloc` here and get the item from a preallocated list.
	 */
	sinsp_threadinfo *child_tinfo = m_inspector->build_threadinfo();

	/* Initialise last exec time to zero (can be overridden in the case of a
	 * thread clone)
	 */
	child_tinfo->m_lastexec_ts = 0;

	/* tid */
	child_tinfo->m_tid = child_tid;

	/* pid */
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	child_tinfo->m_pid = *(int64_t *)parinfo->m_val;

	/* ptid. */
	parinfo = evt->get_param(5);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	child_tinfo->m_ptid = *(int64_t *)parinfo->m_val;

	/* `vtid` and `vpid`
	 * We preset these values for old scap-files compatibility.
	 */
	child_tinfo->m_vtid = child_tinfo->m_tid;
	child_tinfo->m_vpid = -1;
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(18);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		child_tinfo->m_vtid = *(int64_t *)parinfo->m_val;

		parinfo = evt->get_param(19);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		child_tinfo->m_vpid = *(int64_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	/* flags */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(8);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(13);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(15);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	child_tinfo->m_flags = *(uint32_t *)parinfo->m_val;

	/* We add this custom `PPM_CL_CLONE_INVERTED` flag.
	 * It means that we received the child event before the caller one and
	 * it will notify the caller that it has to do nothing because we already
	 * populated the thread info in the child.
	 */
	child_tinfo->m_flags |= PPM_CL_CLONE_INVERTED;

	/* Lookup the thread info of the leader thread if we are a new thread while if we are
	 * a new process we copy it from the parent.
	 *
	 * Note that the lookup thread could be different from the caller one!
	 * If they are different we cannot completely trust the info we obtain from lookup thread
	 * becuase they could be stale! For example the caller may have called `prctl` changing its comm,
	 * while the lookup thread still have the old `comm`.
	 */
	int64_t lookup_tid;

	bool is_thread_leader = !(child_tinfo->m_flags & PPM_CL_CLONE_THREAD);
	if(is_thread_leader)
	{
		/* We need to copy data from the parent */
		lookup_tid = child_tinfo->m_ptid;
	}
	else
	{
		/* We need to copy data from the thread leader */
		lookup_tid = child_tinfo->m_pid;

		/* Please note this is not the right behavior, it is something we do to be compliant with `/proc` scan.
		 *
		 * In our approximation threads will never have their `fdtable` they will use the main thread one, for this reason, we keep
		 * the main thread alive until we have some threads in the group.
		 */
		child_tinfo->m_flags |= PPM_CL_CLONE_FILES;
	}

	auto lookup_tinfo = m_inspector->get_thread_ref(lookup_tid, true);
	/* This happens only if we reach the max entries in our table otherwise we should obtain a new fresh empty
	 * thread info to populate even if we are not able to recover any information!
	 * If `caller_tinfo == nullptr` we return, we won't have enough space for the child in the table!
	 */
	if(lookup_tinfo == nullptr)
	{
		/* Invalidate the thread_info associated with this event */
		ASSERT(false);
		evt->m_tinfo = nullptr;
		delete child_tinfo;
		return;
	}

	if(lookup_tinfo->is_invalid())
	{
		valid_lookup_thread = false;

		if(!is_thread_leader)
		{
			/* If the main thread was invalid we should be able to recover some info */

			/* pid. */
			/* the new thread pid is the same of the main thread */
			lookup_tinfo->m_pid = child_tinfo->m_pid;

			/* ptid */
			/* the new thread ptid is the same of the main thread */
			lookup_tinfo->m_ptid = child_tinfo->m_ptid;

			/* vpid */
			/* we are in the same thread group, the vpid is the same of the child */
			lookup_tinfo->m_vpid = child_tinfo->m_vpid;

			/* vtid */
			/* we are a main thread so vtid==vpid */
			lookup_tinfo->m_vtid = lookup_tinfo->m_vpid;

			/* Create thread groups and parenting relationships */
			m_inspector->m_thread_manager->create_thread_dependencies(lookup_tinfo);
		}
	}

	/* We need to do this here, in this way we can use this info to populate the lookup thread
	 * if it is invalid.
	 */

	/* exe */
	parinfo = evt->get_param(1);
	child_tinfo->m_exe = (char *)parinfo->m_val;

	/* comm */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		child_tinfo->m_comm = child_tinfo->m_exe;
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(13);
		child_tinfo->m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	/* args */
	parinfo = evt->get_param(2);
	child_tinfo->set_args(parinfo->m_val, parinfo->m_len);

	if(valid_lookup_thread)
	{
		/* Please note that these data could be wrong if the lookup thread
		 * is not the caller! for example, if the child is created by a thread
		 * the thread could have different info with respect to the thread leader,
		 * for example `comm` could be different! This is a sort of best effort
		 * enrichment...
		 */

		child_tinfo->m_exepath = lookup_tinfo->m_exepath;

		child_tinfo->m_exe_writable = lookup_tinfo->m_exe_writable;

		child_tinfo->m_exe_upper_layer = lookup_tinfo->m_exe_upper_layer;

		child_tinfo->m_exe_from_memfd = lookup_tinfo->m_exe_from_memfd;

		child_tinfo->m_root = lookup_tinfo->m_root;

		child_tinfo->m_sid = lookup_tinfo->m_sid;

		child_tinfo->m_vpgid = lookup_tinfo->m_vpgid;

		child_tinfo->m_tty = lookup_tinfo->m_tty;

		child_tinfo->m_loginuser = lookup_tinfo->m_loginuser;

		child_tinfo->m_cap_permitted = lookup_tinfo->m_cap_permitted;

		child_tinfo->m_cap_inheritable = lookup_tinfo->m_cap_inheritable;

		child_tinfo->m_cap_effective = lookup_tinfo->m_cap_effective;

		child_tinfo->m_exe_ino = lookup_tinfo->m_exe_ino;

		child_tinfo->m_exe_ino_ctime = lookup_tinfo->m_exe_ino_ctime;

		child_tinfo->m_exe_ino_mtime = lookup_tinfo->m_exe_ino_mtime;

		child_tinfo->m_exe_ino_ctime_duration_clone_ts = lookup_tinfo->m_exe_ino_ctime_duration_clone_ts;

		/* We are a new thread leader */
		if(is_thread_leader)
		{
			/* We populate fdtable, cwd and env only if we are
			 * a new leader thread, all not leader threads will use the same information
			 * of the main thread.
			 */

			/* Copy the fd list:
			 * XXX this is a gross oversimplification that will need to be fixed.
			 * What we do is: if the child is NOT a thread, we copy all the parent fds.
			 * The right thing to do is looking at PPM_CL_CLONE_FILES, but there are
			 * syscalls like open and pipe2 that can override PPM_CL_CLONE_FILES with the O_CLOEXEC flag
			 */
			sinsp_fdtable *fd_table_ptr = lookup_tinfo->get_fd_table();
			if(fd_table_ptr != NULL)
			{
				child_tinfo->m_fdtable = *(fd_table_ptr);

				/* Track down that those are cloned fds.
				 * This flag `FLAGS_IS_CLONED` seems to be never used...
				 */
				for(auto fdit = child_tinfo->m_fdtable.m_table.begin();
				    fdit != child_tinfo->m_fdtable.m_table.end(); ++fdit)
				{
					fdit->second.set_is_cloned();
				}

				/* It's important to reset the cache of the child thread, to prevent it from
				 * referring to an element in the parent's table.
				 */
				child_tinfo->m_fdtable.reset_cache();
			}
			else
			{
				/* This should never happen */
				g_logger.format(sinsp_logger::SEV_DEBUG,
						"cannot get fd table in sinsp_parser::parse_clone_exit.");
				ASSERT(false);
			}

			/* Not a thread, copy cwd */
			child_tinfo->m_cwd = lookup_tinfo->get_cwd();

			/* Not a thread, copy env */
			child_tinfo->m_env = lookup_tinfo->m_env;
		}
		else
		{
			/* If we are a new thread we keep the same lastexec time of the main thread */
			child_tinfo->m_lastexec_ts = lookup_tinfo->m_lastexec_ts;
		}
	}
	else
	{
		/* Please note that here `comm`, `exe`, ... could be different from our thread, so this is an
		 * approximation */
		if(!is_thread_leader)
		{
			/* exe */
			lookup_tinfo->m_exe = child_tinfo->m_exe;

			/* comm */
			lookup_tinfo->m_comm = child_tinfo->m_comm;

			/* args */
			parinfo = evt->get_param(2);
			lookup_tinfo->set_args(parinfo->m_val, parinfo->m_len);
		}
	}

	/* fdlimit */
	parinfo = evt->get_param(7);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	child_tinfo->m_fdlimit = *(int64_t *)parinfo->m_val;

	/* Generic memory info */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_X:
	case PPME_SYSCALL_VFORK_17_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		/* pgflt_maj */
		parinfo = evt->get_param(8);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		child_tinfo->m_pfmajor = *(uint64_t *)parinfo->m_val;

		/* pgflt_min */
		parinfo = evt->get_param(9);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		child_tinfo->m_pfminor = *(uint64_t *)parinfo->m_val;

		/* vm_size */
		parinfo = evt->get_param(10);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		child_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;

		/* vm_rss */
		parinfo = evt->get_param(11);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		child_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;

		/* vm_swap */
		parinfo = evt->get_param(12);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		child_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	/* uid */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(9);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(14);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(16);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	child_tinfo->set_user(*(int32_t *)parinfo->m_val);

	/* gid */
	switch(etype)
	{
	case PPME_SYSCALL_CLONE_11_X:
		parinfo = evt->get_param(10);
		break;
	case PPME_SYSCALL_CLONE_16_X:
	case PPME_SYSCALL_FORK_X:
	case PPME_SYSCALL_VFORK_X:
		parinfo = evt->get_param(15);
		break;
	case PPME_SYSCALL_CLONE_17_X:
	case PPME_SYSCALL_FORK_17_X:
	case PPME_SYSCALL_VFORK_17_X:
		parinfo = evt->get_param(16);
		break;
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(17);
		break;
	default:
		ASSERT(false);
	}
	ASSERT(parinfo->m_len == sizeof(int32_t));
	child_tinfo->set_group(*(int32_t *)parinfo->m_val);

	/* Set cgroups and heuristically detect container id */
	switch(etype)
	{
	case PPME_SYSCALL_FORK_20_X:
	case PPME_SYSCALL_VFORK_20_X:
	case PPME_SYSCALL_CLONE_20_X:
	case PPME_SYSCALL_CLONE3_X:
		parinfo = evt->get_param(14);
		child_tinfo->set_cgroups(parinfo->m_val, parinfo->m_len);
		m_inspector->m_container_manager.resolve_container(child_tinfo, m_inspector->is_live());
		break;
	}

	/* Initialize the thread clone time */
	child_tinfo->m_clone_ts = evt->get_ts();

	/* Get pid namespace start ts - convert monotonic time in ns to epoch ts */
	if(evt->get_num_params() > 20)
	{
		parinfo = evt->get_param(20);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		/* If we are in container! */
		if(child_tinfo->m_flags & PPM_CL_CHILD_IN_PIDNS || 
			child_tinfo->m_flags & PPM_CL_CLONE_NEWPID ||
			child_tinfo->m_tid != child_tinfo->m_vtid)
		{
			child_tinfo->m_pidns_init_start_ts =
				*(uint64_t *)parinfo->m_val + m_inspector->m_machine_info->boot_ts_epoch;
		}
		else
		{
			child_tinfo->m_pidns_init_start_ts = m_inspector->m_machine_info->boot_ts_epoch;
		}
	}

	/*=============================== CREATE NEW THREAD-INFO ===========================*/

	/* Add the new thread to the table */
	bool thread_added = m_inspector->add_thread(child_tinfo);

	/* Update the evt->m_tinfo of the child.
	 * We update it here, in this way the `on_clone`
	 * callback will use updated info.
	 */
	evt->m_tinfo = child_tinfo;

	/* Refresh user / loginuser / group */
	if(child_tinfo->m_container_id.empty() == false)
	{
		child_tinfo->set_user(child_tinfo->m_user.uid);
		child_tinfo->set_loginuser(child_tinfo->m_loginuser.uid);
		child_tinfo->set_group(child_tinfo->m_group.gid);
	}

	//
	// If there's a listener, invoke it
	//
	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_clone(evt, child_tinfo);
	}

	/* If we had to erase a previous entry for this tid and rebalance the table,
	 * make sure we reinitialize the child_tinfo pointer for this event, as the thread
	 * generating it might have gone away.
	 */

	if(tid_collision != -1)
	{
		reset(evt);
#ifdef HAS_ANALYZER
		m_inspector->m_tid_collisions.push_back(tid_collision);
#endif
		/* Right now we have collisions only on the clone() caller */
		DBG_SINSP_INFO("tid collision for %" PRIu64 "(%s)", tid_collision, child_tinfo->m_comm.c_str());
	}

	if(!thread_added)
	{
		evt->m_tinfo = nullptr;
		delete child_tinfo;
	}

	/*=============================== CREATE NEW THREAD-INFO ===========================*/

	return;
}

void sinsp_parser::parse_clone_exit(sinsp_evt *evt)
{
	sinsp_evt_param* parinfo;
	int64_t childtid;

	//
	// Validate the return value and get the child tid
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	if(parinfo->m_val == NULL)
	{
		return;
	}
	childtid = *(int64_t *)parinfo->m_val;
	/* Please note that if the child is in a namespace different from the init one
	 * we should never use this `childtid` otherwise we will use a thread id referred to 
	 * an internal namespace and not to the init one!
	 */	
	if(childtid < 0)
	{
		//
		// clone() failed. Do nothing and keep going.
		//
		return;
	}
	else if(childtid == 0)
	{
		parse_clone_exit_child(evt);
	}
	else
	{
		parse_clone_exit_caller(evt, childtid);
	}
	return;
}

void sinsp_parser::parse_execve_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	uint16_t etype = evt->get_type();
	sinsp_evt *enter_evt = &m_tmp_evt;

	// Validate the return value
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	/* Some architectures like s390x send a `PPME_SYSCALL_EXECVEAT_X` exit event
	 * when the `execveat` syscall succeeds, for this reason, we need to manage also
	 * this event in the parser.
	 */
	if(retval < 0)
	{
		return;
	}

	//
	// We get here when `execve` or `execveat` return. The thread has already been added by a previous fork or clone,
	// and we just update the entry with the new information.
	//
	if(evt->m_tinfo == nullptr)
	{
		//
		// No thread to update?
		// We probably missed the start event, so we will just do nothing
		//
		//fprintf(stderr, "comm = %s, args = %s\n",evt->get_param(1)->m_val,evt->get_param(1)->m_val);
		//ASSERT(false);
		return;
	}

	/* In some corner cases an execve is thrown by a secondary thread when 
	 * the main thread is already dead. In these cases the secondary thread
	 * will become a main thread (it will change its tid) and here we will have
	 * an execve exit event called by a main thread that is dead.
	 * What we need to do is to set the main thread as alive again and then
	 * a new PROC_EXIT event will kill it again.
	 * This is what happens with `stress-ng --exec`.
	 */
	if(evt->m_tinfo->is_dead())
	{
		evt->m_tinfo->resurrect_thread();
	}

	// Get the exe
	parinfo = evt->get_param(1);
	evt->m_tinfo->m_exe = parinfo->m_val;
	evt->m_tinfo->m_lastexec_ts = evt->get_ts();

	auto container_id = evt->m_tinfo->m_container_id;

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
		// Old trace files didn't have comm, so just set it to exe
		evt->m_tinfo->m_comm = evt->m_tinfo->m_exe;
		break;
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
		// Get the comm
		parinfo = evt->get_param(13);
		evt->m_tinfo->m_comm = parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// Get the command arguments
	parinfo = evt->get_param(2);
	evt->m_tinfo->set_args(parinfo->m_val, parinfo->m_len);

	// Get the pid
	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	evt->m_tinfo->m_pid = *(uint64_t *)parinfo->m_val;

	//
	// In case this thread is a fake entry,
	// try to at least patch the parent, since
	// we have it from the execve event
	//
	if(evt->m_tinfo->is_invalid())
	{
		parinfo = evt->get_param(5);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_ptid = *(uint64_t *)parinfo->m_val;

		/* We are not in a namespace we recover also vtid and vpid */
		if((evt->m_tinfo->m_flags & PPM_CL_CHILD_IN_PIDNS) == 0)
		{
			evt->m_tinfo->m_vtid = evt->m_tinfo->m_tid;
			evt->m_tinfo->m_vpid = evt->m_tinfo->m_pid;
		}

		auto tinfo = m_inspector->get_thread_ref(evt->m_tinfo->m_tid, false);
		/* Create thread groups and parenting relationships */
		m_inspector->m_thread_manager->create_thread_dependencies(tinfo);
	}

	// Get the fdlimit
	parinfo = evt->get_param(7);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	evt->m_tinfo->m_fdlimit = *(int64_t *)parinfo->m_val;

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
		break;
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
		// Get the pgflt_maj
		parinfo = evt->get_param(8);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_pfmajor = *(uint64_t *)parinfo->m_val;

		// Get the pgflt_min
		parinfo = evt->get_param(9);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_pfminor = *(uint64_t *)parinfo->m_val;

		// Get the vm_size
		parinfo = evt->get_param(10);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_rss
		parinfo = evt->get_param(11);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;

		// Get the vm_swap
		parinfo = evt->get_param(12);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
		break;
	case PPME_SYSCALL_EXECVE_14_X:
		// Get the environment
		parinfo = evt->get_param(13);
		evt->m_tinfo->set_env(parinfo->m_val, parinfo->m_len);
		break;
	case PPME_SYSCALL_EXECVE_15_X:
		// Get the environment
		parinfo = evt->get_param(14);
		evt->m_tinfo->set_env(parinfo->m_val, parinfo->m_len);
		break;
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
		// Get the environment
		parinfo = evt->get_param(15);
		evt->m_tinfo->set_env(parinfo->m_val, parinfo->m_len);

		//
		// Set cgroups and heuristically detect container id
		//
		parinfo = evt->get_param(14);
		evt->m_tinfo->set_cgroups(parinfo->m_val, parinfo->m_len);

		//
		// Resync container status after an execve, we need to do it
		// because at container startup docker spawn a process with vpid=1
		// outside of container cgroup and correct cgroups are
		// assigned just before doing execve:
		//
		// 1. docker-runc calls fork() and created process with vpid=1
		// 2. docker-runc changes cgroup hierarchy of it
		// 3. vpid=1 execve to the real process the user wants to run inside the container
		//
		m_inspector->m_container_manager.resolve_container(evt->m_tinfo, m_inspector->is_live() || m_inspector->is_syscall_plugin());
		break;
	default:
		ASSERT(false);
	}

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
		break;
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
		// Get the tty
		parinfo = evt->get_param(16);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->m_tty = *(uint32_t *) parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	/*
	 * Get `exepath`
	 */
	if(evt->get_num_params() > 27)
	{
		/* In new event versions, with 28 parameters, we can obtain the full exepath with resolved symlinks
		 * directly from the kernel.
		 */

		/* Parameter 28: trusted_exepath (type: PT_FSPATH) */
		parinfo = evt->get_param(27);
		evt->m_tinfo->m_exepath = parinfo->m_val;
	}
	else
	{	
		/* ONLY VALID FOR OLD SCAP-FILES:
		 * In older event versions we can only rely on our userspace reconstruction
		 */

		/* We introduced the `filename` argument in the enter event
		 * only from version `EXECVE_18_E`.
		 * Moreover if we are not able to retrieve the enter event
		 * we can do nothing.
		 */
		if((etype == PPME_SYSCALL_EXECVE_18_X ||
			etype == PPME_SYSCALL_EXECVE_19_X ||
			etype == PPME_SYSCALL_EXECVEAT_X)
			&&
			retrieve_enter_event(enter_evt, evt))
		{
			char fullpath[SCAP_MAX_PATH_SIZE] = {0};

			/* We need to manage the 2 possible cases:
			* - enter event is an `EXECVE`
			* - enter event is an `EXECVEAT`
			*/
			if(enter_evt->get_type() == PPME_SYSCALL_EXECVE_18_E ||
			enter_evt->get_type() == PPME_SYSCALL_EXECVE_19_E)
			{
				/*
				* Get filename
				*/
				parinfo = enter_evt->get_param(0);
				/* This could happen only if we are not able to get the info from the kernel,
				* because if the syscall was successful the pathname was surely here the problem
				* is that for some reason we were not able to get it with our instrumentation,
				* for example when the `bpf_probe_read()` call fails in BPF.
				*/
				if(strncmp(parinfo->m_val, "<NA>", 5) == 0)
				{
					strlcpy(fullpath, "<NA>", 5);
				}
				else
				{
					/* Here the filename can be relative or absolute. */
					sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
													evt->m_tinfo->m_cwd.c_str(),
													(uint32_t)evt->m_tinfo->m_cwd.size(),
													parinfo->m_val,
													(uint32_t)parinfo->m_len);
				}
			}
			else if(enter_evt->get_type() == PPME_SYSCALL_EXECVEAT_E)
			{
				/*
				* Get dirfd
				*/
				parinfo = enter_evt->get_param(0);
				ASSERT(parinfo->m_len == sizeof(int64_t));
				int64_t dirfd = *(int64_t *)parinfo->m_val;

				/*
				* Get flags
				*/
				parinfo = enter_evt->get_param(2);
				ASSERT(parinfo->m_len == sizeof(uint32_t));
				uint32_t flags = *(uint32_t *)parinfo->m_val;

				/*
				* Get pathname
				*/

				/* The pathname could be:
				* - (1) relative (to dirfd).
				* - (2) absolute.
				* - (3) empty in the kernel because the user specified the `AT_EMPTY_PATH` flag.
				*   In this case, `dirfd` must refer to a file.
				*   Please note:
				*   The path is empty in the kernel but in userspace, we will obtain a `<NA>`.
				* - (4) empty in the kernel because we fail to recover it from the registries.
				* 	 Please note:
				*   The path is empty in the kernel but in userspace, we will obtain a `<NA>`.
				*/
				parinfo = enter_evt->get_param(1);
				char *pathname = parinfo->m_val;
				uint32_t namelen = parinfo->m_len;

				/* If the pathname is `<NA>` here we shouldn't have problems during `parse_dirfd`.
				* It doesn't start with "/" so it is not considered an absolute path.
				*/
				std::string sdir;
				parse_dirfd(evt, pathname, dirfd, &sdir);

				/* (4) In this case, we were not able to recover the pathname from the kernel or
				* we are not able to recover information about `dirfd` in our `sinsp` state.
				* Fallback to `<NA>`.
				*/
				if((!(flags & PPM_EXVAT_AT_EMPTY_PATH) && strncmp(pathname, "<NA>", 5) == 0) ||
				sdir.compare("<UNKNOWN>") == 0)
				{
					/* we copy also the string terminator `\0`. */
					strlcpy(fullpath, "<NA>", 5);
				}
				/* (3) In this case we have already obtained the `exepath` and it is `sdir`, we just need
				* to sanitize it.
				*/
				else if(flags & PPM_EXVAT_AT_EMPTY_PATH)
				{
					/* We explicitly set the `pathlen` to `0`, since `pathname` is `<NA>`
					* as we said in case (3), and we don't want to consider it as a valid
					* part of the final path. In this case `sdir` will always be
					* an absolute path.
					*/
					sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
									"\0",
									0,
									sdir.c_str(),
									(uint32_t)sdir.length());

				}
				/* (2)/(1) If it is relative or absolute we craft the `fullpath` as usual:
				* - `sdir` + `pathname`
				*/
				else
				{
					sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE,
												sdir.c_str(),
												(uint32_t)sdir.length(),
												pathname,
												namelen);
				}
			}
			evt->m_tinfo->m_exepath = fullpath;
		}
	}

	switch(etype)
	{
	case PPME_SYSCALL_EXECVE_8_X:
	case PPME_SYSCALL_EXECVE_13_X:
	case PPME_SYSCALL_EXECVE_14_X:
	case PPME_SYSCALL_EXECVE_15_X:
	case PPME_SYSCALL_EXECVE_16_X:
	case PPME_SYSCALL_EXECVE_17_X:
	case PPME_SYSCALL_EXECVE_18_X:
		break;
	case PPME_SYSCALL_EXECVE_19_X:
	case PPME_SYSCALL_EXECVEAT_X:
		// Get the vpgid
		parinfo = evt->get_param(17);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		evt->m_tinfo->m_vpgid = *(int64_t *) parinfo->m_val;
		break;
	default:
		ASSERT(false);
	}

	// From scap version 1.2, event types of existent
	// events are no longer changed.
	// sinsp_evt::get_num_params() can instead be used
	// to identify the version of the event.
	// For example:
	//
	// if(evt->get_num_params() > 18)
	// {
	//   ...
	// }

	// Get the loginuid
	if(evt->get_num_params() > 18)
	{
		parinfo = evt->get_param(18);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		evt->m_tinfo->set_loginuser(*(uint32_t *) parinfo->m_val);
	}

	// Get execve flags
	if(evt->get_num_params() > 19)
	{
		parinfo = evt->get_param(19);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t flags = *(uint32_t *) parinfo->m_val;

		evt->m_tinfo->m_exe_writable = ((flags & PPM_EXE_WRITABLE) != 0);
		evt->m_tinfo->m_exe_upper_layer = ((flags & PPM_EXE_UPPER_LAYER) != 0);
		evt->m_tinfo->m_exe_from_memfd = ((flags & PPM_EXE_FROM_MEMFD) != 0);
	}

	// Get capabilities
	if(evt->get_num_params() > 22)
	{
		if(etype == PPME_SYSCALL_EXECVE_19_X || etype == PPME_SYSCALL_EXECVEAT_X)
		{
			parinfo = evt->get_param(20);
			ASSERT(parinfo->m_len == sizeof(uint64_t));
			evt->m_tinfo->m_cap_inheritable = *(uint64_t *)parinfo->m_val;

			parinfo = evt->get_param(21);
			ASSERT(parinfo->m_len == sizeof(uint64_t));
			evt->m_tinfo->m_cap_permitted = *(uint64_t *)parinfo->m_val;

			parinfo = evt->get_param(22);
			ASSERT(parinfo->m_len == sizeof(uint64_t));
			evt->m_tinfo->m_cap_effective = *(uint64_t *)parinfo->m_val;
		}
	}

	// Get exe ino fields
	if(evt->get_num_params() > 25)
	{
		parinfo = evt->get_param(23);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_exe_ino = *(uint64_t *)parinfo->m_val;

		parinfo = evt->get_param(24);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_exe_ino_ctime = *(uint64_t *)parinfo->m_val;

		parinfo = evt->get_param(25);
		ASSERT(parinfo->m_len == sizeof(uint64_t));
		evt->m_tinfo->m_exe_ino_mtime = *(uint64_t *)parinfo->m_val;

		if(evt->m_tinfo->m_clone_ts != 0)
		{
			evt->m_tinfo->m_exe_ino_ctime_duration_clone_ts = evt->m_tinfo->m_clone_ts - evt->m_tinfo->m_exe_ino_ctime;
		}

		if(evt->m_tinfo->m_pidns_init_start_ts != 0 && (evt->m_tinfo->m_exe_ino_ctime > evt->m_tinfo->m_pidns_init_start_ts))
		{
			evt->m_tinfo->m_exe_ino_ctime_duration_pidns_start = evt->m_tinfo->m_exe_ino_ctime - evt->m_tinfo->m_pidns_init_start_ts;
		}
	}

	// Get uid
	if(evt->get_num_params() > 26)
	{
		parinfo = evt->get_param(26);
		evt->m_tinfo->m_user.uid = *(uint32_t *)parinfo->m_val;
	}

	//
	// execve starts with a clean fd list, so we get rid of the fd list that clone
	// copied from the parent
	// XXX validate this
	//
	//  scap_fd_free_table(tinfo);

	//
	// Clear the flags for this thread, making sure to propagate the inverted
	// and shell pipe flags
	//

	auto spf = evt->m_tinfo->m_flags & (PPM_CL_PIPE_SRC | PPM_CL_PIPE_DST | PPM_CL_IS_MAIN_THREAD);
	bool inverted = ((evt->m_tinfo->m_flags & PPM_CL_CLONE_INVERTED) != 0);

	evt->m_tinfo->m_flags = PPM_CL_ACTIVE;

	evt->m_tinfo->m_flags |= spf;
	if(inverted)
	{
		evt->m_tinfo->m_flags |= PPM_CL_CLONE_INVERTED;
	}

	//
	// This process' name changed, so we need to include it in the protocol again
	//
	evt->m_tinfo->m_flags |= PPM_CL_NAME_CHANGED;

	//
	// Recompute the program hash
	//
	evt->m_tinfo->compute_program_hash();

	//
	// Refresh user / loginuser / group
	// if we happen to change container id
	//
	if(container_id != evt->m_tinfo->m_container_id)
	{
		evt->m_tinfo->set_user(evt->m_tinfo->m_user.uid);
		evt->m_tinfo->set_loginuser(evt->m_tinfo->m_loginuser.uid);
		evt->m_tinfo->set_group(evt->m_tinfo->m_group.gid);
	}

	//
	// If there's a listener, invoke it
	//
	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_execve(evt);
	}

	/* If any of the threads in a thread group performs an
	 * execve, then all threads other than the thread group
	 * leader are terminated, and the new program is executed in
	 * the thread group leader.
	 * 
	 * if `evt->m_tinfo->m_tginfo->get_thread_count() > 1` it means
	 * we still have some not leader threads in the group.
	 */
	if(evt->m_tinfo->m_tginfo != nullptr && evt->m_tinfo->m_tginfo->get_thread_count() > 1)
	{
		for(const auto& thread : evt->m_tinfo->m_tginfo->get_thread_list())
		{
			auto thread_ptr = thread.lock().get();
			/* we don't want to remove the main thread since it is the one
			 * running in this parser!
			 */
			if(thread_ptr == nullptr || thread_ptr->is_main_thread())
			{
				continue;
			}
			m_inspector->remove_thread(thread_ptr->m_tid);
		}
	}
	return;
}

/* Different possible cases:
 * - the pathname is absolute:
 *	 sdir = "."
 * - the pathname is relative:
 *   - if `dirfd` is `PPM_AT_FDCWD` -> sdir = cwd.
 *   - if we have no information about `dirfd` -> sdir = "<UNKNOWN>".
 *   - if `dirfd` has a valid vaule for us -> sdir = path + "/" at the end.
 */
void sinsp_parser::parse_dirfd(sinsp_evt *evt, char* name, int64_t dirfd, OUT std::string* sdir)
{
	bool is_absolute = false;
	/* This should never happen but just to be sure. */
	if(name != NULL)
	{
		is_absolute = (name[0] == '/');
	}

	std::string tdirstr;

	if(is_absolute)
	{
		//
		// The path is absolute.
		// Some processes (e.g. irqbalance) actually do this: they pass an invalid fd and
		// and absolute path, and openat succeeds.
		//
		*sdir = ".";
	}
	else if(dirfd == PPM_AT_FDCWD)
	{
		*sdir = evt->m_tinfo->get_cwd();
	}
	else
	{
		evt->m_fdinfo = evt->m_tinfo->get_fd(dirfd);

		if(evt->m_fdinfo == NULL)
		{
			ASSERT(false);
			*sdir = "<UNKNOWN>";
		}
		else
		{
			if(evt->m_fdinfo->m_name[evt->m_fdinfo->m_name.length()] == '/')
			{
				*sdir = evt->m_fdinfo->m_name;
			}
			else
			{
				tdirstr = evt->m_fdinfo->m_name + '/';
				*sdir = tdirstr;
			}
		}
	}
}

template <typename T>
void schedule_more_evts(sinsp* inspector, void* data, T* client, ppm_event_code evt_type)
{
#ifdef HAS_CAPTURE
	ASSERT(data);
	bool good_event = false;
	metaevents_state* state = (metaevents_state*)data;

	if(state->m_new_group == true)
	{
		state->m_new_group = false;
		inspector->add_meta_event(&state->m_metaevt);
		return;
	}

	ASSERT(client);
	if(!client->get_capture_events().size())
	{
		SINSP_STR_ERROR(
			std::string("An event scheduled but no events available."
			            "All pending event requests for "
			            "[") + typeid(T).name() + "] are cancelled.");
		state->m_new_group = false;
		state->m_n_additional_events_to_add = 0;
		inspector->remove_meta_event_callback();
		return;
	}
	std::string payload = client->dequeue_capture_event();
	std::size_t tot_len = sizeof(scap_evt) + sizeof(uint16_t) + payload.size() + 1;

	if(tot_len > state->m_scap_buf_size)
	{
		sinsp_parser::init_scapevt(*state, evt_type, tot_len);
	}

	state->m_piscapevt->len = tot_len;
	state->m_piscapevt->nparams = 1;
	uint16_t* plen = (uint16_t*)((char *)state->m_piscapevt + sizeof(struct ppm_evt_hdr));
	plen[0] = (uint16_t)payload.size() + 1;
	uint8_t* edata = (uint8_t*)plen + sizeof(uint16_t);
	memcpy(edata, payload.c_str(), plen[0]);
	good_event = true;

	state->m_n_additional_events_to_add--;
	if(state->m_n_additional_events_to_add == 0)
	{
		inspector->remove_meta_event_callback();
	}
	else if(good_event)
	{
		inspector->add_meta_event(&state->m_metaevt);
	}
#endif // HAS_CAPTURE
}

#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)
void schedule_more_k8s_evts(sinsp* inspector, void* data)
{
	schedule_more_evts(inspector, data, inspector->get_k8s_client(), PPME_K8S_E);
}

void sinsp_parser::schedule_k8s_events()
{
#ifdef HAS_CAPTURE
	//
	// schedule k8s events, if any available
	//
	k8s* k8s_client = 0;
	if(m_inspector && (k8s_client = m_inspector->m_k8s_client))
	{
		int event_count = k8s_client->get_capture_events().size();
		if(event_count)
		{
			m_k8s_metaevents_state.m_piscapevt->tid = 0;
			m_k8s_metaevents_state.m_piscapevt->ts = m_inspector->m_lastevent_ts;
			m_k8s_metaevents_state.m_new_group = true;
			m_k8s_metaevents_state.m_n_additional_events_to_add = event_count;
			m_inspector->add_meta_event_callback(&schedule_more_k8s_evts, &m_k8s_metaevents_state);

			schedule_more_k8s_evts(m_inspector, &m_k8s_metaevents_state);
		}
	}
#endif // HAS_CAPTURE
}

void schedule_more_mesos_evts(sinsp* inspector, void* data)
{
	schedule_more_evts(inspector, data, inspector->get_mesos_client(), PPME_MESOS_E);
}

void sinsp_parser::schedule_mesos_events()
{
#ifdef HAS_CAPTURE
	//
	// schedule mesos events, if any available
	//
	mesos* mesos_client = 0;
	if(m_inspector && (mesos_client = m_inspector->m_mesos_client))
	{
		int event_count = mesos_client->get_capture_events().size();
		if(event_count)
		{
			m_mesos_metaevents_state.m_piscapevt->tid = 0;
			m_mesos_metaevents_state.m_piscapevt->ts = m_inspector->m_lastevent_ts;
			m_mesos_metaevents_state.m_new_group = true;
			m_mesos_metaevents_state.m_n_additional_events_to_add = event_count;
			m_inspector->add_meta_event_callback(&schedule_more_mesos_evts, &m_mesos_metaevents_state);

			schedule_more_mesos_evts(m_inspector, &m_mesos_metaevents_state);
		}
	}
#endif // HAS_CAPTURE
}
#endif // #if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)

void sinsp_parser::parse_open_openat_creat_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	char *name;
	char *enter_evt_name;
	uint32_t namelen;
	uint32_t enter_evt_namelen;
	uint32_t flags;
	uint32_t enter_evt_flags;
	sinsp_fdinfo_t fdi;
	sinsp_evt *enter_evt = &m_tmp_evt;
	std::string sdir;
	uint16_t etype = evt->get_type();
	uint32_t dev = 0;
	uint64_t ino = 0;
	bool lastevent_retrieved = false;

	ASSERT(evt->m_tinfo);
	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	if(etype != PPME_SYSCALL_OPEN_BY_HANDLE_AT_X)
	{
		//
		// Load the enter event so we can access its arguments
		//
		lastevent_retrieved = retrieve_enter_event(enter_evt, evt);
	}

	//
	// Check the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	//
	// Parse the parameters, based on the event type
	//
	if(etype == PPME_SYSCALL_OPEN_X)
	{
		parinfo = evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		if(evt->get_num_params() > 4)
		{
			parinfo = evt->get_param(4);
			ASSERT(parinfo->m_len == sizeof(uint32_t));
			dev = *(uint32_t *)parinfo->m_val;
			if (evt->get_num_params() > 5)
			{
				parinfo = evt->get_param(5);
				ASSERT(parinfo->m_len == sizeof(uint64_t));
				ino = *(uint64_t *)parinfo->m_val;
			}
		}

		//
		// Compare with enter event parameters
		//
		if(lastevent_retrieved && enter_evt->get_num_params() >= 2)
		{
			parinfo = enter_evt->get_param(0);
			enter_evt_name = parinfo->m_val;
			enter_evt_namelen = parinfo->m_len;

			parinfo = enter_evt->get_param(1);
			ASSERT(parinfo->m_len == sizeof(uint32_t));
			enter_evt_flags = *(uint32_t *)parinfo->m_val;

			if(enter_evt_namelen != 0 && strncmp(enter_evt_name, "<NA>", 5) != 0)
			{
				name = enter_evt_name;
				namelen = enter_evt_namelen;

				// keep PPM_O_F_CREATED flag if present
				if (flags & PPM_O_F_CREATED)
					flags = enter_evt_flags | PPM_O_F_CREATED;
				else
					flags = enter_evt_flags;
			}
		}

		sdir = evt->m_tinfo->get_cwd();
	}
	else if(etype == PPME_SYSCALL_CREAT_X)
	{
		parinfo = evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		flags = 0;

		if(evt->get_num_params() > 3)
		{
			parinfo = evt->get_param(3);
			ASSERT(parinfo->m_len == sizeof(uint32_t));
			dev = *(uint32_t *)parinfo->m_val;
			if (evt->get_num_params() > 4)
			{
				parinfo = evt->get_param(4);
				ASSERT(parinfo->m_len == sizeof(uint64_t));
				ino = *(uint64_t *)parinfo->m_val;
			}
		}

		if(lastevent_retrieved && enter_evt->get_num_params() >= 1)
		{
			parinfo = enter_evt->get_param(0);
			enter_evt_name = parinfo->m_val;
			enter_evt_namelen = parinfo->m_len;

			enter_evt_flags = 0;

			if(enter_evt_namelen != 0 && strncmp(enter_evt_name, "<NA>", 5) != 0)
			{
				name = enter_evt_name;
				namelen = enter_evt_namelen;

				// keep PPM_O_F_CREATED flag if present
				if (flags & PPM_O_F_CREATED)
					flags = enter_evt_flags | PPM_O_F_CREATED;
				else
					flags = enter_evt_flags;
			}
		}

		sdir = evt->m_tinfo->get_cwd();
	}
	else if(etype == PPME_SYSCALL_OPENAT_X)
	{
		parinfo = enter_evt->get_param(1);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = enter_evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		int64_t dirfd = *(int64_t *)parinfo->m_val;

		parse_dirfd(evt, name, dirfd, &sdir);
	}
	else if(etype == PPME_SYSCALL_OPENAT_2_X || etype == PPME_SYSCALL_OPENAT2_X)
	{
		parinfo = evt->get_param(2);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		parinfo = evt->get_param(3);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		parinfo = evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		int64_t dirfd = *(int64_t *)parinfo->m_val;

		if(etype == PPME_SYSCALL_OPENAT_2_X && evt->get_num_params() > 5)
		{
			parinfo = evt->get_param(5);
			ASSERT(parinfo->m_len == sizeof(uint32_t));
			dev = *(uint32_t *)parinfo->m_val;
			if (evt->get_num_params() > 6)
			{
				parinfo = evt->get_param(6);
				ASSERT(parinfo->m_len == sizeof(uint64_t));
				ino = *(uint64_t *)parinfo->m_val;
			}
		}

		//
		// Compare with enter event parameters
		//
		if(lastevent_retrieved && enter_evt->get_num_params() >= 3)
		{
			parinfo = enter_evt->get_param(1);
			enter_evt_name = parinfo->m_val;
			enter_evt_namelen = parinfo->m_len;

			parinfo = enter_evt->get_param(2);
			ASSERT(parinfo->m_len == sizeof(uint32_t));
			enter_evt_flags = *(uint32_t *)parinfo->m_val;

			parinfo = enter_evt->get_param(0);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			int64_t enter_evt_dirfd = *(int64_t *)parinfo->m_val;

			if(enter_evt_namelen != 0 && strncmp(enter_evt_name, "<NA>", 5) != 0)
			{
				name = enter_evt_name;
				namelen = enter_evt_namelen;

				// keep PPM_O_F_CREATED flag if present
				if (flags & PPM_O_F_CREATED)
					flags = enter_evt_flags | PPM_O_F_CREATED;
				else
					flags = enter_evt_flags;

				dirfd = enter_evt_dirfd;
			}
		}

		parse_dirfd(evt, name, dirfd, &sdir);
	}
	else if (etype == PPME_SYSCALL_OPEN_BY_HANDLE_AT_X)
	{
		/*
		 * Flags
		 */
		parinfo = evt->get_param(2);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		flags = *(uint32_t *)parinfo->m_val;

		/*
		 * Path
		 */
		parinfo = evt->get_param(3);
		name = parinfo->m_val;
		namelen = parinfo->m_len;

		// since open_by_handle_at returns an absolute path we will always start at /
		sdir = "";
	}
	else
	{
		ASSERT(false);
		return;
	}

	// XXX not implemented yet
	//parinfo = evt->get_param(2);
	//ASSERT(parinfo->m_len == sizeof(uint32_t));
	//mode = *(uint32_t*)parinfo->m_val;

	char fullpath[SCAP_MAX_PATH_SIZE];

	sinsp_utils::concatenate_paths(fullpath, SCAP_MAX_PATH_SIZE, sdir.c_str(), (uint32_t)sdir.length(),
		name, namelen);

	if(fd >= 0)
	{
		//
		// Populate the new fdi
		//
		if(flags & PPM_O_DIRECTORY)
		{
			fdi.m_type = SCAP_FD_DIRECTORY;
		}
		else
		{
			fdi.m_type = SCAP_FD_FILE_V2;
		}

		fdi.m_openflags = flags;
		fdi.m_mount_id = 0;
		fdi.m_dev = dev;
		fdi.m_ino = ino;
		fdi.add_filename_raw(name);
		fdi.add_filename(fullpath);

		//
		// If this is a user event fd, mark it with the proper flag
		//
		if(fdi.m_name == USER_EVT_DEVICE_NAME)
		{
			fdi.m_flags |= sinsp_fdinfo_t::FLAGS_IS_TRACER_FILE;
		}
		else
		{
			fdi.m_flags |= sinsp_fdinfo_t::FLAGS_IS_NOT_TRACER_FD;
		}

		//
		// Add the fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);

		//
		// Call the protocol decoder callbacks associated to this event
		//
		std::vector<sinsp_protodecoder*>::iterator it;
		for(it = m_open_callbacks.begin(); it != m_open_callbacks.end(); ++it)
		{
			(*it)->on_event(evt, CT_OPEN);
		}
	}

	if(m_inspector->get_observer() && !(flags & PPM_O_DIRECTORY))
	{
		m_inspector->get_observer()->on_file_open(evt, fullpath, flags);
	}
}

void sinsp_parser::parse_fchmod_fchown_exit(sinsp_evt *evt)
{
	sinsp_evt_param* parinfo;

	// Both of these syscalls act on fds although they do not
	// create them. Take the fd argument and attempt to look up
	// the fd from the thread.
	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(1)->type == PT_FD);
	int64_t fd = *(int64_t *)parinfo->m_val;
	evt->m_tinfo->m_lastevent_fd = fd;
	evt->m_fdinfo = evt->m_tinfo->get_fd(fd);
}

//
// Helper function to allocate a socket fd, initialize it by parsing its parameters and add it to the fd table of the given thread.
//
inline void sinsp_parser::add_socket(sinsp_evt *evt, int64_t fd, uint32_t domain, uint32_t type, uint32_t protocol)
{
	sinsp_fdinfo_t fdi;

	//
	// Populate the new fdi
	//
	memset(&(fdi.m_sockinfo.m_ipv4info), 0, sizeof(fdi.m_sockinfo.m_ipv4info));
	fdi.m_type = SCAP_FD_UNKNOWN;
	fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UNKNOWN;

	if(domain == PPM_AF_UNIX)
	{
		fdi.m_type = SCAP_FD_UNIX_SOCK;
	}
	else if(domain == PPM_AF_INET || domain == PPM_AF_INET6)
	{
		fdi.m_type = (domain == PPM_AF_INET)? SCAP_FD_IPV4_SOCK : SCAP_FD_IPV6_SOCK;

		uint8_t l4proto = SCAP_L4_UNKNOWN;
		if(protocol == IPPROTO_TCP)
		{
			l4proto = (type == SOCK_RAW)? SCAP_L4_RAW : SCAP_L4_TCP;
		}
		else if(protocol == IPPROTO_UDP)
		{
			l4proto = (type == SOCK_RAW)? SCAP_L4_RAW : SCAP_L4_UDP;
		}
		else if(protocol == IPPROTO_IP)
		{
			//
			// XXX: we mask type because, starting from linux 2.6.27, type can be ORed with
			//      SOCK_NONBLOCK and SOCK_CLOEXEC. We need to validate that byte masking is
			//      acceptable
			//
			if((type & 0xff) == SOCK_STREAM)
			{
				l4proto = SCAP_L4_TCP;
			}
			else if((type & 0xff) == SOCK_DGRAM)
			{
				l4proto = SCAP_L4_UDP;
			}
			else
			{
				ASSERT(false);
			}
		}
		else if(protocol == IPPROTO_ICMP)
		{
			l4proto = (type == SOCK_RAW)? SCAP_L4_RAW : SCAP_L4_ICMP;
		}
		else if(protocol == IPPROTO_RAW)
		{
			l4proto = SCAP_L4_RAW;
		}

		if(domain == PPM_AF_INET)
		{
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = l4proto;
		}
		else
		{
			memset(&(fdi.m_sockinfo.m_ipv6info), 0, sizeof(fdi.m_sockinfo.m_ipv6info));
			fdi.m_sockinfo.m_ipv6info.m_fields.m_l4proto = l4proto;
		}
	}
	else if(domain == PPM_AF_NETLINK)
	{
		fdi.m_type = SCAP_FD_NETLINK;
	}
	else
	{
		if(domain != 10 && // IPv6
#ifdef _WIN32
			domain != AF_INET6 && // IPv6 on Windows
#endif
			domain != 17)   // AF_PACKET, used for packet capture
		{
			//
			// IPv6 will go here
			//
			ASSERT(false);
		}
	}

	if(fdi.m_type == SCAP_FD_UNKNOWN)
	{
		SINSP_STR_DEBUG("Unknown fd fd=" + std::to_string(fd) +
		                " domain=" + std::to_string(domain) +
		                " type=" + std::to_string(type) +
		                " protocol=" + std::to_string(protocol) +
		                " pid=" + std::to_string(evt->m_tinfo->m_pid) +
		                " comm=" + evt->m_tinfo->m_comm);
	}

#ifndef INCLUDE_UNKNOWN_SOCKET_FDS
	if(fdi.m_type == SCAP_FD_UNKNOWN)
	{
		return;
	}
#endif

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

/**
 * If we receive a call to 'sendto()' and the event's m_fdinfo is nullptr,
 * then we likely missed the call to 'socket()' that created the file
 * descriptor.  In that case, we'll guess that it's a SOCK_DGRAM/UDP socket
 * and create the fdinfo based on that.
 *
 * Preconditions: evt->m_fdinfo == nullptr and
 *                evt->m_tinfo != nullptr
 *
 */
inline void sinsp_parser::infer_sendto_fdinfo(sinsp_evt* const evt)
{
	if((evt->m_fdinfo != nullptr) || (evt->m_tinfo == nullptr))
	{
		ASSERT(evt->m_fdinfo == nullptr);
		ASSERT(evt->m_tinfo != nullptr);
		return;
	}

	const uint32_t FILE_DESCRIPTOR_PARAM = 0;
	const uint32_t SOCKET_TUPLE_PARAM = 2;

	sinsp_evt_param* parinfo = nullptr;

	parinfo = evt->get_param(FILE_DESCRIPTOR_PARAM);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(FILE_DESCRIPTOR_PARAM)->type == PT_FD);
	const int64_t fd = *((int64_t*) parinfo->m_val);

	if(fd < 0)
	{
		// Call to sendto() with an invalid file descriptor
		return;
	}

	parinfo = evt->get_param(SOCKET_TUPLE_PARAM);
	const char addr_family = *((char*) parinfo->m_val);

	if((addr_family == AF_INET) || (addr_family == AF_INET6))
	{
		const uint32_t domain = (addr_family == AF_INET)
		                        ? PPM_AF_INET
		                        : PPM_AF_INET6;

#ifndef _WIN32
		SINSP_DEBUG("Call to sendto() with fd=%d; missing socket() "
		            "data. Adding socket %s/SOCK_DGRAM/IPPROTO_UDP "
		            "for command '%s', pid %d",
		            fd,
		            (domain == PPM_AF_INET) ? "PPM_AF_INET"
		                                    : "PPM_AF_INET6",
		            evt->m_tinfo->get_comm().c_str(),
		            evt->m_tinfo->m_pid);
#endif

		// Here we're assuming sendto() means SOCK_DGRAM/UDP, but it
		// can be used with TCP.  We have no way to know for sure at
		// this point.
		add_socket(evt, fd, domain, SOCK_DGRAM, IPPROTO_UDP);
	}
}

void sinsp_parser::parse_socket_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	uint32_t domain;
	uint32_t type;
	uint32_t protocol;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// NOTE: we don't check the return value of get_param() because we know the arguments we need are there.
	// XXX this extraction would be much faster if we parsed the event manually to extract the
	// parameters in one scan. We don't care too much because we assume that we get here
	// seldom enough that saving few tens of CPU cycles is not important.
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// socket() failed. Nothing to add to the table.
		//
		return;
	}

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	//
	// Load the enter event so we can access its arguments
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Extract the arguments
	//
	parinfo = enter_evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	domain = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	type = *(uint32_t *)parinfo->m_val;

	parinfo = enter_evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	protocol = *(uint32_t *)parinfo->m_val;

	//
	// Allocate a new fd descriptor, populate it and add it to the thread fd table
	//
	add_socket(evt, fd, domain, type, protocol);
}

void sinsp_parser::parse_bind_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	const char *parstr;
	uint8_t *packed_data;
	uint8_t family;

	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if(retval < 0)
	{
		return;
	}

	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		ASSERT(!(evt->m_fdinfo->is_unix_socket() || evt->m_fdinfo->is_ipv4_socket()));
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	family = *packed_data;

	//
	// Update the FD info with this tuple, assume that if port > 0, means that
	// the socket is used for listening
	//
	if(family == PPM_AF_INET)
	{
		uint32_t ip = *(uint32_t *)(packed_data + 1);
		uint16_t port = *(uint16_t *)(packed_data + 5);
		if(port > 0)
		{
			evt->m_fdinfo->m_type = SCAP_FD_IPV4_SERVSOCK;
			evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip = ip;
			evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port = port;
			evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto =
					evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto;
			evt->m_fdinfo->set_role_server();
		}
	}
	else if (family == PPM_AF_INET6)
	{
		uint8_t* ip = packed_data + 1;
		uint16_t port = *(uint16_t *)(packed_data + 17);
		if(port > 0)
		{
			if(sinsp_utils::is_ipv4_mapped_ipv6(ip))
			{
				evt->m_fdinfo->m_type = SCAP_FD_IPV4_SERVSOCK;
				evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto =
					evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_l4proto;
				evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_ip = *(uint32_t *)(packed_data + 13);
				evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_port = port;
			}
			else
			{
				evt->m_fdinfo->m_type = SCAP_FD_IPV6_SERVSOCK;
				evt->m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_port = port;
				memcpy(evt->m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_ip.m_b, ip, sizeof(ipv6addr));
				evt->m_fdinfo->m_sockinfo.m_ipv6serverinfo.m_l4proto =
					evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_l4proto;
			}
			evt->m_fdinfo->set_role_server();
		}
	}
	//
	// Update the name of this socket
	//
	evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);

	//
	// If there's a listener callback, invoke it
	//
	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_bind(evt);
	}
}

/**
 * Register a socket in pending state
 */
void sinsp_parser::parse_connect_enter(sinsp_evt *evt){
    sinsp_evt_param *parinfo;
    const char *parstr;
    uint8_t *packed_data;

    if(evt->m_fdinfo == NULL)
    {
        return;
    }

	if (m_track_connection_status) {
		evt->m_fdinfo->set_socket_pending();
	}

	if(evt->get_num_params() < 2)
	{
		switch(evt->m_fdinfo->m_type)
		{
		case SCAP_FD_IPV4_SOCK:
			evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = 0;
			evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = 0;
			break;
		case SCAP_FD_IPV6_SOCK:
			evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip = ipv6addr::empty_address;
			evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport = 0;
			break;
		default:
			break;
		}
		sinsp_utils::sockinfo_to_str(&evt->m_fdinfo->m_sockinfo,
					     evt->m_fdinfo->m_type, &evt->m_paramstr_storage[0],
					     (uint32_t)evt->m_paramstr_storage.size(),
					     m_inspector->m_hostname_and_port_resolution_enabled);

		evt->m_fdinfo->m_name = &evt->m_paramstr_storage[0];
		return;
	}

    parinfo = evt->get_param(1);
    if(parinfo->m_len == 0)
    {
		//
		// Address can be NULL:
		// sk is a TCP fastopen active socket and
		// TCP_FASTOPEN_CONNECT sockopt is set and
		// we already have a valid cookie for this socket.
		//
        return;
    }

	packed_data = (uint8_t*)parinfo->m_val;

	uint8_t family = *packed_data;

	if(family == PPM_AF_INET)
	{
		evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
		memcpy(&evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, packed_data + 1, sizeof(uint32_t));
		memcpy(&evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport, packed_data + 5, sizeof(uint16_t));
	}
	else if (family == PPM_AF_INET6)
	{
		uint16_t port;
		memcpy(&port, packed_data + 17, sizeof(uint16_t));
		uint8_t* ip = packed_data + 1;
		if(sinsp_utils::is_ipv4_mapped_ipv6(ip))
		{
			evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
			memcpy(&evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip, packed_data + 13, sizeof(uint32_t));
			evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = port;
		}
		else
		{
			evt->m_fdinfo->m_type = SCAP_FD_IPV6_SOCK;
			evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport = port;
			memcpy(evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip.m_b, ip, sizeof(ipv6addr));
		}
	} else {

        //
        // Add the friendly name to the fd info
        //
        evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);

#ifndef HAS_ANALYZER
        //
        // Update the FD with this tuple
        //
        evt->m_fdinfo->set_unix_info(packed_data);
#endif
	}

    //
    // If there's a listener callback and we're tracking connection status, invoke it
    //
    if(m_track_connection_status && m_inspector->get_observer())
    {
        m_inspector->get_observer()->on_connect(evt, packed_data);
    }
}

inline void sinsp_parser::fill_client_socket_info(sinsp_evt *evt, uint8_t *packed_data, bool overwrite_dest) {
    uint8_t family;
    const char *parstr;
    bool changed;

    //
    // Validate the family
    //
    family = *packed_data;

    //
    // Fill the fd with the socket info
    //
    if(family == PPM_AF_INET || family == PPM_AF_INET6)
    {
        if(family == PPM_AF_INET6)
        {
            //
            // Check to see if it's an IPv4-mapped IPv6 address
            // (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
            //
            uint8_t* sip = packed_data + 1;
            uint8_t* dip = packed_data + 19;

            if(!(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip)))
            {
                evt->m_fdinfo->m_type = SCAP_FD_IPV6_SOCK;
                changed = m_inspector->m_parser->set_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data, overwrite_dest);
            }
            else
            {
                evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
                changed = m_inspector->m_parser->set_ipv4_mapped_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data, overwrite_dest);
            }
        }
        else
        {
            evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;

            //
            // Update the FD info with this tuple
            //
            changed = m_inspector->m_parser->set_ipv4_addresses_and_ports(evt->m_fdinfo, packed_data, overwrite_dest);
        }

        if(changed && evt->m_fdinfo->is_role_server() && evt->m_fdinfo->is_udp_socket())
        {
            // connect done by a udp server, swap the addresses
            swap_addresses(evt->m_fdinfo);
        }

        //
        // Add the friendly name to the fd info
        //
		sinsp_utils::sockinfo_to_str(&evt->m_fdinfo->m_sockinfo,
										evt->m_fdinfo->m_type, &evt->m_paramstr_storage[0],
										(uint32_t)evt->m_paramstr_storage.size(),
										m_inspector->m_hostname_and_port_resolution_enabled);

		evt->m_fdinfo->m_name = &evt->m_paramstr_storage[0];
    }
    else
    {
        if(!evt->m_fdinfo->is_unix_socket())
        {
            //
            // This should happen only in case of a bug in our code, because I'm assuming that the OS
            // causes a connect with the wrong socket type to fail.
            // Assert in debug mode and just keep going in release mode.
            //
            ASSERT(false);
        }

        //
        // Add the friendly name to the fd info
        //
        evt->m_fdinfo->m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);

#ifndef HAS_ANALYZER
        //
        // Update the FD with this tuple
        //
        evt->m_fdinfo->set_unix_info(packed_data);
#endif
    }

    if(evt->m_fdinfo->is_role_none())
    {
        //
        // Mark this fd as a client
        //
        evt->m_fdinfo->set_role_client();
    }
}

void sinsp_parser::parse_connect_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	uint8_t *packed_data;
	std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	int64_t retval;
	int64_t fd;
	bool force_overwrite_stale_data = false;

	if(evt->m_fdinfo == NULL)
	{
		// Perhaps we dropped the connect enter event.
		// try harder to be resilient.
		if(evt->get_num_params() > 2)
		{
	                parinfo = evt->get_param(2);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			fd = *(int64_t *)parinfo->m_val;
			if(fd < 0)
			{
				//
				// Accept failure.
				// Do nothing.
				//
				return;
			}
			evt->m_tinfo->m_lastevent_fd = fd;
			evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
			if (evt->m_fdinfo == NULL)
			{
				// Ok this is a completely new fd;
				// we probably lost too many events.
				// Bye.
				return;
			}
			// ok we got stale data; we probably missed the connect enter event on this thread.
			// Force overwrite existing fdinfo socket data
			force_overwrite_stale_data = true;
		}
		else
		{
			return;
		}
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	retval = *(int64_t*)parinfo->m_val;

	if (m_track_connection_status)
	{
		if (retval == -SE_EINPROGRESS) {
			evt->m_fdinfo->set_socket_pending();
		} else if(retval < 0) {
			evt->m_fdinfo->set_socket_failed();
		} else {
			evt->m_fdinfo->set_socket_connected();
		}
	}
	else
	{
		if (retval < 0 && retval != -SE_EINPROGRESS)
		{
			return;
		}
		else
		{
			evt->m_fdinfo->set_socket_connected();
		}
	}

	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// Address can be NULL:
		// sk is a TCP fastopen active socket and
		// TCP_FASTOPEN_CONNECT sockopt is set and
		// we already have a valid cookie for this socket.
		//
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

    fill_client_socket_info(evt, packed_data, force_overwrite_stale_data);

	//
	// Call the protocol decoder callbacks associated to this event
	//
	std::vector<sinsp_protodecoder*>::iterator it;
	for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
	{
		(*it)->on_event(evt, CT_CONNECT);
	}

	//
	// If there's a listener callback, invoke it
	//
	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_connect(evt, packed_data);
	}
}

void sinsp_parser::parse_accept_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;
	uint8_t* packed_data;
	std::unordered_map<int64_t, sinsp_fdinfo_t>::iterator fdit;
	sinsp_fdinfo_t fdi;
	const char *parstr;

	//
	// Lookup the thread
	//
	if(evt->m_tinfo == nullptr)
	{
		ASSERT(false);
		return;
	}

	//
	// Extract the fd
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// Accept failure.
		// Do nothing.
		//
		return;
	}

	//
	// Update the last event fd. It's needed by the filtering engine
	//
	evt->m_tinfo->m_lastevent_fd = fd;

	//
	// Extract the address
	//
	parinfo = evt->get_param(1);
	if(parinfo->m_len == 0)
	{
		//
		// No address, there's nothing we can really do with this.
		// This happens for socket types that we don't support, so we have the assertion
		// to make sure that this is not a type of socket that we support.
		//
		return;
	}

	packed_data = (uint8_t*)parinfo->m_val;

	//
	// Populate the fd info class
	//
	if(*packed_data == PPM_AF_INET)
	{
		set_ipv4_addresses_and_ports(&fdi, packed_data);
		fdi.m_type = SCAP_FD_IPV4_SOCK;
		fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
	}
	else if(*packed_data == PPM_AF_INET6)
	{
		//
		// Check to see if it's an IPv4-mapped IPv6 address
		// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
		//
		uint8_t* sip = packed_data + 1;
		uint8_t* dip = packed_data + 19;

		if(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip))
		{
			set_ipv4_mapped_ipv6_addresses_and_ports(&fdi, packed_data);
			fdi.m_type = SCAP_FD_IPV4_SOCK;
			fdi.m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_TCP;
		}
		else
		{
			set_ipv6_addresses_and_ports(&fdi, packed_data);
			fdi.m_type = SCAP_FD_IPV6_SOCK;
			fdi.m_sockinfo.m_ipv6info.m_fields.m_l4proto = SCAP_L4_TCP;
		}
	}
	else if(*packed_data == PPM_AF_UNIX)
	{
		fdi.m_type = SCAP_FD_UNIX_SOCK;
		fdi.set_unix_info(packed_data);
	}
	else
	{
		//
		// Unsupported family
		//
		return;
	}

	fdi.m_name = evt->get_param_as_str(1, &parstr, sinsp_evt::PF_SIMPLE);
	fdi.m_flags = 0;

	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_accept(evt, fd, packed_data, &fdi);
	}

	//
	// Mark this fd as a server
	//
	fdi.set_role_server();

	//
	// Mark this fd as a connected socket
	//
	fdi.set_socket_connected();

	//
	// Add the entry to the table
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_close_enter(sinsp_evt *evt)
{
	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);
	if(evt->m_fdinfo == NULL)
	{
		return;
	}

	evt->m_fdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
}

//
// This function takes care of cleaning up the FD and removing it from all the tables
// (process FD table, connection table...).
// It's invoked when a close() or a thread exit happens.
//
void sinsp_parser::erase_fd(erase_fd_params* params)
{
	if(params->m_fdinfo == NULL)
	{
		//
		// This happens when more than one close has been canceled at the same time for
		// this thread. Since we currently handle just one canceling at at time (we
		// don't have a list of canceled closes, just a single entry), the second one
		// will generate a failed FD lookup. We do nothing.
		// NOTE: I do realize that this can cause a connection leak, I just assume that it's
		//       rare enough that the delayed connection cleanup (when the timestamp expires)
		//       is acceptable.
		//
		ASSERT(params->m_fd == CANCELED_FD_NUMBER);
		return;
	}

	//
	// Schedule the fd for removal
	//
	if(params->m_remove_from_table)
	{
		m_inspector->m_tid_of_fd_to_remove = params->m_tinfo->m_tid;
		m_inspector->m_fds_to_remove->push_back(params->m_fd);
	}

	if(m_inspector->get_observer())
	{
		m_inspector->get_observer()->on_erase_fd(params);
	}
}

void sinsp_parser::parse_close_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// If the close() was successful, do the cleanup
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL || evt->m_tinfo == nullptr)
		{
			return;
		}

		//
		// a close gets canceled when the same fd is created successfully between
		// close enter and close exit.
		//
		erase_fd_params eparams;

		if(evt->m_fdinfo->m_flags & sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED)
		{
			evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_CANCELED;
			eparams.m_fd = CANCELED_FD_NUMBER;
			eparams.m_fdinfo = evt->m_tinfo->get_fd(CANCELED_FD_NUMBER);
		}
		else
		{
			eparams.m_fd = evt->m_tinfo->m_lastevent_fd;
			eparams.m_fdinfo = evt->m_fdinfo;
		}

		//
		// Remove the fd from the different tables
		//
		eparams.m_remove_from_table = true;
		eparams.m_tinfo = evt->m_tinfo;
		eparams.m_ts = evt->get_ts();

		erase_fd(&eparams);
	}
	else
	{
		if(evt->m_fdinfo != NULL)
		{
			evt->m_fdinfo->m_flags &= ~sinsp_fdinfo_t::FLAGS_CLOSE_IN_PROGRESS;
		}

		//
		// It is normal when a close fails that the fd lookup failed, so we revert the
		// increment of m_n_failed_fd_lookups (for the enter event too if there's one).
		//
#ifdef GATHER_INTERNAL_STATS
		m_inspector->m_stats->m_n_failed_fd_lookups--;
#endif
		if(evt->m_tinfo && evt->m_tinfo->is_lastevent_data_valid())
		{
#ifdef GATHER_INTERNAL_STATS
			m_inspector->m_stats->m_n_failed_fd_lookups--;
#endif
		}
	}
}

void sinsp_parser::add_pipe(sinsp_evt *evt, int64_t fd, uint64_t ino, uint32_t openflags)
{
	//
	// lookup the thread info
	//
	if(!evt->m_tinfo)
	{
		return;
	}

	//
	// Populate the new fdi
	//
	sinsp_fdinfo_t fdi = {};
	fdi.m_type = SCAP_FD_FIFO;
	fdi.m_ino = ino;
	fdi.m_openflags = openflags;

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_socketpair_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd1, fd2;
	int64_t retval;
	uint64_t source_address;
	uint64_t peer_address;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		//
		// socketpair() failed. Nothing to add to the table.
		//
		return;
	}

	if(evt->m_tinfo == nullptr)
	{
		// There is nothing we can do here if tinfo is missing
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd1 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd2 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	source_address = *(uint64_t *)parinfo->m_val;

	parinfo = evt->get_param(4);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	peer_address = *(uint64_t *)parinfo->m_val;

	sinsp_fdinfo_t fdi;
	fdi.m_type = SCAP_FD_UNIX_SOCK;
	fdi.m_sockinfo.m_unixinfo.m_fields.m_source = source_address;
	fdi.m_sockinfo.m_unixinfo.m_fields.m_dest = peer_address;
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd1, &fdi);
	evt->m_tinfo->add_fd(fd2, &fdi);
}

void sinsp_parser::parse_pipe_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd1, fd2;
	int64_t retval;
	uint64_t ino;
	uint32_t openflags = 0;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		//
		// pipe() failed. Nothing to add to the table.
		//
		return;
	}

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd1 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd2 = *(int64_t *)parinfo->m_val;

	parinfo = evt->get_param(3);
	ASSERT(parinfo->m_len == sizeof(uint64_t));
	ino = *(uint64_t *)parinfo->m_val;

	if(evt->get_type() == PPME_SYSCALL_PIPE2_X)
	{
		parinfo = evt->get_param(4);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		openflags = *(uint32_t *)parinfo->m_val;
	}

	add_pipe(evt, fd1, ino, openflags);
	add_pipe(evt, fd2, ino, openflags);
}


void sinsp_parser::parse_thread_exit(sinsp_evt *evt)
{
	/* We set the `m_tinfo` in `reset()`.
	 * If we don't have the thread info we do nothing, this thread is already deleted
	 */
	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	/* [Mark thread as dead]
	 * We mark the thread as dead here and we will remove it 
	 * from the table during remove_thread().
	 * Please note that the `!evt->m_tinfo->is_dead()` shouldn't be
	 * necessary at all since here we shouldn't receive dead threads.
	 * This is first place where we mark threads as dead.
	 */
	if(evt->m_tinfo->m_tginfo != nullptr && !evt->m_tinfo->is_dead())
	{
		evt->m_tinfo->m_tginfo->decrement_thread_count();
	}
	evt->m_tinfo->set_dead();

	/* [Store the tid to remove] 
	 * We set the current tid to remove. We don't remove it here so we can parse the event
	 */
	m_inspector->m_tid_to_remove = evt->get_tid();

	/* If this thread has no children we don't send the reaper info from the kernel,
	 * so we do nothing.
	 */
	if(evt->m_tinfo->m_children.size() == 0)
	{
		return;
	}

	/* [Set the reaper to the current thread]
	 * We need to set the reaper for this thread
	 */
	if(evt->get_type() == PPME_PROCEXIT_1_E && evt->get_num_params() > 4)
	{
		sinsp_evt_param *parinfo = evt->get_param(4);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		evt->m_tinfo->m_reaper_tid = *(int64_t *)parinfo->m_val;
	}
	else
	{
		evt->m_tinfo->m_reaper_tid = -1;
	}
}

inline bool sinsp_parser::update_ipv4_addresses_and_ports(sinsp_fdinfo_t* fdinfo,
	uint32_t tsip, uint16_t tsport, uint32_t tdip, uint16_t tdport, bool overwrite_dest)
{
	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		if((tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport) ||
			(tdip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip &&
			tdport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport &&
			tsip == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip &&
			tsport == fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport)
			)
		{
			return false;
		}
	}

	bool changed = false;

	if(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip != tsip) {
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip = tsip;
		changed = true;
	}

	if(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport != tsport) {
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport = tsport;
		changed = true;
	}

	if(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip == 0 ||
		(overwrite_dest && fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip != tdip)) {
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = tdip;
		changed = true;
	}

	if(fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport == 0 ||
		(overwrite_dest && fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport != tdport)) {
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = tdport;
		changed = true;
	}

	return changed;
}

bool sinsp_parser::set_ipv4_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data, bool overwrite_dest)
{
	uint32_t tsip, tdip;
	uint16_t tsport, tdport;

	memcpy(&tsip, packed_data + 1, sizeof(uint32_t));
	memcpy(&tsport, packed_data + 5, sizeof(uint16_t));
	memcpy(&tdip, packed_data + 7, sizeof(uint32_t));
	memcpy(&tdport, packed_data + 11, sizeof(uint16_t));

	return update_ipv4_addresses_and_ports(fdinfo, tsip, tsport, tdip, tdport, overwrite_dest);
}

bool sinsp_parser::set_ipv4_mapped_ipv6_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data, bool overwrite_dest)
{
	uint32_t tsip, tdip;
	uint16_t tsport, tdport;

	tsip = *(uint32_t *)(packed_data + 13);
	tsport = *(uint16_t *)(packed_data + 17);
	tdip = *(uint32_t *)(packed_data + 31);
	tdport = *(uint16_t *)(packed_data + 35);

	return update_ipv4_addresses_and_ports(fdinfo, tsip, tsport, tdip, tdport, overwrite_dest);
}

bool sinsp_parser::set_ipv6_addresses_and_ports(sinsp_fdinfo_t* fdinfo, uint8_t* packed_data, bool overwrite_dest)
{
	ipv6addr tsip, tdip;
	uint16_t tsport, tdport;

	memcpy((uint8_t *) tsip.m_b, packed_data + 1, sizeof(tsip.m_b));
	tsport = *(uint16_t *)(packed_data + 17);

	memcpy((uint8_t *) tdip.m_b, packed_data + 19, sizeof(tdip.m_b));
	tdport = *(uint16_t *)(packed_data + 35);

	if(fdinfo->m_type == SCAP_FD_IPV6_SOCK)
	{
		if((tsip == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip &&
			tsport == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport &&
			tdip == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip &&
			tdport == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport) ||
			(tdip == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip &&
			tdport == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport &&
			tsip == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip &&
			tsport == fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport)
			)
		{
			return false;
		}
	}

	bool changed = false;

	if(fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip != tsip) {
		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip = tsip;
		changed = true;
	}

	if(fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport != tsport) {
		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport = tsport;
		changed = true;
	}

	if(fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip == ipv6addr::empty_address ||
		(overwrite_dest && fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip != tdip)) {
		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip = tdip;
		changed = true;
	}

	if(fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport == 0 ||
		(overwrite_dest && fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport != tdport)) {
		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport = tdport;
		changed = true;
	}

	return changed;
}


// Return false if the update didn't happen (for example because the tuple is NULL)
bool sinsp_parser::update_fd(sinsp_evt *evt, sinsp_evt_param *parinfo)
{
	uint8_t* packed_data = (uint8_t*)parinfo->m_val;
	uint8_t family = *packed_data;

	if(parinfo->m_len == 0)
	{
		return false;
	}

	if(family == PPM_AF_INET)
	{
		if(evt->m_fdinfo->m_type == SCAP_FD_IPV4_SERVSOCK)
		{
			//
			// If this was previously a server socket, propagate the L4 protocol
			//
			evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto =
				evt->m_fdinfo->m_sockinfo.m_ipv4serverinfo.m_l4proto;
		}

		evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;
		if(set_ipv4_addresses_and_ports(evt->m_fdinfo, packed_data) == false)
		{
			return false;
		}
	}
	else if(family == PPM_AF_INET6)
	{
		//
		// Check to see if it's an IPv4-mapped IPv6 address
		// (http://en.wikipedia.org/wiki/IPv6#IPv4-mapped_IPv6_addresses)
		//
		uint8_t* sip = packed_data + 1;
		uint8_t* dip = packed_data + 19;

		if(sinsp_utils::is_ipv4_mapped_ipv6(sip) && sinsp_utils::is_ipv4_mapped_ipv6(dip))
		{
			evt->m_fdinfo->m_type = SCAP_FD_IPV4_SOCK;

			if(set_ipv4_mapped_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data) == false)
			{
				return false;
			}
		}
		else
		{
			// It's not an ipv4-mapped ipv6 address. Extract it as a normal address.
			if(set_ipv6_addresses_and_ports(evt->m_fdinfo, packed_data) == false)
			{
				return false;
			}
		}
	}
	else if(family == PPM_AF_UNIX)
	{
		evt->m_fdinfo->m_type = SCAP_FD_UNIX_SOCK;
		evt->m_fdinfo->set_unix_info(packed_data);
		evt->m_fdinfo->m_name = ((char*)packed_data) + 17;

		//
		// Call the protocol decoder callbacks to notify the decoders that this FD
		// changed.
		//
		std::vector<sinsp_protodecoder*>::iterator it;
		for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
		{
			(*it)->on_event(evt, CT_TUPLE_CHANGE);
		}

		return true;
	}

	//
	// If we reach this point and the protocol is not set yet, we assume this
	// connection is UDP, because TCP would fail if the address is changed in
	// the middle of a connection.
	//
	if(evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		if(evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto == SCAP_L4_UNKNOWN)
		{
			evt->m_fdinfo->m_sockinfo.m_ipv4info.m_fields.m_l4proto = SCAP_L4_UDP;
		}
	}
	else if(evt->m_fdinfo->m_type == SCAP_FD_IPV6_SOCK)
	{
		if(evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_l4proto == SCAP_L4_UNKNOWN)
		{
			evt->m_fdinfo->m_sockinfo.m_ipv6info.m_fields.m_l4proto = SCAP_L4_UDP;
		}
	}

	//
	// If this is an incomplete tuple, patch it using interface info
	//
	m_inspector->m_network_interfaces.update_fd(evt->m_fdinfo);

	//
	// Call the protocol decoder callbacks to notify the decoders that this FD
	// changed.
	//
	std::vector<sinsp_protodecoder*>::iterator it;
	for(it = m_connect_callbacks.begin(); it != m_connect_callbacks.end(); ++it)
	{
		(*it)->on_event(evt, CT_TUPLE_CHANGE);
	}

	return true;
}

void sinsp_parser::swap_addresses(sinsp_fdinfo_t* fdinfo)
{
	if(fdinfo->m_type == SCAP_FD_IPV4_SOCK)
	{
		uint32_t tip;
		uint16_t tport;

		tip = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip;
		tport = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport;
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sip = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip;
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_sport = fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport;
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dip = tip;
		fdinfo->m_sockinfo.m_ipv4info.m_fields.m_dport = tport;
	}
	else
	{
		ipv6addr tip;
		uint16_t tport;

		tip = fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip;
		tport = fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport;

		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sip = fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip;;
		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_sport = fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport;

		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dip = tip;
		fdinfo->m_sockinfo.m_ipv6info.m_fields.m_dport = tport;
	}
}

uint32_t sinsp_parser::parse_tracer(sinsp_evt *evt, int64_t retval)
{
	sinsp_threadinfo* tinfo = evt->m_tinfo;
	ASSERT(tinfo);

	//
	// Extract the data buffer
	//
	sinsp_evt_param *parinfo = evt->get_param(1);
	char* data = parinfo->m_val;
	uint32_t datalen = parinfo->m_len;
	sinsp_tracerparser* p = tinfo->m_tracer_parser;

	if(p == NULL)
	{
		p = tinfo->m_tracer_parser = new sinsp_tracerparser(m_inspector);
	}

	p->m_tinfo = tinfo;

	p->process_event_data(data, datalen, evt->get_ts());

	if(p->m_res == sinsp_tracerparser::RES_TRUNCATED)
	{
		if(!m_inspector->m_is_dumping)
		{
			evt->m_filtered_out = true;
		}

		return p->m_res;
	}

	p->m_args.first = &p->m_argnames;
	p->m_args.second = &p->m_argvals;

	//
	// Populate the user event that we will send up the stack instead of the write
	//
	uint8_t* fakeevt_storage = (uint8_t*)m_fake_userevt;
	m_fake_userevt->ts = evt->m_pevt->ts;
	m_fake_userevt->tid = evt->m_pevt->tid;
	m_fake_userevt->nparams = 3;

	if(p->m_res == sinsp_tracerparser::RES_OK)
	{
		if(p->m_type_str[0] == '>')
		{
			m_fake_userevt->type = PPME_TRACER_E;
		}
		else
		{
			m_fake_userevt->type = PPME_TRACER_X;
		}

		uint16_t *lens = (uint16_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr));
		lens[0] = 8;
		lens[1] = 8;
		lens[2] = 8;

		*(uint64_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr) + 6) = p->m_id;
		*(uint64_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr) + 14) = (uint64_t)&p->m_tags;
		*(uint64_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr) + 22) = (uint64_t)&p->m_args;
	}
	else
	{
		uint32_t flags = evt->m_fdinfo->m_flags;

		if(!(flags & sinsp_fdinfo_t::FLAGS_IS_TRACER_FD))
		{
			return p->m_res;
		}

		//
		// Parsing error.
		// We don't know the direction, so we use enter.
		//
		p->m_argnames.clear();
		p->m_argvals.clear();

		m_fake_userevt->type = PPME_TRACER_E;

		uint16_t *lens = (uint16_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr));
		lens[0] = 8;
		lens[1] = 8;
		lens[2] = 8;

		p->m_tags.clear();
		m_tracer_error_string = "invalid tracer " + std::string(data, datalen) + ", len" + std::to_string(datalen);
		p->m_tags.push_back((char*)m_tracer_error_string.c_str());
		*(uint64_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr) + 6) = 0;
		*(uint64_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr) + 14) = (uint64_t)&p->m_tags;
		*(uint64_t *)(fakeevt_storage + sizeof(struct ppm_evt_hdr) + 22) = (uint64_t)&p->m_args;
	}

	scap_evt* tevt = evt->m_pevt;
	evt->m_pevt = m_fake_userevt;
	evt->init();
	evt->m_poriginal_evt = tevt;
	evt->m_flags |= (uint32_t)sinsp_evt::SINSP_EF_IS_TRACER;

	//
	// Update some thread information
	//
	tinfo->m_lastevent_fd = -1;
	tinfo->m_lastevent_type = PPME_TRACER_E;
	tinfo->m_latency = 0;
	tinfo->m_last_latency_entertime = 0;

	return p->m_res;
}

bool sinsp_parser::detect_and_process_tracer_write(sinsp_evt *evt,
	int64_t retval,
	ppm_event_flags eflags)
{
	//
	// Tracers get into the engine as normal writes, but the FD has a flag to
	// quickly recognize them.
	//
	uint32_t flags = evt->m_fdinfo->m_flags;

	if(!(flags & sinsp_fdinfo_t::FLAGS_IS_NOT_TRACER_FD))
	{
		sinsp_fdinfo_t* orifdinfo = evt->m_fdinfo;
		if(orifdinfo->m_flags & sinsp_fdinfo_t::FLAGS_IS_TRACER_FD)
		{
			parse_tracer(evt, retval);
			return true;
		}
		else
		{
			if(orifdinfo->m_flags & sinsp_fdinfo_t::FLAGS_IS_TRACER_FILE)
			{
				if(eflags & EF_WRITES_TO_FD)
				{
					//
					// We have not determined if this FD is a tracer FD or not.
					// We're going to try to parse it.
					// If the parsing succeeds, we mark it as a tracer FD. If it
					// fails we mark it an NOT a tracer FD. Otherwise, we wait
					// for the next buffer and we'll try again.
					//
					sinsp_tracerparser::parse_result pres =
						(sinsp_tracerparser::parse_result)parse_tracer(evt, retval);

					if(pres == sinsp_tracerparser::RES_OK)
					{
						//
						// This FD has been recognized to be a tracer one.
						// We do two things: mark it for future reference, and tell
						// the driver to enable tracers capture (if we haven't done
						// it yet).
						//
						orifdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_IS_TRACER_FD;
						m_inspector->enable_tracers_capture();
						return true;
					}
					else if (pres == sinsp_tracerparser::RES_FAILED)
					{
						orifdinfo->m_flags |= sinsp_fdinfo_t::FLAGS_IS_NOT_TRACER_FD;
					}
				}
			}
		}
	}

	return false;
}

void sinsp_parser::parse_fspath_related_exit(sinsp_evt* evt)
{
	sinsp_evt *enter_evt = &m_tmp_evt;
	if(retrieve_enter_event(enter_evt, evt))
	{
		evt->save_enter_event_params(enter_evt);
	}
}

void sinsp_parser::parse_rw_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	int64_t tid = evt->get_tid();
	sinsp_evt *enter_evt = &m_tmp_evt;
	ppm_event_flags eflags = evt->get_info_flags();

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	if(evt->m_fdinfo == NULL)
	{
		if(m_inspector->is_capture())
		{
			if((evt->get_dump_flags() & SCAP_DF_TRACER) != 0)
			{
				parse_tracer(evt, retval);
				return;
			}
		}

		return;
	}

	//
	// Check if this is a tracer write on /dev/null, treat it in a special way
	//
	if(detect_and_process_tracer_write(evt, retval, eflags))
	{
		return;
	}

	//
	// If the operation was successful, validate that the fd exists
	//
	if(retval >= 0)
	{
		uint16_t etype = evt->get_type();

		if (evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
		    evt->m_fdinfo->m_type == SCAP_FD_IPV6_SOCK) {
			evt->m_fdinfo->set_socket_connected();
		}

		if(eflags & EF_READS_FROM_FD)
		{
			char *data;
			uint32_t datalen;
			int32_t tupleparam = -1;

			if(etype == PPME_SOCKET_RECVFROM_X)
			{
				tupleparam = 2;
			}
			else if(etype == PPME_SOCKET_RECVMSG_X)
			{
				tupleparam = 3;
			}

			if(tupleparam != -1 && (evt->m_fdinfo->m_name.length() == 0 || !evt->m_fdinfo->is_tcp_socket()))
			{
				//
				// recvfrom contains tuple info.
				// If the fd still doesn't contain tuple info (because the socket is a
				// datagram one or because some event was lost),
				// add it here.
				//
				if(update_fd(evt, evt->get_param(tupleparam)))
				{
					const char *parstr;

					scap_fd_type fdtype = evt->m_fdinfo->m_type;

					if(fdtype == SCAP_FD_IPV4_SOCK ||
					   fdtype == SCAP_FD_IPV6_SOCK)
					{
						if(evt->m_fdinfo->is_role_none())
						{
								evt->m_fdinfo->set_net_role_by_guessing(m_inspector,
									evt->m_tinfo,
									evt->m_fdinfo,
									true);
						}

						if(evt->m_fdinfo->is_role_client())
						{
							swap_addresses(evt->m_fdinfo);
						}

						sinsp_utils::sockinfo_to_str(&evt->m_fdinfo->m_sockinfo,
							fdtype, &evt->m_paramstr_storage[0],
							(uint32_t)evt->m_paramstr_storage.size(),
							m_inspector->m_hostname_and_port_resolution_enabled);

						evt->m_fdinfo->m_name = &evt->m_paramstr_storage[0];
					}
					else
					{
						evt->m_fdinfo->m_name = evt->get_param_as_str(tupleparam, &parstr, sinsp_evt::PF_SIMPLE);
					}
				}
			}

			//
			// Extract the data buffer
			//
			if(etype == PPME_SYSCALL_READV_X || etype == PPME_SYSCALL_PREADV_X || etype == PPME_SOCKET_RECVMSG_X)
			{
				parinfo = evt->get_param(2);
			}
			else
			{
				parinfo = evt->get_param(1);
			}

			datalen = parinfo->m_len;
			data = parinfo->m_val;

			//
			// If there's an fd listener, call it now
			//
			if(m_inspector->get_observer())
			{
				m_inspector->get_observer()->on_read(evt, tid, evt->m_tinfo->m_lastevent_fd, evt->m_fdinfo,
					data, (uint32_t)retval, datalen);
			}

			//
			// Call the protocol decoder callbacks associated to this event
			//
			if(evt->m_fdinfo->m_callbacks)
			{
				std::vector<sinsp_protodecoder*>* cbacks = &(evt->m_fdinfo->m_callbacks->m_read_callbacks);

				for(auto it = cbacks->begin(); it != cbacks->end(); ++it)
				{
					(*it)->on_read(evt, data, datalen);
				}
			}
		}
		else
		{
			char *data;
			uint32_t datalen;
			int32_t tupleparam = -1;

			if(etype == PPME_SOCKET_SENDTO_X || etype == PPME_SOCKET_SENDMSG_X)
			{
				tupleparam = 2;
			}

			if(tupleparam != -1 && (evt->m_fdinfo->m_name.length() == 0 || !evt->m_fdinfo->is_tcp_socket()))
			{
				//
				// sendto contains tuple info in the enter event.
				// If the fd still doesn't contain tuple info (because the socket is a datagram one or because some event was lost),
				// add it here.
				//
				if(!retrieve_enter_event(enter_evt, evt))
				{
					return;
				}

				if(update_fd(evt, enter_evt->get_param(tupleparam)))
				{
					const char *parstr;

					scap_fd_type fdtype = evt->m_fdinfo->m_type;

					if(fdtype == SCAP_FD_IPV4_SOCK ||
					   fdtype == SCAP_FD_IPV6_SOCK)
					{
						if(evt->m_fdinfo->is_role_none())
						{
								evt->m_fdinfo->set_net_role_by_guessing(m_inspector,
									evt->m_tinfo,
									evt->m_fdinfo,
									false);
						}

						if(evt->m_fdinfo->is_role_server())
						{
							swap_addresses(evt->m_fdinfo);
						}

						sinsp_utils::sockinfo_to_str(&evt->m_fdinfo->m_sockinfo,
							fdtype, &evt->m_paramstr_storage[0],
							(uint32_t)evt->m_paramstr_storage.size(),
							m_inspector->m_hostname_and_port_resolution_enabled);

						evt->m_fdinfo->m_name = &evt->m_paramstr_storage[0];
					}
					else
					{
						evt->m_fdinfo->m_name = enter_evt->get_param_as_str(tupleparam, &parstr, sinsp_evt::PF_SIMPLE);
					}
				}
			}

			//
			// Extract the data buffer
			//
			parinfo = evt->get_param(1);
			datalen = parinfo->m_len;
			data = parinfo->m_val;

			//
			// If there's an fd listener, call it now
			//
			if(m_inspector->get_observer())
			{
				m_inspector->get_observer()->on_write(evt, tid, evt->m_tinfo->m_lastevent_fd, evt->m_fdinfo,
					data, (uint32_t)retval, datalen);
			}

			//
			// Call the protocol decoder callbacks associated to this event
			//
			if(evt->m_fdinfo->m_callbacks)
			{
				std::vector<sinsp_protodecoder*>* cbacks = &(evt->m_fdinfo->m_callbacks->m_write_callbacks);

				for(auto it = cbacks->begin(); it != cbacks->end(); ++it)
				{
					(*it)->on_write(evt, data, datalen);
				}
			}
		}
	} else if (m_track_connection_status) {
		if (evt->m_fdinfo->m_type == SCAP_FD_IPV4_SOCK ||
		    evt->m_fdinfo->m_type == SCAP_FD_IPV6_SOCK) {
			evt->m_fdinfo->set_socket_failed();
			if (m_inspector->get_observer())
			{
				m_inspector->get_observer()->on_socket_status_changed(evt);
			}
		}
	}
}

void sinsp_parser::parse_sendfile_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	if(!evt->m_fdinfo)
	{
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the operation was successful, validate that the fd exists
	//
	if(retval >= 0)
	{
		sinsp_evt *enter_evt = &m_tmp_evt;
		int64_t fdin;

		if(!retrieve_enter_event(enter_evt, evt))
		{
			return;
		}

		//
		// Extract the in FD
		//
		parinfo = enter_evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(int64_t));
		fdin = *(int64_t *)parinfo->m_val;

		//
		// If there's an fd listener, call it now
		//
		if(m_inspector->get_observer())
		{
			m_inspector->get_observer()->on_sendfile(evt, fdin, (uint32_t)retval);
		}
	}
}

void sinsp_parser::parse_eventfd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t fd;

	//
	// lookup the thread info
	//
	if(evt->m_tinfo == nullptr)
	{
		ASSERT(false);
		return;
	}

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	fd = *(int64_t *)parinfo->m_val;

	if(fd < 0)
	{
		//
		// eventfd() failed. Nothing to add to the table.
		//
		return;
	}

	//
	// Populate the new fdi
	//
	sinsp_fdinfo_t fdi = {};
	fdi.m_type = SCAP_FD_EVENT;

	if(evt->get_type() == PPME_SYSCALL_EVENTFD2_X)
	{
		parinfo = evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		fdi.m_openflags = *(uint16_t *)parinfo->m_val;
	}

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_chdir_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// In case of success, update the thread working dir
	//
	if(retval >= 0)
	{
		sinsp_evt_param *parinfo;

		// Update the thread working directory
		parinfo = evt->get_param(1);
		evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
	}
}

void sinsp_parser::parse_fchdir_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// In case of success, update the thread working dir
	//
	if(retval >= 0)
	{
		//
		// Find the fd name
		//
		if(evt->m_fdinfo == NULL || evt->m_tinfo == nullptr)
		{
			return;
		}

		// Update the thread working directory
		evt->m_tinfo->set_cwd((char *)evt->m_fdinfo->m_name.c_str(),
		                 (uint32_t)evt->m_fdinfo->m_name.size());
	}
}

void sinsp_parser::parse_getcwd_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		if(evt->m_tinfo == nullptr)
		{
			//
			// No thread in the table. We won't store this event, which mean that
			// we won't be able to parse the corresponding exit event and we'll have
			// to drop the information it carries.
			//
			ASSERT(false);
			return;
		}

		parinfo = evt->get_param(1);

#ifdef _DEBUG
		std::string chkstr = std::string(parinfo->m_val);

		if(chkstr != "/")
		{
			if(chkstr + "/"  != evt->m_tinfo->get_cwd())
			{
				//
				// This shouldn't happen, because we should be able to stay in synch by
				// following chdir(). If it does, it's almost sure there was an event drop.
				// In that case, we use this value to update the thread cwd.
				//
#if defined(HAS_CAPTURE) && !defined(_WIN32)
#ifdef _DEBUG
				int target_res;
				char target_name[1024];
				target_res = readlink((chkstr + "/").c_str(),
					target_name,
					sizeof(target_name) - 1);

				if(target_res > 0)
				{
					target_name[target_res] = '\0';
					if(target_name != evt->m_tinfo->get_cwd())
					{
						printf("%s != %s", target_name, evt->m_tinfo->get_cwd().c_str());
						ASSERT(false);
					}
				}

#endif
#endif
			}
		}
#endif

		evt->m_tinfo->set_cwd(parinfo->m_val, parinfo->m_len);
	}
}

void sinsp_parser::parse_shutdown_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	retval = *(int64_t *)parinfo->m_val;

	//
	// If the operation was successful, do the cleanup
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		if(m_inspector->get_observer())
		{
			m_inspector->get_observer()->on_socket_shutdown(evt);
		}
	}
}

void sinsp_parser::parse_dup_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		//
		// Heuristic to determine if a thread is part of a shell pipe
		//
		if(retval == 0)
		{
			evt->m_tinfo->m_flags |= PPM_CL_PIPE_DST;
		}
		if(retval == 1)
		{
			evt->m_tinfo->m_flags |= PPM_CL_PIPE_SRC;
		}

		if(evt->m_fdinfo == NULL)
		{
			return;
		}
		//
		// If the old FD is in the table, remove it properly.
		// The old FD is:
		// 	- dup(): fd number of a previously closed fd that has not been removed from the fd_table
		//		     and has been reassigned to the newly created fd by dup()(very rare condition);
		//  - dup2(): fd number of an existing fd that we pass to the dup2() as the "newfd". dup2()
	    //			  will close the existing one. So we need to clean it up / overwrite;
		//  - dup3(): same as dup2().
		//
		sinsp_fdinfo_t* oldfdinfo = evt->m_tinfo->get_fd(retval);

		if(oldfdinfo != NULL)
		{
			erase_fd_params eparams;

			eparams.m_fd = retval;
			eparams.m_fdinfo = oldfdinfo;
			eparams.m_remove_from_table = false;
			eparams.m_tinfo = evt->m_tinfo;
			eparams.m_ts = evt->get_ts();

			erase_fd(&eparams);
		}

		//
		// If we are handling the dup3() event exit then we add the flags to the new file descriptor.
		//
		if (evt->get_type() == PPME_SYSCALL_DUP3_X){
			uint32_t flags;

			//
			// Get the flags parameter.
			//
			parinfo = evt->get_param(3);
			ASSERT(parinfo->m_len == sizeof(uint32_t));
			flags = *(uint32_t *)parinfo->m_val;

			//
			// We keep the previously flags that has been set on the original file descriptor and
			// just set/reset O_CLOEXEC flag base on the value received by dup3() syscall.
			//
			if (flags){
				//
				// set the O_CLOEXEC flag.
				//
				evt->m_fdinfo->m_openflags |= flags;
			}else{
				//
				// reset the O_CLOEXEC flag.
				//
				evt->m_fdinfo->m_openflags &= ~PPM_O_CLOEXEC;
			}

		}

		//
		// Add the new fd to the table.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, evt->m_fdinfo);
	}
}

void sinsp_parser::parse_single_param_fd_exit(sinsp_evt* evt, scap_fd_type type)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	//
	// Check if the syscall was successful
	//
	if(retval < 0)
	{
		return;
	}

	sinsp_fdinfo_t fdi = {};

	//
	// Populate the new fdi
	//
	fdi.m_type = type;

	if(evt->get_type() == PPME_SYSCALL_INOTIFY_INIT1_X)
	{
		parinfo = evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		fdi.m_openflags = *(uint16_t *)parinfo->m_val;
	}

	if(evt->get_type() == PPME_SYSCALL_SIGNALFD4_X)
	{
		parinfo = evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint16_t));
		fdi.m_openflags = *(uint16_t *)parinfo->m_val;
	}

	//
	// Add the fd to the table.
	//
	evt->m_fdinfo = evt->m_tinfo->add_fd(retval, &fdi);
}

void sinsp_parser::parse_getrlimit_setrlimit_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;
	uint8_t resource;
	int64_t curval;

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		//
		// Load the enter event so we can access its arguments
		//
		if(!retrieve_enter_event(enter_evt, evt))
		{
			return;
		}

		//
		// Extract the resource number
		//
		parinfo = enter_evt->get_param(0);
		resource = *(uint8_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint8_t));

		if(resource == PPM_RLIMIT_NOFILE)
		{
			//
			// Extract the current value for the resource
			//
			parinfo = evt->get_param(1);
			curval = *(uint64_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint64_t));

			if(curval != -1)
			{
				auto main_thread = evt->m_tinfo->get_main_thread();
				if(main_thread == nullptr)
				{
					return;
				}
				main_thread->m_fdlimit = curval;
			}
			else
			{
				ASSERT(false);
			}
		}
	}
}

void sinsp_parser::parse_prlimit_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;
	uint8_t resource;
	int64_t newcur;
	int64_t tid;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		//
		// Load the enter event so we can access its arguments
		//
		if(!retrieve_enter_event(enter_evt, evt))
		{
			return;
		}

		//
		// Extract the resource number
		//
		parinfo = enter_evt->get_param(1);
		resource = *(uint8_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint8_t));

		if(resource == PPM_RLIMIT_NOFILE)
		{
			//
			// Extract the current value for the resource
			//
			parinfo = evt->get_param(1);
			newcur = *(uint64_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint64_t));

			if(newcur != -1)
			{
				//
				// Extract the tid and look for its process info
				//
				parinfo = enter_evt->get_param(0);
				tid = *(int64_t *)parinfo->m_val;
				ASSERT(parinfo->m_len == sizeof(int64_t));

				if(tid == 0)
				{
					tid = evt->get_tid();
				}

				sinsp_threadinfo* ptinfo = m_inspector->get_thread_ref(tid, true, true).get();
				/* If the thread info is invalid we cannot recover the main thread because we don't even
				 * have the `pid` of the thread.
				 */
				if(ptinfo == nullptr || ptinfo->is_invalid())
				{
					ASSERT(false);
					return;
				}

				//
				// update the process fdlimit
				//
				auto main_thread = ptinfo->get_main_thread();
				if(main_thread == nullptr)
				{
					return;
				}
				main_thread->m_fdlimit = newcur;
			}
		}
	}
}

void sinsp_parser::parse_select_poll_epollwait_enter(sinsp_evt *evt)
{
	if(evt->m_tinfo == nullptr)
	{
		ASSERT(false);
		return;
	}

	if(evt->m_tinfo->m_lastevent_data == NULL)
	{
		evt->m_tinfo->m_lastevent_data = reserve_event_buffer();
		if(evt->m_tinfo->m_lastevent_data == NULL)
		{
			throw sinsp_exception("cannot reserve event buffer in sinsp_parser::parse_select_poll_epollwait_enter.");
		}
	}
	*(uint64_t*)evt->m_tinfo->m_lastevent_data = evt->get_ts();
}
void sinsp_parser::parse_fcntl_enter(sinsp_evt *evt)
{
	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	sinsp_evt_param *parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int8_t));
	uint8_t cmd = *(int8_t *)parinfo->m_val;

	if(cmd == PPM_FCNTL_F_DUPFD || cmd == PPM_FCNTL_F_DUPFD_CLOEXEC)
	{
		store_event(evt);
	}
}

void sinsp_parser::parse_fcntl_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	//
	// If this is not a F_DUPFD or F_DUPFD_CLOEXEC command, ignore it
	//
	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	//
	// Check if the syscall was successful
	//
	if(retval >= 0)
	{
		if(evt->m_fdinfo == NULL)
		{
			return;
		}

		//
		// Add the new fd to the table.
		// NOTE: dup2 and dup3 accept an existing FD and in that case they close it.
		//       For us it's ok to just overwrite it.
		//
		evt->m_fdinfo = evt->m_tinfo->add_fd(retval, evt->m_fdinfo);
	}
}

void sinsp_parser::parse_context_switch(sinsp_evt* evt)
{
	if(evt->m_tinfo != nullptr)
	{
		sinsp_evt_param *parinfo;
		parinfo = evt->get_param(1);
		evt->m_tinfo->m_pfmajor = *(uint64_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint64_t));

		parinfo = evt->get_param(2);
		evt->m_tinfo->m_pfminor = *(uint64_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint64_t));

		auto main_tinfo = evt->m_tinfo->get_main_thread();
		if(main_tinfo)
		{
			parinfo = evt->get_param(3);
			main_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint32_t));

			parinfo = evt->get_param(4);
			main_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint32_t));

			parinfo = evt->get_param(5);
			main_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
			ASSERT(parinfo->m_len == sizeof(uint32_t));
		}
	}
}

void sinsp_parser::parse_brk_munmap_mmap_exit(sinsp_evt* evt)
{
	ASSERT(evt->m_tinfo);
	if(evt->m_tinfo != nullptr)
	{
		sinsp_evt_param *parinfo;

		parinfo = evt->get_param(1);
		evt->m_tinfo->m_vmsize_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));

		parinfo = evt->get_param(2);
		evt->m_tinfo->m_vmrss_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));

		parinfo = evt->get_param(3);
		evt->m_tinfo->m_vmswap_kb = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));
	}
}

void sinsp_parser::parse_setresuid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_euid = *(uint32_t *)parinfo->m_val;

		if(new_euid < std::numeric_limits<uint32_t>::max())
		{
			if (evt->get_thread_info()) {
				evt->get_thread_info()->set_user(new_euid);
			}
		}
	}
}

void sinsp_parser::parse_setresgid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(1);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_egid = *(uint32_t *)parinfo->m_val;

		if(new_egid < std::numeric_limits<uint32_t>::max())
		{
			if (evt->get_thread_info()) {
				evt->get_thread_info()->set_group(new_egid);
			}
		}
	}
}

void sinsp_parser::parse_setuid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_euid = *(uint32_t *)parinfo->m_val;
		if (evt->get_thread_info()) {
			evt->get_thread_info()->set_user(new_euid);
		}
	}
}

void sinsp_parser::parse_setgid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	sinsp_evt *enter_evt = &m_tmp_evt;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0 && retrieve_enter_event(enter_evt, evt))
	{
		parinfo = enter_evt->get_param(0);
		ASSERT(parinfo->m_len == sizeof(uint32_t));
		uint32_t new_egid = *(uint32_t *)parinfo->m_val;
		if (evt->get_thread_info()) {
			evt->get_thread_info()->set_group(new_egid);
		}
	}
}

namespace
{
	std::string generate_error_message(const Json::Value& value, const char* field) {
		std::string val_as_string = value.isConvertibleTo(Json::stringValue) ? value.asString().c_str() : "value not convertible to string";
		std::string err_msg = "Unable to convert json value '" + val_as_string + "' for the field: '" + field +"'";

		return err_msg;
	}

	bool check_int64_json_is_convertible(const Json::Value& value, const char* field) {
		if(!value.isNull())
		{
			// isConvertibleTo doesn't seem to work on large 64 bit numbers
			if(value.isInt64()) {
				return true;
			} else {
				std::string err_msg = generate_error_message(value, field);
				SINSP_DEBUG("%s",err_msg.c_str());
			}
		}
		return false;
	}

	bool check_json_val_is_convertible(const Json::Value& value, Json::ValueType other, const char* field, bool log_message=false)
	{
		if(value.isNull()) {
			return false;
		}

		if(!value.isConvertibleTo(other)) {
			std::string err_msg;

			if(log_message) {
				err_msg = generate_error_message(value, field);
				SINSP_WARNING("%s",err_msg.c_str());
			} else {
				if(g_logger.get_severity() >= sinsp_logger::SEV_DEBUG) {
					err_msg = generate_error_message(value, field);
					SINSP_DEBUG("%s",err_msg.c_str());
				}
			}
			return false;
		}
		return true;
	}
}

void sinsp_parser::parse_container_json_evt(sinsp_evt *evt)
{
	ASSERT(m_inspector);

	if(evt->m_tinfo_ref != nullptr)
	{
		const auto& container_id = evt->m_tinfo_ref->m_container_id;
		const auto container = m_inspector->m_container_manager.get_container(container_id);
		if(container != nullptr && container->is_successful())
		{
			SINSP_DEBUG("Ignoring container event for already successful lookup of %s", container_id.c_str());
			evt->m_filtered_out = true;
			return;
		}
	}

	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo);
	ASSERT(parinfo->m_len > 0);
	std::string json(parinfo->m_val, parinfo->m_len);
	SINSP_DEBUG("Parsing Container JSON=%s", json.c_str());
	Json::Value root;
	if(Json::Reader().parse(json, root))
	{
		auto container_info = std::make_shared<sinsp_container_info>();
		const Json::Value& container = root["container"];
		const Json::Value& id = container["id"];
		if(check_json_val_is_convertible(id, Json::stringValue, "id"))
		{
			container_info->m_id = id.asString();
		}
		const Json::Value& full_id = container["full_id"];
		if(check_json_val_is_convertible(full_id, Json::stringValue, "full_id"))
		{
			container_info->m_full_id = full_id.asString();
		}
		const Json::Value& type = container["type"];
		if(check_json_val_is_convertible(type, Json::uintValue, "type"))
		{
			container_info->m_type = static_cast<sinsp_container_type>(type.asUInt());
		}
		const Json::Value& name = container["name"];
		if(check_json_val_is_convertible(name, Json::stringValue, "name"))
		{
			container_info->m_name = name.asString();
		}

		const Json::Value& is_pod_sandbox = container["is_pod_sandbox"];
		if(check_json_val_is_convertible(is_pod_sandbox, Json::booleanValue, "is_pod_sandbox"))
		{
			container_info->m_is_pod_sandbox = is_pod_sandbox.asBool();
		}

		const Json::Value& image = container["image"];
		if(check_json_val_is_convertible(image, Json::stringValue, "image"))
		{
			container_info->m_image = image.asString();
		}
		const Json::Value& imageid = container["imageid"];
		if(check_json_val_is_convertible(imageid, Json::stringValue, "imageid"))
		{
			container_info->m_imageid = imageid.asString();
		}
		const Json::Value& imagerepo = container["imagerepo"];
		if(check_json_val_is_convertible(imagerepo, Json::stringValue, "imagerepo"))
		{
			container_info->m_imagerepo = imagerepo.asString();
		}
		const Json::Value& imagetag = container["imagetag"];
		if(check_json_val_is_convertible(imagetag, Json::stringValue, "imagetag"))
		{
			container_info->m_imagetag = imagetag.asString();
		}
		const Json::Value& imagedigest = container["imagedigest"];
		if(check_json_val_is_convertible(imagedigest, Json::stringValue, "imagedigest"))
		{
			container_info->m_imagedigest = imagedigest.asString();
		}
		const Json::Value& privileged = container["privileged"];
		if(check_json_val_is_convertible(privileged, Json::booleanValue, "privileged"))
		{
			container_info->m_privileged = privileged.asBool();
		}
		const Json::Value& lookup_state = container["lookup_state"];
		if(check_json_val_is_convertible(lookup_state, Json::uintValue, "lookup_state"))
		{
			container_info->set_lookup_status(static_cast<sinsp_container_lookup::state>(lookup_state.asUInt()));
			switch(container_info->get_lookup_status())
			{
			case sinsp_container_lookup::state::STARTED:
			case sinsp_container_lookup::state::SUCCESSFUL:
			case sinsp_container_lookup::state::FAILED:
				break;
			default:
				container_info->set_lookup_status(sinsp_container_lookup::state::SUCCESSFUL);
			}

			// state == STARTED doesn't make sense in a scap file
			// as there's no actual lookup that would ever finish
			if(!evt->m_tinfo_ref && container_info->get_lookup_status() == sinsp_container_lookup::state::STARTED)
			{
				SINSP_DEBUG("Rewriting lookup_state = STARTED from scap file to FAILED for container %s",
					container_info->m_id.c_str());
				container_info->set_lookup_status(sinsp_container_lookup::state::FAILED);
			}
		}

		const Json::Value& created_time = container["created_time"];
		if(check_int64_json_is_convertible(created_time, "created_time"))
		{
			container_info->m_created_time = created_time.asInt64();
		}

#if !defined(MINIMAL_BUILD) && !defined(_WIN32) && !defined(__EMSCRIPTEN__)
		libsinsp::container_engine::docker_async_source::parse_json_mounts(container["Mounts"], container_info->m_mounts);
#endif

		const Json::Value& user = container["User"];
		if(check_json_val_is_convertible(user, Json::stringValue, "User"))
		{
			container_info->m_container_user = user.asString();
		}

		sinsp_container_info::container_health_probe::parse_health_probes(container, container_info->m_health_probes);

		const Json::Value& contip = container["ip"];
		if(check_json_val_is_convertible(contip, Json::stringValue, "ip"))
		{
			uint32_t ip;

			if(inet_pton(AF_INET, contip.asString().c_str(), &ip) == -1)
			{
				throw sinsp_exception("Invalid 'ip' field while parsing container info: " + json);
			}

			container_info->m_container_ip = ntohl(ip);
		}

		const Json::Value& cniresult = container["cni_json"];
		if(check_json_val_is_convertible(cniresult, Json::stringValue, "cni_json"))
		{
			container_info->m_pod_cniresult = cniresult.asString();
		}

		const Json::Value &port_mappings = container["port_mappings"];

		if(check_json_val_is_convertible(port_mappings, Json::arrayValue, "port_mappings"))
		{
			for (Json::Value::ArrayIndex i = 0; i != port_mappings.size(); i++)
			{
				sinsp_container_info::container_port_mapping map;
				const Json::Value &host_ip = port_mappings[i]["HostIp"];
				// We log message for HostIp conversion failure at Warning level
				if(check_json_val_is_convertible(host_ip, Json::intValue, "HostIp", true)) {
					map.m_host_ip = host_ip.asInt();
				}
				const Json::Value& host_port = port_mappings[i]["HostPort"];
				// We log message for HostPort conversion failure at Warning level
				if(check_json_val_is_convertible(host_port, Json::intValue, "HostPort", true)) {
					map.m_host_port = (uint16_t) host_port.asInt();
				}
				const Json::Value& container_port = port_mappings[i]["ContainerPort"];
				// We log message for ContainerPort conversion failure at Warning level
				if(check_json_val_is_convertible(container_port, Json::intValue, "ContainerPort", true)) {
					map.m_container_port = (uint16_t) container_port.asInt();
				}
				container_info->m_port_mappings.push_back(map);
			}
		}

		std::vector<std::string> labels = container["labels"].getMemberNames();
		for(std::vector<std::string>::const_iterator it = labels.begin(); it != labels.end(); ++it)
		{
			std::string val = container["labels"][*it].asString();
			container_info->m_labels[*it] = val;
		}

		const Json::Value& env_vars = container["env"];

		for(const auto& env_var : env_vars)
		{
			if(env_var.isString())
			{
				container_info->m_env.emplace_back(env_var.asString());
			}
		}

		const Json::Value& memory_limit = container["memory_limit"];
		if(check_int64_json_is_convertible(memory_limit, "memory_limit"))
		{
			container_info->m_memory_limit = memory_limit.asInt64();
		}

		const Json::Value& swap_limit = container["swap_limit"];
		if(check_int64_json_is_convertible(swap_limit, "swap_limit"))
		{
			container_info->m_swap_limit = swap_limit.asInt64();
		}

		const Json::Value& cpu_shares = container["cpu_shares"];
		if(check_int64_json_is_convertible(cpu_shares, "cpu_shares"))
		{
			container_info->m_cpu_shares = cpu_shares.asInt64();
		}

		const Json::Value& cpu_quota = container["cpu_quota"];
		if(check_int64_json_is_convertible(cpu_quota, "cpu_quota"))
		{
			container_info->m_cpu_quota = cpu_quota.asInt64();
		}

		const Json::Value& cpu_period = container["cpu_period"];
		if(check_int64_json_is_convertible(cpu_period, "cpu_period"))
		{
			container_info->m_cpu_period = cpu_period.asInt64();
		}

		const Json::Value& cpuset_cpu_count = container["cpuset_cpu_count"];
		if(check_json_val_is_convertible(cpuset_cpu_count, Json::intValue, "cpuset_cpu_count"))
		{
			container_info->m_cpuset_cpu_count = cpuset_cpu_count.asInt();
		}

		const Json::Value& mesos_task_id = container["mesos_task_id"];
		if(check_json_val_is_convertible(mesos_task_id, Json::stringValue, "mesos_task_id"))
		{
			container_info->m_mesos_task_id = mesos_task_id.asString();
		}

		const Json::Value& metadata_deadline = container["metadata_deadline"];
		if(!metadata_deadline.isNull())
		{
			// isConvertibleTo doesn't seem to work on large 64 bit numbers
			if(metadata_deadline.isUInt64()) {
				container_info->m_metadata_deadline = metadata_deadline.asUInt64();
			} else {
				SINSP_DEBUG("Unable to convert json value for field: %s", "metadata_deadline");
			}
		}

		if(!container_info->is_successful())
		{
			SINSP_DEBUG("Filtering container event for failed lookup of %s (but calling callbacks anyway)", container_info->m_id.c_str());
			evt->m_filtered_out = true;
		}
		evt->m_tinfo_ref = container_info->get_tinfo(m_inspector);
		evt->m_tinfo = evt->m_tinfo_ref.get();
		m_inspector->m_container_manager.add_container(container_info, evt->get_thread_info(true));
		/*
		SINSP_STR_DEBUG("Container\n-------\nID:" + container_info.m_id +
		                "\nType: " + std::to_string(container_info.m_type) +
		                "\nName: " + container_info.m_name +
		                "\nImage: " + container_info.m_image +
		                "\nMesos Task ID: " + container_info.m_mesos_task_id);
		*/
	}
	else
	{
		std::string errstr;
		errstr = Json::Reader().getFormattedErrorMessages();
		throw sinsp_exception("Invalid JSON encountered while parsing container info: " + json + "error=" + errstr);
	}
}

void sinsp_parser::parse_container_evt(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	auto container = std::make_shared<sinsp_container_info>();

	parinfo = evt->get_param(0);
	container->m_id = parinfo->m_val;

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	container->m_type = (sinsp_container_type) *(uint32_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	container->m_name = parinfo->m_val;

	parinfo = evt->get_param(3);
	container->m_image = parinfo->m_val;

	m_inspector->m_container_manager.add_container(container, evt->get_thread_info(true));
}

void sinsp_parser::parse_user_evt(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	uint32_t uid, gid;
	const char *name, *home, *shell, *container_id;

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	uid = *(uint32_t *)parinfo->m_val;

	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	gid = *(uint32_t *)parinfo->m_val;

	parinfo = evt->get_param(2);
	name = parinfo->m_val;

	parinfo = evt->get_param(3);
	home = parinfo->m_val;

	parinfo = evt->get_param(4);
	shell = parinfo->m_val;

	parinfo = evt->get_param(5);
	container_id = parinfo->m_val;

	if (evt->m_pevt->type == PPME_USER_ADDED_E)
	{
		m_inspector->m_usergroup_manager.add_user(container_id, -1, uid, gid, name, home, shell);
	} else
	{
		m_inspector->m_usergroup_manager.rm_user(container_id, uid);
	}
}

void sinsp_parser::parse_group_evt(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	uint32_t gid;
	const char *name, *container_id;

	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	gid = *(uint32_t *)parinfo->m_val;

	parinfo = evt->get_param(1);
	name = parinfo->m_val;
	parinfo = evt->get_param(2);
	container_id = parinfo->m_val;

	if ( evt->m_pevt->type == PPME_GROUP_ADDED_E)
	{
		m_inspector->m_usergroup_manager.add_group(container_id, -1, gid, name);
	} else
	{
		m_inspector->m_usergroup_manager.rm_group(container_id, gid);
	}
}

void sinsp_parser::parse_cpu_hotplug_enter(sinsp_evt *evt)
{
	if(m_inspector->is_live() || m_inspector->is_syscall_plugin())
	{
		throw sinsp_exception("CPU " + evt->get_param_value_str("cpu") +
				      " configuration change detected. Aborting.");
	}
}

void sinsp_parser::parse_prctl_exit_event(sinsp_evt *evt)
{
	/* Parameter 1: res (type: PT_ERRNO) */
	sinsp_evt_param* parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	int64_t retval = *(int64_t *)parinfo->m_val;

	if(retval < 0)
	{
		/* we are not interested in parsing something if the syscall fails */
		return;
	}

	/* prctl could be called by the main thread but also by a secondary thread */
	auto caller_tinfo = evt->get_thread_info();
	/* only invalid threads have `caller_tinfo->m_tginfo == nullptr` */
	if(caller_tinfo == nullptr || caller_tinfo->is_invalid())
	{
		return;
	}

	bool child_subreaper = false;

	/* Parameter 2: option (type: PT_ENUMFLAGS32) */
	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	uint32_t option = *(uint32_t *)parinfo->m_val;
	switch(option)
	{
		case PPM_PR_SET_CHILD_SUBREAPER:
			/* Parameter 4: arg2_int (type: PT_INT64) */
			parinfo = evt->get_param(3);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			/* If the user provided an arg2 != 0, we set the child_subreaper
			 * attribute for the calling process. If arg2 is zero, unset the attribute
			 */
			child_subreaper = (*(int64_t *)parinfo->m_val) != 0 ? true : false;
			caller_tinfo->m_tginfo->set_reaper(child_subreaper);
			break;

		case PPM_PR_GET_CHILD_SUBREAPER:
			/* Parameter 4: arg2_int (type: PT_INT64) */
			parinfo = evt->get_param(3);
			ASSERT(parinfo->m_len == sizeof(int64_t));
			/* arg2 != 0 means the calling process is a child_subreaper */
			child_subreaper = (*(int64_t *)parinfo->m_val) != 0 ? true : false;
			caller_tinfo->m_tginfo->set_reaper(child_subreaper);
			break;

		default:
			break;
	}
}


uint8_t* sinsp_parser::reserve_event_buffer()
{
	if(m_tmp_events_buffer.empty())
	{
		return (uint8_t*)malloc(sizeof(uint8_t)*SP_EVT_BUF_SIZE);
	}
	else
	{
		auto ptr = m_tmp_events_buffer.top();
		m_tmp_events_buffer.pop();
		return ptr;
	}
}

#if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD) && !defined(__EMSCRIPTEN__)
int sinsp_parser::get_k8s_version(const std::string& json)
{
	if(m_k8s_capture_version == k8s_state_t::CAPTURE_VERSION_NONE)
	{
		SINSP_STR_DEBUG(json);
		Json::Value root;
		if(Json::Reader().parse(json, root))
		{
			const Json::Value& items = root["items"]; // new
			if(!items.isNull())
			{
				SINSP_STR_DEBUG("K8s capture version " +
				                std::to_string(k8s_state_t::CAPTURE_VERSION_2) +
				                " detected.");
				m_k8s_capture_version = k8s_state_t::CAPTURE_VERSION_2;
				return m_k8s_capture_version;
			}

			const Json::Value& object = root["object"]; // old
			if(!object.isNull())
			{
				SINSP_STR_DEBUG("K8s capture version " +
				                std::to_string(k8s_state_t::CAPTURE_VERSION_2) +
				                " detected.");
				m_k8s_capture_version = k8s_state_t::CAPTURE_VERSION_1;
				return m_k8s_capture_version;
			}
			throw sinsp_exception("Unrecognized K8s capture format.");
		}
		else
		{
			std::string errstr;
			errstr = Json::Reader().getFormattedErrorMessages();
			throw sinsp_exception("Invalid K8s capture JSON encountered (" + errstr + ")");
		}
	}

	return m_k8s_capture_version;
}

void sinsp_parser::parse_k8s_evt(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo);
	ASSERT(parinfo->m_len > 0);
	std::string json(parinfo->m_val, parinfo->m_len);
	//SINSP_STR_DEBUG(json);
	ASSERT(m_inspector);
	if(!m_inspector)
	{
		throw sinsp_exception("Inspector is null, K8s client can not be created.");
	}
	if(!m_inspector->m_k8s_client)
	{
		m_inspector->make_k8s_client();
	}
	if(m_inspector->m_k8s_client)
	{
		m_inspector->m_k8s_client->simulate_watch_event(std::move(json), get_k8s_version(json));
	}
	else
	{
		throw sinsp_exception("K8s client can not be created.");
	}
}

void sinsp_parser::parse_mesos_evt(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo = evt->get_param(0);
	ASSERT(parinfo);
	ASSERT(parinfo->m_len > 0);
	std::string json(parinfo->m_val, parinfo->m_len);
	//SINSP_STR_DEBUG(json);
	ASSERT(m_inspector);
	ASSERT(m_inspector->m_mesos_client);
	m_inspector->m_mesos_client->simulate_event(json);
}
#endif // #if !defined(CYGWING_AGENT) && !defined(MINIMAL_BUILD)

void sinsp_parser::parse_chroot_exit(sinsp_evt *evt)
{
	auto parinfo = evt->get_param(0);
	auto retval = *(int64_t *)parinfo->m_val;
	if(retval == 0 && evt->m_tinfo != nullptr)
	{
		const char* resolved_path;
		auto path = evt->get_param_as_str(1, &resolved_path);
		if(resolved_path[0] == 0)
		{
			evt->m_tinfo->m_root = path;
		}
		else
		{
			evt->m_tinfo->m_root = resolved_path;
		}
		// Root change, let's detect if we are on a container
		ASSERT(m_inspector);
		auto container_id = evt->m_tinfo->m_container_id;
		m_inspector->m_container_manager.resolve_container(evt->m_tinfo, m_inspector->is_live() || m_inspector->is_syscall_plugin());
		//
		// Refresh user / loginuser / group
		// if we happen to change container id
		//
		if(container_id != evt->m_tinfo->m_container_id)
		{
			evt->m_tinfo->set_user(evt->m_tinfo->m_user.uid);
			evt->m_tinfo->set_loginuser(evt->m_tinfo->m_loginuser.uid);
			evt->m_tinfo->set_group(evt->m_tinfo->m_group.gid);
		}
	}
}

void sinsp_parser::parse_setsid_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval >= 0)
	{
		if (evt->get_thread_info()) {
			evt->get_thread_info()->m_sid = retval;
		}
	}
}

void sinsp_parser::parse_getsockopt_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	int64_t retval;
	int64_t err;
	int64_t fd;
	int8_t level, optname;

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	parinfo = evt->get_param(1);
	fd = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	evt->m_tinfo->m_lastevent_fd = fd;

	// right now we only parse getsockopt() for SO_ERROR options
	// if that ever changes, move this check inside
	// the `if (level == PPM_SOCKOPT_LEVEL_SOL_SOCKET ...)` block
	if (!m_track_connection_status)
	{
		return;
	}

	//evt->m_fdinfo = evt->m_tinfo->get_fd(evt->m_tinfo->m_lastevent_fd);

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		return;
	}

	parinfo = evt->get_param(2);
	level = *(int8_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int8_t));

	parinfo = evt->get_param(3);
	optname = *(int8_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int8_t));

	if(level == PPM_SOCKOPT_LEVEL_SOL_SOCKET && optname == PPM_SOCKOPT_SO_ERROR)
	{
		auto main_thread = evt->m_tinfo->get_main_thread();
		if(main_thread == nullptr)
		{
			return;
		}
		evt->m_fdinfo = main_thread->get_fd(fd);
		if (!evt->m_fdinfo)
		{
			return;
		}

		parinfo = evt->get_param(4);
		ASSERT(*parinfo->m_val == PPM_SOCKOPT_IDX_ERRNO);
		ASSERT(parinfo->m_len == sizeof(int64_t) + 1);
		err = *(int64_t *)(parinfo->m_val + 1); // add 1 byte to skip over PT_DYN param index

		evt->m_errorcode = (int32_t)err;
		if (err < 0)
		{
			evt->m_fdinfo->set_socket_failed();
		}
		else
		{
			evt->m_fdinfo->set_socket_connected();
		}
		if (m_inspector->get_observer())
		{
			m_inspector->get_observer()->on_socket_status_changed(evt);
		}
	}
}

void sinsp_parser::parse_capset_exit(sinsp_evt *evt)
{
	sinsp_evt_param *parinfo;
	sinsp_threadinfo *tinfo;
	int64_t retval;

	//
	// Extract the return value
	//
	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0 || evt->m_tinfo == nullptr)
	{
		return;
	}

	tinfo = evt->m_tinfo;

	//
	// Extract and update thread capabilities
	//
	parinfo = evt->get_param(1);
	tinfo->m_cap_inheritable = *(uint64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(uint64_t));

	parinfo = evt->get_param(2);
	tinfo->m_cap_permitted = *(uint64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(uint64_t));

	parinfo = evt->get_param(3);
	tinfo->m_cap_effective = *(uint64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(uint64_t));
}

void sinsp_parser::parse_unshare_setns_exit(sinsp_evt *evt)
{
	sinsp_evt *enter_evt = &m_tmp_evt;
	sinsp_evt_param *parinfo;
	sinsp_threadinfo *tinfo;
	int64_t retval;
	uint32_t flags = 0;

	parinfo = evt->get_param(0);
	retval = *(int64_t *)parinfo->m_val;
	ASSERT(parinfo->m_len == sizeof(int64_t));

	if(retval < 0)
	{
		return;
	}

	if(!retrieve_enter_event(enter_evt, evt))
	{
		return;
	}

	uint16_t etype = evt->m_pevt->type;

	//
	// Retrieve flags from enter event
	//
	if(etype == PPME_SYSCALL_UNSHARE_X)
	{
		parinfo = enter_evt->get_param(0);
		flags = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));
	}
	else if(etype == PPME_SYSCALL_SETNS_X)
	{
		parinfo = enter_evt->get_param(1);
		flags = *(uint32_t *)parinfo->m_val;
		ASSERT(parinfo->m_len == sizeof(uint32_t));
	}

	//
	// Update capabilities
	//
	if(flags & PPM_CL_CLONE_NEWUSER && evt->m_tinfo != nullptr)
	{
		tinfo = evt->m_tinfo;
		uint64_t max_caps = sinsp_utils::get_max_caps();
		tinfo->m_cap_inheritable = max_caps;
		tinfo->m_cap_permitted = max_caps;
		tinfo->m_cap_effective = max_caps;
	}
}

void sinsp_parser::free_event_buffer(uint8_t *ptr)
{
	if(m_tmp_events_buffer.size() < m_inspector->m_thread_manager->m_threadtable.size())
	{
		m_tmp_events_buffer.push(ptr);
	}
	else
	{
		free(ptr);
	}
}

void sinsp_parser::parse_memfd_create_exit(sinsp_evt *evt, scap_fd_type type)
{
	sinsp_evt_param* parinfo;
	int64_t fd;
	char *name;
	uint32_t flags;
	sinsp_fdinfo_t fdi;


	ASSERT(evt->m_tinfo)
	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	/* ret (fd) */
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(0)->type == PT_FD);
	fd = *(int64_t *)parinfo->m_val;
	
	/* name */
	/*
	Suppose you create a memfd named libstest resulting in a fd.name libstest while on disk 
	(e.g. ls -l /proc/$PID/fd/$FD_NUM) it may look like /memfd:libstest (deleted)
	*/
	parinfo = evt->get_param(1);
	name = parinfo->m_val;
	
	/* flags */
	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	flags = *(uint32_t *)parinfo->m_val;

	if(fd >= 0)
	{
		fdi.m_type = type;
		fdi.add_filename(name);
		fdi.m_openflags = flags;
	}

	if(fdi.m_name == USER_EVT_DEVICE_NAME)
	{
		fdi.m_flags |= sinsp_fdinfo_t::FLAGS_IS_TRACER_FILE;
	}
	else
	{
		fdi.m_flags |= sinsp_fdinfo_t::FLAGS_IS_NOT_TRACER_FD;
	}

	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_pidfd_open_exit(sinsp_evt *evt)
{
	sinsp_evt_param* parinfo;
	int64_t fd;
	int64_t pid;
	int64_t flags;
	sinsp_fdinfo_t fdi;

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	/* ret (fd) */
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(0)->type == PT_FD);
	fd = *(int64_t *)parinfo->m_val;

	/* pid (fd) */
	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(1)->type == PT_PID);
	pid = *(int64_t *)parinfo->m_val;
	
	/* flags */
	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(uint32_t));
	flags = *(uint32_t *)parinfo->m_val;

	if(fd >= 0)
	{
		// note: approximating equivalent filename as in:
		// https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html
		char fname[SCAP_MAX_PATH_SIZE];
		snprintf(fname,
		         sizeof(fname),
		         "%s/proc/%lld",
		         scap_get_host_root(),
		         (long long) pid);
		fdi.m_type = scap_fd_type::SCAP_FD_PIDFD;
		fdi.add_filename(fname);
		fdi.m_openflags = flags;
		fdi.m_pid = pid;
	}

	evt->m_fdinfo = evt->m_tinfo->add_fd(fd, &fdi);
}

void sinsp_parser::parse_pidfd_getfd_exit(sinsp_evt *evt)
{

	sinsp_evt_param* parinfo;
	int64_t fd;
	int64_t pidfd;
	int64_t targetfd;

	if(evt->m_tinfo == nullptr)
	{
		return;
	}

	/* ret (fd) */
	parinfo = evt->get_param(0);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(0)->type == PT_FD);
	fd = *(int64_t *)parinfo->m_val;

	/* pidfd */
	parinfo = evt->get_param(1);
	ASSERT(parinfo->m_len == sizeof(int64_t));
	ASSERT(evt->get_param_info(1)->type == PT_FD);
	pidfd = *(int64_t *)parinfo->m_val;

	/* targetfd */
	parinfo = evt->get_param(2);
	ASSERT(parinfo->m_len == sizeof(int64_t))
	ASSERT(evt->get_param_info(2)->type == PT_FD);
	targetfd = *(int64_t *)parinfo->m_val;

	/* flags */
	// currently unused: https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html

	auto pidfd_fdinfo = evt->m_tinfo->get_fd(pidfd);
	if (pidfd_fdinfo == nullptr || !pidfd_fdinfo->is_pidfd())
	{
		return;
	}

	auto pidfd_tinfo = m_inspector->get_thread_ref(pidfd_fdinfo->m_pid);
	if (pidfd_tinfo == nullptr)
	{
		return;
	}
	
	auto targetfd_fdinfo = pidfd_tinfo->get_fd(targetfd);
	if (targetfd_fdinfo == nullptr)
	{
		return;
	}
	evt->m_tinfo->add_fd(fd, targetfd_fdinfo);
}
