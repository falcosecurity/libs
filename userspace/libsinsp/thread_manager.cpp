// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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

#ifndef _WIN32
#include <unistd.h>
#include <limits.h>
#endif
#include <stdio.h>
#include <algorithm>
#include <cinttypes>
#include <libscap/strl.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/sinsp_observer.h>
#include <libscap/scap-int.h>

extern sinsp_evttables g_infotables;

static void copy_ipv6_address(uint32_t (&dest)[4], const uint32_t (&src)[4]) {
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

static void fd_to_scap(scap_fdinfo& dst, const sinsp_fdinfo& src) {
	dst.type = src.m_type;
	dst.ino = src.m_ino;
	dst.fd = src.m_fd;

	switch(dst.type) {
	case SCAP_FD_IPV4_SOCK:
		dst.info.ipv4info.sip = src.m_sockinfo.m_ipv4info.m_fields.m_sip;
		dst.info.ipv4info.dip = src.m_sockinfo.m_ipv4info.m_fields.m_dip;
		dst.info.ipv4info.sport = src.m_sockinfo.m_ipv4info.m_fields.m_sport;
		dst.info.ipv4info.dport = src.m_sockinfo.m_ipv4info.m_fields.m_dport;
		dst.info.ipv4info.l4proto = src.m_sockinfo.m_ipv4info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		dst.info.ipv4serverinfo.ip = src.m_sockinfo.m_ipv4serverinfo.m_ip;
		dst.info.ipv4serverinfo.port = src.m_sockinfo.m_ipv4serverinfo.m_port;
		dst.info.ipv4serverinfo.l4proto = src.m_sockinfo.m_ipv4serverinfo.m_l4proto;
		break;
	case SCAP_FD_IPV6_SOCK:
		copy_ipv6_address(dst.info.ipv6info.sip, src.m_sockinfo.m_ipv6info.m_fields.m_sip.m_b);
		copy_ipv6_address(dst.info.ipv6info.dip, src.m_sockinfo.m_ipv6info.m_fields.m_dip.m_b);
		dst.info.ipv6info.sport = src.m_sockinfo.m_ipv6info.m_fields.m_sport;
		dst.info.ipv6info.dport = src.m_sockinfo.m_ipv6info.m_fields.m_dport;
		dst.info.ipv6info.l4proto = src.m_sockinfo.m_ipv6info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(dst.info.ipv6serverinfo.ip, src.m_sockinfo.m_ipv6serverinfo.m_ip.m_b);
		dst.info.ipv6serverinfo.port = src.m_sockinfo.m_ipv6serverinfo.m_port;
		dst.info.ipv6serverinfo.l4proto = src.m_sockinfo.m_ipv6serverinfo.m_l4proto;
		break;
	case SCAP_FD_UNIX_SOCK:
		dst.info.unix_socket_info.source = src.m_sockinfo.m_unixinfo.m_fields.m_source;
		dst.info.unix_socket_info.destination = src.m_sockinfo.m_unixinfo.m_fields.m_dest;
		strlcpy(dst.info.unix_socket_info.fname,
		        src.m_name.c_str(),
		        sizeof(dst.info.unix_socket_info.fname));
		break;
	case SCAP_FD_FILE_V2:
		dst.info.regularinfo.open_flags = src.m_openflags;
		strlcpy(dst.info.regularinfo.fname, src.m_name.c_str(), sizeof(dst.info.regularinfo.fname));
		dst.info.regularinfo.dev = src.m_dev;
		dst.info.regularinfo.mount_id = src.m_mount_id;
		break;
	case SCAP_FD_FIFO:
	case SCAP_FD_FILE:
	case SCAP_FD_DIRECTORY:
	case SCAP_FD_UNSUPPORTED:
	case SCAP_FD_SIGNALFD:
	case SCAP_FD_EVENTPOLL:
	case SCAP_FD_EVENT:
	case SCAP_FD_INOTIFY:
	case SCAP_FD_TIMERFD:
	case SCAP_FD_NETLINK:
	case SCAP_FD_BPF:
	case SCAP_FD_USERFAULTFD:
	case SCAP_FD_IOURING:
	case SCAP_FD_MEMFD:
	case SCAP_FD_PIDFD:
		strlcpy(dst.info.fname, src.m_name.c_str(), sizeof(dst.info.fname));
		break;
	default:
		ASSERT(false);
		break;
	}
}

static const auto s_threadinfo_static_fields = sinsp_threadinfo::get_static_fields();

sinsp_thread_manager::sinsp_thread_manager(
        const sinsp_mode& sinsp_mode,
        const sinsp_threadinfo_factory& threadinfo_factory,
        sinsp_observer* const& observer,
        const std::shared_ptr<const sinsp_plugin>& input_plugin,
        const bool& large_envs_enabled,
        const timestamper& timestamper,
        const int64_t& sinsp_pid,
        const uint64_t& threads_purging_scan_time_ns,
        const uint64_t& thread_timeout_ns,
        const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
        scap_platform* const& scap_platform,
        scap_t* const& scap_handle,
        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& thread_manager_dyn_fields,
        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& fdtable_dyn_fields,
        const std::shared_ptr<sinsp_usergroup_manager>& usergroup_manager):
        built_in_table{s_thread_table_name, &s_threadinfo_static_fields, thread_manager_dyn_fields},
        m_sinsp_mode{sinsp_mode},
        m_threadinfo_factory{threadinfo_factory},
        m_observer{observer},
        m_input_plugin{input_plugin},
        m_large_envs_enabled{large_envs_enabled},
        m_timestamper{timestamper},
        m_sinsp_pid{sinsp_pid},
        m_threads_purging_scan_time_ns{threads_purging_scan_time_ns},
        m_thread_timeout_ns{thread_timeout_ns},
        m_sinsp_stats_v2{sinsp_stats_v2},
        m_scap_platform{scap_platform},
        m_scap_handle{scap_handle},
        m_fdtable_dyn_fields{fdtable_dyn_fields},
        m_max_thread_table_size(m_thread_table_default_size),
        m_last_proc_lookup_period_start(sinsp_utils::get_current_time_ns()),
        m_usergroup_manager{usergroup_manager} {
	clear();
}

void sinsp_thread_manager::clear() {
	m_threadtable.clear();
	m_thread_groups.clear();
	m_last_tid = -1;
	m_last_tinfo.reset();
	m_last_flush_time_ns = 0;
}

/* This is called on the table after the `/proc` scan */
void sinsp_thread_manager::create_thread_dependencies(
        const std::shared_ptr<sinsp_threadinfo>& tinfo) {
	/* This should never happen */
	if(tinfo == nullptr) {
		throw sinsp_exception(
		        "There is a NULL pointer in the thread table, this should never happen");
	}

	/* For invalid threads we do nothing.
	 * They won't have a valid parent or a valid thread group.
	 * We use them just to see which tid calls a syscall.
	 */
	if(tinfo->is_invalid()) {
		tinfo->update_main_fdtable();
		return;
	}

	/* This is a defensive check, it should never happen
	 * a thread that calls this method should never have a thread group info
	 */
	if(tinfo->m_tginfo != nullptr) {
		tinfo->update_main_fdtable();
		return;
	}

	bool reaper = false;
	/* reaper should be true if we are an init process for the init namespace or for an inner
	 * namespace */
	if(tinfo->m_pid == 1 || tinfo->m_vpid == 1) {
		reaper = true;
	}

	/* Create the thread group info for the thread. */
	auto tginfo = get_thread_group_info(tinfo->m_pid);
	if(tginfo == nullptr) {
		tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, reaper, tinfo);
		set_thread_group_info(tinfo->m_pid, tginfo);
	} else {
		tginfo->add_thread_to_group(tinfo, tinfo->is_main_thread());
	}
	tinfo->m_tginfo = tginfo;

	// update fdtable cached pointer for all threads in the group (which includes
	// the current thread), as their leader might have changed or we simply need
	// to first initialize it. Then we do the same with the thread's children.
	for(const auto& thread : tginfo->get_thread_list()) {
		if(auto thread_ptr = thread.lock().get(); thread_ptr != nullptr) {
			thread_ptr->update_main_fdtable();
		}
	}
	for(const auto& thread : tinfo->m_children) {
		if(auto thread_ptr = thread.lock().get(); thread_ptr != nullptr) {
			thread_ptr->update_main_fdtable();
		}
	}

	/* init group has no parent */
	if(tinfo->m_pid == 1) {
		return;
	}

	/* Assign the child to the parent for the first time, we are a thread
	 * just created and we need to assign us to a parent.
	 * Remember that in `/proc` scan the `ptid` is `ppid`.
	 * If we don't find the parent in the table we can do nothing, so we consider
	 * INIT as the new parent.
	 * Here we avoid scanning `/proc` to not trigger a possible recursion
	 * on all the parents
	 */
	const auto parent_thread = find_thread(tinfo->m_ptid, true);
	if(parent_thread == nullptr || parent_thread->is_invalid()) {
		/* If we have a valid parent we assign the new child to it otherwise we set ptid = 0. */
		tinfo->m_ptid = 0;
		tinfo->update_main_fdtable();
		return;
	}
	parent_thread->add_child(tinfo);
}

const std::shared_ptr<sinsp_threadinfo>& sinsp_thread_manager::add_thread(
        std::unique_ptr<sinsp_threadinfo> threadinfo,
        const bool must_create_thread_dependencies) {
	/* We have no more space */
	if(m_threadtable.size() >= m_max_thread_table_size && threadinfo->m_pid != m_sinsp_pid) {
		if(m_sinsp_stats_v2 != nullptr) {
			// rate limit messages to avoid spamming the logs
			if(m_sinsp_stats_v2->m_n_drops_full_threadtable % m_max_thread_table_size == 0) {
				libsinsp_logger()->format(
				        sinsp_logger::SEV_INFO,
				        "Thread table full, dropping tid %lu (pid %lu, comm \"%s\")",
				        threadinfo->m_tid,
				        threadinfo->m_pid,
				        threadinfo->m_comm.c_str());
			}
			m_sinsp_stats_v2->m_n_drops_full_threadtable++;
		}

		return m_nullptr_tinfo_ret;
	}

	auto tinfo_shared_ptr = std::shared_ptr<sinsp_threadinfo>(std::move(threadinfo));

	if(must_create_thread_dependencies) {
		create_thread_dependencies(tinfo_shared_ptr);
	}

	if(tinfo_shared_ptr->dynamic_fields() != dynamic_fields()) {
		throw sinsp_exception("adding entry with incompatible dynamic defs to thread table");
	}

	if(tinfo_shared_ptr->get_fdtable().dynamic_fields() != m_fdtable_dyn_fields) {
		throw sinsp_exception(
		        "adding entry with incompatible dynamic defs to of file descriptor sub-table");
	}

	if(m_sinsp_stats_v2 != nullptr) {
		m_sinsp_stats_v2->m_n_added_threads++;
	}

	if(m_last_tid == tinfo_shared_ptr->m_tid) {
		m_last_tid = -1;
		m_last_tinfo.reset();
	}

	tinfo_shared_ptr->update_main_fdtable();
	return m_threadtable.put(tinfo_shared_ptr);
}

void sinsp_thread_manager::remove_child_from_parent(int64_t ptid) {
	auto parent = find_thread(ptid, true).get();
	if(parent == nullptr) {
		return;
	}

	parent->m_not_expired_children--;

	/* Clean expired children if necessary. */
	if((parent->m_children.size() - parent->m_not_expired_children) >=
	   DEFAULT_EXPIRED_CHILDREN_THRESHOLD) {
		parent->clean_expired_children();
	}
}

/* Taken from `find_new_reaper` kernel function:
 *
 * When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists.
 * 2. give them to the first ancestor process which prctl'd itself as a
 *    child_subreaper for its children (like a service manager)
 * 3. give them to the init process (PID 1) in our pid namespace
 */
sinsp_threadinfo* sinsp_thread_manager::find_new_reaper(sinsp_threadinfo* tinfo) {
	if(tinfo == nullptr) {
		throw sinsp_exception("cannot call find_new_reaper() on a null tinfo");
	}

	/* First we check in our thread group for alive threads */
	if(tinfo->m_tginfo != nullptr && tinfo->m_tginfo->get_thread_count() > 0) {
		for(const auto& thread_weak : tinfo->m_tginfo->get_thread_list()) {
			if(thread_weak.expired()) {
				continue;
			}
			auto thread = thread_weak.lock().get();
			if(!thread->is_dead() && thread != tinfo) {
				return thread;
			}
		}
	}

	/* This is a best-effort logic to detect loops.
	 * If a parent points to a thread that is a child of
	 * the current `tinfo` it is possible that we are not
	 * able to detect the loop and we assign the wrong reaper.
	 * By the way, this should never happen and this logic is here
	 * just to avoid infinite loops, is not here to guarantee 100%
	 * correctness.
	 * We should never have a self-loop but if we have it
	 * we break it and we return a `nullptr` as a reaper.
	 */
	std::unordered_set<int64_t> loop_detection_set{tinfo->m_tid};
	uint16_t prev_set_size = 1;

	auto parent_tinfo = find_thread(tinfo->m_ptid, true).get();
	while(parent_tinfo != nullptr) {
		prev_set_size = loop_detection_set.size();
		loop_detection_set.insert(parent_tinfo->m_tid);
		if(loop_detection_set.size() == prev_set_size) {
			/* loop detected */
			ASSERT(false);
			break;
		}

		/* The only possible case in which we break here is:
		 * - the parent is not in a namespace while the child yes
		 *
		 * WARNING: this is a best-effort check, in sinsp we have no knowledge of
		 * namespace level so it's possible that the parent is in a different namespace causing
		 * a container escape! We are not able to detect it with the actual info.
		 */
		if(parent_tinfo->is_in_pid_namespace() != tinfo->is_in_pid_namespace()) {
			break;
		}

		if(parent_tinfo->m_tginfo != nullptr && parent_tinfo->m_tginfo->is_reaper() &&
		   parent_tinfo->m_tginfo->get_thread_count() > 0) {
			for(const auto& thread_weak : parent_tinfo->m_tginfo->get_thread_list()) {
				if(thread_weak.expired()) {
					continue;
				}
				auto thread = thread_weak.lock().get();
				if(!thread->is_dead()) {
					return thread;
				}
			}
		}
		parent_tinfo = find_thread(parent_tinfo->m_ptid, true).get();
	}

	return nullptr;
}

void sinsp_thread_manager::remove_main_thread_fdtable(sinsp_threadinfo* main_thread) const {
	// All this logic is intended to just call the `m_observer->on_erase_fd` callback, so just
	// returns if there is no observer.
	if(m_observer == nullptr) {
		return;
	}

	// Please note that the main thread is not always here, it is possible that for some reason we
	// lose it!
	if(main_thread == nullptr) {
		return;
	}

	sinsp_fdtable* fd_table_ptr = main_thread->get_fd_table();
	if(fd_table_ptr == nullptr) {
		return;
	}

	erase_fd_params eparams;
	eparams.m_remove_from_table = false;
	eparams.m_tinfo = main_thread;

	fd_table_ptr->loop([&](int64_t fd, sinsp_fdinfo& fdinfo) {
		// The canceled fd should always be deleted immediately, so if it appears here it means we
		// have a problem. Note: it looks like that the canceled FD may appear here in case of high
		// drop, and we need to recover. This was an assertion failure, now removed.
		eparams.m_fd = fd;
		eparams.m_fdinfo = &fdinfo;
		m_observer->on_erase_fd(&eparams);
		return true;
	});
}

void sinsp_thread_manager::remove_thread(int64_t tid) {
	auto thread_to_remove = m_threadtable.get_ref(tid);

	/* This should never happen but just to be sure. */
	if(thread_to_remove == nullptr) {
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_failed_thread_lookups++;
		}
		return;
	}

	/* [Remove invalid threads]
	 * All threads should have a m_tginfo apart from the invalid ones
	 * which don't have a group or children.
	 */
	if(thread_to_remove->is_invalid() || thread_to_remove->m_tginfo == nullptr) {
		remove_child_from_parent(thread_to_remove->m_ptid);
		m_threadtable.erase(tid);
		m_last_tid = -1;
		m_last_tinfo.reset();
		return;
	}

	/* [Mark the thread as dead]
	 * If didn't lose the PROC_EXIT event we have already done it
	 */
	if(!thread_to_remove->is_dead()) {
		/* we should decrement only if the thread is alive */
		thread_to_remove->m_tginfo->decrement_thread_count();
		thread_to_remove->set_dead();
	}

	/* [Reparent children]
	 * There are different cases:
	 * 1. We have no children so we have nothing to reparent.
	 * 2. We receive a PROC_EXIT event for this thread, with reaper info:
	 *   - Reaper 0 means that the kernel didn't find any children for this thread,
	 *     probably we are not correctly aligned with it. In this case, we will use our userspace
	 * logic to find a reaper.
	 *   - Reaper -1 means that we cannot find the correct reaper info in the kernel due
	 *     to BPF verifier limits. In this case, we will use our userspace logic to find a reaper.
	 *   - Reaper > 0 means the kernel sent us a valid reaper we will use it if present in our
	 * thread table. If not present we will use our userspace logic.
	 * 3. We receive an old version of the PROC_EXIT event without reaper info. In this case,
	 *    we use our userspace logic.
	 * 4. We lost the PROC_EXIT event, so we are here because the purging logic called us. Also
	 *    in this case we use our userspace logic.
	 *
	 * So excluding the case in which the kernel sent us a valid reaper we always fallback to
	 * our userspace logic.
	 */
	if(thread_to_remove->m_children.size()) {
		sinsp_threadinfo* reaper_tinfo = nullptr;

		if(thread_to_remove->m_reaper_tid > 0) {
			/* The kernel sent us a valid reaper
			 * We should have the reaper thread in the table, but if we don't have
			 * it, we try to create it from /proc
			 */
			reaper_tinfo = get_thread(thread_to_remove->m_reaper_tid).get();
		}

		if(reaper_tinfo == nullptr || reaper_tinfo->is_invalid()) {
			/* Fallback case:
			 * We search for a reaper in best effort traversing our table
			 */
			reaper_tinfo = find_new_reaper(thread_to_remove.get());
		}

		if(reaper_tinfo != nullptr) {
			/* We update the reaper tid if necessary. */
			thread_to_remove->m_reaper_tid = reaper_tinfo->m_tid;

			/* If that thread group was not marked as a reaper we mark it now.
			 * Since the reaper could be also a thread in the same thread group
			 * we need to exclude that case. In all other cases, we want to mark
			 * the thread group as a reaper:
			 * - init process of a namespace.
			 * - process that called prctl on itself.
			 * Please note that in the kernel init processes are not marked with
			 * `is_child_subreaper` but here we don't make distinctions we mark reapers and sub
			 * reapers with the same flag.
			 */
			if(reaper_tinfo->m_pid != thread_to_remove->m_pid && reaper_tinfo->m_tginfo) {
				reaper_tinfo->m_tginfo->set_reaper(true);
			}
		}
		thread_to_remove->assign_children_to_reaper(reaper_tinfo);
	}

	/* [Remove main thread]
	 * We remove the main thread if there are no other threads in the group
	 */
	if((thread_to_remove->m_tginfo->get_thread_count() == 0)) {
		remove_main_thread_fdtable(thread_to_remove->get_main_thread());

		/* we remove the main thread and the thread group */
		/* even if thread_to_remove is not the main thread the parent will be
		 * the same so it's ok.
		 */
		remove_child_from_parent(thread_to_remove->m_ptid);
		m_thread_groups.erase(thread_to_remove->m_pid);
		m_threadtable.erase(thread_to_remove->m_pid);
	}

	/* [Remove the current thread]
	 * We remove the current thread if it is not the main one.
	 * If we are the main thread and it's time to be removed, we are removed
	 * in the previous `if`.
	 */
	if(!thread_to_remove->is_main_thread()) {
		remove_child_from_parent(thread_to_remove->m_ptid);
		m_threadtable.erase(tid);
	}

	/* Maybe we removed the thread info that was cached, we clear
	 * the cache just to be sure.
	 */
	m_last_tid = -1;
	m_last_tinfo.reset();
	if(m_sinsp_stats_v2 != nullptr) {
		m_sinsp_stats_v2->m_n_removed_threads++;
	}
}

void sinsp_thread_manager::fix_sockets_coming_from_proc(const bool resolve_hostname_and_port) {
	m_threadtable.loop([&](sinsp_threadinfo& tinfo) {
		tinfo.fix_sockets_coming_from_proc(m_server_ports, resolve_hostname_and_port);
		return true;
	});
}

void sinsp_thread_manager::clear_thread_pointers(sinsp_threadinfo& tinfo) {
	sinsp_fdtable* fdt = tinfo.get_fd_table();
	if(fdt != NULL) {
		fdt->reset_cache();
	}
}

void sinsp_thread_manager::reset_child_dependencies() {
	m_threadtable.loop([&](sinsp_threadinfo& tinfo) {
		tinfo.clean_expired_children();
		/* Little optimization: only the main thread cleans the thread group from expired threads.
		 * Downside: if the main thread is not present in the thread group because we lost it we
		 * don't clean the thread group from expired threads.
		 */
		if(tinfo.is_main_thread() && tinfo.m_tginfo != nullptr) {
			tinfo.m_tginfo->clean_expired_threads();
		}
		clear_thread_pointers(tinfo);
		return true;
	});
}

void sinsp_thread_manager::create_thread_dependencies_after_proc_scan() {
	m_threadtable.const_loop_shared_pointer([&](const std::shared_ptr<sinsp_threadinfo>& tinfo) {
		create_thread_dependencies(tinfo);
		return true;
	});
}

void sinsp_thread_manager::free_dump_fdinfos(std::vector<scap_fdinfo*>* fdinfos_to_free) {
	for(uint32_t j = 0; j < fdinfos_to_free->size(); j++) {
		free(fdinfos_to_free->at(j));
	}

	fdinfos_to_free->clear();
}

// NOTE: This does *not* populate any array-based fields (comm, exe,
// exepath, args, env, cwd, cgroups, root)
void sinsp_thread_manager::thread_to_scap(sinsp_threadinfo& tinfo, scap_threadinfo* sctinfo) {
	//
	// Fill in the thread data
	//

	// NOTE: This is doing a shallow copy of the strings from
	// tinfo, and is valid only as long as tinfo is valid.

	sctinfo->tid = tinfo.m_tid;
	sctinfo->pid = tinfo.m_pid;
	sctinfo->ptid = tinfo.m_ptid;
	sctinfo->sid = tinfo.m_sid;
	sctinfo->vpgid = tinfo.m_vpgid;
	sctinfo->pgid = tinfo.m_pgid;

	sctinfo->flags = tinfo.m_flags;
	sctinfo->fdlimit = tinfo.m_fdlimit;
	sctinfo->uid = tinfo.m_uid;
	sctinfo->gid = tinfo.m_gid;
	sctinfo->vmsize_kb = tinfo.m_vmsize_kb;
	sctinfo->vmrss_kb = tinfo.m_vmrss_kb;
	sctinfo->vmswap_kb = tinfo.m_vmswap_kb;
	sctinfo->pfmajor = tinfo.m_pfmajor;
	sctinfo->pfminor = tinfo.m_pfminor;
	sctinfo->vtid = tinfo.m_vtid;
	sctinfo->vpid = tinfo.m_vpid;
	sctinfo->fdlist = NULL;
	sctinfo->loginuid = tinfo.m_loginuid;
	sctinfo->filtered_out = tinfo.m_filtered_out;
}

sinsp_fdinfo* sinsp_thread_manager::add_thread_fd_from_scap(sinsp_threadinfo& tinfo,
                                                            const scap_fdinfo& fdinfo,
                                                            const bool resolve_hostname_and_port) {
	const auto newfdinfo = tinfo.add_fd_from_scap(fdinfo, resolve_hostname_and_port);
	if(!newfdinfo) {
		return nullptr;
	}

	// We keep note of all the host bound server ports. We'll need them later when patching
	// connections direction.
	uint16_t server_port;
	switch(newfdinfo->m_type) {
	case SCAP_FD_IPV4_SERVSOCK:
		server_port = newfdinfo->m_sockinfo.m_ipv4serverinfo.m_port;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		server_port = newfdinfo->m_sockinfo.m_ipv6serverinfo.m_port;
		break;
	default:
		return newfdinfo;
	}

	m_server_ports.insert(server_port);
	return newfdinfo;
}

void sinsp_thread_manager::maybe_log_max_lookup(int64_t tid, bool scan_sockets, uint64_t period) {
	if(m_proc_lookup_period) {
		if(m_n_proc_lookups == m_max_n_proc_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max process lookup number (%d)"
			                          " in the last %" PRIu64 "ms, duration=%" PRIu64 "ms",
			                          m_n_proc_lookups,
			                          period / 1000000,
			                          m_n_proc_lookups_duration_ns / 1000000);
		}
		if(scan_sockets && m_n_proc_lookups == m_max_n_proc_socket_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max socket lookup number (%d)"
			                          " in the last %" PRIu64 "ms, tid=%" PRIu64
			                          ", duration=%" PRIu64 "ms",
			                          m_n_proc_lookups,
			                          period / 1000000,
			                          tid,
			                          m_n_proc_lookups_duration_ns / 1000000);
		}
	} else {
		if(m_n_proc_lookups == m_max_n_proc_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max process lookup number (%d)"
			                          ", duration=%" PRIu64 "ms",
			                          m_n_proc_lookups,
			                          m_n_proc_lookups_duration_ns / 1000000);
		}
		if(scan_sockets && m_n_proc_lookups == m_max_n_proc_socket_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max socket lookup number (%d), tid=%" PRIu64
			                          ", duration=%" PRIu64 "ms",
			                          m_n_proc_lookups,
			                          tid,
			                          m_n_proc_lookups_duration_ns / 1000000);
		}
	}
}

void sinsp_thread_manager::traverse_parent_state(sinsp_threadinfo& tinfo, visitor_func_t& visitor) {
	// Use two pointers starting at this, traversing the parent
	// state, at different rates. If they ever equal each other
	// before slow is NULL there's a loop.

	sinsp_threadinfo *slow = find_thread(tinfo.m_ptid, true).get(), *fast = slow;

	// Move fast to its parent
	fast = (fast ? find_thread(fast->m_ptid, true).get() : fast);

	// The slow pointer must be valid and not have a tid of -1.
	while(slow && slow->m_tid != -1) {
		if(!visitor(slow)) {
			break;
		}

		// Advance slow one step and advance fast two steps
		slow = find_thread(slow->m_ptid, true).get();

		// advance fast 2 steps, checking to see if we meet
		// slow after each step.
		for(uint32_t i = 0; i < 2; i++) {
			fast = (fast ? find_thread(fast->m_ptid, true).get() : fast);

			// If not at the end but fast == slow or if
			// slow points to itself, there's a loop in
			// the thread state.
			if(slow && (slow == fast || slow->m_tid == slow->m_ptid)) {
				tinfo.report_thread_loop(*slow);
				return;
			}
		}
	}
}
sinsp_threadinfo* sinsp_thread_manager::get_oldest_matching_ancestor(
        sinsp_threadinfo* tinfo,
        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
        bool is_virtual_id) {
	int64_t id = get_thread_id(tinfo);
	if(id == -1) {
		// the id is not set
		return nullptr;
	}

	// If we are using a non virtual id or if the id is virtual but we are in the init namespace we
	// can access the thread table directly!
	// if is_virtual_id == false we don't care about the namespace in which we are
	sinsp_threadinfo* leader = nullptr;
	if(!is_virtual_id || !tinfo->is_in_pid_namespace()) {
		leader = find_thread(id, true).get();
		if(leader != nullptr) {
			return leader;
		}
	}

	// If we are in a pid_namespace we cannot use directly m_sid to access the table
	// since it could be related to a pid namespace.
	visitor_func_t visitor = [id, &leader, get_thread_id](sinsp_threadinfo* pt) {
		if(get_thread_id(pt) != id) {
			return false;
		}
		leader = pt;
		return true;
	};

	traverse_parent_state(*tinfo, visitor);
	return leader;
}

std::string sinsp_thread_manager::get_ancestor_field_as_string(
        sinsp_threadinfo* tinfo,
        const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
        const std::function<std::string(sinsp_threadinfo*)>& get_field_str,
        bool is_virtual_id) {
	auto ancestor = get_oldest_matching_ancestor(tinfo, get_thread_id, is_virtual_id);
	if(ancestor) {
		return get_field_str(ancestor);
	}
	return "";
}

void sinsp_thread_manager::dump_threads_to_file(scap_dumper_t* dumper) {
	if(m_threadtable.size() == 0) {
		return;
	}

	scap_dumper_t* proclist_dumper = scap_write_proclist_begin();
	if(proclist_dumper == nullptr) {
		throw sinsp_exception("Failed to create proclist dumper");
	}

	uint32_t totlen = 0;
	m_threadtable.loop([&](sinsp_threadinfo& tinfo) {
		if(tinfo.m_filtered_out) {
			return true;
		}

		scap_threadinfo sctinfo{};
		struct iovec *args_iov, *envs_iov, *cgroups_iov;
		int argscnt, envscnt, cgroupscnt;
		std::string argsrem, envsrem, cgroupsrem;
		uint32_t entrylen = 0;
		const auto& cg = tinfo.cgroups();

		memset(&sctinfo, 0, sizeof(scap_threadinfo));

		thread_to_scap(tinfo, &sctinfo);
		tinfo.args_to_iovec(&args_iov, &argscnt, argsrem);
		tinfo.env_to_iovec(&envs_iov, &envscnt, envsrem);
		tinfo.cgroups_to_iovec(&cgroups_iov, &cgroupscnt, cgroupsrem, cg);

		if(scap_write_proclist_entry_bufs(proclist_dumper,
		                                  &sctinfo,
		                                  &entrylen,
		                                  tinfo.m_comm.c_str(),
		                                  tinfo.m_exe.c_str(),
		                                  tinfo.m_exepath.c_str(),
		                                  args_iov,
		                                  argscnt,
		                                  envs_iov,
		                                  envscnt,
		                                  (tinfo.get_cwd() == "" ? "/" : tinfo.get_cwd().c_str()),
		                                  cgroups_iov,
		                                  cgroupscnt,
		                                  tinfo.m_root.c_str()) != SCAP_SUCCESS) {
			sinsp_exception exc(scap_dump_getlasterr(proclist_dumper));
			scap_dump_close(proclist_dumper);
			throw exc;
		}

		totlen += entrylen;

		free(args_iov);
		free(envs_iov);
		free(cgroups_iov);

		return true;
	});

	if(scap_write_proclist_end(dumper, proclist_dumper, totlen) != SCAP_SUCCESS) {
		throw sinsp_exception(scap_dump_getlasterr(dumper));
	}

	//
	// Dump the FDs
	//

	m_threadtable.loop([&](sinsp_threadinfo& tinfo) {
		if(tinfo.m_filtered_out) {
			return true;
		}

		scap_threadinfo sctinfo{};

		memset(&sctinfo, 0, sizeof(scap_threadinfo));

		// Note: as scap_fd_add/scap_write_proc_fds do not use
		// any of the array-based fields like comm, etc. a
		// shallow copy is safe
		thread_to_scap(tinfo, &sctinfo);

		if(tinfo.is_main_thread()) {
			//
			// Add the FDs
			//
			sinsp_fdtable* fd_table_ptr = tinfo.get_fd_table();
			if(fd_table_ptr == NULL) {
				return false;
			}

			bool should_exit = false;
			fd_table_ptr->loop([&](int64_t fd, sinsp_fdinfo& info) {
				//
				// Allocate the scap fd info
				//
				scap_fdinfo* scfdinfo = (scap_fdinfo*)malloc(sizeof(scap_fdinfo));
				if(scfdinfo == NULL) {
					scap_fd_free_proc_fd_table(&sctinfo);
					should_exit = true;
					return false;
				}

				//
				// Populate the fd info
				//
				fd_to_scap(*scfdinfo, info);

				//
				// Add the new fd to the scap table.
				//
				if(scap_fd_add(&sctinfo, scfdinfo) != SCAP_SUCCESS) {
					scap_fd_free_proc_fd_table(&sctinfo);
					throw sinsp_exception("Failed to add fd to hash table");
				}

				return true;
			});

			if(should_exit) {
				return false;
			}
		}

		//
		// Dump the thread to disk
		//
		if(scap_write_proc_fds(dumper, &sctinfo) != SCAP_SUCCESS) {
			throw sinsp_exception(
			        "error calling scap_write_proc_fds in "
			        "sinsp_thread_manager::dump_threads_to_file (" +
			        std::string(scap_dump_getlasterr(dumper)) + ")");
		}

		scap_fd_free_proc_fd_table(&sctinfo);
		return true;
	});
}

const threadinfo_map_t::ptr_t& sinsp_thread_manager::get_thread(const int64_t tid,
                                                                const bool lookup_only,
                                                                const bool main_thread) {
	const auto& sinsp_proc = find_thread(tid, lookup_only);

	if(!sinsp_proc && (m_threadtable.size() < m_max_thread_table_size || tid == m_sinsp_pid)) {
		// Certain code paths can lead to this point from scap_open() (incomplete example:
		// scap_proc_scan_proc_dir() -> resolve_container() -> get_env()). Adding a
		// defensive check here to protect both, callers of get_env and get_thread.
		if(!m_scap_handle) {
			libsinsp_logger()->format(sinsp_logger::SEV_INFO,
			                          "%s: Unable to complete for tid=%" PRIu64
			                          ": sinsp::scap_t* is uninitialized",
			                          __func__,
			                          tid);
			return m_nullptr_tinfo_ret;
		}

		scap_threadinfo scap_proc{};
		bool have_scap_proc = false;

		// leaving scap_proc uninitialized could lead to undefined behaviour.
		// to be safe we should initialized to zero.
		memset(&scap_proc, 0, sizeof(scap_threadinfo));

		scap_proc.tid = -1;
		scap_proc.pid = -1;
		scap_proc.ptid = -1;

		// unfortunately, sinsp owns the threade factory
		auto newti = m_threadinfo_factory.create();

		if(main_thread) {
			m_n_main_thread_lookups++;
		}

		if(m_max_n_proc_lookups < 0 || m_n_proc_lookups < m_max_n_proc_lookups) {
			bool scan_sockets = false;
			if(m_max_n_proc_socket_lookups < 0 || m_n_proc_lookups < m_max_n_proc_socket_lookups) {
				scan_sockets = true;
			}

			const uint64_t ts_start = sinsp_utils::get_current_time_ns();
			if(scap_proc_get(m_scap_platform, tid, &scap_proc, scan_sockets) == SCAP_SUCCESS) {
				have_scap_proc = true;
			}
			const uint64_t ts_end = sinsp_utils::get_current_time_ns();

			m_n_proc_lookups_duration_ns += (ts_end - ts_start);
			m_n_proc_lookups++;

			const uint64_t actual_proc_lookup_period = (ts_end - m_last_proc_lookup_period_start);

			maybe_log_max_lookup(tid, scan_sockets, actual_proc_lookup_period);

			if(m_proc_lookup_period && actual_proc_lookup_period >= m_proc_lookup_period) {
				reset_thread_counters();
				m_last_proc_lookup_period_start = ts_end;
			}
		}

		if(have_scap_proc) {
			newti->init(scap_proc, is_large_envs_enabled());
			// we haven't run container detection yet, so use an empty container_id
			// and hope the usergroup_updater fixes it later
			m_usergroup_manager->add_user("",
			                              newti->m_pid,
			                              newti->m_uid,
			                              newti->m_gid,
			                              must_notify_thread_user_update());
			m_usergroup_manager->add_group("",
			                               newti->m_pid,
			                               newti->m_gid,
			                               must_notify_thread_user_update());
		} else {
			//
			// Add a fake entry to avoid a continuous lookup
			//
			newti->m_tid = tid;
			newti->m_pid = -1;
			newti->m_ptid = -1;
			newti->m_reaper_tid = -1;
			newti->m_not_expired_children = 0;
			newti->m_comm = "<NA>";
			newti->m_exe = "<NA>";
			newti->m_uid = 0xffffffff;
			newti->m_gid = 0xffffffff;
			newti->m_loginuid = 0xffffffff;
		}

		//
		// Done. Add the new thread to the list.
		//
		add_thread(std::move(newti), true);
		return find_thread(tid, lookup_only);
	}

	return sinsp_proc;
}

/* `lookup_only==true` means that we don't fill the `m_last_tinfo` field */
const threadinfo_map_t::ptr_t& sinsp_thread_manager::find_thread(int64_t tid, bool lookup_only) {
	//
	// Try looking up in our simple cache
	//
	if(m_last_tid >= 0 && tid == m_last_tid && m_last_tinfo) {
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_cached_thread_lookups++;
		}
		// This allows us to avoid performing an actual timestamp lookup
		// for something that may not need to be precise
		m_last_tinfo->m_lastaccess_ts = m_timestamper.get_cached_ts();
		m_last_tinfo->update_main_fdtable();
		return m_last_tinfo;
	}

	//
	// Caching failed, do a real lookup
	//
	const auto& thr = m_threadtable.get_ref(tid);

	if(thr) {
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_noncached_thread_lookups++;
		}
		if(!lookup_only) {
			m_last_tid = tid;
			m_last_tinfo = thr;
			thr->m_lastaccess_ts = m_timestamper.get_cached_ts();
		}
		thr->update_main_fdtable();
		return thr;
	} else {
		if(m_sinsp_stats_v2 != nullptr) {
			m_sinsp_stats_v2->m_n_failed_thread_lookups++;
		}

		return m_nullptr_tinfo_ret;
	}
}

sinsp_threadinfo* sinsp_thread_manager::get_ancestor_process(sinsp_threadinfo& tinfo, uint32_t n) {
	sinsp_threadinfo* mt = tinfo.get_main_thread();

	for(uint32_t i = 0; i < n; i++) {
		if(mt == nullptr) {
			return nullptr;
		}
		mt = find_thread(mt->m_ptid, true).get();
		if(mt == nullptr) {
			return nullptr;
		}
		mt = mt->get_main_thread();
	}

	return mt;
}

void sinsp_thread_manager::set_max_thread_table_size(uint32_t value) {
	m_max_thread_table_size = value;
}

std::unique_ptr<libsinsp::state::table_entry> sinsp_thread_manager::new_entry() const {
	return m_threadinfo_factory.create();
}
