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
#include <cinttypes>
#include <libscap/strl.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <libsinsp/sinsp_observer.h>
#include <libscap/scap-int.h>
#include <libscap/scap_platform_api.h>

extern sinsp_evttables g_infotables;

static void copy_ipv6_address(uint32_t (&dest)[4], const uint32_t (&src)[4]) {
	dest[0] = src[0];
	dest[1] = src[1];
	dest[2] = src[2];
	dest[3] = src[3];
}

static void fd_to_scap(scap_fdinfo& dst, const sinsp_fdinfo& src) {
	dst.type = src.get_type();
	dst.ino = src.get_ino();
	dst.fd = src.get_fd_num();

	auto si = src.get_sockinfo();
	switch(dst.type) {
	case SCAP_FD_IPV4_SOCK:
		dst.info.ipv4info.sip = si.m_ipv4info.m_fields.m_sip;
		dst.info.ipv4info.dip = si.m_ipv4info.m_fields.m_dip;
		dst.info.ipv4info.sport = si.m_ipv4info.m_fields.m_sport;
		dst.info.ipv4info.dport = si.m_ipv4info.m_fields.m_dport;
		dst.info.ipv4info.l4proto = si.m_ipv4info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		dst.info.ipv4serverinfo.ip = si.m_ipv4serverinfo.m_ip;
		dst.info.ipv4serverinfo.port = si.m_ipv4serverinfo.m_port;
		dst.info.ipv4serverinfo.l4proto = si.m_ipv4serverinfo.m_l4proto;
		break;
	case SCAP_FD_IPV6_SOCK:
		copy_ipv6_address(dst.info.ipv6info.sip, si.m_ipv6info.m_fields.m_sip.m_b);
		copy_ipv6_address(dst.info.ipv6info.dip, si.m_ipv6info.m_fields.m_dip.m_b);
		dst.info.ipv6info.sport = si.m_ipv6info.m_fields.m_sport;
		dst.info.ipv6info.dport = si.m_ipv6info.m_fields.m_dport;
		dst.info.ipv6info.l4proto = si.m_ipv6info.m_fields.m_l4proto;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		copy_ipv6_address(dst.info.ipv6serverinfo.ip, si.m_ipv6serverinfo.m_ip.m_b);
		dst.info.ipv6serverinfo.port = si.m_ipv6serverinfo.m_port;
		dst.info.ipv6serverinfo.l4proto = si.m_ipv6serverinfo.m_l4proto;
		break;
	case SCAP_FD_UNIX_SOCK:
		dst.info.unix_socket_info.source = si.m_unixinfo.m_fields.m_source;
		dst.info.unix_socket_info.destination = si.m_unixinfo.m_fields.m_dest;
		strlcpy(dst.info.unix_socket_info.fname,
		        src.get_name().c_str(),
		        sizeof(dst.info.unix_socket_info.fname));
		break;
	case SCAP_FD_FILE_V2:
		dst.info.regularinfo.open_flags = src.get_openflags();
		strlcpy(dst.info.regularinfo.fname,
		        src.get_name().c_str(),
		        sizeof(dst.info.regularinfo.fname));
		dst.info.regularinfo.dev = src.get_dev();
		dst.info.regularinfo.mount_id = src.get_mount_id();
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
		strlcpy(dst.info.fname, src.get_name().c_str(), sizeof(dst.info.fname));
		break;
	default:
		ASSERT(false);
		break;
	}
}

static const auto s_threadinfo_static_fields = sinsp_threadinfo::get_static_fields();

template<typename SyncPolicy>
sinsp_thread_manager_impl<SyncPolicy>::sinsp_thread_manager_impl(
        const sinsp_threadinfo_factory& threadinfo_factory,
        sinsp_observer* const& observer,
        const timestamper& timestamper,
        const int64_t& sinsp_pid,
        const uint64_t& threads_purging_scan_time_ns,
        const uint64_t& thread_timeout_ns,
        const std::shared_ptr<sinsp_stats_v2>& sinsp_stats_v2,
        scap_platform* const& scap_platform,
        scap_t* const& scap_handle,
        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& thread_manager_dyn_fields,
        const std::shared_ptr<libsinsp::state::dynamic_field_infos>& fdtable_dyn_fields):
        extensible_table{s_thread_table_name,
                         &s_threadinfo_static_fields,
                         thread_manager_dyn_fields},
        m_threadinfo_factory{threadinfo_factory},
        m_observer{observer},
        m_timestamper{timestamper},
        m_sinsp_pid{sinsp_pid},
        m_threads_purging_scan_time_ns{threads_purging_scan_time_ns},
        m_thread_timeout_ns{thread_timeout_ns},
        m_sinsp_stats_v2{sinsp_stats_v2},
        m_scap_platform{scap_platform},
        m_scap_handle{scap_handle},
        m_fdtable_dyn_fields{fdtable_dyn_fields},
        m_max_thread_table_size(m_thread_table_default_size) {
	m_last_proc_lookup_period_start.store(sinsp_utils::get_current_time_ns());
	clear();
}

template<typename SyncPolicy>
std::shared_ptr<thread_group_info> sinsp_thread_manager_impl<SyncPolicy>::get_thread_group_info(
        const int64_t pid) const {
	std::shared_lock lock(m_thread_groups_mutex);
	auto it = m_thread_groups.find(pid);
	if(it != m_thread_groups.end()) {
		return it->second;
	}
	return nullptr;
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::set_thread_group_info(
        const int64_t pid,
        const std::shared_ptr<thread_group_info>& tginfo) {
	std::unique_lock lock(m_thread_groups_mutex);
	// It should be impossible to have a pid conflict. Right now we manage it by replacing the
	// old entry with the new one.
	if(const auto [it, inserted] = m_thread_groups.emplace(pid, tginfo); !inserted) {
		it->second = tginfo;
	}
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::clear() {
	{
		std::unique_lock lock(m_thread_groups_mutex);
		m_thread_groups.clear();
	}
	m_last_flush_time_ns.store(0);
	{
		std::unique_lock lock(m_recently_exited_mutex);
		m_recently_exited_tids.fill({});
		m_recently_exited_write_idx = 0;
	}
}

template<typename SyncPolicy>
bool sinsp_thread_manager_impl<SyncPolicy>::foreach_entry(
        std::function<bool(libsinsp::state::table_entry& e)> pred) {
	return m_threadtable.loop([&pred](sinsp_threadinfo_impl<SyncPolicy>& e) { return pred(e); });
}

/* This is called on the table after the `/proc` scan */
template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::create_thread_dependencies(
        const std::shared_ptr<sinsp_threadinfo_impl<SyncPolicy>>& tinfo) {
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
	if(tinfo->get_tginfo() != nullptr) {
		tinfo->update_main_fdtable();
		return;
	}

	bool reaper = false;
	/* reaper should be true if we are an init process for the init namespace or for an inner
	 * namespace */
	if(tinfo->get_pid() == 1 || tinfo->get_vpid() == 1) {
		reaper = true;
	}

	/* Create the thread group info for the thread. */
	auto tginfo = get_thread_group_info(tinfo->get_pid());
	if(tginfo == nullptr) {
		tginfo = std::make_shared<thread_group_info>(tinfo->get_pid(), reaper, tinfo);
		set_thread_group_info(tinfo->get_pid(), tginfo);
	} else {
		tginfo->add_thread_to_group(tinfo, tinfo->is_main_thread());
	}
	tinfo->set_tginfo(tginfo);

	// update fdtable cached pointer for all threads in the group (which includes
	// the current thread), as their leader might have changed or we simply need
	// to first initialize it. Then we do the same with the thread's children.
	for(const auto& thread : tginfo->get_thread_list()) {
		if(auto thread_ptr = thread.lock().get(); thread_ptr != nullptr) {
			thread_ptr->update_main_fdtable();
		}
	}
	tinfo->for_each_child([](const std::shared_ptr<sinsp_threadinfo_impl<SyncPolicy>>& child) {
		child->update_main_fdtable();
	});

	/* init group has no parent */
	if(tinfo->get_pid() == 1) {
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
	const auto parent_thread = find_thread(tinfo->get_ptid(), true);
	if(parent_thread == nullptr || parent_thread->is_invalid()) {
		/* If we have a valid parent we assign the new child to it otherwise we set ptid = 0. */
		tinfo->set_ptid(0);
		tinfo->update_main_fdtable();
		return;
	}
	parent_thread->add_child(tinfo);
}

/* Can be called when:
 * 1. We crafted a new event to create in clone parsers. (`must_create_thread_dependencies==true`)
 * 2. We are doing a proc scan with a callback or without. (`must_create_thread_dependencies==true`)
 * 3. We are trying to obtain thread info from /proc through `get_thread_ref`
 */
template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t sinsp_thread_manager_impl<SyncPolicy>::add_thread(
        std::unique_ptr<sinsp_threadinfo_impl<SyncPolicy>> threadinfo,
        const bool must_create_thread_dependencies) {
	/* We have no more space */
	if(m_threadtable.size() >= m_max_thread_table_size && threadinfo->get_pid() != m_sinsp_pid) {
		if(m_sinsp_stats_v2 != nullptr) {
			auto& c = m_sinsp_stats_v2->get_thread_counters();
			// rate limit messages to avoid spamming the logs
			if(c.get_n_drops_full_threadtable() % m_max_thread_table_size == 0) {
				libsinsp_logger()->format(
				        sinsp_logger::SEV_INFO,
				        "Thread table full, dropping tid %lu (pid %lu, comm \"%s\")",
				        threadinfo->m_tid,
				        threadinfo->get_pid(),
				        threadinfo->get_comm().c_str());
			}
			c.inc_n_drops_full_threadtable();
		}

		return {};
	}

	auto tinfo_shared_ptr =
	        std::shared_ptr<sinsp_threadinfo_impl<SyncPolicy>>(std::move(threadinfo));

	if(must_create_thread_dependencies) {
		create_thread_dependencies(tinfo_shared_ptr);
	}

	if(tinfo_shared_ptr->get_fdtable().dynamic_fields() != m_fdtable_dyn_fields) {
		throw sinsp_exception(
		        "adding entry with incompatible dynamic defs to of file descriptor sub-table");
	}

	if(m_sinsp_stats_v2 != nullptr) {
		auto& c = m_sinsp_stats_v2->get_thread_counters();
		c.inc_n_added_threads();
	}

	tinfo_shared_ptr->update_main_fdtable();
	return m_threadtable.put(tinfo_shared_ptr);
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::remove_child_from_parent(
        int64_t ptid,
        const std::shared_ptr<sinsp_threadinfo_impl<SyncPolicy>>& child) {
	typename threadinfo_map_impl_t<SyncPolicy>::ptr_t parent = find_thread(ptid, true);
	if(!parent) {
		return;
	}

	parent->remove_child_and_maybe_clean(child);
}

/* Taken from `find_new_reaper` kernel function:
 *
 * When we die, we re-parent all our children, and try to:
 * 1. give them to another thread in our thread group, if such a member exists.
 * 2. give them to the first ancestor process which prctl'd itself as a
 *    child_subreaper for its children (like a service manager)
 * 3. give them to the init process (PID 1) in our pid namespace
 */
template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t
sinsp_thread_manager_impl<SyncPolicy>::find_new_reaper(sinsp_threadinfo_impl<SyncPolicy>* tinfo) {
	if(tinfo == nullptr) {
		throw sinsp_exception("cannot call find_new_reaper() on a null tinfo");
	}

	/* First we check in our thread group for alive threads */
	if(tinfo->get_tginfo() != nullptr && tinfo->get_tginfo()->get_thread_count() > 0) {
		for(const auto& thread_weak : tinfo->get_tginfo()->get_thread_list()) {
			if(thread_weak.expired()) {
				continue;
			}
			auto thread_ptr = thread_weak.lock();
			if(!thread_ptr->is_dead() && thread_ptr.get() != tinfo) {
				return thread_ptr;
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

	auto parent_ptr = find_thread(tinfo->get_ptid(), true);
	sinsp_threadinfo_impl<SyncPolicy>* parent_tinfo = parent_ptr.get();
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

		if(parent_tinfo->get_tginfo() != nullptr && parent_tinfo->get_tginfo()->is_reaper() &&
		   parent_tinfo->get_tginfo()->get_thread_count() > 0) {
			for(const auto& thread_weak : parent_tinfo->get_tginfo()->get_thread_list()) {
				if(thread_weak.expired()) {
					continue;
				}
				auto thread_ptr = thread_weak.lock();
				if(!thread_ptr->is_dead()) {
					return thread_ptr;
				}
			}
		}
		parent_ptr = find_thread(parent_tinfo->get_ptid(), true);
		parent_tinfo = parent_ptr.get();
	}

	return {};
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::remove_main_thread_fdtable(
        sinsp_threadinfo_impl<SyncPolicy>* main_thread) const {
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

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::remove_thread(int64_t tid) {
	auto thread_to_remove_ref = m_threadtable.get_ref(tid);
	if(!thread_to_remove_ref) {
		if(m_sinsp_stats_v2 != nullptr) {
			auto& c = m_sinsp_stats_v2->get_thread_counters();
			c.inc_n_failed_thread_lookups();
		}
		return;
	}
	std::shared_ptr<sinsp_threadinfo_impl<SyncPolicy>> thread_to_remove = thread_to_remove_ref;

	/* [Remove invalid threads]
	 * All threads should have a m_tginfo apart from the invalid ones
	 * which don't have a group or children.
	 */
	if(thread_to_remove->is_invalid() || thread_to_remove->get_tginfo() == nullptr) {
		remove_child_from_parent(thread_to_remove->get_ptid(), thread_to_remove);
		m_threadtable.erase(tid);
		return;
	}

	/* [Mark the thread as dead]
	 * If didn't lose the PROC_EXIT event we have already done it
	 */
	if(!thread_to_remove->is_dead()) {
		/* we should decrement only if the thread is alive */
		thread_to_remove->get_tginfo()->decrement_thread_count();
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
	if(thread_to_remove->has_children()) {
		typename threadinfo_map_impl_t<SyncPolicy>::ptr_t reaper_tinfo;

		if(thread_to_remove->get_reaper_tid() > 0) {
			/* The kernel sent us a valid reaper
			 * We should have the reaper thread in the table, but if we don't have
			 * it, we try to create it from /proc
			 */
			reaper_tinfo = get_thread(thread_to_remove->get_reaper_tid());
		}

		if(!reaper_tinfo || reaper_tinfo->is_invalid()) {
			/* Fallback case:
			 * We search for a reaper in best effort traversing our table
			 */
			reaper_tinfo = find_new_reaper(thread_to_remove.get());
		}

		if(reaper_tinfo) {
			/* We update the reaper tid if necessary. */
			thread_to_remove->set_reaper_tid(reaper_tinfo->m_tid);

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
			if(reaper_tinfo->get_pid() != thread_to_remove->get_pid() &&
			   reaper_tinfo->get_tginfo()) {
				reaper_tinfo->get_tginfo()->set_reaper(true);
			}
		}
		thread_to_remove->assign_children_to_reaper(reaper_tinfo.get());
	}

	/* [Remove main thread]
	 * We remove the main thread if there are no other threads in the group
	 */
	if((thread_to_remove->get_tginfo()->get_thread_count() == 0)) {
		auto main_thread_holder = thread_to_remove->get_main_thread();
		remove_main_thread_fdtable(main_thread_holder.get());

		/* we remove the main thread and the thread group */
		/* even if thread_to_remove is not the main thread the parent will be
		 * the same so it's ok.
		 */
		thread_to_remove->get_tginfo()->remove_thread_from_list(thread_to_remove);
		remove_child_from_parent(thread_to_remove->get_ptid(), thread_to_remove);
		{
			std::unique_lock lock(m_thread_groups_mutex);
			m_thread_groups.erase(thread_to_remove->get_pid());
		}
		// Only init (tid 1) has m_pid 1; ensure we never erase key 1 when removing a non-init
		// thread
		ASSERT(thread_to_remove->get_pid() != 1 || thread_to_remove->m_tid == 1);
		m_threadtable.erase(thread_to_remove->get_pid());
	}

	/* [Remove the current thread]
	 * We remove the current thread if it is not the main one.
	 * If we are the main thread and it's time to be removed, we are removed
	 * in the previous `if`.
	 */
	if(!thread_to_remove->is_main_thread()) {
		thread_to_remove->get_tginfo()->remove_thread_from_list(thread_to_remove);
		remove_child_from_parent(thread_to_remove->get_ptid(), thread_to_remove);
		m_threadtable.erase(tid);
	}
	if(m_sinsp_stats_v2 != nullptr) {
		auto& c = m_sinsp_stats_v2->get_thread_counters();
		c.inc_n_removed_threads();
	}
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::fix_sockets_coming_from_proc(
        const bool resolve_hostname_and_port) {
	std::set<uint16_t> server_ports_copy;
	{
		std::shared_lock lock(m_server_ports_mutex);
		server_ports_copy = m_server_ports;
	}
	m_threadtable.loop([&](sinsp_threadinfo_impl<SyncPolicy>& tinfo) {
		tinfo.fix_sockets_coming_from_proc(server_ports_copy, resolve_hostname_and_port);
		return true;
	});
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::clear_thread_pointers(
        sinsp_threadinfo_impl<SyncPolicy>& tinfo) {
	sinsp_fdtable* fdt = tinfo.get_fd_table();
	if(fdt != NULL) {
		fdt->reset_cache();
	}
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::reset_child_dependencies() {
	m_threadtable.loop([&](sinsp_threadinfo_impl<SyncPolicy>& tinfo) {
		tinfo.clean_expired_children();
		/* Little optimization: only the main thread cleans the thread group from expired threads.
		 * Downside: if the main thread is not present in the thread group because we lost it we
		 * don't clean the thread group from expired threads.
		 */
		if(tinfo.is_main_thread() && tinfo.get_tginfo() != nullptr) {
			tinfo.get_tginfo()->clean_expired_threads();
		}
		clear_thread_pointers(tinfo);
		return true;
	});
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::create_thread_dependencies_after_proc_scan() {
	m_threadtable.const_loop_shared_pointer(
	        [&](const std::shared_ptr<sinsp_threadinfo_impl<SyncPolicy>>& tinfo) {
		        create_thread_dependencies(tinfo);
		        return true;
	        });
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::free_dump_fdinfos(
        std::vector<scap_fdinfo*>* fdinfos_to_free) {
	for(uint32_t j = 0; j < fdinfos_to_free->size(); j++) {
		free(fdinfos_to_free->at(j));
	}

	fdinfos_to_free->clear();
}

// NOTE: This does *not* populate any array-based fields (comm, exe,
// exepath, args, env, cwd, cgroups, root)
template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::thread_to_scap(sinsp_threadinfo_impl<SyncPolicy>& tinfo,
                                                           scap_threadinfo* sctinfo) {
	//
	// Fill in the thread data
	//

	// NOTE: This is doing a shallow copy of the strings from
	// tinfo, and is valid only as long as tinfo is valid.

	sctinfo->tid = tinfo.m_tid;
	sctinfo->pid = tinfo.get_pid();
	sctinfo->ptid = tinfo.get_ptid();
	sctinfo->sid = tinfo.get_sid();
	sctinfo->vpgid = tinfo.get_vpgid();
	sctinfo->pgid = tinfo.get_pgid();

	sctinfo->flags = tinfo.get_flags();
	sctinfo->fdlimit = tinfo.get_fdlimit();
	sctinfo->uid = tinfo.get_uid();
	sctinfo->gid = tinfo.get_gid();
	sctinfo->vmsize_kb = tinfo.get_vmsize_kb();
	sctinfo->vmrss_kb = tinfo.get_vmrss_kb();
	sctinfo->vmswap_kb = tinfo.get_vmswap_kb();
	sctinfo->pfmajor = tinfo.get_pfmajor();
	sctinfo->pfminor = tinfo.get_pfminor();
	sctinfo->vtid = tinfo.get_vtid();
	sctinfo->vpid = tinfo.get_vpid();
	sctinfo->fdlist = NULL;
	sctinfo->loginuid = tinfo.get_loginuid();
	sctinfo->filtered_out = tinfo.get_filtered_out();
}

template<typename SyncPolicy>
std::shared_ptr<sinsp_fdinfo_impl<SyncPolicy>>
sinsp_thread_manager_impl<SyncPolicy>::add_thread_fd_from_scap(
        sinsp_threadinfo_impl<SyncPolicy>& tinfo,
        const scap_fdinfo& fdinfo,
        const bool resolve_hostname_and_port) {
	auto newfdinfo = tinfo.add_fd_from_scap(fdinfo, resolve_hostname_and_port);
	if(!newfdinfo) {
		return nullptr;
	}

	// We keep note of all the host bound server ports. We'll need them later when patching
	// connections direction.
	uint16_t server_port;
	switch(newfdinfo->get_type()) {
	case SCAP_FD_IPV4_SERVSOCK:
		server_port = newfdinfo->get_sockinfo().m_ipv4serverinfo.m_port;
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		server_port = newfdinfo->get_sockinfo().m_ipv6serverinfo.m_port;
		break;
	default:
		return newfdinfo;
	}

	{
		std::unique_lock lock(m_server_ports_mutex);
		m_server_ports.insert(server_port);
	}
	return newfdinfo;
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::maybe_log_max_lookup(int64_t tid,
                                                                 bool scan_sockets,
                                                                 uint64_t period) {
	if(m_proc_lookup_period) {
		if(m_n_proc_lookups.load() == m_max_n_proc_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max process lookup number (%d)"
			                          " in the last %" PRIu64 "ms, duration=%" PRIu64 "ms",
			                          m_n_proc_lookups.load(),
			                          period / 1000000,
			                          m_n_proc_lookups_duration_ns.load() / 1000000);
		}
		if(scan_sockets && m_n_proc_lookups.load() == m_max_n_proc_socket_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max socket lookup number (%d)"
			                          " in the last %" PRIu64 "ms, tid=%" PRIu64
			                          ", duration=%" PRIu64 "ms",
			                          m_n_proc_lookups.load(),
			                          period / 1000000,
			                          tid,
			                          m_n_proc_lookups_duration_ns.load() / 1000000);
		}
	} else {
		if(m_n_proc_lookups.load() == m_max_n_proc_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max process lookup number (%d)"
			                          ", duration=%" PRIu64 "ms",
			                          m_n_proc_lookups.load(),
			                          m_n_proc_lookups_duration_ns.load() / 1000000);
		}
		if(scan_sockets && m_n_proc_lookups.load() == m_max_n_proc_socket_lookups) {
			libsinsp_logger()->format(sinsp_logger::SEV_DEBUG,
			                          "Reached max socket lookup number (%d), tid=%" PRIu64
			                          ", duration=%" PRIu64 "ms",
			                          m_n_proc_lookups.load(),
			                          tid,
			                          m_n_proc_lookups_duration_ns.load() / 1000000);
		}
	}
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::traverse_parent_state(
        sinsp_threadinfo_impl<SyncPolicy>& tinfo,
        visitor_func_t& visitor) {
	// Floyd's cycle detection: two pointers traverse the parent chain at
	// different rates. If they meet before reaching the end, there's a loop.
	// We hold shared_ptr locals so the underlying threadinfo stays alive
	// even if another thread concurrently erases it from the table.

	auto slow = find_thread(tinfo.get_ptid(), true);
	auto fast = slow;

	fast = (fast ? find_thread(fast->get_ptid(), true) : fast);

	while(slow && slow->m_tid != -1) {
		if(!visitor(slow.get())) {
			break;
		}

		slow = find_thread(slow->get_ptid(), true);

		for(uint32_t i = 0; i < 2; i++) {
			fast = (fast ? find_thread(fast->get_ptid(), true) : fast);

			if(slow && (slow.get() == fast.get() || slow->m_tid == slow->get_ptid())) {
				tinfo.report_thread_loop(*slow);
				return;
			}
		}
	}
}
template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t
sinsp_thread_manager_impl<SyncPolicy>::get_oldest_matching_ancestor(
        sinsp_threadinfo_impl<SyncPolicy>* tinfo,
        const std::function<int64_t(sinsp_threadinfo_impl<SyncPolicy>*)>& get_thread_id,
        bool is_virtual_id) {
	int64_t id = get_thread_id(tinfo);
	if(id == -1) {
		// the id is not set
		return {};
	}

	// If we are using a non virtual id or if the id is virtual but we are in the init namespace we
	// can access the thread table directly!
	// if is_virtual_id == false we don't care about the namespace in which we are
	if(!is_virtual_id || !tinfo->is_in_pid_namespace()) {
		auto leader = find_thread(id, true);
		if(leader) {
			return leader;
		}
	}

	// If we are in a pid_namespace we cannot use directly m_sid to access the table
	// since it could be related to a pid namespace.
	int64_t leader_tid = -1;
	visitor_func_t visitor =
	        [id, &leader_tid, get_thread_id](sinsp_threadinfo_impl<SyncPolicy>* pt) {
		        if(get_thread_id(pt) != id) {
			        return false;
		        }
		        leader_tid = pt->m_tid;
		        return true;
	        };

	traverse_parent_state(*tinfo, visitor);
	if(leader_tid != -1) {
		return find_thread(leader_tid, true);
	}
	return {};
}

template<typename SyncPolicy>
std::string sinsp_thread_manager_impl<SyncPolicy>::get_ancestor_field_as_string(
        sinsp_threadinfo_impl<SyncPolicy>* tinfo,
        const std::function<int64_t(sinsp_threadinfo_impl<SyncPolicy>*)>& get_thread_id,
        const std::function<std::string(sinsp_threadinfo_impl<SyncPolicy>*)>& get_field_str,
        bool is_virtual_id) {
	auto ancestor = get_oldest_matching_ancestor(tinfo, get_thread_id, is_virtual_id);
	if(ancestor) {
		return get_field_str(ancestor.get());
	}
	return "";
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::dump_threads_to_file(scap_dumper_t* dumper) {
	if(m_threadtable.size() == 0) {
		return;
	}

	scap_dumper_t* proclist_dumper = scap_write_proclist_begin();
	if(proclist_dumper == nullptr) {
		throw sinsp_exception("Failed to create proclist dumper");
	}

	uint32_t totlen = 0;
	m_threadtable.loop([&](sinsp_threadinfo_impl<SyncPolicy>& tinfo) {
		if(tinfo.get_filtered_out()) {
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
		                                  tinfo.get_comm().c_str(),
		                                  tinfo.get_exe().c_str(),
		                                  tinfo.get_exepath().c_str(),
		                                  args_iov,
		                                  argscnt,
		                                  envs_iov,
		                                  envscnt,
		                                  (tinfo.get_cwd() == "" ? "/" : tinfo.get_cwd().c_str()),
		                                  cgroups_iov,
		                                  cgroupscnt,
		                                  tinfo.get_root().c_str()) != SCAP_SUCCESS) {
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

	m_threadtable.loop([&](sinsp_threadinfo_impl<SyncPolicy>& tinfo) {
		if(tinfo.get_filtered_out()) {
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

template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t sinsp_thread_manager_impl<SyncPolicy>::get_thread(
        const int64_t tid,
        const bool lookup_only,
        const bool main_thread) {
	auto sinsp_proc = find_thread(tid, lookup_only);

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
			return {};
		}

		bool thread_fetched = false;

		if(main_thread) {
			m_n_main_thread_lookups.fetch_add(1);
		}

		if(m_max_n_proc_lookups < 0 || m_n_proc_lookups.load() < m_max_n_proc_lookups) {
			bool scan_sockets = false;
			if(m_max_n_proc_socket_lookups < 0 ||
			   m_n_proc_lookups.load() < m_max_n_proc_socket_lookups) {
				scan_sockets = true;
			}

			const uint64_t ts_start = sinsp_utils::get_current_time_ns();
			thread_fetched = scap_proc_get(m_scap_platform, tid, scan_sockets) == SCAP_SUCCESS;
			const uint64_t ts_end = sinsp_utils::get_current_time_ns();

			m_n_proc_lookups_duration_ns.fetch_add(ts_end - ts_start);
			m_n_proc_lookups.fetch_add(1);

			const uint64_t actual_proc_lookup_period =
			        (ts_end - m_last_proc_lookup_period_start.load());

			maybe_log_max_lookup(tid, scan_sockets, actual_proc_lookup_period);

			if(m_proc_lookup_period && actual_proc_lookup_period >= m_proc_lookup_period) {
				reset_thread_counters();
				m_last_proc_lookup_period_start.store(ts_end);
			}
		}

		// Add a fake entry to avoid a continuous lookup.
		if(!thread_fetched) {
			auto fake_tinfo = m_threadinfo_factory.create();
			fake_tinfo->m_tid = tid;
			fake_tinfo->set_pid(-1);
			fake_tinfo->set_ptid(-1);
			fake_tinfo->set_reaper_tid(-1);
			fake_tinfo->set_not_expired_children(0);
			fake_tinfo->set_comm("<NA>");
			fake_tinfo->set_exe("<NA>");
			fake_tinfo->set_uid(0xffffffff);
			fake_tinfo->set_gid(0xffffffff);
			fake_tinfo->set_loginuid(0xffffffff);
			add_thread(std::move(fake_tinfo), true);
		}

		return find_thread(tid, lookup_only);
	}

	return sinsp_proc;
}

template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t
sinsp_thread_manager_impl<SyncPolicy>::get_or_create_fake_thread(int64_t tid) {
	auto existing = find_thread(tid, true);
	if(existing) {
		return existing;
	}
	auto fake_tinfo = m_threadinfo_factory.create();
	fake_tinfo->m_tid = tid;
	fake_tinfo->set_pid(-1);
	fake_tinfo->set_ptid(-1);
	fake_tinfo->set_reaper_tid(-1);
	fake_tinfo->set_not_expired_children(0);
	fake_tinfo->set_comm("<NA>");
	fake_tinfo->set_exe("<NA>");
	fake_tinfo->set_uid(0xffffffff);
	fake_tinfo->set_gid(0xffffffff);
	fake_tinfo->set_loginuid(0xffffffff);
	add_thread(std::move(fake_tinfo), true);
	return find_thread(tid, false);
}

template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t
sinsp_thread_manager_impl<SyncPolicy>::find_thread(int64_t tid, bool lookup_only) {
	auto thr = m_threadtable.get_ref(tid);
	if(thr) {
		if(m_sinsp_stats_v2 != nullptr) {
			auto& c = m_sinsp_stats_v2->get_thread_counters();
			c.inc_n_noncached_thread_lookups();
		}
		if(!lookup_only) {
			thr->set_lastaccess_ts(m_timestamper.get_cached_ts());
		}
		thr->update_main_fdtable();
		return thr;
	}
	if(m_sinsp_stats_v2 != nullptr) {
		auto& c = m_sinsp_stats_v2->get_thread_counters();
		c.inc_n_failed_thread_lookups();
	}
	return {};
}

template<typename SyncPolicy>
typename threadinfo_map_impl_t<SyncPolicy>::ptr_t sinsp_thread_manager_impl<
        SyncPolicy>::get_ancestor_process(sinsp_threadinfo_impl<SyncPolicy>& tinfo, uint32_t n) {
	auto mt = tinfo.get_main_thread();

	for(uint32_t i = 0; i < n; i++) {
		if(!mt) {
			return {};
		}
		auto parent = find_thread(mt->get_ptid(), true);
		if(!parent) {
			return {};
		}
		mt = parent->get_main_thread();
	}

	if(mt) {
		return find_thread(mt->m_tid, true);
	}
	return {};
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::set_max_thread_table_size(uint32_t value) {
	m_max_thread_table_size = value;
}

static constexpr uint64_t make_key(uint64_t ptid, uint64_t tid) {
	constexpr uint64_t mask32 = 0xFFFFFFFFULL;
	return ((ptid & mask32) << 32) | (tid & mask32);
}

template<typename SyncPolicy>
void sinsp_thread_manager_impl<SyncPolicy>::record_recently_exited(int64_t tid,
                                                                   int64_t ptid,
                                                                   uint64_t ts) {
	std::unique_lock lock(m_recently_exited_mutex);
	m_recently_exited_tids[m_recently_exited_write_idx] = {make_key(ptid, tid), ts};
	m_recently_exited_write_idx = (m_recently_exited_write_idx + 1) % RECENTLY_EXITED_RING_SIZE;
}

template<typename SyncPolicy>
bool sinsp_thread_manager_impl<SyncPolicy>::has_recently_exited(int64_t tid,
                                                                int64_t ptid,
                                                                uint64_t ts) const {
	/* Only match entries within a 2-second window to avoid false positives
	 * from TID recycling. This matches CLONE_STALE_TIME_NS used elsewhere
	 * in the clone parsers. The composite (ptid, tid) key provides a second
	 * layer of protection: both TIDs would need to be recycled simultaneously
	 * for a false positive to occur.
	 */
	static constexpr uint64_t MAX_AGE_NS = 2ULL * 1000000000ULL;
	const uint64_t key = make_key(ptid, tid);
	std::shared_lock lock(m_recently_exited_mutex);
	for(size_t i = 0; i < RECENTLY_EXITED_RING_SIZE; i++) {
		if(m_recently_exited_tids[i].key == key && ts >= m_recently_exited_tids[i].ts &&
		   (ts - m_recently_exited_tids[i].ts) < MAX_AGE_NS) {
			return true;
		}
	}
	return false;
}

template<typename SyncPolicy>
std::unique_ptr<libsinsp::state::table_entry> sinsp_thread_manager_impl<SyncPolicy>::new_entry()
        const {
	return m_threadinfo_factory.create();
}

template<typename SyncPolicy>
bool sinsp_thread_manager_impl<SyncPolicy>::remove_inactive_threads() {
	const uint64_t last_event_ts = m_timestamper.get_cached_ts();

	if(m_last_flush_time_ns == 0) {
		// Set the first table scan for 30 seconds in, so that we can spot bugs in the logic without
		// having to wait for tens of minutes.
		if(m_threads_purging_scan_time_ns > 30 * ONE_SECOND_IN_NS) {
			m_last_flush_time_ns =
			        last_event_ts - m_threads_purging_scan_time_ns + 30 * ONE_SECOND_IN_NS;
		} else {
			m_last_flush_time_ns = last_event_ts - m_threads_purging_scan_time_ns;
		}
	}

	if(last_event_ts <= m_last_flush_time_ns + m_threads_purging_scan_time_ns) {
		return false;
	}

	libsinsp_logger()->format(sinsp_logger::SEV_DEBUG, "Flushing thread table");
	m_last_flush_time_ns = last_event_ts;

	// Here we loop over the table in search of threads to delete. We remove:
	// 1. Invalid threads.
	// 2. Threads that we are not using and that are no more alive in /proc.
	std::unordered_set<int64_t> to_delete;
	loop_threads([&to_delete, last_event_ts, this](const sinsp_threadinfo_impl<SyncPolicy>& tinfo) {
		if(tinfo.is_invalid() || (last_event_ts > tinfo.get_lastaccess_ts() + m_thread_timeout_ns &&
		                          !scap_is_thread_alive(m_scap_platform,
		                                                tinfo.get_pid(),
		                                                tinfo.m_tid,
		                                                tinfo.get_comm().c_str()))) {
			to_delete.insert(tinfo.m_tid);
		}
		return true;
	});

	for(const auto& tid_to_remove : to_delete) {
		remove_thread(tid_to_remove);
	}

	// Clean expired threads in the group and children.
	reset_child_dependencies();
	return true;
}

template class sinsp_thread_manager_impl<sync_policy_default>;
