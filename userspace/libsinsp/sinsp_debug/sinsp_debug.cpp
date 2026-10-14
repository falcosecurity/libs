

#include <libsinsp/sinsp.h>
#include <iostream>
#include <csignal>
#include <cinttypes>
#include <set>

static bool g_interrupted = false;

static void sigint_handler(int signum) {
	g_interrupted = true;
}

std::string thread_info_to_string(sinsp_threadinfo* tinfo) {
	std::ostringstream out;
	if(tinfo->is_main_thread()) {
		/* Main thread notation */
		out << "[" << tinfo->get_comm() << "]";
	} else {
		/* Secondary thread notation */
		out << "{" << tinfo->get_comm() << "}";
	}

	/* if it is a reaper add (R)*/
	if(tinfo->m_tginfo && tinfo->m_tginfo->is_reaper()) {
		out << "💀";
	}

	out << " t: " << tinfo->m_tid;
	out << ", p: " << tinfo->m_pid;
	out << ", rpt: " << tinfo->get_ptid();  // rpt (real parent tid)
	out << ", vt: " << tinfo->m_vtid;
	out << ", vp: " << tinfo->m_vpid;
	out << ", vs: " << tinfo->m_sid;  // vs (we call it sid but it is a vsid)
	out << ", vpg: " << tinfo->m_vpgid;
	out << ", ct: " << tinfo->is_in_pid_namespace();
	out << ", e: " << tinfo->get_exepath();

	return out.str();
}

void display_thread_lineage(sinsp_thread_manager& thread_manager, sinsp_threadinfo* tinfo) {
	sinsp_thread_manager::visitor_func_t scap_file_visitor = [](sinsp_threadinfo* pt) {
		if(pt == nullptr) {
			printf("X - Null thread info detected\n");
		}

		printf("⬇️ %s\n", thread_info_to_string(pt).c_str());

		/* The parent could be 0 when we don't find the real parent */
		if(pt->m_tid == 1 || pt->get_ptid() == 0 || pt->is_invalid()) {
			printf("END\n\n");
			return false;
		}
		return true;
	};

	printf("📜 Task Lineage for tid: %" PRId64 "\n", tinfo->m_tid);
	printf("⬇️ %s\n", thread_info_to_string(tinfo).c_str());

	/* If the thread is invalid it has no parent */
	if(tinfo->is_invalid() || tinfo->get_ptid() == 0) {
		printf("END\n\n");
		return;
	}

	thread_manager.traverse_parent_state(*tinfo, scap_file_visitor);
}

std::string rank_to_string(uint64_t rank) {
	if(rank == UINT64_MAX) {
		return "pending";
	}
	if(rank >= thread_group_info::s_unknown_parent_rank) {
		return "unknown+" + std::to_string(rank - thread_group_info::s_unknown_parent_rank);
	}
	return std::to_string(rank);
}

std::string group_to_string(const thread_group_info& group) {
	std::ostringstream out;
	out << "pid: " << group.get_tgroup_pid() << ", rank: " << rank_to_string(group.get_rank());
	if(group.is_dead()) {
		out << ", 🪦 tombstone, reaper: "
		    << (group.is_reaper_known() ? "known" : "unknown (readers search above it)");
	} else {
		out << ", live threads: " << group.get_thread_count();
	}
	if(group.is_reaper()) {
		out << " 💀";
	}
	return out.str();
}

/* The parent links as they are stored: one hop per group, tombstones included. The links go
 * down in rank, so the loop ends.
 */
void display_parent_links(sinsp_thread_manager& thread_manager, sinsp_threadinfo* tinfo) {
	printf("🔗 Parent links for tid: %" PRId64 "\n", tinfo->m_tid);
	const thread_group_info* group = tinfo->m_tginfo.get();
	if(group == nullptr) {
		printf("   no thread group, so no parent to follow\n\n");
		return;
	}
	printf("   %s\n", group_to_string(*group).c_str());
	while(group->get_parent() != nullptr) {
		printf("⬆️ tid %" PRId64 " in %s\n",
		       group->get_parent_tid(),
		       group_to_string(*group->get_parent()).c_str());
		group = group->get_parent().get();
	}
	if(group->get_parent_tid() > 0) {
		printf("⬆️ tid %" PRId64 ", not linked (%s)\n",
		       group->get_parent_tid(),
		       group->awaits_parent() ? "not in the table yet" : "the link was refused");
	}
	auto parent = thread_manager.get_parent_thread(*tinfo);
	printf("   a reader gets: %s\n\n",
	       parent != nullptr ? thread_info_to_string(parent).c_str() : "no parent");
}

std::string kernel_reaper_to_string(int64_t reaper_tid) {
	if(reaper_tid > 0) {
		return "tid " + std::to_string(reaper_tid);
	}
	if(reaper_tid == 0) {
		return "none (the kernel saw no children)";
	}
	return "unknown (an old event, or the kernel did not compute one)";
}

/* The processes that link to the group of `tinfo`, and the tid that each link names. Their
 * links do not change when `tinfo` exits.
 */
void display_linked_children(sinsp_thread_manager& thread_manager, sinsp_threadinfo* tinfo) {
	std::set<const thread_group_info*> seen;
	thread_manager.get_threads()->loop([&](sinsp_threadinfo& child) {
		const auto& group = child.m_tginfo;
		if(group != nullptr && group->get_parent() == tinfo->m_tginfo &&
		   seen.insert(group.get()).second) {
			printf("- child pid: %" PRId64 " links to tid %" PRId64
			       " in this group, and the link does not change\n",
			       group->get_tgroup_pid(),
			       group->get_parent_tid());
		}
		return true;
	});
}

/* sinsp removes an exited thread when it reads the next event. */
struct pending_exit {
	int64_t tid = -1;
	std::weak_ptr<thread_group_info> group;
};

void display_removal(const pending_exit& exited) {
	auto group = exited.group.lock();
	if(group == nullptr) {
		printf("🧹 tid %" PRId64 " removed: its group is freed, because nothing links to it\n\n",
		       exited.tid);
		return;
	}
	printf("🧹 tid %" PRId64 " removed: group %s, %ld other references\n",
	       exited.tid,
	       group_to_string(*group).c_str(),
	       group.use_count() - 1);
	if(group->get_parent() != nullptr) {
		printf("⬆️ tid %" PRId64 " in %s\n",
		       group->get_parent_tid(),
		       group_to_string(*group->get_parent()).c_str());
	}
	printf("\n");
}

int main(int argc, char** argv) {
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	if(argc != 2) {
		std::cerr << "You need to provide the scap-file path. Bye!" << std::endl;
		exit(EXIT_FAILURE);
	}
	std::string file_path = argv[1];
	sinsp inspector;
	/* Show the parent links that sinsp refuses or links late, as they happen */
	libsinsp_logger()->set_severity(sinsp_logger::SEV_DEBUG);
	libsinsp_logger()->add_callback_log([](std::string&& str, sinsp_logger::severity) {
		if(str.find("parent link") != std::string::npos) {
			printf("⚠️ %s\n", str.c_str());
		}
	});
	inspector.open_savefile(file_path);

	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl;
	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl;
	std::cout << "-- Read all threads from /proc" << std::endl;
	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl;
	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl << std::endl;

	// Print lineage for all threads in the table
	inspector.m_thread_manager->get_threads()->loop([&](sinsp_threadinfo& tinfo) {
		printf("* %s\n", thread_info_to_string(&tinfo).c_str());
		return true;
	});

	std::cout << std::endl << std::endl << "-- Start capture" << std::endl;

	inspector.start_capture();

	std::cout << "-- Read from the loop" << std::endl;

	sinsp_evt* ev = nullptr;
	int32_t res = 0;
	pending_exit exited;
	while(!g_interrupted) {
		res = inspector.next(&ev);

		/* next() removed the thread, and then parsed the new event */
		if(exited.tid != -1) {
			display_removal(exited);
			exited = {};
		}

		if(res == SCAP_EOF) {
			std::cout << "-- EOF" << std::endl;
			g_interrupted = true;
			break;
		}

		if(res != SCAP_SUCCESS) {
			continue;
		}

		auto tinfo = ev->get_thread_info();
		if(tinfo == nullptr) {
			continue;
		}

		// Print all interesting events
		uint16_t evt_type = ev->get_type();
		switch(evt_type) {
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
		case PPME_SYSCALL_CLONE3_X: {
			int64_t child_tid = ev->get_syscall_return_value();
			if(child_tid == 0) {
				printf("🧵 CLONE CHILD EXIT: evt_num(%" PRIu64 ")\n", ev->get_num());
			} else {
				printf("🧵 CLONE CALLER EXIT for child (%" PRId64 "): evt_num(%" PRIu64 ")\n",
				       child_tid,
				       ev->get_num());
			}
			/* A clone links the process past its dead parents */
			display_parent_links(*inspector.m_thread_manager, tinfo);
			display_thread_lineage(*inspector.m_thread_manager, tinfo);
		} break;

		case PPME_SYSCALL_EXECVE_19_X:
		case PPME_SYSCALL_EXECVEAT_X:
			printf("🟢 EXECVE EXIT: evt_num(%" PRIu64 ")\n", ev->get_num());
			/* An execve links the process past its dead parents */
			display_parent_links(*inspector.m_thread_manager, tinfo);
			display_thread_lineage(*inspector.m_thread_manager, tinfo);
			break;

		case PPME_PROCEXIT_1_E:
			printf("💥 THREAD EXIT: evt_num(%" PRIu64 ")\n", ev->get_num());
			printf("- reaper from the kernel: %s\n",
			       kernel_reaper_to_string(tinfo->m_reaper_tid).c_str());
			display_linked_children(*inspector.m_thread_manager, tinfo);
			display_parent_links(*inspector.m_thread_manager, tinfo);
			exited = {tinfo->m_tid, tinfo->m_tginfo};
			break;

		default:
			break;
		}
	}

	inspector.stop_capture();

	std::cout << "-- Stop capture" << std::endl << std::endl;

	std::cout << "📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜" << std::endl;
	std::cout << "📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜" << std::endl;
	std::cout << "-- Print all lineages of the table" << std::endl;
	std::cout << "📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜" << std::endl;
	std::cout << "📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜📜" << std::endl << std::endl;

	// Print lineage for all threads in the table
	inspector.m_thread_manager->get_threads()->loop([&](sinsp_threadinfo& tinfo) {
		display_thread_lineage(*inspector.m_thread_manager, &tinfo);
		return true;
	});

	return 0;
}
