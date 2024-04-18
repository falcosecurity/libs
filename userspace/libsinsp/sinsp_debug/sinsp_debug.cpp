
#include <libsinsp/sinsp.h>
#include <iostream>
#include <csignal>

static bool g_interrupted = false;

static void sigint_handler(int signum) { g_interrupted = true; }

std::string thread_info_to_string(sinsp_threadinfo* tinfo)
{
	std::ostringstream out;
	if(tinfo->is_main_thread())
	{
		/* Main thread notation */
		out << "[" << tinfo->get_comm() << "]";
	}
	else
	{
		/* Secondary thread notation */
		out << "{" << tinfo->get_comm() << "}";
	}

	/* if it is a reaper add (R)*/
	if(tinfo->m_tginfo && tinfo->m_tginfo->is_reaper())
	{
		out << "💀";
	}

	out << " t: " << tinfo->m_tid;
	out << ", p: " << tinfo->m_pid;
	out << ", rpt: " << tinfo->m_ptid; // rpt (real parent tid)
	out << ", vt: " << tinfo->m_vtid;
	out << ", vp: " << tinfo->m_vpid;
	out << ", vs: " << tinfo->m_sid; // vs (we call it sid but it is a vsid)
	out << ", vpg: " << tinfo->m_vpgid;
	out << ", ct: " << tinfo->is_in_pid_namespace();
	out << ", e: " << tinfo->get_exepath();

	return out.str();
}

void display_thread_lineage(sinsp_threadinfo* tinfo)
{
	sinsp_threadinfo::visitor_func_t scap_file_visitor = [](sinsp_threadinfo* pt)
	{
		if(pt == nullptr)
		{
			printf("X - Null thread info detected\n");
		}

		printf("⬇️ %s\n", thread_info_to_string(pt).c_str());

		/* The parent could be 0 when we don't find the real parent */
		if(pt->m_tid == 1 || pt->m_ptid == 0 || pt->is_invalid())
		{
			printf("END\n\n");
			return false;
		}
		return true;
	};

	printf("📜 Task Lineage for tid: %ld\n", tinfo->m_tid);
	printf("⬇️ %s\n", thread_info_to_string(tinfo).c_str());

	/* If the thread is invalid it has no parent */
	if(tinfo->is_invalid() || tinfo->m_ptid == 0)
	{
		printf("END\n\n");
		return;
	}

	tinfo->traverse_parent_state(scap_file_visitor);
}

int main(int argc, char** argv)
{
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	if(argc != 2)
	{
		std::cerr << "You need to provide the scap-file path. Bye!" << std::endl;
		exit(EXIT_FAILURE);
	}
	std::string file_path = argv[1];
	sinsp inspector;
	inspector.open_savefile(file_path);

	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl;
	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl;
	std::cout << "-- Read all threads from /proc" << std::endl;
	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl;
	std::cout << "ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ ℹ️ " << std::endl << std::endl;

	// Print lineage for all threads in the table
	inspector.m_thread_manager->get_threads()->loop(
		[&](sinsp_threadinfo& tinfo)
		{
			printf("* %s\n", thread_info_to_string(&tinfo).c_str());
			return true;
		});

	std::cout << std::endl << std::endl << "-- Start capture" << std::endl;

	inspector.start_capture();

	std::cout << "-- Read from the loop" << std::endl;

	sinsp_evt* ev = nullptr;
	int32_t res = 0;
	while(!g_interrupted)
	{
		res = inspector.next(&ev);
		if(res == SCAP_EOF)
		{
			std::cout << "-- EOF" << std::endl;
			g_interrupted = true;
			break;
		}

		if(res != SCAP_SUCCESS)
		{
			continue;
		}

		auto tinfo = ev->get_thread_info();
		if(tinfo == nullptr)
		{
			continue;
		}

		// Print all interesting events
		uint16_t evt_type = ev->get_type();
		switch(evt_type)
		{
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
		{
			int64_t child_tid = ev->get_param(0)->as<int64_t>();
			if(child_tid == 0)
			{
				printf("🧵 CLONE CHILD EXIT: evt_num(%ld)\n", ev->get_num());
			}
			else
			{
				printf("🧵 CLONE CALLER EXIT for child (%ld): evt_num(%ld)\n", child_tid,
				       ev->get_num());
			}
			display_thread_lineage(tinfo);
		}
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
			printf("🟢 EXECVE EXIT: evt_num(%ld)\n", ev->get_num());
			display_thread_lineage(tinfo);
			break;

		case PPME_PROCEXIT_E:
		case PPME_PROCEXIT_1_E:
			printf("💥 THREAD EXIT: evt_num(%ld)\n", ev->get_num());
			for(const auto& child : tinfo->m_children)
			{
				if(!child.expired())
				{
					auto child_shr = child.lock().get();
					printf("- move child, tid: %ld, ptid: %ld (dead) to a new reaper.\n",
					       child_shr->m_tid, child_shr->m_ptid);
				}
			}
			display_thread_lineage(tinfo);
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
	inspector.m_thread_manager->get_threads()->loop(
		[&](sinsp_threadinfo& tinfo)
		{
			display_thread_lineage(&tinfo);
			return true;
		});

	return 0;
}
