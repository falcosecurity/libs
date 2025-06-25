// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include "sys_call_test.h"
#include "subprocess.h"

#include <gtest/gtest.h>

#include <libsinsp/event.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>

#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <algorithm>
#include <cassert>
#include <list>
#include <memory>

TEST_F(sys_call_test, process_signalfd_kill) {
	int callnum = 0;

	int ptid = -1;     // parent tid
	int ctid = -1;     // child tid
	int gptid;         // grandparent tid
	int xstatus = 33;  // child exit value
	int ssfd;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_tid() == ptid || evt->get_tid() == ctid;
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		int status;
		int sfd;
		ctid = fork();

		if(ctid >= 0)  // fork succeeded
		{
			if(ctid == 0) {
				//
				// CHILD PROCESS
				//
				sigset_t mask;

				/* We will handle SIGTERM and SIGINT. */
				sigemptyset(&mask);
				sigaddset(&mask, SIGTERM);
				sigaddset(&mask, SIGINT);

				/* Block the signals that we handle using signalfd(), so they don't
				 * cause signal handlers or default signal actions to execute. */
				if(sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
					FAIL();
				}

				/* Create a file descriptor from which we will read the signals. */
				sfd = signalfd(-1, &mask, 0);
				if(sfd < 0) {
					FAIL();
				}

				while(true) {
					/** The buffer for read(), this structure contains information
					 * about the signal we've read. */
					struct signalfd_siginfo si;

					ssize_t res;

					res = read(sfd, &si, sizeof(si));

					if(res < 0) {
						FAIL();
					}
					if(res != sizeof(si)) {
						FAIL();
					}

					if(si.ssi_signo == SIGTERM) {
						continue;
					} else if(si.ssi_signo == SIGINT) {
						break;
					} else {
						FAIL();
					}
				}

				/* Close the file descriptor if we no longer need it. */
				close(sfd);

				sleep(1);

				//
				// Remember to use _exit or the test system will get fucked!!
				//
				_exit(xstatus);
			} else {
				//
				// PARENT PROCESS
				//
				ptid = gettid();
				gptid = getppid();

				//
				// Give the client some time install its handlers
				//
				usleep(200000);

				kill(ctid, SIGTERM);
				kill(ctid, SIGINT);

				//
				// Wait for child to exit, and store its status
				//
				ASSERT_EQ(waitpid(ctid, &status, 0), ctid);
			}
		} else {
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SIGNALFD_E) {
			EXPECT_EQ(-1, std::stoi(e->get_param_value_str("fd", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("mask")));
			EXPECT_EQ(0, std::stol(e->get_param_value_str("flags")));
			callnum++;
		} else if(type == PPME_SYSCALL_SIGNALFD4_E) {
			EXPECT_EQ(-1, stoi(e->get_param_value_str("fd", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("mask")));
			callnum++;
		} else if(type == PPME_SYSCALL_SIGNALFD_X) {
			ssfd = std::stoi(e->get_param_value_str("res", false));
			callnum++;
		}
		if(type == PPME_SYSCALL_SIGNALFD4_X) {
			ssfd = std::stoi(e->get_param_value_str("res", false));
			EXPECT_EQ(-1, stoi(e->get_param_value_str("fd", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("mask")));
			callnum++;
		} else if(type == PPME_SYSCALL_READ_E) {
			if(callnum == 2) {
				EXPECT_EQ("<s>", e->get_param_value_str("fd"));
				EXPECT_EQ(ssfd, std::stoi(e->get_param_value_str("fd", false)));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_KILL_E) {
			if(callnum == 3) {
				EXPECT_EQ("libsinsp_e2e_te", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, std::stoi(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGTERM", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGTERM, std::stoi(e->get_param_value_str("sig", false)));
				callnum++;
			} else if(callnum == 5) {
				EXPECT_EQ("libsinsp_e2e_te", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, std::stoi(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGINT", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGINT, std::stoi(e->get_param_value_str("sig", false)));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_KILL_X) {
			if(callnum == 4) {
				EXPECT_EQ(0, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("libsinsp_e2e_te", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, std::stoi(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGTERM", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGTERM, std::stoi(e->get_param_value_str("sig", false)));
				callnum++;
			} else if(callnum == 6) {
				EXPECT_EQ(0, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("libsinsp_e2e_te", e->get_param_value_str("pid"));
				EXPECT_EQ(ctid, std::stoi(e->get_param_value_str("pid", false)));
				EXPECT_EQ("SIGINT", e->get_param_value_str("sig"));
				EXPECT_EQ(SIGINT, std::stoi(e->get_param_value_str("sig", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   libsinsp::events::all_sc_set());
	});

	EXPECT_EQ(7, callnum);
}

// This test is disabled until the new syscall for sleep is implemented.
TEST_F(sys_call_test, DISABLED_process_usleep) {
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [](sinsp* inspector) {
		struct timespec req;
		req.tv_sec = 0;
		req.tv_nsec = 123456;
		nanosleep(&req, nullptr);
		req.tv_sec = 5;
		req.tv_nsec = 0;
		nanosleep(&req, nullptr);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_NANOSLEEP_E) {
			if(callnum == 0) {
				if(std::stoll(e->get_param_value_str("interval", false)) == 123456000) {
					callnum++;
				}
			} else if(callnum == 2) {
				EXPECT_EQ(5000000000, std::stoll(e->get_param_value_str("interval", false)));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_NANOSLEEP_X) {
			EXPECT_EQ(0, stoi(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(4, callnum);
}

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

TEST_F(sys_call_test, process_inotify) {
	int callnum = 0;
	int fd;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		int length;
		int wd;
		char buffer[EVENT_BUF_LEN];

		//
		// creating the INOTIFY instance
		//
		fd = inotify_init();

		/*checking for error*/
		if(fd < 0) {
			FAIL();
		}

		//
		// The IN_MODIFY flag causes a notification when a file is written, which should
		// happen immediately under /proc/
		//
		wd = inotify_add_watch(fd, "/proc/", IN_MODIFY | IN_CREATE | IN_OPEN);

		//
		// read to determine the event changes
		//
		length = read(fd, buffer, EVENT_BUF_LEN);
		if(length < 0) {
			FAIL();
		}

		//
		// removing the watch
		//
		inotify_rm_watch(fd, wd);

		//
		// closing the INOTIFY instance
		//
		close(fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		std::string name(e->get_name());

		if(type == PPME_SYSCALL_INOTIFY_INIT_E) {
			EXPECT_EQ(0, std::stoi(e->get_param_value_str("flags")));
			callnum++;
		} else if(type == PPME_SYSCALL_INOTIFY_INIT1_E) {
			callnum++;
		} else if(type == PPME_SYSCALL_INOTIFY_INIT_X || type == PPME_SYSCALL_INOTIFY_INIT1_X) {
			EXPECT_EQ(fd, std::stoi(e->get_param_value_str("res", false)));
			callnum++;
		} else if(name.find("read") != std::string::npos && e->get_direction() == SCAP_ED_IN) {
			if(callnum == 2) {
				EXPECT_EQ("<i>", e->get_param_value_str("fd"));
				EXPECT_EQ(fd, std::stoi(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   libsinsp::events::all_sc_set());
	});

	EXPECT_EQ(3, callnum);
}

TEST(procinfo, process_not_existent) {
	sinsp inspector;
	inspector.open_nodriver(true);

	const auto& thread_manager = inspector.m_thread_manager;
	//
	// The first lookup should fail
	//
	EXPECT_EQ(NULL, thread_manager->get_thread_ref(0xffff, false, true).get());

	//
	// Even the second, to confirm that nothing was added to the table
	//
	EXPECT_EQ(NULL, thread_manager->get_thread_ref(0xffff, false, true).get());

	//
	// Now a new entry should be added to the process list...
	//
	sinsp_threadinfo* tinfo = thread_manager->get_thread_ref(0xffff, true, true).get();
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if(tinfo) {
		EXPECT_EQ("<NA>", tinfo->m_comm);
	}

	//
	// ...and confirm
	//
	tinfo = thread_manager->get_thread_ref(0xffff, false, true).get();
	EXPECT_NE((sinsp_threadinfo*)NULL, tinfo);
	if(tinfo) {
		EXPECT_EQ("<NA>", tinfo->m_comm);
	}

	inspector.close();
}

TEST_F(sys_call_test, process_rlimit) {
	int callnum = 0;
	struct rlimit curr_rl;
	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		// Called directly because libc likes prlimit()
		syscall(SYS_getrlimit, RLIMIT_NOFILE, (struct rlimit*)33);
		syscall(SYS_getrlimit, RLIMIT_NOFILE, &curr_rl);

		struct rlimit new_rl;
		new_rl.rlim_cur = 5000;
		new_rl.rlim_max = 10000;
		syscall(SYS_setrlimit, RLIMIT_NOFILE, &new_rl);
		syscall(SYS_getrlimit, RLIMIT_NOFILE, &new_rl);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_GETRLIMIT_E) {
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoll(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if(type == PPME_SYSCALL_GETRLIMIT_X) {
			if(callnum == 1) {
				EXPECT_GT((int64_t)0, std::stoll(e->get_param_value_str("res", false)));
			} else {
				EXPECT_EQ((int64_t)0, std::stoll(e->get_param_value_str("res", false)));

				if(callnum == 7) {
					EXPECT_EQ((int64_t)5000, std::stoll(e->get_param_value_str("cur", false)));
					EXPECT_EQ((int64_t)10000, std::stoll(e->get_param_value_str("max", false)));
				}
			}

			callnum++;
		}
		if(type == PPME_SYSCALL_SETRLIMIT_E) {
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoll(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if(type == PPME_SYSCALL_SETRLIMIT_X) {
			EXPECT_EQ((int64_t)0, std::stoll(e->get_param_value_str("res", false)));

			if(callnum == 5) {
				EXPECT_EQ((int64_t)5000, std::stoll(e->get_param_value_str("cur", false)));
				EXPECT_EQ((int64_t)10000, std::stoll(e->get_param_value_str("max", false)));
			}

			callnum++;
		}
		if(type == PPME_SYSCALL_PRLIMIT_E) {
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoll(e->get_param_value_str("resource", false)));
			callnum++;
		}
		if(type == PPME_SYSCALL_PRLIMIT_X) {
			int64_t res = std::stoll(e->get_param_value_str("res", false));
			int64_t newcur = std::stoll(e->get_param_value_str("newcur", false));
			int64_t newmax = std::stoll(e->get_param_value_str("newmax", false));
			int64_t oldcur = std::stoll(e->get_param_value_str("oldcur", false));
			int64_t oldmax = std::stoll(e->get_param_value_str("oldmax", false));
			switch(callnum) {
			case 1:
				EXPECT_GT(0, res);
				break;
			case 3:
				EXPECT_EQ(0, res);
				EXPECT_EQ(-1, newcur);
				EXPECT_EQ(-1, newmax);
				break;
			case 5:
				EXPECT_EQ(0, res);
				EXPECT_EQ(5000, newcur);
				EXPECT_EQ(10000, newmax);
				EXPECT_EQ(-1, oldcur);
				EXPECT_EQ(-1, oldmax);
				break;
			case 7:
				EXPECT_EQ(0, res);
				EXPECT_EQ(-1, newcur);
				EXPECT_EQ(-1, newmax);
				EXPECT_EQ(5000, oldcur);
				EXPECT_EQ(10000, oldmax);
				break;
			}
			callnum++;
		}
	};

	after_capture_t cleanup = [&](sinsp* inspector) {
		syscall(SYS_setrlimit, RLIMIT_NOFILE, &curr_rl);
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, process_prlimit) {
	int callnum = 0;
	struct rlimit orirl;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		struct rlimit newrl;
		struct rlimit oldrl;

		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &orirl);
		newrl.rlim_cur = 5000;
		newrl.rlim_max = 10000;
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, &newrl, &oldrl);
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, NULL, &oldrl);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PRLIMIT_E) {
			EXPECT_EQ((int64_t)PPM_RLIMIT_NOFILE,
			          std::stoll(e->get_param_value_str("resource", false)));
			EXPECT_EQ((int64_t)getpid(), std::stoll(e->get_param_value_str("pid", false)));
			callnum++;
		} else if(type == PPME_SYSCALL_PRLIMIT_X) {
			EXPECT_GE((int64_t)0, std::stoll(e->get_param_value_str("res", false)));

			if(callnum == 1) {
				EXPECT_EQ((int64_t)0, std::stoll(e->get_param_value_str("newcur", false)));
				EXPECT_EQ((int64_t)0, std::stoll(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)orirl.rlim_cur,
				          std::stoll(e->get_param_value_str("oldcur", false)));
				EXPECT_EQ((int64_t)orirl.rlim_max,
				          std::stoll(e->get_param_value_str("oldmax", false)));
			} else if(callnum == 3) {
				EXPECT_EQ((int64_t)5000, std::stoll(e->get_param_value_str("newcur", false)));
				EXPECT_EQ((int64_t)10000, std::stoll(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)orirl.rlim_cur,
				          std::stoll(e->get_param_value_str("oldcur", false)));
				EXPECT_EQ((int64_t)orirl.rlim_max,
				          std::stoll(e->get_param_value_str("oldmax", false)));
			} else if(callnum == 5) {
				EXPECT_EQ((int64_t)0, std::stoll(e->get_param_value_str("newcur", false)));
				EXPECT_EQ((int64_t)0, std::stoll(e->get_param_value_str("newmax", false)));
				EXPECT_EQ((int64_t)5000, std::stoll(e->get_param_value_str("oldcur", false)));
				EXPECT_EQ((int64_t)10000, std::stoll(e->get_param_value_str("oldmax", false)));
			}

			callnum++;
		}
	};

	after_capture_t cleanup = [&](sinsp* inspector) {
		syscall(SYS_prlimit64, getpid(), RLIMIT_NOFILE, &orirl, NULL);
	};

	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   event_capture::do_nothing,
		                   event_capture::do_nothing,
		                   cleanup);
	});

	EXPECT_EQ(6, callnum);
}

class loadthread {
public:
	loadthread() {
		m_die = false;
		m_tid = -1;
		m_utime_delta = 0;
		m_prevutime = 0;
	}

	uint64_t read_utime() {
		struct rusage ru;
		getrusage(RUSAGE_THREAD, &ru);
		return ru.ru_utime.tv_sec * 1000000 + ru.ru_utime.tv_usec;
	}

	void run() {
		uint64_t k = 0;
		uint64_t t = 0;
		m_tid = syscall(SYS_gettid);

		m_prevutime = read_utime();

		while(true) {
			t += k;
			t = t % 35689;

			if(m_read_cpu) {
				auto utime = read_utime();
				m_utime_delta = utime - m_prevutime;
				m_prevutime = utime;
				m_read_cpu = false;
			}

			if(m_die) {
				return;
			}
		}
	}

	int64_t get_tid() { return m_tid; }

	uint64_t m_prevutime;
	uint64_t m_utime_delta;
	std::atomic<bool> m_die;
	std::atomic<bool> m_read_cpu;
	int64_t m_tid;
};

TEST_F(sys_call_test, process_scap_proc_get) {
	int callnum = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [](sinsp* inspector) {
		usleep(1000);

		int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		EXPECT_LT(0, s);

		int s1 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		EXPECT_LT(0, s);

		usleep(1000000);

		close(s);
		close(s1);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_NANOSLEEP_E) {
			if(callnum == 0) {
				scap_threadinfo scap_proc;

				auto rc =
				        scap_proc_get(param.m_inspector->get_scap_platform(), 0, &scap_proc, false);
				EXPECT_NE(SCAP_SUCCESS, rc);

				int64_t tid = e->get_tid();
				rc = scap_proc_get(param.m_inspector->get_scap_platform(), tid, &scap_proc, false);
				EXPECT_EQ(SCAP_SUCCESS, rc);
			} else {
				scap_threadinfo scap_proc;
				scap_fdinfo* fdi;
				scap_fdinfo* tfdi;
				uint32_t nsocks = 0;
				int64_t tid = e->get_tid();

				//
				// try with scan_sockets=true
				//
				auto rc = scap_proc_get(param.m_inspector->get_scap_platform(),
				                        tid,
				                        &scap_proc,
				                        false);
				EXPECT_EQ(SCAP_SUCCESS, rc);

				HASH_ITER(hh, scap_proc.fdlist, fdi, tfdi) {
					if(fdi->type == SCAP_FD_IPV4_SOCK) {
						nsocks++;
					}
				}

				EXPECT_EQ(0U, nsocks);

				//
				// try with scan_sockets=false
				//
				rc = scap_proc_get(param.m_inspector->get_scap_platform(), tid, &scap_proc, true);
				EXPECT_EQ(SCAP_SUCCESS, rc);

				HASH_ITER(hh, scap_proc.fdlist, fdi, tfdi) {
					if(fdi->type == SCAP_FD_IPV4_SOCK) {
						nsocks++;
					}
				}

				EXPECT_EQ(0U, nsocks);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

TEST_F(sys_call_test, procinfo_processchild_cpuload) {
	int callnum = 0;
	int lastcpu = 0;
	int64_t ctid = -1;

	loadthread ct;
	std::thread th(&loadthread::run, std::ref(ct));

	sleep(2);
	ctid = ct.get_tid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return true; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		for(uint32_t j = 0; j < 5; j++) {
			sleep(1);
		}

		ct.m_die = true;

		th.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_PROCINFO_E) {
			sinsp_threadinfo* tinfo = e->get_thread_info();

			if(tinfo) {
				if(tinfo->m_tid == ctid) {
					auto tcpu = e->get_param(0)->as<uint64_t>();

					uint64_t delta = tcpu - lastcpu;

					ct.m_read_cpu = true;

					if(callnum != 0) {
						EXPECT_GT(delta, 0U);
						EXPECT_LT(delta, 110U);
					}

					lastcpu = tcpu;

					callnum++;
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

TEST_F(sys_call_test, procinfo_two_processchilds_cpuload) {
	int callnum = 0;
	int lastcpu = 0;
	int lastcpu1 = 0;

	loadthread ct;
	std::thread th(&loadthread::run, std::ref(ct));

	loadthread ct1;
	std::thread th1(&loadthread::run, std::ref(ct1));

	sleep(2);
	int64_t ctid = ct.get_tid();
	int64_t ctid1 = ct1.get_tid();

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return true; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		for(uint32_t j = 0; j < 5; j++) {
			sleep(1);
		}

		ct.m_die = true;
		ct1.m_die = true;

		th.join();
		th1.join();
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_PROCINFO_E) {
			sinsp_threadinfo* tinfo = e->get_thread_info();

			if(tinfo) {
				if(tinfo->m_tid == ctid) {
					auto tcpu = e->get_param(0)->as<uint64_t>();

					uint64_t delta = tcpu - lastcpu;

					if(callnum > 2) {
						EXPECT_GT(delta, 0U);
						EXPECT_LT(delta, 110U);
					}

					lastcpu = tcpu;

					callnum++;
				} else if(tinfo->m_tid == ctid1) {
					auto tcpu = e->get_param(0)->as<uint64_t>();

					uint64_t delta = tcpu - lastcpu1;

					if(callnum > 2) {
						EXPECT_GT(delta, 0U);
						EXPECT_LT(delta, 110U);
					}

					lastcpu1 = tcpu;

					callnum++;
				}
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}
