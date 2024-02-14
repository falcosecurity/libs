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

#include "sys_call_test.h"

#include "event_capture.h"
#include "subprocess.h"

#include <cstdint>
#include <libscap/scap-int.h>
#include <libscap/scap_platform.h>

#include <gtest/gtest.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>

#include <algorithm>
#include <cassert>
#include <list>
#include <numeric>

using namespace std;

TEST_F(sys_call_test, stat)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		std::string evt_name(evt->get_name());
		return evt_name.find("stat") != std::string::npos && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		struct stat sb;
		stat("/tmp", &sb);
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, open_close)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return (0 == strcmp(evt->get_name(), "open") || 0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")) &&
		       m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if ((0 == strcmp(param.m_evt->get_name(), "open") ||
		     0 == strcmp(param.m_evt->get_name(), "openat")) &&
		    param.m_evt->get_direction() == SCAP_ED_OUT)
		{
			EXPECT_EQ("<f>/tmp", param.m_evt->get_param_value_str("fd"));
		}
		callnum++;
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, open_close_dropping)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return (0 == strcmp(evt->get_name(), "open") || 0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")) &&
		       m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		int fd = open("/tmp", O_RDONLY);
		close(fd);
		inspector->stop_dropping_mode();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if ((0 == strcmp(param.m_evt->get_name(), "open") ||
		     0 == strcmp(param.m_evt->get_name(), "openat")) &&
		    param.m_evt->get_direction() == SCAP_ED_OUT)
		{
			EXPECT_EQ("<f>/tmp", param.m_evt->get_param_value_str("fd"));
		}
		callnum++;
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, fcntl_getfd)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl") && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) { fcntl(0, F_GETFL); };

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fcntl_getfd_dropping)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl") && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		fcntl(0, F_GETFL);
		inspector->stop_dropping_mode();
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(0, callnum);
}

TEST_F(sys_call_test, bind_error)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "bind") && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector) { bind(0, NULL, 0); };

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, bind_error_dropping)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "bind") && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		bind(0, NULL, 0);
		inspector->stop_dropping_mode();
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(1, callnum);
}

TEST_F(sys_call_test, close_badfd)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "close") && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		close(-1);
		close(INT_MAX);
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, close_badfd_dropping)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "close") && m_tid_filter(evt);
	};

	run_callback_t test = [](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
		close(-1);
		close(INT_MAX);
		inspector->stop_dropping_mode();
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(0, callnum);
}

TEST(inspector, invalid_file_name)
{
	sinsp inspector;
	ASSERT_THROW(inspector.open_savefile("invalid_file_name"), sinsp_exception);
}

TEST_F(sys_call_test, ioctl)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	int status;
	run_callback_t test = [&](sinsp* inspector)
	{
		int fd;

		fd = open("/dev/ttyS0", O_RDONLY);
		ioctl(fd, TIOCMGET, &status);
		close(fd);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_IOCTL_3_E)
		{
			std::ostringstream oss;
			oss << std::hex << std::uppercase << TIOCMGET;
			EXPECT_EQ("<f>/dev/ttyS0", e->get_param_value_str("fd"));
			EXPECT_EQ(oss.str(), e->get_param_value_str("request"));
			oss.str("");
			oss.clear();
			oss << std::hex << std::uppercase << ((unsigned long)&status);
			EXPECT_EQ(oss.str(), e->get_param_value_str("argument"));
			callnum++;
		}
		else if (type == PPME_SYSCALL_IOCTL_3_X)
		{
			string res = e->get_param_value_str("res");
			EXPECT_TRUE(res == "0" || res == "EIO");
			callnum++;
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
}

TEST_F(sys_call_test, shutdown)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	int sock;
	run_callback_t test = [&](sinsp* inspector)
	{
		if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{
			FAIL() << "socket() failed";
			return;
		}

		shutdown(sock, SHUT_RD);
		shutdown(sock, SHUT_WR);
		shutdown(sock, SHUT_RDWR);

		close(sock);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SOCKET_SHUTDOWN_E)
		{
			EXPECT_EQ(std::to_string(sock), e->get_param_value_str("fd", false));

			if (callnum == 0)
			{
				EXPECT_EQ("0", e->get_param_value_str("how", false));
			}
			else if (callnum == 2)
			{
				EXPECT_EQ("1", e->get_param_value_str("how", false));
			}
			else if (callnum == 4)
			{
				EXPECT_EQ("2", e->get_param_value_str("how", false));
			}

			callnum++;
		}
		else if (type == PPME_SOCKET_SHUTDOWN_X)
		{
			EXPECT_GT(0, std::stoll(e->get_param_value_str("res", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(6, callnum);
}

TEST_F(sys_call_test, timerfd)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	int fd;
	run_callback_t test = [&](sinsp* inspector)
	{
		int ret;
		unsigned int ns;
		unsigned int sec;
		struct itimerspec itval;
		unsigned int period = 100000;
		unsigned long long missed;

		/* Create the timer */
		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1)
		{
			FAIL();
		}

		/* Make the timer periodic */
		sec = period / 1000000;
		ns = (period - (sec * 1000000)) * 1000;
		itval.it_interval.tv_sec = sec;
		itval.it_interval.tv_nsec = ns;
		itval.it_value.tv_sec = sec;
		itval.it_value.tv_nsec = ns;
		ret = timerfd_settime(fd, 0, &itval, NULL);

		/* Wait for the next timer event. If we have missed any the
		   number is written to "missed" */
		ret = read(fd, &missed, sizeof(missed));
		if (ret == -1)
		{
			FAIL();
		}

		close(fd);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_TIMERFD_CREATE_E)
		{
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("clockid")));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("flags")));
			callnum++;
		}
		else if (type == PPME_SYSCALL_TIMERFD_CREATE_X)
		{
			EXPECT_EQ(fd, std::stoll(e->get_param_value_str("res", false)));
			callnum++;
		}
		else if (type == PPME_SYSCALL_READ_E)
		{
			if (callnum == 2)
			{
				EXPECT_EQ("<t>", e->get_param_value_str("fd"));
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(3, callnum);
}

TEST_F(sys_call_test, timestamp)
{
	static const uint64_t TIMESTAMP_DELTA_NS =
	    1000000;  // We should at least always have 1 ms resolution
	uint64_t timestampv[20];
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](sinsp* inspector)
	{
		useconds_t sleep_period = 10;
		struct timeval tv;
		for (uint32_t j = 0; j < sizeof(timestampv) / sizeof(timestampv[0]); ++j)
		{
			syscall(SYS_gettimeofday, &tv, NULL);
			timestampv[j] = tv.tv_sec * 1000000000LL + tv.tv_usec * 1000;
			usleep(sleep_period);
			sleep_period *= 2;
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if (param.m_evt->get_type() == PPME_GENERIC_X &&
		    param.m_evt->get_param_value_str("ID") == "gettimeofday")
		{
			EXPECT_LE(param.m_evt->get_ts(), timestampv[callnum] + TIMESTAMP_DELTA_NS);
			EXPECT_GE(param.m_evt->get_ts(), timestampv[callnum] - TIMESTAMP_DELTA_NS);
			++callnum;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ((int)(sizeof(timestampv) / sizeof(timestampv[0])), callnum);
}

TEST_F(sys_call_test, brk)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [](sinsp* inspector)
	{
		sbrk(1000);
		sbrk(100000);
	};

	uint32_t before_brk_vmsize;
	uint32_t before_brk_vmrss;
	uint32_t after_brk_vmsize;
	uint32_t after_brk_vmrss;
	bool ignore_this_call = false;

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_BRK_4_E)
		{
			uint64_t addr = e->get_param_by_name("addr")->as<uint64_t>();
			if (addr == 0)
			{
				ignore_this_call = true;
				return;
			}

			callnum++;
		}
		else if (type == PPME_SYSCALL_BRK_4_X)
		{
			if (ignore_this_call)
			{
				ignore_this_call = false;
				return;
			}

			uint32_t vmsize = e->get_param_by_name("vm_size")->as<uint32_t>();
			uint32_t vmrss = e->get_param_by_name("vm_rss")->as<uint32_t>();

			EXPECT_EQ(e->get_thread_info(false)->m_vmsize_kb, vmsize);
			EXPECT_EQ(e->get_thread_info(false)->m_vmrss_kb, vmrss);

			if (callnum == 1)
			{
				before_brk_vmsize = vmsize;
				before_brk_vmrss = vmrss;
			}
			else if (callnum == 3)
			{
				after_brk_vmsize = vmsize;
				after_brk_vmrss = vmrss;

				EXPECT_GT(after_brk_vmsize, before_brk_vmsize + 50);
				EXPECT_GE(after_brk_vmrss, before_brk_vmrss);
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, mmap)
{
	int callnum = 0;
	int errno2;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	void* p;

	run_callback_t test = [&](sinsp* inspector)
	{
		munmap((void*)0x50, 300);
		p = mmap(0,
		         0,
		         PROT_EXEC | PROT_READ | PROT_WRITE,
		         MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE,
		         -1,
		         0);
		EXPECT_EQ((uint64_t)-1, (uint64_t)p);
		errno2 = errno;
		p = mmap(NULL, 1003520, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		EXPECT_NE((uint64_t)0, (uint64_t)p);
		munmap(p, 1003520);
	};

	uint32_t enter_vmsize;
	uint32_t enter_vmrss;
	uint32_t exit_vmsize;
	uint32_t exit_vmrss;

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_MUNMAP_E)
		{
			callnum++;

			enter_vmsize = e->get_thread_info(false)->m_vmsize_kb;
			enter_vmrss = e->get_thread_info(false)->m_vmrss_kb;

			switch (callnum)
			{
			case 1:
				EXPECT_EQ("50", e->get_param_value_str("addr"));
				EXPECT_EQ("300", e->get_param_value_str("length"));
				break;
			case 7:
			{
				uint64_t addr = e->get_param_by_name("addr")->as<uint64_t>();
#ifdef __LP64__
				EXPECT_EQ((uint64_t)p, addr);
#else
				EXPECT_EQ(((uint32_t)p), addr);
#endif
				EXPECT_EQ("1003520", e->get_param_value_str("length"));
				break;
			}
			default:
				EXPECT_TRUE(false);
			}
		}
		else if (type == PPME_SYSCALL_MUNMAP_X)
		{
			callnum++;

			exit_vmsize = e->get_param_by_name("vm_size")->as<uint32_t>();
			exit_vmrss = e->get_param_by_name("vm_rss")->as<uint32_t>();
			EXPECT_EQ(e->get_thread_info(false)->m_vmsize_kb, exit_vmsize);
			EXPECT_EQ(e->get_thread_info(false)->m_vmrss_kb, exit_vmrss);

			switch (callnum)
			{
			case 2:
				EXPECT_EQ("EINVAL", e->get_param_value_str("res"));
				EXPECT_EQ("-22", e->get_param_value_str("res", false));
				break;
			case 8:
				EXPECT_EQ("0", e->get_param_value_str("res"));
				EXPECT_GT(enter_vmsize, exit_vmsize + 500);
				EXPECT_GE(enter_vmrss, enter_vmrss);
				break;
			default:
				EXPECT_TRUE(false);
			}
		}
		else if (type == PPME_SYSCALL_MMAP_E || type == PPME_SYSCALL_MMAP2_E)
		{
			callnum++;

			enter_vmsize = e->get_thread_info(false)->m_vmsize_kb;
			enter_vmrss = e->get_thread_info(false)->m_vmrss_kb;

			switch (callnum)
			{
			case 3:
				EXPECT_EQ("0", e->get_param_value_str("addr"));
				EXPECT_EQ("0", e->get_param_value_str("length"));
				EXPECT_EQ("PROT_READ|PROT_WRITE|PROT_EXEC", e->get_param_value_str("prot"));
				EXPECT_EQ("MAP_SHARED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_DENYWRITE",
				          e->get_param_value_str("flags"));
#ifdef __LP64__
				// It looks that starting from kernel 4.9, fd is -1 also on 64bit
				EXPECT_TRUE(e->get_param_value_str("fd", false) == "4294967295" ||
				            e->get_param_value_str("fd", false) == "-1");
#else
				EXPECT_EQ("-1", e->get_param_value_str("fd", false));
#endif
				if (type == PPME_SYSCALL_MMAP_E)
				{
					EXPECT_EQ("0", e->get_param_value_str("offset"));
				}
				else
				{
					EXPECT_EQ("0", e->get_param_value_str("pgoffset"));
				}
				break;
			case 5:
				EXPECT_EQ("0", e->get_param_value_str("addr"));
				EXPECT_EQ("1003520", e->get_param_value_str("length"));
				EXPECT_EQ("PROT_READ|PROT_WRITE", e->get_param_value_str("prot"));
				EXPECT_EQ("MAP_PRIVATE|MAP_ANONYMOUS", e->get_param_value_str("flags"));
#ifdef __LP64__
				EXPECT_TRUE(e->get_param_value_str("fd", false) == "4294967295" ||
				            e->get_param_value_str("fd", false) == "-1");
#else
				EXPECT_EQ("-1", e->get_param_value_str("fd", false));
#endif
				if (type == PPME_SYSCALL_MMAP_E)
				{
					EXPECT_EQ("0", e->get_param_value_str("offset"));
				}
				else
				{
					EXPECT_EQ("0", e->get_param_value_str("pgoffset"));
				}
				break;
			default:
				EXPECT_TRUE(false);
			}
		}
		else if (type == PPME_SYSCALL_MMAP_X || type == PPME_SYSCALL_MMAP2_X)
		{
			callnum++;

			exit_vmsize = e->get_param_by_name("vm_size")->as<uint32_t>();
			exit_vmrss = e->get_param_by_name("vm_rss")->as<uint32_t>();
			EXPECT_EQ(e->get_thread_info(false)->m_vmsize_kb, exit_vmsize);
			EXPECT_EQ(e->get_thread_info(false)->m_vmrss_kb, exit_vmrss);

			switch (callnum)
			{
			case 4:
			{
				uint64_t res = e->get_param_by_name("res")->as<uint64_t>();
				EXPECT_EQ(-errno2, (int64_t)res);
				break;
			}
			case 6:
			{
				uint64_t res = e->get_param_by_name("res")->as<uint64_t>();
				EXPECT_EQ((uint64_t)p, res);
				EXPECT_GT(exit_vmsize, enter_vmsize + 500);
				EXPECT_GE(exit_vmrss, enter_vmrss);
				break;
			}
			default:
				EXPECT_TRUE(false);
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, quotactl_ko)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
		       evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA),
		         "/dev/xxx",
		         2,
		         (caddr_t) "/quota.user");  // 2 => QFMT_VFS_V0
		quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			++callnum;
			switch (callnum)
			{
			case 1:

				printf("quotactl: on str: %s\n", e->get_param_value_str("cmd").c_str());
				EXPECT_EQ("Q_QUOTAON", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", e->get_param_value_str("quota_fmt"));
				break;
			case 3:
				EXPECT_EQ("Q_QUOTAOFF", e->get_param_value_str("cmd"));
				EXPECT_EQ("GRPQUOTA", e->get_param_value_str("type"));
			}
		}
		else if (type == PPME_SYSCALL_QUOTACTL_X)
		{
			++callnum;
			switch (callnum)
			{
			case 2:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
				EXPECT_EQ("/quota.user", e->get_param_value_str("quotafilepath"));
				break;
			case 4:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, quotactl_ok)
{
	int callnum = 0;

	// Clean environment
	auto ret = system("umount /tmp/testquotamnt");
	ret = system("rm -rf /tmp/testquotactl /tmp/testquotamnt");
	// Setup a tmpdisk to test quotas
	char command[] =
	    "dd if=/dev/zero of=/tmp/testquotactl bs=1M count=200 &&\n"
	    "echo y | mkfs.ext4 -q /tmp/testquotactl &&\n"
	    "mkdir -p /tmp/testquotamnt &&\n"
	    "mount -o usrquota,grpquota,loop=/dev/loop0 /tmp/testquotactl /tmp/testquotamnt &&\n"
	    "quotacheck -cug /tmp/testquotamnt";
	ret = system(command);
	if (ret != 0)
	{
		// If we don't have quota utilities, skip this test
		return;
	}

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
		       evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	struct dqblk mydqblk;
	struct dqinfo mydqinfo;
	run_callback_t test = [&](sinsp* inspector)
	{
		quotactl(QCMD(Q_QUOTAON, USRQUOTA),
		         "/dev/loop0",
		         2,
		         (caddr_t) "/tmp/testquotamnt/aquota.user");  // 2 => QFMT_VFS_V0
		quotactl(QCMD(Q_GETQUOTA, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqblk);  // 0 => root user
		quotactl(QCMD(Q_GETINFO, USRQUOTA), "/dev/loop0", 0, (caddr_t)&mydqinfo);
		quotactl(QCMD(Q_QUOTAOFF, USRQUOTA), "/dev/loop0", 0, NULL);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			++callnum;
			switch (callnum)
			{
			case 1:
				EXPECT_EQ("Q_QUOTAON", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", e->get_param_value_str("quota_fmt"));
				break;
			case 3:
				EXPECT_EQ("Q_GETQUOTA", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("0", e->get_param_value_str("id"));
				break;
			case 5:
				EXPECT_EQ("Q_GETINFO", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				break;
			case 7:
				EXPECT_EQ("Q_QUOTAOFF", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				break;
			}
		}
		else if (type == PPME_SYSCALL_QUOTACTL_X)
		{
			++callnum;
			switch (callnum)
			{
			case 2:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				EXPECT_EQ("/tmp/testquotamnt/aquota.user", e->get_param_value_str("quotafilepath"));
				break;
			case 4:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				EXPECT_EQ(mydqblk.dqb_bhardlimit,
				          *reinterpret_cast<const uint64_t*>(
				              e->get_param_by_name("dqb_bhardlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_bsoftlimit,
				          *reinterpret_cast<const uint64_t*>(
				              e->get_param_by_name("dqb_bsoftlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_curspace,
				          *reinterpret_cast<const uint64_t*>(
				              e->get_param_by_name("dqb_curspace")->m_val));
				EXPECT_EQ(mydqblk.dqb_ihardlimit,
				          *reinterpret_cast<const uint64_t*>(
				              e->get_param_by_name("dqb_ihardlimit")->m_val));
				EXPECT_EQ(mydqblk.dqb_isoftlimit,
				          *reinterpret_cast<const uint64_t*>(
				              e->get_param_by_name("dqb_isoftlimit")->m_val));
				EXPECT_EQ(
				    mydqblk.dqb_btime,
				    *reinterpret_cast<const uint64_t*>(e->get_param_by_name("dqb_btime")->m_val));
				EXPECT_EQ(
				    mydqblk.dqb_itime,
				    *reinterpret_cast<const uint64_t*>(e->get_param_by_name("dqb_itime")->m_val));
				break;
			case 6:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				EXPECT_EQ(
				    mydqinfo.dqi_bgrace,
				    *reinterpret_cast<const uint64_t*>(e->get_param_by_name("dqi_bgrace")->m_val));
				EXPECT_EQ(
				    mydqinfo.dqi_igrace,
				    *reinterpret_cast<const uint64_t*>(e->get_param_by_name("dqi_igrace")->m_val));
				break;
			case 8:
				EXPECT_EQ("0", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/loop0", e->get_param_value_str("special"));
				break;
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, getsetuid_and_gid)
{
	static const uint32_t test_gid = 6566;
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](sinsp* inspector)
	{
		auto res = setuid(0);
		EXPECT_EQ(0, res);
		res = setgid(test_gid);
		EXPECT_EQ(0, res);
		getuid();
		geteuid();
		getgid();
		getegid();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		switch (type)
		{
		case PPME_SYSCALL_SETUID_E:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("uid", false));
			EXPECT_EQ("root", e->get_param_value_str("uid"));
			break;
		case PPME_SYSCALL_SETUID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			break;
		case PPME_SYSCALL_SETGID_E:
			++callnum;
			EXPECT_EQ("6566", e->get_param_value_str("gid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("gid"));
			break;
		case PPME_SYSCALL_SETGID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			break;
		case PPME_SYSCALL_GETUID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("uid", false));
			EXPECT_EQ("root", e->get_param_value_str("uid"));
			break;
		case PPME_SYSCALL_GETEUID_X:
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("euid", false));
			EXPECT_EQ("root", e->get_param_value_str("euid"));
			break;
		case PPME_SYSCALL_GETGID_X:
			++callnum;
			EXPECT_EQ("6566", e->get_param_value_str("gid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("gid"));
			break;
		case PPME_SYSCALL_GETEGID_X:
			++callnum;
			EXPECT_EQ("6566", e->get_param_value_str("egid", false));
			EXPECT_EQ("<NA>", e->get_param_value_str("egid"));
			break;
		case PPME_SYSCALL_GETUID_E:
		case PPME_SYSCALL_GETEUID_E:
		case PPME_SYSCALL_GETGID_E:
		case PPME_SYSCALL_GETEGID_E:
			++callnum;
			break;
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(12, callnum);
}

#ifdef __x86_64__

TEST_F(sys_call_test32, execve_ia32_emulation)
{
	int callnum = 0;

	std::unique_ptr<sinsp_filter> is_subprocess_execve;
	before_open_t before_open = [&](sinsp* inspector)
	{
		sinsp_filter_compiler compiler(inspector,
		                               "evt.type=execve and proc.apid=" + std::to_string(getpid()));
		is_subprocess_execve.reset(compiler.compile());
	};

	event_filter_t filter = [&](sinsp_evt* evt) { return is_subprocess_execve->run(evt); };

	run_callback_t test = [&](sinsp* inspector)
	{
		auto ret = system("./resources/execve32 ./resources/execve ./resources/execve32");
		EXPECT_EQ(0, ret);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		auto tinfo = e->get_thread_info(true);
		if (type == PPME_SYSCALL_EXECVE_19_E || type == PPME_SYSCALL_EXECVE_18_E ||
		    type == PPME_SYSCALL_EXECVE_17_E)
		{
			++callnum;
			switch (callnum)
			{
			case 1:
				EXPECT_EQ(tinfo->m_comm, "libsinsp_e2e_te");
				break;
			case 3:
				EXPECT_EQ(tinfo->m_comm, "sh");
				break;
			case 5:
				EXPECT_EQ(tinfo->m_comm, "execve32");
				break;
			case 7:
				EXPECT_EQ(tinfo->m_comm, "execve");
				break;
			}
		}
		else if (type == PPME_SYSCALL_EXECVE_19_X || type == PPME_SYSCALL_EXECVE_18_X ||
		         type == PPME_SYSCALL_EXECVE_17_X)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			auto comm = e->get_param_value_str("comm", false);
			switch (callnum)
			{
			case 2:
				EXPECT_EQ(comm, "sh");
				break;
			case 4:
				EXPECT_EQ(comm, "execve32");
				break;
			case 6:
				EXPECT_EQ(comm, "execve");
				break;
			case 8:
				EXPECT_EQ(comm, "execve32");
				break;
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, before_open); });
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test32, quotactl_ko)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return evt->get_type() == PPME_SYSCALL_QUOTACTL_X ||
		       evt->get_type() == PPME_SYSCALL_QUOTACTL_E;
	};

	run_callback_t test = [&](sinsp* inspector)
	{
		subprocess handle("./test_helper_32", {"quotactl_ko"});
		handle.wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_QUOTACTL_E)
		{
			++callnum;
			switch (callnum)
			{
			case 1:
				EXPECT_EQ("Q_QUOTAON", e->get_param_value_str("cmd"));
				EXPECT_EQ("USRQUOTA", e->get_param_value_str("type"));
				EXPECT_EQ("QFMT_VFS_V0", e->get_param_value_str("quota_fmt"));
				break;
			case 3:
				EXPECT_EQ("Q_QUOTAOFF", e->get_param_value_str("cmd"));
				EXPECT_EQ("GRPQUOTA", e->get_param_value_str("type"));
			}
		}
		else if (type == PPME_SYSCALL_QUOTACTL_X)
		{
			++callnum;
			switch (callnum)
			{
			case 2:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
				EXPECT_EQ("/quota.user", e->get_param_value_str("quotafilepath"));
				break;
			case 4:
				EXPECT_EQ("-2", e->get_param_value_str("res", false));
				EXPECT_EQ("/dev/xxx", e->get_param_value_str("special"));
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

#endif

TEST_F(sys_call_test, get_n_tracepoint_hit_smoke)
{
	int callnum = 0;
	vector<long> old_evts;
	event_filter_t filter = [&](sinsp_evt* evt) { return false; };
	run_callback_t test = [&](sinsp* inspector)
	{
		uint64_t t_finish = sinsp_utils::get_current_time_ns() + 500000000;
		auto ncpu = inspector->get_machine_info()->num_cpus;
		// just test the tracepoint hit
		auto evts_vec = inspector->get_n_tracepoint_hit();
		for (unsigned j = 0; j < ncpu; ++j)
		{
			EXPECT_GE(evts_vec[j], 0) << "cpu=" << j;
		}
		while (sinsp_utils::get_current_time_ns() < t_finish)
		{
			tee(-1, -1, 0, 0);
		}
		auto evts_vec2 = inspector->get_n_tracepoint_hit();
		for (unsigned j = 0; j < ncpu; ++j)
		{
			EXPECT_GE(evts_vec2[j], evts_vec[j]) << "cpu=" << j;
		}
		old_evts = evts_vec2;
	};
	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	// rerun again to check that counters are properly reset when userspace shutdowns
	test = [&](sinsp* inspector)
	{
		// we can't compare by cpu because processes may be scheduled on other cpus
		// let's just compare the whole sum for now
		auto evts_vec = inspector->get_n_tracepoint_hit();
		auto new_count = std::accumulate(evts_vec.begin(), evts_vec.end(), 0);
		auto old_count = std::accumulate(old_evts.begin(), old_evts.end(), 0);
		EXPECT_LT(new_count, old_count);
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(0, callnum);
}

TEST_F(sys_call_test, setns_test)
{
	int callnum = 0;
	int fd;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return m_tid_filter(evt) &&
		       (evt->get_type() == PPME_SYSCALL_SETNS_E || evt->get_type() == PPME_SYSCALL_SETNS_X);
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		fd = open("/proc/self/ns/net", O_RDONLY);
		ASSERT_NE(0, fd);
		ASSERT_EQ(0, setns(fd, CLONE_NEWNET));
		ASSERT_EQ(0, close(fd));
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		switch (type)
		{
		case PPME_SYSCALL_SETNS_E:
			EXPECT_EQ("<f>/proc/self/ns/net", e->get_param_value_str("fd"));
			break;
		case PPME_SYSCALL_SETNS_X:
			EXPECT_EQ("0", e->get_param_value_str("res"));
			break;
		}
		++callnum;
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, unshare_)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		auto tinfo = evt->get_thread_info(true);
		return tinfo->get_comm() == "libsinsp_e2e_te" && (evt->get_type() == PPME_SYSCALL_UNSHARE_E ||
		                                        evt->get_type() == PPME_SYSCALL_UNSHARE_X);
	};
	run_callback_t test = [&](sinsp* inspector)
	{
		auto child = fork();
		if (child == 0)
		{
			unshare(CLONE_NEWUTS);
			// _exit prevents asan from complaining for a false positive memory leak.
			_exit(0);
		}
		waitpid(child, NULL, 0);
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		switch (type)
		{
		case PPME_SYSCALL_UNSHARE_E:
			EXPECT_EQ("CLONE_NEWUTS", e->get_param_value_str("flags"));
			break;
		case PPME_SYSCALL_UNSHARE_X:
			EXPECT_EQ("0", e->get_param_value_str("res"));
			break;
		}
		++callnum;
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}
