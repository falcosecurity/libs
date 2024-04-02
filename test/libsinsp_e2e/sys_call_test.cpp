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

uint32_t get_server_address()
{
	struct ifaddrs* interfaceArray = NULL;
	struct ifaddrs* tempIfAddr = NULL;
	int rc = 0;
	uint32_t address = 0;

	rc = getifaddrs(&interfaceArray);
	if (rc != 0)
	{
		return -1;
	}
	for (tempIfAddr = interfaceArray; tempIfAddr != NULL; tempIfAddr = tempIfAddr->ifa_next)
	{
		if (tempIfAddr->ifa_addr == NULL)
		{
			// "eql" interface like on EC2
			continue;
		}

		if (tempIfAddr->ifa_addr->sa_family != AF_INET)
		{
			continue;
		}

		if (0 == strcmp("lo", tempIfAddr->ifa_name))
		{
			continue;
		}
		address = *(uint32_t*)&((struct sockaddr_in*)tempIfAddr->ifa_addr)->sin_addr;
		break;
	}
	freeifaddrs(interfaceArray);

	return address;
}

TEST_F(sys_call_test, stat)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		std::string evt_name(evt->get_name());
		return evt_name.find("stat") != std::string::npos && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
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

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if((0 == strcmp(param.m_evt->get_name(), "open") || 0 == strcmp(param.m_evt->get_name(), "openat") ||
		   0 == strcmp(param.m_evt->get_name(), "close")) && "<f>/tmp" == param.m_evt->get_param_value_str("fd"))
		{
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, open_close_dropping)
{
	int callnum = 0;

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
	};

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return (0 == strcmp(evt->get_name(), "open") || 0 == strcmp(evt->get_name(), "openat") ||
		        0 == strcmp(evt->get_name(), "close")) &&
		       m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
	{
		int fd = open("/tmp", O_RDONLY);
		close(fd);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if((0 == strcmp(param.m_evt->get_name(), "open") || 0 == strcmp(param.m_evt->get_name(), "openat") ||
		   0 == strcmp(param.m_evt->get_name(), "close")) && "<f>/tmp" == param.m_evt->get_param_value_str("fd"))
		{
			callnum++;
		}
	};

	before_close_t cleanup = [&](sinsp* inspector)
	{
		inspector->stop_dropping_mode();
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fcntl_getfd)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl") && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle) { fcntl(0, F_GETFL); };

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fcntl_getfd_dropping)
{
	int callnum = 0;

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
	};

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "fcntl") && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
	{
		fcntl(0, F_GETFL);
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	before_close_t cleanup = [&](sinsp* inspector)
	{
		inspector->stop_dropping_mode();
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });
	EXPECT_EQ(0, callnum);
}

TEST_F(sys_call_test, bind_error)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "bind") && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle) { bind(0, NULL, 0); };

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, bind_error_dropping)
{
	int callnum = 0;

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
	};

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "bind") && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
	{
		bind(0, NULL, 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param) { callnum++; };

	before_close_t cleanup = [&](sinsp* inspector)
	{
		inspector->stop_dropping_mode();
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });
	EXPECT_EQ(1, callnum);
}

TEST_F(sys_call_test, close_badfd)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "close") && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
	{
		close(-1);
		close(INT_MAX);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		int fd = param.m_evt->get_param(0)->as<int64_t>();
		if(param.m_evt->get_direction() == SCAP_ED_IN &&
		   (fd == -1 || fd == INT_MAX))
		{
			callnum++;
		}
		else if(param.m_evt->get_direction() == SCAP_ED_OUT && fd == -EBADF)
		{
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, close_badfd_dropping)
{
	int callnum = 0;

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->start_dropping_mode(1);
	};

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return 0 == strcmp(evt->get_name(), "close") && m_tid_filter(evt);
	};

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
	{
		close(-1);
		close(INT_MAX);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		int fd = param.m_evt->get_param(0)->as<int64_t>();
		if(param.m_evt->get_direction() == SCAP_ED_IN &&
		   (fd == -1 || fd == INT_MAX))
		{
			callnum++;
		}
		else if(param.m_evt->get_direction() == SCAP_ED_OUT && fd == -EBADF)
		{
			callnum++;
		}
	};

	before_close_t cleanup = [&](sinsp* inspector)
	{
		inspector->stop_dropping_mode();
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });
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
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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

	run_callback_t test = [](concurrent_object_handle<sinsp> inspector_handle)
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

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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
				callnum--;
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
				callnum--;
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
				callnum--;
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
				callnum--;
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

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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

	uint32_t orig_uid  = getuid();
	uint32_t orig_euid = geteuid();
	uint32_t orig_gid  = getgid();
	uint32_t orig_egid = getegid();

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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

	// This has to be done without a callback otherwise the test will not
	// work.
	int result = 0;
	result += setuid(orig_uid);
	result += seteuid(orig_euid);
	result += setgid(orig_gid);
	result += setegid(orig_egid);

	if(result != 0)
	{
		FAIL() << "Cannot restore initial id state.";
	}

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
		is_subprocess_execve = compiler.compile();
	};

	event_filter_t filter = [&](sinsp_evt* evt) { return is_subprocess_execve->run(evt); };

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		auto ret = system(LIBSINSP_TEST_RESOURCES_PATH "execve32 "
						  LIBSINSP_TEST_RESOURCES_PATH "execve "
						  LIBSINSP_TEST_RESOURCES_PATH "execve32");
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

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		subprocess handle(LIBSINSP_TEST_PATH "/test_helper_32", {"quotactl_ko"});
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

TEST_F(sys_call_test, setns_test)
{
	int callnum = 0;
	int fd;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return m_tid_filter(evt) &&
		       (evt->get_type() == PPME_SYSCALL_SETNS_E || evt->get_type() == PPME_SYSCALL_SETNS_X);
	};
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
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

TEST_F(sys_call_test, sendmsg_recvmsg_SCM_RIGHTS)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		auto tinfo = evt->get_thread_info(true);
		return tinfo->get_comm() == "libsinsp_e2e_te" && evt->get_type() == PPME_SOCKET_RECVMSG_X;
	};
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		int server_sd, worker_sd, pair_sd[2];
		int rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_sd);
		ASSERT_GE(rc, 0);
		server_sd = pair_sd[0];
		worker_sd = pair_sd[1];

		auto child = fork();
		if (child == 0)
		{
			struct msghdr child_msg = {};
			struct cmsghdr *cmsghdr;
			struct iovec iov[1];
			char buf[CMSG_SPACE(sizeof(int))], c;

			iov[0].iov_base = &c;
			iov[0].iov_len = sizeof(c);
			memset(buf, 0x0d, sizeof(buf));
			cmsghdr = (struct cmsghdr *)buf;
			cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
			cmsghdr->cmsg_level = SOL_SOCKET;
			cmsghdr->cmsg_type = SCM_RIGHTS;
			child_msg.msg_iov = iov;
			child_msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
			child_msg.msg_control = cmsghdr;
			child_msg.msg_controllen = CMSG_LEN(sizeof(int));
			rc = recvmsg(worker_sd, &child_msg, 0);
			ASSERT_GE(rc, 0);
			// _exit prevents asan from complaining for a false positive memory leak.
			_exit(0);
		}
		else
		{
			struct msghdr parent_msg = {};
			struct cmsghdr *cmsghdr;
			struct iovec iov[1];
			int *p;
			char buf[CMSG_SPACE(sizeof(int))], c;

			FILE *f = tmpfile();
			ASSERT_NE(nullptr, f);
			int fd = fileno(f);

			c = '*';
			iov[0].iov_base = &c;
			iov[0].iov_len = sizeof(c);
			memset(buf, 0x0b, sizeof(buf));
			cmsghdr = (struct cmsghdr *)buf;
			cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
			cmsghdr->cmsg_level = SOL_SOCKET;
			cmsghdr->cmsg_type = SCM_RIGHTS;
			parent_msg.msg_iov = iov;
			parent_msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
			parent_msg.msg_control = cmsghdr;
			parent_msg.msg_controllen = CMSG_LEN(sizeof(int));
			p = (int *)CMSG_DATA(cmsghdr);
			*p = fd;

			rc = sendmsg(server_sd, &parent_msg, 0);
			ASSERT_GE(rc, 0);
			waitpid(child, NULL, 0);
			fclose(f);
		}
	};
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if (e->get_num_params() >= 5)
		{
			auto parinfo = e->get_param(4);
			if(parinfo->m_len > sizeof(cmsghdr))
			{
				cmsghdr cmsg = {};
				memcpy(&cmsg, parinfo->m_val, sizeof(cmsghdr));
				if(cmsg.cmsg_type == SCM_RIGHTS)
				{
					++callnum;
				}
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(1, callnum);
}

TEST_F(sys_call_test, ppoll_timeout)
{
	int callnum = 0;
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		auto ti = evt->get_thread_info(false);
		return (evt->get_type() == PPME_SYSCALL_PPOLL_E ||
		        evt->get_type() == PPME_SYSCALL_PPOLL_X) &&
			ti->m_comm == "test_helper";
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		subprocess handle(LIBSINSP_TEST_PATH "/test_helper", {"ppoll_timeout"});
		handle.wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_PPOLL_E)
		{
			//
			// stdin and stdout can be a file or a fifo depending
			// on how the tests are invoked
			//
			string fds = e->get_param_value_str("fds");
			EXPECT_TRUE(fds == "3:p1 4:p4" || fds == "4:p1 5:p4");
			EXPECT_EQ("1000000", e->get_param_value_str("timeout", false));
			EXPECT_EQ("SIGHUP SIGCHLD", e->get_param_value_str("sigmask", false));
			callnum++;
		}
		else if (type == PPME_SYSCALL_PPOLL_X)
		{
			int64_t res = stoi(e->get_param_value_str("res"));

			EXPECT_EQ(res, 1);

			string fds = e->get_param_value_str("fds");

			EXPECT_TRUE(fds == "3:p0 4:p4" || fds == "4:p0 5:p4");

			callnum++;
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, getsetresuid_and_gid)
{
	static const uint32_t test_uid = 5454;
	static const uint32_t test_gid = 6565;
	int callnum = 0;
	uint32_t uids[3];
	uint32_t gids[3];

	uint32_t orig_uids[3];
	uint32_t orig_gids[3];

	bool setresuid_e_ok = false;
	bool setresgid_e_ok = false;

	bool getresuid_e_ok = false;
	bool getresgid_e_ok = false;

	bool getresuid_ok = false;
	bool getresgid_ok = false;

	bool setresuid_ok = false;
	bool setresgid_ok = false;

	getresuid(&orig_uids[0], &orig_uids[1], &orig_uids[2]);
	getresgid(&orig_gids[0], &orig_gids[1], &orig_gids[2]);

	// Clean environment
	int ret = system("userdel testsetresuid");
	ret = system("groupdel testsetresgid");
	usleep(200);

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt)
	{
		auto type = evt->get_type();
		auto tinfo = evt->get_thread_info(true);
		return tinfo->m_comm != "sudo" &&
			(type == PPME_USER_ADDED_E || type == PPME_USER_ADDED_X ||
			type == PPME_GROUP_ADDED_E || type == PPME_GROUP_ADDED_X ||
			type == PPME_SYSCALL_GETRESUID_E || type == PPME_SYSCALL_GETRESUID_X ||
			type == PPME_SYSCALL_GETRESGID_E || type == PPME_SYSCALL_GETRESGID_X ||
			type == PPME_SYSCALL_SETRESUID_E || type == PPME_SYSCALL_SETRESUID_X ||
			type == PPME_SYSCALL_SETRESGID_E || type == PPME_SYSCALL_SETRESGID_X); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		char command[] = "useradd -u 5454 testsetresuid && "
			"groupadd -g 6565 testsetresgid && "
			"sudo -u testsetresuid echo && "
			"sudo -g testsetresgid echo";
		ret = system(command);
		ASSERT_EQ(0, ret);

		auto res = setresuid(test_uid, -1, -1);
		EXPECT_EQ(0, res);
		res = setresgid(test_gid, -1, -1);
		EXPECT_EQ(0, res);
		getresuid(uids, uids + 1, uids + 2);
		getresgid(gids, gids + 1, gids + 2);
	};

	//
	// OUTPUT VALIDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if (type == PPME_SYSCALL_SETRESUID_E && e->get_param_value_str("ruid", false) != "-1" && !setresuid_e_ok)
		{
			++callnum;
			EXPECT_EQ("5454", e->get_param_value_str("ruid", false));
			EXPECT_EQ("testsetresuid", e->get_param_value_str("ruid"));
			EXPECT_EQ("-1", e->get_param_value_str("euid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("euid"));
			EXPECT_EQ("-1", e->get_param_value_str("suid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("suid"));
			setresuid_e_ok = true;
		}
		else if (type == PPME_SYSCALL_SETRESUID_X && !setresuid_ok)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			setresuid_ok = true;
		}
		else if (type == PPME_SYSCALL_SETRESGID_E && e->get_param_value_str("rgid", false) != "-1" && !setresgid_e_ok)
		{
			++callnum;
			EXPECT_EQ("6565", e->get_param_value_str("rgid", false));
			EXPECT_EQ("testsetresgid", e->get_param_value_str("rgid"));
			EXPECT_EQ("-1", e->get_param_value_str("egid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("egid"));
			EXPECT_EQ("-1", e->get_param_value_str("sgid", false));
			EXPECT_EQ("<NONE>", e->get_param_value_str("sgid"));
			setresgid_e_ok = true;
		}
		else if (type == PPME_SYSCALL_SETRESGID_X && !setresgid_ok)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			setresgid_ok = true;
		}
		else if (type == PPME_SYSCALL_GETRESUID_E && !getresuid_e_ok)
		{
			++callnum;
			getresuid_e_ok = true;
		}
		else if (type == PPME_SYSCALL_GETRESGID_E && !getresgid_e_ok)
		{
			++callnum;
			getresgid_e_ok = true;
		}
		else if (type == PPME_SYSCALL_GETRESUID_X && !getresuid_ok)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			EXPECT_EQ("5454", e->get_param_value_str("ruid", false));
			EXPECT_EQ("testsetresuid", e->get_param_value_str("ruid"));
			EXPECT_EQ("0", e->get_param_value_str("euid", false));
			EXPECT_EQ("root", e->get_param_value_str("euid"));
			EXPECT_EQ("0", e->get_param_value_str("suid", false));
			EXPECT_EQ("root", e->get_param_value_str("suid"));
			getresuid_ok = true;
		}
		else if (type == PPME_SYSCALL_GETRESGID_X && !getresgid_ok)
		{
			++callnum;
			EXPECT_EQ("0", e->get_param_value_str("res", false));
			EXPECT_EQ("6565", e->get_param_value_str("rgid", false));
			EXPECT_EQ("testsetresgid", e->get_param_value_str("rgid"));
			EXPECT_EQ("0", e->get_param_value_str("egid", false));
			EXPECT_EQ("root", e->get_param_value_str("egid"));
			EXPECT_EQ("0", e->get_param_value_str("sgid", false));
			EXPECT_EQ("root", e->get_param_value_str("sgid"));
			getresgid_ok = true;
		}
	};

	before_close_t cleanup = [&](sinsp* inspector)
	{
		int result = 0;

		result += setresuid(orig_uids[0], orig_uids[1], orig_uids[2]);
		result += setresgid(orig_gids[0], orig_gids[1], orig_gids[2]);

		if(result != 0)
		{
			FAIL() << "Cannot restore initial id state.";
		}
	};
	
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, event_capture::do_nothing, cleanup); });
	EXPECT_EQ(8, callnum);
}

TEST_F(sys_call_test, failing_execve)
{
	int callnum = 0;

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	const char* eargv[] = {"/non/existent", "arg0", "arg1", "", "arg3", NULL};

	const char* eenvp[] = {"env0", "env1", "", "env3", NULL};

	//
	// Touch the memory so it won't generate a PF in the driver
	//
	printf("%s %s %s %s %s\n", eargv[0], eargv[1], eargv[2], eargv[3], eargv[4]);
	printf("%s %s %s %s\n", eenvp[0], eenvp[1], eenvp[2], eenvp[3]);

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		int ret = execve(eargv[0], (char* const*)eargv, (char* const*)eenvp);
		ASSERT_TRUE(ret < 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if (type == PPME_SYSCALL_EXECVE_19_E || type == PPME_SYSCALL_EXECVE_18_E)
		{
			++callnum;

			string filename = e->get_param_value_str("filename");
			EXPECT_EQ(filename, eargv[0]);
		}
		else if (type == PPME_SYSCALL_EXECVE_19_X || type == PPME_SYSCALL_EXECVE_18_X)
		{
			++callnum;

			string res = e->get_param_value_str("res");
			EXPECT_EQ(res, "ENOENT");

			string exe = e->get_param_value_str("exe");
			EXPECT_EQ(exe, eargv[0]);

			string args = e->get_param_value_str("args");
			EXPECT_EQ(args, "arg0.arg1..arg3.");

			string env = e->get_param_value_str("env");
			EXPECT_EQ(env, "env0.env1..env3.");
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}

#ifdef __x86_64__

TEST_F(sys_call_test32, failing_execve)
{
	int callnum = 0;

	// INIT FILTER
	std::unique_ptr<sinsp_filter> is_subprocess_execve;
	before_open_t before_open = [&](sinsp* inspector)
	{
		sinsp_filter_compiler compiler(inspector,
		                               "evt.type=execve and proc.apid=" + std::to_string(getpid()));
		is_subprocess_execve.reset(compiler.compile().release());
	};

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return is_subprocess_execve->run(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		auto ret = system(LIBSINSP_TEST_RESOURCES_PATH "execve32_fail");
		ASSERT_TRUE(ret > 0);
		ret = system(LIBSINSP_TEST_RESOURCES_PATH "execve32 ./fail");
		ASSERT_TRUE(ret > 0);
	};

	//
	// OUTPUT VALIDATION
	//
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
				EXPECT_EQ(tinfo->m_comm, "libsinsp_e2e_te");
				break;
			case 7:
				EXPECT_EQ(tinfo->m_comm, "sh");
				break;
			case 9:
				EXPECT_EQ(tinfo->m_comm, "execve32");
				break;
			default:
				FAIL() << "Wrong execve entry callnum (" << callnum << ")";
			}
		}
		else if (type == PPME_SYSCALL_EXECVE_19_X || type == PPME_SYSCALL_EXECVE_18_X ||
		         type == PPME_SYSCALL_EXECVE_17_X)
		{
			++callnum;

			auto res = e->get_param_value_str("res", false);
			auto comm = e->get_param_value_str("comm", false);
			auto exe = e->get_param_value_str("exe", false);
			switch (callnum)
			{
			case 2:
				EXPECT_EQ("0", res);
				EXPECT_EQ(comm, "sh");
				break;
			case 4:
				EXPECT_EQ("-2", res);
				EXPECT_EQ(comm, "sh");
				EXPECT_EQ(exe, LIBSINSP_TEST_RESOURCES_PATH "execve32_fail");
				break;
			case 6:
				EXPECT_EQ("0", res);
				EXPECT_EQ(comm, "sh");
				break;
			case 8:
				EXPECT_EQ("0", res);
				EXPECT_EQ(comm, "execve32");
				EXPECT_EQ(exe, LIBSINSP_TEST_RESOURCES_PATH "execve32");
				break;
			case 10:
				EXPECT_EQ("-2", res);
				EXPECT_EQ(comm, "execve32");
				EXPECT_EQ(exe, "./fail");
				break;
			default:
				FAIL() << "Wrong execve exit callnum (" << callnum << ")";
			}
		}
	};
	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, before_open); });
	EXPECT_EQ(10, callnum);
}

#endif
