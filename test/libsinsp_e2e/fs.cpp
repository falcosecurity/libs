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

#include "event_capture.h"
#include "subprocess.h"
#include "sys_call_test.h"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <libsinsp/event.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/sinsp_int.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <algorithm>
#include <cassert>
#include <climits>
#include <iostream>
#include <list>
#include <mutex>

#define DATA "AAAAAAAAA"

#define FILENAME "test_tmpfile"
#define DIRNAME "test_tmpdir"
#define UNEXISTENT_DIRNAME "/unexistent/pippo"

/////////////////////////////////////////////////////////////////////////////////////
// creat/unlink
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_creat_ulink) {
	int callnum = 0;
	char bcwd[1024];

	ASSERT_TRUE(getcwd(bcwd, 1024) != NULL);
	std::string cwd(bcwd);
	cwd += "/";

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		int fd = creat(FILENAME, 0644);

		if(fd < 0) {
			FAIL();
		}

		ASSERT_TRUE(write(fd, "ABCD", sizeof("ABCD")) >= 0);
		close(fd);
		unlink(FILENAME);
		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		std::string name(e->get_name());

#if defined(__x86_64__)
		if(type == PPME_SYSCALL_CREAT_E)
#else
		if(name.find("open") != std::string::npos && e->get_direction() == SCAP_ED_IN)
#endif
		{
			callnum++;
		}
#if defined(__x86_64__)
		else if(type == PPME_SYSCALL_CREAT_X)
#else
		else if(name.find("open") != std::string::npos && e->get_direction() == SCAP_ED_OUT)
#endif
		{
			if(callnum == 1) {
				std::string fname = e->get_param_value_str("name", false);
				if(fname == FILENAME) {
					EXPECT_EQ("0644", e->get_param_value_str("mode"));
				}

				EXPECT_LT(0, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_UNLINK_2_E || type == PPME_SYSCALL_UNLINKAT_2_E) {
			if(callnum == 2 || callnum == 4) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_UNLINK_2_X || type == PPME_SYSCALL_UNLINKAT_2_X) {
			if(callnum == 3) {
				if(type == PPME_SYSCALL_UNLINK_2_X) {
					EXPECT_EQ(FILENAME, e->get_param_value_str("path", false));
					EXPECT_EQ(cwd + FILENAME, e->get_param_value_str("path"));
				} else {
					EXPECT_EQ(FILENAME, e->get_param_value_str("name", false));
				}
				EXPECT_LE(0, std::stoi(e->get_param_value_str("res", false)));
				callnum++;
			} else if(callnum == 5) {
				EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(6, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// mkdir/rmdir
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_mkdir_rmdir) {
	int callnum = 0;
	char bcwd[1024];

	ASSERT_TRUE(getcwd(bcwd, 1024) != NULL);
	std::string cwd(bcwd);
	cwd += "/";

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		mkdir(UNEXISTENT_DIRNAME, 0);

		if(mkdir(DIRNAME, 0) != 0) {
			FAIL();
		}

		if(rmdir(DIRNAME) != 0) {
			FAIL();
		}

		if(rmdir(DIRNAME) == 0) {
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_MKDIR_2_E) {
			if(callnum == 0) {
				EXPECT_EQ("0", e->get_param_value_str("mode"));
				callnum++;
			} else if(callnum == 2) {
				EXPECT_EQ("0", e->get_param_value_str("mode"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_MKDIRAT_E) {
			if(callnum == 0) {
				callnum++;
			} else if(callnum == 2) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_MKDIR_2_X || type == PPME_SYSCALL_MKDIRAT_X) {
			if(callnum == 1) {
				EXPECT_NE("0", e->get_param_value_str("res"));
				EXPECT_EQ(UNEXISTENT_DIRNAME, e->get_param_value_str("path"));
				EXPECT_EQ(UNEXISTENT_DIRNAME, e->get_param_value_str("path", false));
				callnum++;
			} else if(callnum == 3) {
				EXPECT_EQ("0", e->get_param_value_str("res"));
				EXPECT_EQ(cwd + DIRNAME, e->get_param_value_str("path"));
				EXPECT_EQ(DIRNAME, e->get_param_value_str("path", false));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_RMDIR_2_E || type == PPME_SYSCALL_UNLINKAT_2_E) {
			if(callnum == 4 || callnum == 6) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_RMDIR_2_X || type == PPME_SYSCALL_UNLINKAT_2_X) {
			if(callnum == 5) {
				EXPECT_LE(0, std::stoi(e->get_param_value_str("res", false)));
				if(type == PPME_SYSCALL_RMDIR_2_X) {
					EXPECT_EQ(DIRNAME, e->get_param_value_str("path", false));
					EXPECT_EQ(cwd + DIRNAME, e->get_param_value_str("path"));
				} else {
					EXPECT_EQ(DIRNAME, e->get_param_value_str("name", false));
				}
				callnum++;
			} else if(callnum == 7) {
				EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
				if(type == PPME_SYSCALL_RMDIR_2_X) {
					EXPECT_EQ(DIRNAME, e->get_param_value_str("path", false));
					EXPECT_EQ(cwd + DIRNAME, e->get_param_value_str("path"));
				} else {
					EXPECT_EQ(DIRNAME, e->get_param_value_str("name", false));
				}
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(8, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// openat
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_openat) {
	int callnum = 0;
	char bcwd[1024];
	int dirfd;
	int fd1;
	int fd2;

	ASSERT_TRUE(getcwd(bcwd, 1024) != NULL);
	std::string cwd(bcwd);
	cwd += "/";

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		dirfd = open(".", O_DIRECTORY);
		if(dirfd <= 0) {
			FAIL();
		}

		//
		// Generate a pagefault to make sure openat_enter doesn't
		// get dropped because FILENAME is not available in memory
		//
		std::string s = FILENAME;
		fd1 = openat(dirfd, FILENAME, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
		if(fd1 <= 0) {
			FAIL();
		}

		ASSERT_TRUE(write(fd1, DATA, sizeof(DATA)) >= 0);

		close(fd1);
		close(dirfd);

		unlink(FILENAME);

		fd2 = openat(AT_FDCWD, FILENAME, O_CREAT | O_WRONLY, S_IRWXU | S_IRWXG | S_IRWXO);
		if(fd2 <= 0) {
			FAIL();
		}

		close(fd2);
		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		std::string filepath = cwd + FILENAME;

		if(type == PPME_SYSCALL_OPENAT_2_X &&
		   param.m_evt->get_param_value_str("name") == filepath &&
		   (std::string("<f>") + filepath) == e->get_param_value_str("fd")) {
			if(callnum == 0) {
				EXPECT_EQ(dirfd, std::stoll(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(fd1, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(std::string("<d>") + bcwd, e->get_param_value_str("dirfd"));
				callnum++;
			} else if(callnum == 1) {
				EXPECT_EQ(-100, std::stoll(e->get_param_value_str("dirfd", false)));
				EXPECT_EQ(fd2, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// pread/pwrite
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_pread) {
	int callnum = 0;
	char buf[32];
	int fd;
	int fd1;
	bool pwrite64_succeeded;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		fd = creat(FILENAME, S_IRWXU);
		if(fd < 0) {
			FAIL();
		}

		ASSERT_TRUE(write(fd, "QWERTYUI", sizeof("QWERTYUI") - 1) >= 0);
		ASSERT_TRUE(pwrite(fd, "ABCD", sizeof("ABCD") - 1, 4) >= 0);
		ssize_t bytes_sent = pwrite64(fd, "ABCD", sizeof("ABCD") - 1, 987654321987654);
		//
		// On NFS, pwrite64 succeeds, so the test must evaluate the return
		// code in the proper way
		//
		pwrite64_succeeded = bytes_sent > 0;

		ASSERT_TRUE(pread64(fd, buf, 32, 1234567891234) < 0);
		close(fd);

		fd1 = open(FILENAME, O_RDONLY);
		if(fd1 < 0) {
			FAIL();
		}

		ASSERT_TRUE(pread(fd1, buf, 4, 4) >= 0);

		close(fd1);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITE_E) {
			if(std::stoll(e->get_param_value_str("fd", false)) == fd) {
				EXPECT_EQ((int)sizeof("QWERTYUI") - 1,
				          std::stoll(e->get_param_value_str("size", false)));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_WRITE_X) {
			if(callnum == 1) {
				EXPECT_EQ((int)sizeof("QWERTYUI") - 1,
				          std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("QWERTYUI", e->get_param_value_str("data"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_PWRITE_E) {
			if(std::stoll(e->get_param_value_str("fd", false)) == fd) {
				if(callnum == 2) {
					EXPECT_EQ((int)sizeof("ABCD") - 1,
					          std::stoll(e->get_param_value_str("size", false)));
					EXPECT_EQ("4", e->get_param_value_str("pos"));
					callnum++;
				} else {
					EXPECT_EQ((int)sizeof("ABCD") - 1,
					          std::stoll(e->get_param_value_str("size", false)));
					EXPECT_EQ("987654321987654", e->get_param_value_str("pos"));
					callnum++;
				}
			}
		} else if(type == PPME_SYSCALL_PWRITE_X) {
			if(callnum == 3) {
				EXPECT_EQ((int)sizeof("ABCD") - 1, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("ABCD", e->get_param_value_str("data"));
				callnum++;
			} else {
				if(pwrite64_succeeded) {
					EXPECT_EQ((int)sizeof("ABCD") - 1,
					          std::stoi(e->get_param_value_str("res", false)));
				} else {
					EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
				}
				EXPECT_EQ("ABCD", e->get_param_value_str("data"));
				callnum++;
			}
		}
		if(type == PPME_SYSCALL_PREAD_E) {
			if(callnum == 6) {
				EXPECT_EQ("32", e->get_param_value_str("size"));
				EXPECT_EQ("1234567891234", e->get_param_value_str("pos"));
				callnum++;
			} else if(callnum == 8) {
				EXPECT_EQ("4", e->get_param_value_str("size"));
				EXPECT_EQ("4", e->get_param_value_str("pos"));
				callnum++;
			} else {
				FAIL();
			}
		} else if(type == PPME_SYSCALL_PREAD_X) {
			if(callnum == 7) {
				EXPECT_NE("0", e->get_param_value_str("res", false));
				callnum++;
			} else if(callnum == 9) {
				EXPECT_EQ((int)sizeof("ABCD") - 1, std::stoi(e->get_param_value_str("res", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(10, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// writev/readv
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_readv) {
	int callnum = 0;
	int fd;
	int fd1;
	int bytes_sent;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		int wv_count;
		char msg1[10] = "aaaaa";
		char msg2[10] = "bbbbb";
		char msg3[10] = "ccccc";
		struct iovec wv[3];
		int rres;

		fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);

		wv[0].iov_base = msg1;
		wv[1].iov_base = msg2;
		wv[2].iov_base = msg3;
		wv[0].iov_len = strlen(msg1);
		wv[1].iov_len = strlen(msg2);
		wv[2].iov_len = strlen(msg3);
		wv_count = 3;

		bytes_sent = writev(fd, wv, wv_count);
		if(bytes_sent <= 0) {
			FAIL();
		}

		close(fd);

		fd1 = open(FILENAME, O_CREAT | O_RDONLY, S_IRWXU);

		wv[0].iov_len = sizeof(msg1);
		wv[1].iov_len = sizeof(msg2);
		wv[2].iov_len = sizeof(msg3);

		rres = readv(fd1, wv, wv_count);
		if(rres <= 0) {
			FAIL();
		}

		close(fd1);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITEV_E) {
			EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
			EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
			callnum++;
		} else if(type == PPME_SYSCALL_WRITEV_X) {
			if(callnum == 1) {
				EXPECT_EQ(15, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_READV_E) {
			EXPECT_EQ(fd1, std::stoll(e->get_param_value_str("fd", false)));
			callnum++;
		} else if(type == PPME_SYSCALL_READV_X) {
			if(callnum == 3) {
				EXPECT_EQ(15, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbbccccc", (e->get_param_value_str("data")).substr(0, 15));
				EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
				EXPECT_EQ(fd1, std::stoll(e->get_param_value_str("fd", false)));
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

	EXPECT_EQ(4, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// pwritev/preadv
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_preadv) {
	int callnum = 0;
	int fd;
	int fd1;
	int bytes_sent;
	bool pwritev64_succeeded;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		int wv_count;
		char msg1[10] = "aaaaa";
		char msg2[10] = "bbbbb";
		char msg3[10] = "ccccc";
		struct iovec wv[3];
		int rres;
		fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);

		ASSERT_TRUE(write(fd, "123456789012345678901234567890", sizeof("QWERTYUI") - 1) >= 0);

		wv[0].iov_base = msg1;
		wv[1].iov_base = msg2;
		wv[2].iov_base = msg3;
		wv[0].iov_len = strlen(msg1);
		wv[1].iov_len = strlen(msg2);
		wv[2].iov_len = strlen(msg3);
		wv_count = 3;

		bytes_sent = pwritev64(fd, wv, wv_count, 132456789012345LL);
		//
		// On NFS, pwritev64 succeeds, so the test must evaluate the return
		// code in the proper way
		//
		pwritev64_succeeded = bytes_sent > 0;

		bytes_sent = pwritev(fd, wv, wv_count, 10);
		if(bytes_sent <= 0) {
			FAIL();
		}

		close(fd);

		fd1 = open(FILENAME, O_CREAT | O_RDONLY, S_IRWXU);

		wv[0].iov_len = sizeof(msg1);
		wv[1].iov_len = sizeof(msg2);
		wv[2].iov_len = sizeof(msg3);

		rres = preadv64(fd1, wv, wv_count, 987654321098);

		rres = preadv(fd1, wv, wv_count, 10);
		if(rres <= 0) {
			FAIL();
		}

		close(fd1);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_PWRITEV_E) {
			if(callnum == 0) {
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
				EXPECT_EQ(132456789012345LL, std::stoll(e->get_param_value_str("pos")));
				callnum++;
			} else {
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, std::stoll(e->get_param_value_str("pos")));
				EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_PWRITEV_X) {
			if(callnum == 1) {
				if(pwritev64_succeeded) {
					EXPECT_EQ(15, std::stoi(e->get_param_value_str("res", false)));
				} else {
					EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
				}
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
				EXPECT_EQ(132456789012345LL, std::stoll(e->get_param_value_str("pos")));
				callnum++;
			} else {
				EXPECT_EQ(15, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbbccccc", e->get_param_value_str("data"));
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, std::stoll(e->get_param_value_str("pos")));
				EXPECT_EQ(15, std::stoll(e->get_param_value_str("size")));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_PREADV_E) {
			if(callnum == 4) {
				EXPECT_EQ(fd1, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(987654321098, std::stoll(e->get_param_value_str("pos")));
				callnum++;
			} else {
				EXPECT_EQ(fd1, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, std::stoll(e->get_param_value_str("pos")));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_PREADV_X) {
			if(callnum == 3) {
				EXPECT_EQ(15, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ("aaaaabbbbb", e->get_param_value_str("data"));
				EXPECT_EQ(30, std::stoll(e->get_param_value_str("size")));
				EXPECT_EQ(fd1, std::stoll(e->get_param_value_str("fd", false)));
				EXPECT_EQ(10, std::stoll(e->get_param_value_str("pos")));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	//	EXPECT_EQ(4, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// dup
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_dup) {
	int callnum = 0;
	int fd;
	int fd1;
	int fd2;
	int fd3;
	int fd4;
	int fd5;
	int fd6;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) {
		uint16_t type = evt->get_type();
		return m_tid_filter(evt) && (type == PPME_SYSCALL_DUP_1_E || type == PPME_SYSCALL_DUP2_E ||
		                             type == PPME_SYSCALL_DUP3_E || type == PPME_SYSCALL_DUP_E ||
		                             type == PPME_SYSCALL_DUP_1_X || type == PPME_SYSCALL_DUP2_X ||
		                             type == PPME_SYSCALL_DUP3_X || type == PPME_SYSCALL_DUP_X);
	};

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		fd = open(FILENAME, O_CREAT | O_WRONLY, 0);
		fd1 = dup(fd);
		fd2 = dup2(fd, 333);
		EXPECT_EQ(333, fd2);
		fd3 = dup2(fd, fd1);
		EXPECT_EQ(fd3, fd1);
		fd4 = dup3(fd3, 444, O_CLOEXEC);
		EXPECT_EQ(444, fd4);
		fd5 = dup2(-1, 33);
		EXPECT_EQ(-1, fd5);
		fd6 = dup2(fd, fd);
		EXPECT_EQ(fd6, fd);

		close(fd);
		close(fd1);
		close(fd2);
		close(fd3);
		close(fd4);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();
		if(type == PPME_SYSCALL_DUP_1_E || type == PPME_SYSCALL_DUP2_E ||
		   type == PPME_SYSCALL_DUP3_E || type == PPME_SYSCALL_DUP_E) {
			if(callnum == 0) {
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			} else if(callnum == 2) {
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			} else if(callnum == 4) {
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			} else if(callnum == 6) {
				EXPECT_EQ(fd3, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			} else if(callnum == 8) {
				EXPECT_EQ("-1", e->get_param_value_str("fd", false));
				callnum++;
			} else if(callnum == 10) {
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));
				callnum++;
			}
		} else if(type == PPME_SYSCALL_DUP_1_X || type == PPME_SYSCALL_DUP2_X ||
		          type == PPME_SYSCALL_DUP3_X || type == PPME_SYSCALL_DUP_X) {
			auto const& thread_manager = param.m_inspector->m_thread_manager;
			ASSERT_NE(
			        (sinsp_threadinfo*)&*thread_manager->get_thread_ref(e->get_tid(), false, true),
			        nullptr);
			if(callnum == 1) {
				EXPECT_EQ(fd1, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd1));
				callnum++;
			} else if(callnum == 3) {
				EXPECT_EQ(fd2, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd2));
				callnum++;
			} else if(callnum == 5) {
				EXPECT_EQ(fd3, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd3));
				callnum++;
			} else if(callnum == 7) {
				EXPECT_EQ(fd4, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd4));
				callnum++;
			} else if(callnum == 9) {
				EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd5));
				callnum++;
			} else if(callnum == 11) {
				EXPECT_EQ(fd6, std::stoi(e->get_param_value_str("res", false)));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

#if defined(__x86_64__)
	EXPECT_EQ(12, callnum);
#else
	// On arm the last dup is skipped: a fcntl is called instead.
	EXPECT_EQ(10, callnum);
#endif
}

/////////////////////////////////////////////////////////////////////////////////////
// fcntl
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_fcntl) {
	int callnum = 0;
	int fd;
	int fd1;
	int fd2;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		fd = open(FILENAME, O_CREAT | O_WRONLY, 0);
		fd1 = fcntl(fd, F_DUPFD, 0);
		fd2 = fcntl(fd, F_DUPFD_CLOEXEC, 0);
		printf("fd: %d %d %d, errno: %d\n", fd, fd1, fd2, errno);

		close(fd);
		close(fd1);
		close(fd2);

		unlink(FILENAME);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_FCNTL_X) {
			const auto& thread_manager = param.m_inspector->m_thread_manager;
			ASSERT_NE(
			        (sinsp_threadinfo*)&*thread_manager->get_thread_ref(e->get_tid(), false, true),
			        nullptr);
			if(callnum == 0) {
				EXPECT_EQ(fd1, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd1));
				callnum++;
			} else if(callnum == 1) {
				EXPECT_EQ(fd2, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_NE((sinsp_threadinfo*)NULL,
				          (sinsp_threadinfo*)&*thread_manager
				                  ->get_thread_ref(e->get_tid(), false, true)
				                  ->get_fd(fd1));
				callnum++;
			}
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}

/////////////////////////////////////////////////////////////////////////////////////
// sendfile
/////////////////////////////////////////////////////////////////////////////////////
TEST_F(sys_call_test, fs_sendfile) {
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;
	off_t offset = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		struct stat stat_buf;

		read_fd = open("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat(read_fd, &stat_buf);

		write_fd = open("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = sendfile(write_fd, read_fd, &offset, size);
		EXPECT_LE(0, res);

		close(read_fd);
		close(write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E) {
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			callnum++;
		} else if(type == PPME_SYSCALL_SENDFILE_X) {
			EXPECT_LE(0, std::stoi(e->get_param_value_str("res", false)));
			EXPECT_EQ(offset, std::stoll(e->get_param_value_str("offset", false)));
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fs_sendfile_nulloff) {
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		struct stat stat_buf;

		read_fd = open("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat(read_fd, &stat_buf);

		write_fd = open("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = sendfile(write_fd, read_fd, NULL, size);
		EXPECT_LE(0, res);

		close(read_fd);
		close(write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E) {
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			callnum++;
		} else if(type == PPME_SYSCALL_SENDFILE_X) {
			EXPECT_LE(0, std::stoi(e->get_param_value_str("res", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fs_sendfile_failed) {
	int callnum = 0;
	// int size;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		int res = sendfile(-1, -2, NULL, 444);
		EXPECT_GT(0, res);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E) {
			EXPECT_NO_THROW({
				EXPECT_EQ("-1", e->get_param_value_str("out_fd", false));
				EXPECT_EQ("-2", e->get_param_value_str("in_fd", false));
				EXPECT_EQ(444, std::stoll(e->get_param_value_str("size", false)));
				EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			});

			callnum++;
		} else if(type == PPME_SYSCALL_SENDFILE_X) {
			EXPECT_NO_THROW({
				EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
				EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
				EXPECT_EQ("-1", e->get_param_value_str("out_fd", false));
				EXPECT_EQ("-2", e->get_param_value_str("in_fd", false));
				EXPECT_EQ(444, std::stoll(e->get_param_value_str("size", false)));
			});
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}

TEST_F(sys_call_test, fs_sendfile_invalidoff) {
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		struct stat stat_buf;

		read_fd = open("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat(read_fd, &stat_buf);

		write_fd = open("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = sendfile(write_fd, read_fd, (off_t*)3333, size);
		EXPECT_GT(0, res);

		close(read_fd);
		close(write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E) {
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			callnum++;
		} else if(type == PPME_SYSCALL_SENDFILE_X) {
			EXPECT_GT(0, std::stoi(e->get_param_value_str("res", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}

#ifdef __i386__
TEST_F(sys_call_test, fs_sendfile64) {
	int callnum = 0;
	int read_fd;
	int write_fd;
	int size;
	loff_t offset = 0;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	//
	// TEST CODE
	//
	run_callback_t test = [&](sinsp* inspector) {
		struct stat stat_buf;

		read_fd = open("/etc/passwd", O_RDONLY);
		EXPECT_LE(0, read_fd);

		fstat(read_fd, &stat_buf);

		write_fd = open("out.txt", O_WRONLY | O_CREAT, stat_buf.st_mode);
		EXPECT_LE(0, write_fd);

		size = stat_buf.st_size;
		int res = syscall(SYS_sendfile64, write_fd, read_fd, &offset, size);
		EXPECT_LE(0, res);

		close(read_fd);
		close(write_fd);
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_SENDFILE_E) {
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			EXPECT_EQ(0, std::stoll(e->get_param_value_str("offset", false)));
			callnum++;
		} else if(type == PPME_SYSCALL_SENDFILE_X) {
			EXPECT_LE(0, std::stoi(e->get_param_value_str("res", false)));
			EXPECT_EQ(offset, std::stoll(e->get_param_value_str("offset", false)));
			EXPECT_EQ(write_fd, std::stoll(e->get_param_value_str("out_fd", false)));
			EXPECT_EQ(read_fd, std::stoll(e->get_param_value_str("in_fd", false)));
			EXPECT_EQ(size, std::stoll(e->get_param_value_str("size", false)));
			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });

	EXPECT_EQ(2, callnum);
}
#endif

TEST_F(sys_call_test, large_read_write) {
	const int buf_size = PPM_MAX_ARG_SIZE * 10;

	std::vector<uint8_t> buf(buf_size);
	int callnum = 0;
	int fd1, fd2;

	srandom(42);

	before_capture_t setup = [&](sinsp* inspector) { inspector->set_snaplen(SNAPLEN_MAX); };

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](sinsp* inspector) {
		fd1 = creat(FILENAME, S_IRWXU);
		if(fd1 < 0) {
			FAIL();
		}

		int res = write(fd1, buf.data(), buf_size);
		EXPECT_EQ(res, buf_size);

		close(fd1);

		fd2 = open(FILENAME, O_RDONLY);
		if(fd2 < 0) {
			FAIL();
		}

		res = read(fd2, buf.data(), buf_size);
		EXPECT_EQ(res, buf_size);

		close(fd2);

		unlink(FILENAME);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITE_E) {
			if(std::stoll(e->get_param_value_str("fd", false)) == fd1) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_WRITE_X) {
			if(callnum == 1) {
				const sinsp_evt_param* p = e->get_param_by_name("data");

				EXPECT_EQ(p->len(), SNAPLEN_MAX);
				EXPECT_EQ(0, memcmp(buf.data(), p->data(), SNAPLEN_MAX));

				callnum++;
			}
		}
		if(type == PPME_SYSCALL_READ_E) {
			if(callnum == 2) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_READ_X) {
			if(callnum == 3) {
				const sinsp_evt_param* p = e->get_param_by_name("data");

				EXPECT_EQ(p->len(), SNAPLEN_MAX);
				EXPECT_EQ(0, memcmp(buf.data(), p->data(), SNAPLEN_MAX));

				callnum++;
			}
		}
	};

	// We don't dump events to scap files, otherwise we could stuck with modern bpf.
	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   event_capture::do_nothing,
		                   setup,
		                   event_capture::do_nothing,
		                   libsinsp::events::all_sc_set(),
		                   131072,
		                   (uint64_t)60 * 1000 * 1000 * 1000,
		                   (uint64_t)60 * 1000 * 1000 * 1000,
		                   false);
	});

	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, large_readv_writev) {
	const int buf_size = PPM_MAX_ARG_SIZE * 10;
	const int chunks = 10;

	char buf[buf_size];
	int callnum = 0;
	int fd;

	srandom(42);

	for(int j = 0; j < buf_size; ++j) {
		buf[j] = random();
	}

	before_capture_t setup = [&](sinsp* inspector) { inspector->set_snaplen(SNAPLEN_MAX); };

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](sinsp* inspector) {
		fd = creat(FILENAME, S_IRWXU);
		if(fd < 0) {
			FAIL();
		}

		struct iovec iovs[chunks];
		int chunk_size = buf_size / chunks;

		int off = 0;
		for(int j = 0; j < chunks; ++j) {
			iovs[j].iov_base = buf + off;
			iovs[j].iov_len = chunk_size;

			off += chunk_size;
		}

		int res = writev(fd, iovs, chunks);
		EXPECT_EQ(res, (int)sizeof(buf));

		close(fd);

		int fd = open(FILENAME, O_RDONLY);
		if(fd < 0) {
			FAIL();
		}

		res = readv(fd, iovs, chunks);
		EXPECT_EQ(res, (int)sizeof(buf));

		close(fd);

		unlink(FILENAME);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		const int max_kmod_buf = getpagesize() - sizeof(struct iovec) * chunks - 1;
		(void)max_kmod_buf;

		sinsp_evt* e = param.m_evt;
		uint16_t type = e->get_type();

		if(type == PPME_SYSCALL_WRITEV_E) {
			if(std::stoll(e->get_param_value_str("fd", false)) == fd) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_WRITEV_X) {
			if(callnum == 1) {
				const sinsp_evt_param* p = e->get_param_by_name("data");
				if(event_capture::s_engine_string == KMOD_ENGINE) {
					//
					// The driver doesn't have the correct behavior for accumulating
					// readv/writev, and it uses a single page as a temporary storage area
					//
					EXPECT_EQ(p->len(), max_kmod_buf);
					EXPECT_EQ(0, memcmp(buf, p->data(), max_kmod_buf));
				} else {
					EXPECT_EQ(p->len(), SNAPLEN_MAX);
					EXPECT_EQ(0, memcmp(buf, p->data(), SNAPLEN_MAX));
				}
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));

				callnum++;
			}
		}
		if(type == PPME_SYSCALL_READV_E) {
			if(callnum == 2) {
				callnum++;
			}
		} else if(type == PPME_SYSCALL_READV_X) {
			if(callnum == 3) {
				const sinsp_evt_param* p = e->get_param_by_name("data");
				if(event_capture::s_engine_string == KMOD_ENGINE) {
					EXPECT_EQ(p->len(), max_kmod_buf);
					EXPECT_EQ(0, memcmp(buf, p->data(), max_kmod_buf));
				} else {
					EXPECT_EQ(p->len(), SNAPLEN_MAX);
					EXPECT_EQ(0, memcmp(buf, p->data(), SNAPLEN_MAX));
				}
				EXPECT_EQ(fd, std::stoll(e->get_param_value_str("fd", false)));

				callnum++;
			}
		}
	};

	// We don't dump events to scap files, otherwise we could stuck with modern bpf.
	ASSERT_NO_FATAL_FAILURE({
		event_capture::run(test,
		                   callback,
		                   filter,
		                   event_capture::do_nothing,
		                   setup,
		                   event_capture::do_nothing,
		                   libsinsp::events::all_sc_set(),
		                   131072,
		                   (uint64_t)60 * 1000 * 1000 * 1000,
		                   (uint64_t)60 * 1000 * 1000 * 1000,
		                   false);
	});

	EXPECT_EQ(4, callnum);
}

TEST_F(sys_call_test, large_open) {
	const int buf_size = PPM_MAX_ARG_SIZE * 10;

	int callnum = 0;

	srandom(42);

	std::string buf;
	while(buf.length() < buf_size) {
		buf.append(std::to_string(random()));
	}

	event_filter_t filter = [&](sinsp_evt* evt) { return m_tid_filter(evt); };

	run_callback_t test = [&](sinsp* inspector) {
#ifdef SYS_open
		int fd = syscall(SYS_open, buf.c_str(), O_RDONLY);
#else
		int fd = syscall(SYS_openat, AT_FDCWD, buf.c_str(), O_RDONLY);
#endif
		EXPECT_EQ(fd, -1);
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_evt* e = param.m_evt;
		std::string name(e->get_name());

		if(name.find("open") != std::string::npos && e->get_direction() == SCAP_ED_IN) {
			callnum++;
		} else if(name.find("open") != std::string::npos && e->get_direction() == SCAP_ED_OUT) {
			const sinsp_evt_param* p = e->get_param_by_name("name");

			if(event_capture::s_engine_string == KMOD_ENGINE) {
				EXPECT_EQ(p->len(), PPM_MAX_ARG_SIZE);
				EXPECT_EQ(buf.substr(0, PPM_MAX_ARG_SIZE - 1), std::string(p->data()));
			} else if(event_capture::s_engine_string == BPF_ENGINE) {
				EXPECT_EQ(p->len(), SNAPLEN_MAX);
				EXPECT_EQ(buf.substr(0, SNAPLEN_MAX - 1), std::string(p->data()));
			} else if(event_capture::s_engine_string == MODERN_BPF_ENGINE) {
				EXPECT_EQ(p->len(), PATH_MAX);
				EXPECT_EQ(buf.substr(0, PATH_MAX - 1), std::string(p->data()));
			}

			callnum++;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	EXPECT_EQ(2, callnum);
}
