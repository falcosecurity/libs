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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#define HELPER_32
#include "tcp_client_server.h"

#include <poll.h>
#include <signal.h>
#include <stdarg.h>

#include <sys/quota.h>
#include <sys/wait.h>

#include <cassert>

using namespace std;

bool is_cgroupv2_mounted() {
	constexpr const char* mounts_file = "/proc/mounts";
	constexpr const char cgroup_v2_prefix[] = "cgroup2 ";
	std::ifstream mounts_file_handle(mounts_file);
	std::string line;
	while(std::getline(mounts_file_handle, line)) {
		if(line.rfind(cgroup_v2_prefix, 0) == 0) {
			return true;
		}
	}
	return false;
}

void proc_mgmt(const vector<string>& args) {
	auto filename = args.at(0).c_str();
	static const char DATA[] = "ABCDEFGHI";
	unlink(filename);

	FILE* f = fopen(filename, "w+");
	fwrite(DATA, sizeof(DATA) - 1, 1, f);
	fclose(f);

	unlink(filename);
}

void mmap_test(const vector<string>& args) {
	int errno2;
	void* p;

	printf("STARTED\n");
	fflush(stdout);

	munmap((void*)0x50, 300);
	p = mmap(0,
	         0,
	         PROT_EXEC | PROT_READ | PROT_WRITE,
	         MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_DENYWRITE,
	         -1,
	         0);
	errno2 = errno;
	p = mmap(NULL, 1003520, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	munmap(p, 1003520);
	printf("%d\n", errno2);
	fflush(stdout);
	printf("%p\n", p);
	fflush(stdout);
}

bool str_to_bool(const string& s) {
	if(s == "true") {
		return true;
	} else {
		return false;
	}
}

void pread_pwrite(const vector<string>& args) {
	char buf[32];
	const auto FILENAME = "test_pread_pwrite";
	int fd = creat(FILENAME, S_IRWXU);
	if(fd < 0) {
		cerr << "ERROR (creat)" << endl;
		return;
	}

	auto ret = write(fd, "ABCDEFGH", sizeof("ABCDEFGH") - 1);
	assert(ret > 0);
	if(ret <= 0) {
		cerr << "ERROR (write)" << endl;
	}

	ret = pwrite(fd, "QWER", sizeof("QWER") - 1, 4);
	assert(ret > 0);
	if(ret <= 0) {
		cerr << "ERROR (pwrite)" << endl;
	}

	ssize_t bytes_sent = pwrite64(fd, "POIU", sizeof("POIU") - 1, 987654321);
	//
	// On NFS, pwrite64 succeeds, so the test must evaluate the return
	// code in the proper way
	//
	bool pwrite64_succeeded = bytes_sent > 0;

	cout << (pwrite64_succeeded ? 1 : 0) << endl;

	if(pread64(fd, buf, 32, 987654321) < 0) {
		cerr << "ERROR (pread64)" << endl;
	}

	close(fd);

	int fd1 = open(FILENAME, O_RDONLY);
	if(fd1 < 0) {
		cerr << "ERROR (open)" << endl;
		return;
	}

	if(pread(fd1, buf, 4, 4) < 0) {
		cerr << "ERROR (pread)" << endl;
	}

	close(fd1);

	unlink(FILENAME);
}

void preadv_pwritev(const vector<string>& args) {
	const auto FILENAME = "test_preadv_pwritev";
	int wv_count;
	char msg1[10] = "aaaaa";
	char msg2[10] = "bbbbb";
	char msg3[10] = "ccccc";
	struct iovec wv[3];
	int rres;
	auto fd = open(FILENAME, O_CREAT | O_WRONLY, S_IRWXU);

	if(write(fd, "123456789012345678901234567890", sizeof("ABCDEFGH") - 1) < 0) {
		cerr << "ERROR (write)" << endl;
	}

	wv[0].iov_base = msg1;
	wv[1].iov_base = msg2;
	wv[2].iov_base = msg3;
	wv[0].iov_len = strlen(msg1);
	wv[1].iov_len = strlen(msg2);
	wv[2].iov_len = strlen(msg3);
	wv_count = 3;

	auto bytes_sent = pwritev64(fd, wv, wv_count, 987654321);
	//
	// On NFS, pwritev64 succeeds, so the test must evaluate the return
	// code in the proper way
	//
	bool pwritev64_succeeded = bytes_sent > 0;

	cout << fd << endl;

	cout << (pwritev64_succeeded ? 1 : 0) << endl;

	bytes_sent = pwritev(fd, wv, wv_count, 10);

	cout << (bytes_sent > 0 ? 1 : 0) << endl;

	close(fd);

	auto fd1 = open(FILENAME, O_CREAT | O_RDONLY, S_IRWXU);

	cout << fd1 << endl;

	wv[0].iov_len = sizeof(msg1);
	wv[1].iov_len = sizeof(msg2);
	wv[2].iov_len = sizeof(msg3);

	rres = preadv64(fd1, wv, wv_count, 987654321);

	rres = preadv(fd1, wv, wv_count, 10);
	if(rres <= 0) {
		cerr << "ERROR" << endl;
	}

	close(fd1);

	unlink(FILENAME);
	cout << flush;
}

void quotactl_ko(const vector<string>& args) {
	quotactl(QCMD(Q_QUOTAON, USRQUOTA),
	         "/dev/xxx",
	         2,
	         (caddr_t) "/quota.user");  // 2 => QFMT_VFS_V0
	quotactl(QCMD(Q_QUOTAOFF, GRPQUOTA), "/dev/xxx", 0, NULL);
}

void quotactl_ok(const vector<string>& args) {
	struct dqblk mydqblk;
	struct dqinfo mydqinfo;
	std::string caddr = args[0] + "/aquota.user";
	quotactl(QCMD(Q_QUOTAON, USRQUOTA),
	         args[1].c_str(),
	         2,
	         (caddr_t)caddr.c_str());  // 2 => QFMT_VFS_V0
	quotactl(QCMD(Q_GETQUOTA, USRQUOTA), args[1].c_str(), 0, (caddr_t)&mydqblk);  // 0 => root user
	fwrite(&mydqblk.dqb_bhardlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_bsoftlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_curspace, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_ihardlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_isoftlimit, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_btime, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqblk.dqb_itime, 1, sizeof(uint64_t), stdout);
	quotactl(QCMD(Q_GETINFO, USRQUOTA), args[1].c_str(), 0, (caddr_t)&mydqinfo);
	fwrite(&mydqinfo.dqi_bgrace, 1, sizeof(uint64_t), stdout);
	fwrite(&mydqinfo.dqi_igrace, 1, sizeof(uint64_t), stdout);
	quotactl(QCMD(Q_QUOTAOFF, USRQUOTA), args[1].c_str(), 0, NULL);
}

void poll_timeout(const vector<string>& args) {
	int my_pipe[2];
	auto ret = pipe(my_pipe);
	if(ret != 0) {
		return;
	}

	struct pollfd ufds[2];
	ufds[0].fd = my_pipe[0];
	ufds[0].events = POLLIN;
	ufds[1].fd = my_pipe[1];
	ufds[1].events = POLLOUT;

	poll(ufds, 2, 20);

	printf("%d\n", my_pipe[0]);
	fflush(stdout);
	printf("%d\n", my_pipe[1]);
	fflush(stdout);
}

void ppoll_timeout(const vector<string>& args) {
	int my_pipe[2];
	auto ret = pipe(my_pipe);
	if(ret != 0) {
		return;
	}

	struct pollfd ufds[2];
	ufds[0].fd = my_pipe[0];
	ufds[0].events = POLLIN;
	ufds[1].fd = my_pipe[1];
	ufds[1].events = POLLOUT;

	struct timespec timeout;
	timeout.tv_sec = 0;
	timeout.tv_nsec = 1000000;

	sigset_t sigs;
	sigemptyset(&sigs);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGCHLD);
	ppoll(ufds, 2, &timeout, &sigs);

	printf("%d\n", my_pipe[0]);
	fflush(stdout);
	printf("%d\n", my_pipe[1]);
	fflush(stdout);
}

void pgid_test(const vector<string>& args) {
	int pgid = atoi(args[0].c_str());

	// Change back to child's process group
	int rc = setpgid(getpid(), pgid);
	if(rc != 0) {
		fprintf(stderr, "Can't call setpgid(): %s\n", strerror(errno));
		return;
	}

	// Now exec echo -n, which just acts as a way for the execve
	// parser to pick up the new pgid.
	char* const exargs[] = {(char*)"/bin/echo", (char*)"-n", nullptr};
	char* const exenv[] = {nullptr};
	if((rc = execve("/bin/echo", exargs, exenv)) != 0) {
		fprintf(stderr, "Can't exec \"/bin/echo -n\": %s\n", strerror(errno));
		return;
	}
}

bool custom_container_set_cgroup() {
	std::string cpu_cgroup;
	if(is_cgroupv2_mounted()) {
		cpu_cgroup = "/sys/fs/cgroup/system.slice/custom_container_foo";
	} else {
		cpu_cgroup = "/sys/fs/cgroup/cpu/custom_container_foo";
	}
	struct stat s;

	if(stat(cpu_cgroup.c_str(), &s) < 0) {
		if(mkdir(cpu_cgroup.c_str(), 0777) < 0) {
			fprintf(stderr,
			        "Could not create cgroup directory %s: %s\n",
			        cpu_cgroup.c_str(),
			        strerror(errno));
			return false;
		}
	}

	auto fp = fopen((cpu_cgroup + "/cgroup.procs").c_str(), "w");
	if(!fp) {
		fprintf(stderr,
		        "Could not open cgroup.procs file in %s: %s\n",
		        cpu_cgroup.c_str(),
		        strerror(errno));
		return false;
	}
	if(fprintf(fp, "%d\n", getpid()) < 0) {
		fprintf(stderr,
		        "Could not write pid to cgroup.procs file in %s: %s\n",
		        cpu_cgroup.c_str(),
		        strerror(errno));
		return false;
	}
	if(fclose(fp) < 0) {
		fprintf(stderr,
		        "Could not close cgroup.procs file in %s: %s\n",
		        cpu_cgroup.c_str(),
		        strerror(errno));
		return false;
	}
	return true;
}

void custom_container_simple() {
	signal(SIGCHLD, SIG_IGN);
	pid_t pid = fork();
	switch(pid) {
	case 0:  // child
	{
		char* const exargs[] = {(char*)"/bin/echo", (char*)"-n", nullptr};
		char* const exenv[] = {(char*)"CUSTOM_CONTAINER_NAME=custom_name",
		                       (char*)"CUSTOM_CONTAINER_IMAGE=custom_image",
		                       nullptr};
		execve("/bin/echo", exargs, exenv);
		exit(127);
	}
	case -1:  // error
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		return;
	default: {
		int status;
		waitpid(pid, &status, 0);
	}
	}
}

void custom_container_huge_env() {
	signal(SIGCHLD, SIG_IGN);
	pid_t pid = fork();
	switch(pid) {
	case 0:  // child
	{
		string junk(100, 'x');
		vector<string> env_vec;
		for(auto i = 0; i < 200; ++i) {
			env_vec.emplace_back("VAR" + to_string(i) + "=" + junk);
		}

		char* exenv[env_vec.size() + 3];
		int i = 0;
		exenv[i++] = const_cast<char*>("CUSTOM_CONTAINER_NAME=custom_name");
		exenv[i++] = const_cast<char*>("CUSTOM_CONTAINER_IMAGE=custom_image");
		for(const auto& var : env_vec) {
			exenv[i++] = const_cast<char*>(var.c_str());
		}
		exenv[i] = nullptr;

		char* const exargs[] = {(char*)"/bin/sleep", (char*)"1", nullptr};
		execve("/bin/sleep", exargs, exenv);
		exit(127);
	}
	case -1:  // error
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		return;
	default: {
		int status;
		waitpid(pid, &status, 0);
	}
	}
}

void custom_container_huge_env_echo() {
	signal(SIGCHLD, SIG_IGN);
	pid_t pid = fork();
	switch(pid) {
	case 0:  // child
	{
		string junk(100, 'x');
		vector<string> env_vec;
		for(auto i = 0; i < 200; ++i) {
			env_vec.emplace_back("VAR" + to_string(i) + "=" + junk);
		}

		char* exenv[env_vec.size() + 3];
		int i = 0;
		exenv[i++] = const_cast<char*>("CUSTOM_CONTAINER_NAME=custom_name");
		exenv[i++] = const_cast<char*>("CUSTOM_CONTAINER_IMAGE=custom_image");
		for(const auto& var : env_vec) {
			exenv[i++] = const_cast<char*>(var.c_str());
		}
		exenv[i] = nullptr;

		char* const exargs[] = {(char*)"/bin/echo", (char*)"-n", nullptr};
		execve("/bin/echo", exargs, exenv);
		exit(127);
	}
	case -1:  // error
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		return;
	default: {
		int status;
		waitpid(pid, &status, 0);
	}
	}
}

void custom_container_huge_env_at_end() {
	signal(SIGCHLD, SIG_IGN);
	pid_t pid = fork();
	switch(pid) {
	case 0:  // child
	{
		string junk(100, 'x');
		vector<string> env_vec;
		for(auto i = 0; i < 200; ++i) {
			env_vec.emplace_back("VAR" + to_string(i) + "=" + junk);
		}

		char* exenv[env_vec.size() + 3];
		int i = 0;
		for(const auto& var : env_vec) {
			exenv[i++] = const_cast<char*>(var.c_str());
		}
		exenv[i++] = const_cast<char*>("CUSTOM_CONTAINER_NAME=custom_name");
		exenv[i++] = const_cast<char*>("CUSTOM_CONTAINER_IMAGE=custom_image");
		exenv[i] = nullptr;

		char* const exargs[] = {(char*)"/bin/sleep", (char*)"1", nullptr};
		execve("/bin/sleep", exargs, exenv);
		exit(127);
	}
	case -1:  // error
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		return;
	default: {
		int status;
		waitpid(pid, &status, 0);
	}
	}
}

void custom_container_halfnhalf() {
	signal(SIGCHLD, SIG_IGN);

	pid_t pid = fork();
	switch(pid) {
	case 0:  // child
	{
		char* const exargs[] = {(char*)"/bin/echo", (char*)"-n", nullptr};
		char* const exenv[] = {(char*)"CUSTOM_CONTAINER_NAME=custom_name", nullptr};
		execve("/bin/echo", exargs, exenv);
		exit(127);
	}
	case -1:  // error
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		return;
	default: {
		pid_t pid2 = fork();
		switch(pid2) {
		case 0:  // child
		{
			char* const exargs[] = {(char*)"/bin/echo", (char*)"-n", nullptr};
			char* const exenv[] = {(char*)"CUSTOM_CONTAINER_IMAGE=custom_image", nullptr};
			execve("/bin/echo", exargs, exenv);
			exit(127);
		}
		case -1:  // error
			fprintf(stderr, "Could not fork: %s\n", strerror(errno));
			return;
		default: {
			int status;
			waitpid(pid, &status, 0);
			waitpid(pid2, &status, 0);
		}
		}
	}
	}
}

void custom_container(const vector<string>& args) {
	if(!custom_container_set_cgroup()) {
		return;
	}

	if(args.empty()) {
		return custom_container_simple();
	}

	const auto& arg = args.at(0);
	if(arg == "halfnhalf") {
		return custom_container_halfnhalf();
	} else if(arg == "huge_env") {
		return custom_container_huge_env();
	} else if(arg == "huge_env_echo") {
		return custom_container_huge_env_echo();
	} else if(arg == "huge_env_at_end") {
		return custom_container_huge_env_at_end();
	}
}

bool cri_container_set_cgroup() {
	std::string cpu_cgroup;
	if(is_cgroupv2_mounted()) {
		cpu_cgroup =
		        "/sys/fs/cgroup/system.slice/"
		        "aec4c703604b4504df03108eef12e8256870eca8aabcb251855a35bf4f0337f1";
	} else {
		cpu_cgroup =
		        "/sys/fs/cgroup/cpu/docker/"
		        "aec4c703604b4504df03108eef12e8256870eca8aabcb251855a35bf4f0337f1";
	}
	struct stat s;

	if(stat(cpu_cgroup.c_str(), &s) < 0) {
		if(mkdir(cpu_cgroup.c_str(), 0777) < 0) {
			fprintf(stderr,
			        "Could not create cgroup directory %s: %s\n",
			        cpu_cgroup.c_str(),
			        strerror(errno));
			return false;
		}
	}

	auto fp = fopen((cpu_cgroup + "/cgroup.procs").c_str(), "w");
	if(!fp) {
		fprintf(stderr,
		        "Could not open cgroup.procs file in %s: %s\n",
		        cpu_cgroup.c_str(),
		        strerror(errno));
		return false;
	}
	if(fprintf(fp, "%d\n", getpid()) < 0) {
		fprintf(stderr,
		        "Could not write pid to cgroup.procs file in %s: %s\n",
		        cpu_cgroup.c_str(),
		        strerror(errno));
		return false;
	}
	if(fclose(fp) < 0) {
		fprintf(stderr,
		        "Could not close cgroup.procs file in %s: %s\n",
		        cpu_cgroup.c_str(),
		        strerror(errno));
		return false;
	}
	return true;
}

void cri_container_simple(char* const exargs[]) {
	signal(SIGCHLD, SIG_IGN);
	pid_t pid = fork();
	switch(pid) {
	case 0:  // child
	{
		char* const exenv[] = {nullptr};
		execve(exargs[0], exargs, exenv);
		exit(127);
	}
	case -1:  // error
		fprintf(stderr, "Could not fork: %s\n", strerror(errno));
		return;
	default: {
		int status;
		waitpid(pid, &status, 0);
	}
	}
}

void cri_container_echo(const vector<string>& args) {
	if(!cri_container_set_cgroup()) {
		return;
	}

	char* const exargs[] = {(char*)"/bin/echo", (char*)"-n", nullptr};
	return cri_container_simple(exargs);
}

void cri_container_sleep_gzip(const vector<string>& args) {
	if(!cri_container_set_cgroup()) {
		return;
	}

	char* const exargs[] = {(char*)"/bin/bash",
	                        (char*)"-c",
	                        (char*)"sleep 2; gzip -V; sleep 1",
	                        nullptr};
	return cri_container_simple(exargs);
}

void cri_container_sleep_bzip2(const vector<string>& args) {
	if(!cri_container_set_cgroup()) {
		return;
	}

	char* const exargs[] = {(char*)"/bin/bash",
	                        (char*)"-c",
	                        (char*)"sleep 2; bzip2 -h > /dev/null 2>&1; sleep 1",
	                        nullptr};
	return cri_container_simple(exargs);
}

void cri_container_sleep_lzcat(const vector<string>& args) {
	if(!cri_container_set_cgroup()) {
		return;
	}

	char* const exargs[] = {(char*)"/bin/bash",
	                        (char*)"-c",
	                        (char*)"sleep 2; lzcat --help; sleep 1",
	                        nullptr};
	return cri_container_simple(exargs);
}

const unordered_map<string, function<void(const vector<string>&)>> func_map = {
        {"proc_mgmt", proc_mgmt},
        {"mmap_test", mmap_test},
        {"tcp_client",
         [](const vector<string>& args) {
	         auto iot = static_cast<iotype>(stoi(args.at(1)));
	         tcp_client client(inet_addr(args.at(0).c_str()),
	                           iot,
	                           args.at(2),
	                           str_to_bool(args.at(3)),
	                           stoi(args.at(4)),
	                           str_to_bool(args.at(5)));
	         client.run();
         }},
        {"tcp_server",
         [](const vector<string>& args) {
	         auto iot = static_cast<iotype>(stoi(args.at(0)));

	         tcp_server server(iot,
	                           str_to_bool(args.at(1)),
	                           str_to_bool(args.at(2)),
	                           str_to_bool(args.at(3)),
	                           stoi(args.at(4)),
	                           str_to_bool(args.at(5)));
	         server.run();
         }},
        {"pread_pwrite", pread_pwrite},
        {"preadv_pwritev", preadv_pwritev},
        {"quotactl_ko", quotactl_ko},
        {"quotactl_ok", quotactl_ok},
        {"poll_timeout", poll_timeout},
        {"ppoll_timeout", ppoll_timeout},
        {"pgid_test", pgid_test},
        {"custom_container", custom_container},
        {"cri_container_echo", cri_container_echo},
        {"cri_container_sleep_gzip", cri_container_sleep_gzip},
        {"cri_container_sleep_bzip2", cri_container_sleep_bzip2},
        {"cri_container_sleep_lzcat", cri_container_sleep_lzcat}};

// Helper to test ia32 emulation on 64bit
int main(int argc, char** argv) {
	if(argc > 1) {
		bool threaded = false;

		// The first argument might be "threaded", meaning
		// that the test should be performed in a spawned
		// thread.
		int j = 1;

		if(strcmp(argv[j], "threaded") == 0) {
			threaded = true;
			j++;
		}

		vector<string> args;
		for(; j < argc; ++j) {
			args.emplace_back(argv[j]);
		}
		auto cmd = args.front();
		args.erase(args.begin());

		auto do_work = [&]() { func_map.at(cmd)(args); };

		if(threaded) {
			std::thread t(do_work);

			t.join();
		} else {
			do_work();
		}
	}
	return 0;
}
