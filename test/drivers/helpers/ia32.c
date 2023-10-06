/*
 * This file gets compiled with -m32 flag by drivers tests CMakefile,
 * and is a dep of drivers_test executable.
 * It just triggers ia32 syscalls to check whether we are able to capture them.
 */

#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>  /* Definition of RESOLVE_* constants */
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/net.h>        /* Definition of SYS_* constants */

int main() {
	struct open_how how;
	how.flags = O_RDWR;
	how.mode = 0;
	how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
	syscall(__NR_openat2, 11, "mock_path", &how, sizeof(struct open_how));
	syscall(__NR_write, 17, NULL, 1013);
	unsigned long args[3] = {0};
	args[0] = AF_INET;
	args[1] = SOCK_RAW;
	args[2] = PF_INET;
	syscall(__NR_socketcall, SYS_SOCKET, args);
	syscall(__NR_socketcall, SYS_ACCEPT4, args);
	syscall(__NR_socketcall, SYS_SEND, args);
	syscall(__NR_socketcall, SYS_ACCEPT, args);
	syscall(__NR_socketcall, -1, args);
	return 0;
}