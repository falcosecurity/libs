/*
 * This file gets compiled with -m32 flag by drivers tests CMakefile,
 * and is a dep of drivers_test executable.
 * It just triggers ia32 syscalls to check whether we are able to capture them.
 */

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <linux/net.h>        /* Definition of SYS_* constants */

int main() {
	syscall(__NR_close, -1);
	unsigned long args[3] = {0};
	syscall(__NR_socketcall, SYS_SOCKET, args);
	syscall(__NR_socketcall, SYS_ACCEPT4, args);
	return 0;
}