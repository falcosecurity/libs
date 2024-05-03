/*
 * This file gets compiled with -m32 flag by drivers tests CMakefile,
 * and is a dep of drivers_test executable.
 * It just triggers ia32 syscalls to check whether we are able to capture them.
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/net.h> /* Definition of SYS_* constants */

#ifdef __NR_openat2
#include <linux/openat2.h> /* Definition of RESOLVE_* constants */
#endif

#define TRY_1_ARGS_CALL(x, a1)                                                                                         \
	if(strncmp(#x, argv[1], sizeof(#x)) == 0)                                                                      \
	{                                                                                                              \
		syscall(x, a1);                                                                                        \
		printf("--> Test_ia32 called '%s'\n", #x);                                                             \
		return 0;                                                                                              \
	}

#define TRY_2_ARGS_CALL(x, a1, a2)                                                                                     \
	if(strncmp(#x, argv[1], sizeof(#x)) == 0)                                                                      \
	{                                                                                                              \
		syscall(x, a1, a2);                                                                                    \
		printf("--> Test_ia32 called '%s'\n", #x);                                                             \
		return 0;                                                                                              \
	}

#define TRY_3_ARGS_CALL(x, a1, a2, a3)                                                                                 \
	if(strncmp(#x, argv[1], sizeof(#x)) == 0)                                                                      \
	{                                                                                                              \
		syscall(x, a1, a2, a3);                                                                                \
		printf("--> Test_ia32 called '%s'\n", #x);                                                             \
		return 0;                                                                                              \
	}

int main(int argc, char** argv)
{
	// Throw some generic syscalls if we just pass the name of the executable
	// todo!: we need to convert it to single `if` like the other cases.
	if(argc == 1)
	{
#ifdef __NR_openat2
		struct open_how how;
		how.flags = O_RDWR;
		how.mode = 0;
		how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
		syscall(__NR_openat2, 11, "mock_path", &how, sizeof(struct open_how));
#endif
		syscall(__NR_write, 17, NULL, 1013);

		syscall(__NR_getegid32);
		syscall(__NR_geteuid32);

		syscall(__NR_umount, "mock_path");

		long int p =
			syscall(__NR_mmap, NULL, 1003520, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		syscall(__NR_munmap, p, 1003520);
		p = syscall(__NR_mmap2, NULL, 1003520, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		syscall(__NR_munmap, p, 1003520);

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

	if(argc != 2)
	{
		fprintf(stderr, "we need exactly one single arg\n");
		return -1;
	}

#ifdef __NR_write
	TRY_3_ARGS_CALL(__NR_write, 17, NULL, 1013)
#endif

#ifdef __NR_clock_gettime
	TRY_2_ARGS_CALL(__NR_clock_gettime, 0, NULL)
#endif

#ifdef __NR_getcpu
	TRY_3_ARGS_CALL(__NR_getcpu, NULL, NULL, NULL)
#endif

#ifdef __NR_gettimeofday
	TRY_2_ARGS_CALL(__NR_gettimeofday, NULL, NULL)
#endif

#ifdef __NR_time
	TRY_1_ARGS_CALL(__NR_time, NULL)
#endif

	fprintf(stderr, "not managed syscall: '%s'\n", argv[1]);
	return -1;
}
