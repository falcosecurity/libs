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
#include <arpa/inet.h>
#include <errno.h>
#include <event_class/network_utils.h>

#ifdef __NR_openat2
#include <linux/openat2.h> /* Definition of RESOLVE_* constants */
#endif

#define TRY_SYSCALL(x, ...)                                                                                            \
	if(strncmp(#x, argv[1], sizeof(#x)) == 0)                                                                      \
	{                                                                                                              \
		syscall(x, ##__VA_ARGS__);                                                                             \
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
	else if(argc == 2)
	{
#ifdef __NR_write
		TRY_SYSCALL(__NR_write, 17, NULL, 1013)
#endif

#ifdef __NR_clock_gettime
		TRY_SYSCALL(__NR_clock_gettime, 0, NULL)
#endif

#ifdef __NR_getcpu
		TRY_SYSCALL(__NR_getcpu, NULL, NULL, NULL)
#endif

#ifdef __NR_gettimeofday
		TRY_SYSCALL(__NR_gettimeofday, NULL, NULL)
#endif

#ifdef __NR_time
		TRY_SYSCALL(__NR_time, NULL)
#endif
	}
	else if(argc == 3)
	{
		/* This if case is used to manage socketcall, we look at argv[2] in this case */

		// Create sockets
		int32_t server_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if(server_socket_fd == -1)
		{
			fprintf(stderr, "socket server failed\n");
			return -1;
		}
		int32_t client_socket_fd = syscall(__NR_socket, AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		if(client_socket_fd == -1)
		{
			fprintf(stderr, "socket client failed\n");
			return -1;
		}

		// Reuse address and port
		int option_value = 1;
		if(syscall(__NR_setsockopt, server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			   sizeof(option_value)) == -1)
		{
			fprintf(stderr, "setsockopt (server addr) failed\n");
			return -1;
		}
		if(syscall(__NR_setsockopt, server_socket_fd, SOL_SOCKET, SO_REUSEPORT, &option_value,
			   sizeof(option_value)) == -1)
		{
			fprintf(stderr, "setsockopt (server port) failed\n");
			return -1;
		}
		if(syscall(__NR_setsockopt, client_socket_fd, SOL_SOCKET, SO_REUSEADDR, &option_value,
			   sizeof(option_value)) == -1)
		{
			fprintf(stderr, "setsockopt (client addr) failed\n");
			return -1;
		}
		if(syscall(__NR_setsockopt, client_socket_fd, SOL_SOCKET, SO_REUSEPORT, &option_value,
			   sizeof(option_value)) == -1)
		{
			fprintf(stderr, "setsockopt (client port) failed\n");
			return -1;
		}

		// populate info
		struct sockaddr_in client_addr = {0};
		struct sockaddr_in server_addr = {0};

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(IPV4_PORT_SERVER);
		if(inet_pton(AF_INET, IPV4_SERVER, &(server_addr.sin_addr)) == -1)
		{
			fprintf(stderr, "inet_pton server failed\n");
			return -1;
		}

		client_addr.sin_family = AF_INET;
		client_addr.sin_port = htons(IPV4_PORT_CLIENT);
		if(inet_pton(AF_INET, IPV4_CLIENT, &(client_addr.sin_addr)) == -1)
		{
			fprintf(stderr, "inet_pton client failed\n");
			return -1;
		}

		// Now we bind the server socket with the server address.
		if(syscall(__NR_bind, server_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1)
		{
			fprintf(stderr, "bind (server) failed\n");
			return -1;
		}

		if(syscall(__NR_listen, server_socket_fd, QUEUE_LENGTH) == -1)
		{
			fprintf(stderr, "listen failed\n");
			return -1;
		}

		// We need to bind the client socket with an address otherwise we cannot assert against it.
		if(syscall(__NR_bind, client_socket_fd, (struct sockaddr*)&client_addr, sizeof(client_addr)) == -1)
		{
			fprintf(stderr, "bind (client) failed\n");
			return -1;
		}

		// The connection will be inprogress so we don't check the errno.
		syscall(__NR_connect, client_socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));

#ifdef __NR_socketcall
		if(strncmp("__NR_accept", argv[2], sizeof("__NR_accept")) == 0)
		{
			uint32_t args[3] = {0};
			args[0] = server_socket_fd;
			args[1] = 0;
			args[2] = 0;

			int connected_socket_fd = syscall(__NR_socketcall, SYS_ACCEPT, (uint32_t*)args);
			if(connected_socket_fd == -1)
			{
				fprintf(stderr, "accept (server) failed\n");
				return -1;
			}
			syscall(__NR_shutdown, connected_socket_fd, 2);
			syscall(__NR_close, connected_socket_fd);
		}

		if(strncmp("__NR_sendto", argv[2], sizeof("__NR_sendto")) == 0)
		{
			char sent_data[NO_SNAPLEN_MESSAGE_LEN] = NO_SNAPLEN_MESSAGE;
			uint32_t sendto_flags = 0;

			unsigned long args[6] = {0};
			args[0] = client_socket_fd;
			args[1] = (unsigned long)sent_data;
			args[2] = sizeof(sent_data);
			args[3] = sendto_flags;
			args[4] = (unsigned long)&server_addr;
			args[5] = sizeof(server_addr);
			int64_t sent_bytes = syscall(__NR_socketcall, SYS_SENDTO, args);
			if(sent_bytes == -1)
			{
				fprintf(stderr, "sendto failed\n");
				return -1;
			}
		}
#endif
		syscall(__NR_shutdown, server_socket_fd, 2);
		syscall(__NR_shutdown, client_socket_fd, 2);
		syscall(__NR_close, server_socket_fd);
		syscall(__NR_close, client_socket_fd);
		return 0;
	}
	else
	{
		fprintf(stderr, "wrong number of args\n");
		return -1;
	}

	fprintf(stderr, "not managed syscall: '%s'\n", argv[1]);
	return -1;
}
