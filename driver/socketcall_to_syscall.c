/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include "ppm_events_public.h"

/* Right now we don't support architectures that have
 * socket-calls both on 64 and 32-bit
 */
#if defined(__KERNEL__) && defined(CONFIG_IA32_EMULATION)
#include <asm/unistd_32.h>
#else
#include <asm/unistd.h>
#endif

/* We need to import them explicitly otherwise if we import `linux/net`
 * we will have a redefinition of syscall codes.
 */
#define SYS_SOCKET 1	  /* sys_socket(2)		*/
#define SYS_BIND 2	  /* sys_bind(2)			*/
#define SYS_CONNECT 3	  /* sys_connect(2)		*/
#define SYS_LISTEN 4	  /* sys_listen(2)		*/
#define SYS_ACCEPT 5	  /* sys_accept(2)		*/
#define SYS_GETSOCKNAME 6 /* sys_getsockname(2)		*/
#define SYS_GETPEERNAME 7 /* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR 8  /* sys_socketpair(2)		*/
#define SYS_SEND 9	  /* sys_send(2)			*/
#define SYS_RECV 10	  /* sys_recv(2)			*/
#define SYS_SENDTO 11	  /* sys_sendto(2)		*/
#define SYS_RECVFROM 12	  /* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN 13	  /* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT 14 /* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT 15 /* sys_getsockopt(2)		*/
#define SYS_SENDMSG 16	  /* sys_sendmsg(2)		*/
#define SYS_RECVMSG 17	  /* sys_recvmsg(2)		*/
#define SYS_ACCEPT4 18	  /* sys_accept4(2)		*/
#define SYS_RECVMMSG 19	  /* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG 20	  /* sys_sendmmsg(2)		*/

int socketcall_code_to_syscall_code(int socketcall_code, bool* is_syscall_return)
{
	/* First we check if we can convert a valid syscall code */
	*is_syscall_return = true;

	switch(socketcall_code)
	{
#ifdef __NR_socket
	case SYS_SOCKET:
		return __NR_socket;
#endif

#ifdef __NR_socketpair
	case SYS_SOCKETPAIR:
		return __NR_socketpair;
#endif

#ifdef __NR_accept
	case SYS_ACCEPT:
		return __NR_accept;
#endif

#ifdef __NR_accept4
	case SYS_ACCEPT4:
		return __NR_accept4;
#endif

#ifdef __NR_bind
	case SYS_BIND:
		return __NR_bind;
#endif

#ifdef __NR_listen
	case SYS_LISTEN:
		return __NR_listen;
#endif

#ifdef __NR_connect
	case SYS_CONNECT:
		return __NR_connect;
#endif

#ifdef __NR_getsockname
	case SYS_GETSOCKNAME:
		return __NR_getsockname;
#endif

#ifdef __NR_getpeername
	case SYS_GETPEERNAME:
		return __NR_getpeername;
#endif

#ifdef __NR_getsockopt
	case SYS_GETSOCKOPT:
		return __NR_getsockopt;
#endif

#ifdef __NR_setsockopt
	case SYS_SETSOCKOPT:
		return __NR_setsockopt;
#endif

#ifdef __NR_recv
	case SYS_RECV:
		return __NR_recv;
#endif

#ifdef __NR_recvfrom
	case SYS_RECVFROM:
		return __NR_recvfrom;
#endif

#ifdef __NR_recvmsg
	case SYS_RECVMSG:
		return __NR_recvmsg;
#endif

#ifdef __NR_recvmmsg
	case SYS_RECVMMSG:
		return __NR_recvmmsg;
#endif

#ifdef __NR_send
	case SYS_SEND:
		return __NR_send;
#endif

#ifdef __NR_sendto
	case SYS_SENDTO:
		return __NR_sendto;
#endif

#ifdef __NR_sendmsg
	case SYS_SENDMSG:
		return __NR_sendmsg;
#endif

#ifdef __NR_sendmmsg
	case SYS_SENDMMSG:
		return __NR_sendmmsg;
#endif

#ifdef __NR_shutdown
	case SYS_SHUTDOWN:
		return __NR_shutdown;
#endif
	default:
		break;
	}

	/* If we cannot convert to a valid syscall id, there are 2 possibilities:
	 * 1. the user provided the wrong socket call code.
	 *	  In this case we will send a generic event at the end of this method
	 * 2. The socket call code is defined but the corresponding
	 *    syscall call is not defined. For example on s390x machines
	 *    `SYS_ACCEPT` is defined but `__NR_accept` is not.
	 * 	  In this way we will send the corresponding event.
	 *
	 * Known cases in which the socket call code is defined but
	 * the corresponding syscall code is not:
	 *
	 * ----- s390x
	 * - `SYS_ACCEPT` is defined but `__NR_accept` is not defined
	 *
	 * ----- x86 with CONFIG_IA32_EMULATION
	 * - `SYS_ACCEPT` is defined but `__NR_accept` is not defined
	 * - `SYS_SEND` is defined but `__NR_send` is not defined
	 * - `SYS_RECV` is defined but `__NR_recv` is not defined
	 */
	*is_syscall_return = false;

	switch(socketcall_code)
	{
	case SYS_SOCKET:
		return PPME_SOCKET_SOCKET_E;

	case SYS_SOCKETPAIR:
		return PPME_SOCKET_SOCKETPAIR_E;

	case SYS_ACCEPT:
		return PPME_SOCKET_ACCEPT_5_E;

	case SYS_ACCEPT4:
		return PPME_SOCKET_ACCEPT4_6_E;

	case SYS_BIND:
		return PPME_SOCKET_BIND_E;

	case SYS_LISTEN:
		return PPME_SOCKET_LISTEN_E;

	case SYS_CONNECT:
		return PPME_SOCKET_CONNECT_E;

	case SYS_GETSOCKNAME:
		return PPME_SOCKET_GETSOCKNAME_E;

	case SYS_GETPEERNAME:
		return PPME_SOCKET_GETPEERNAME_E;

	case SYS_GETSOCKOPT:
		return PPME_SOCKET_GETSOCKOPT_E;

	case SYS_SETSOCKOPT:
		return PPME_SOCKET_SETSOCKOPT_E;

	case SYS_RECV:
		return PPME_SOCKET_RECV_E;

	case SYS_RECVFROM:
		return PPME_SOCKET_RECVFROM_E;

	case SYS_RECVMSG:
		return PPME_SOCKET_RECVMSG_E;

	case SYS_RECVMMSG:
		return PPME_SOCKET_RECVMMSG_E;

	case SYS_SEND:
		return PPME_SOCKET_SEND_E;

	case SYS_SENDTO:
		return PPME_SOCKET_SENDTO_E;

	case SYS_SENDMSG:
		return PPME_SOCKET_SENDMSG_E;

	case SYS_SENDMMSG:
		return PPME_SOCKET_SENDMMSG_E;

	case SYS_SHUTDOWN:
		return PPME_SOCKET_SHUTDOWN_E;

	default:
		break;
	}

	return PPME_GENERIC_E;
}
