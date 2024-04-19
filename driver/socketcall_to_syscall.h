// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef SOCKETCALL_TO_SYSCALL_H
#define SOCKETCALL_TO_SYSCALL_H

#include "ppm_events_public.h"

/* Right now we don't support architectures that have
 * socket-calls both on 64 and 32-bit
 */
#include <linux/net.h>

static inline int socketcall_code_to_syscall_code(int socketcall_code, bool* is_syscall_return)
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
#ifdef SYS_SOCKET
	case SYS_SOCKET:
		return PPME_SOCKET_SOCKET_E;
#endif

#ifdef SYS_SOCKETPAIR
	case SYS_SOCKETPAIR:
		return PPME_SOCKET_SOCKETPAIR_E;
#endif

#ifdef SYS_ACCEPT
	case SYS_ACCEPT:
		return PPME_SOCKET_ACCEPT_5_E;
#endif

#ifdef SYS_ACCEPT4
	case SYS_ACCEPT4:
		return PPME_SOCKET_ACCEPT4_6_E;
#endif

#ifdef SYS_BIND
	case SYS_BIND:
		return PPME_SOCKET_BIND_E;
#endif

#ifdef SYS_LISTEN
	case SYS_LISTEN:
		return PPME_SOCKET_LISTEN_E;
#endif

#ifdef SYS_CONNECT
	case SYS_CONNECT:
		return PPME_SOCKET_CONNECT_E;
#endif

#ifdef SYS_GETSOCKNAME
	case SYS_GETSOCKNAME:
		return PPME_SOCKET_GETSOCKNAME_E;
#endif

#ifdef SYS_GETPEERNAME
	case SYS_GETPEERNAME:
		return PPME_SOCKET_GETPEERNAME_E;
#endif

#ifdef SYS_GETSOCKOPT
	case SYS_GETSOCKOPT:
		return PPME_SOCKET_GETSOCKOPT_E;
#endif

#ifdef SYS_SETSOCKOPT
	case SYS_SETSOCKOPT:
		return PPME_SOCKET_SETSOCKOPT_E;
#endif

#ifdef SYS_RECV
	case SYS_RECV:
		return PPME_SOCKET_RECV_E;
#endif

#ifdef SYS_RECVFROM
	case SYS_RECVFROM:
		return PPME_SOCKET_RECVFROM_E;
#endif

#ifdef SYS_RECVMSG
	case SYS_RECVMSG:
		return PPME_SOCKET_RECVMSG_E;
#endif

#ifdef SYS_RECVMMSG
	case SYS_RECVMMSG:
		return PPME_SOCKET_RECVMMSG_E;
#endif

#ifdef SYS_SEND
	case SYS_SEND:
		return PPME_SOCKET_SEND_E;
#endif

#ifdef SYS_SENDTO
	case SYS_SENDTO:
		return PPME_SOCKET_SENDTO_E;
#endif

#ifdef SYS_SENDMSG
	case SYS_SENDMSG:
		return PPME_SOCKET_SENDMSG_E;
#endif

#ifdef SYS_SENDMMSG
	case SYS_SENDMMSG:
		return PPME_SOCKET_SENDMMSG_E;
#endif

#ifdef SYS_SHUTDOWN
	case SYS_SHUTDOWN:
		return PPME_SOCKET_SHUTDOWN_E;
#endif

	default:
		break;
	}

	return -1;
}

#endif /* SOCKETCALL_TO_SYSCALL_H */
