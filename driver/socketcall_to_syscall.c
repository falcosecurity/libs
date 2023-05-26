/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include <linux/kconfig.h>

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
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)		*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)		*/

/* Please note that here `socketcall_syscall_id` could be the code
 * on 64-bit or 32-bit.
 */
int socketcall_code_to_syscall_code(int socketcall_code)
{
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

	case SYS_ACCEPT:
#if defined(CONFIG_S390) && defined(__NR_accept4)
		return __NR_accept4;
#elif defined(__NR_accept)
		return __NR_accept;
#endif
		break;

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

	/* if we are not able to convert the
	 * socketcall code we return -1
	 */
	return -1;
}
