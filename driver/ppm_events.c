// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/compat.h>
#include <linux/kobject.h>
#include <linux/cdev.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <net/compat.h>
#include <net/ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/mman.h>
#include <linux/in.h>
#include <asm/syscall.h>
#include "ppm_ringbuffer.h"
#include "ppm_events_public.h"
#include "ppm_events.h"
#include "ppm.h"
#include "ppm_flag_helpers.h"
#include "ppm_version.h"

/*
 * The kernel patched with grsecurity makes the default access_ok trigger a
 * might_sleep(), so if present we use the one defined by them
 */
#ifdef access_ok_noprefault
#define ppm_access_ok access_ok_noprefault
#else
#ifdef HAS_ACCESS_OK_2
#define ppm_access_ok(type, addr, size) access_ok(addr, size)
#else
#define ppm_access_ok(type, addr, size) access_ok(type, addr, size)
#endif
#endif

static void memory_dump(char *p, size_t size) {
	unsigned int j;

	for(j = 0; j < size; j += 8)
		pr_info("%*ph\n", 8, &p[j]);
}

static inline bool in_port_range(uint16_t port, uint16_t min, uint16_t max) {
	return port >= min && port <= max;
}

/*
 * Globals
 */
uint32_t g_http_options_intval;
uint32_t g_http_get_intval;
uint32_t g_http_head_intval;
uint32_t g_http_post_intval;
uint32_t g_http_put_intval;
uint32_t g_http_delete_intval;
uint32_t g_http_trace_intval;
uint32_t g_http_connect_intval;
uint32_t g_http_resp_intval;

/*
 * What this function does is basically a special memcpy
 * so that, if the page fault handler detects the address is invalid,
 * won't kill the process but will return a positive number
 * Plus, this doesn't sleep.
 * The risk is that if the buffer is partially paged out, we get an error.
 * Returns the number of bytes NOT read.
 */
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n) {
	unsigned long res = n;

	pagefault_disable();

	if(likely(ppm_access_ok(VERIFY_READ, from, n)))
		res = __copy_from_user_inatomic(to, from, n);

	pagefault_enable();

	return res;
}

/*
 * On some kernels (e.g. 2.6.39), even with preemption disabled, the strncpy_from_user,
 * instead of returning -1 after a page fault, schedules the process, so we drop events
 * because of the preemption. This function reads the user buffer in atomic chunks, and
 * returns when:
 * 1. there's an error (returns `-1`).
 * 2. the terminator is found. (the `\0` is computed in the overall length)
 * 3. we have read `n` bytes. (in this case, we don't have the `\0` but it's ok we will add it in
 * the caller)
 */
/// TODO: we need to change the return value to `int` and the third param from `unsigned long n` to
/// 'uint32_t n`
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n) {
	long string_length = 0;
	long res = -1;
	unsigned long bytes_to_read = 4;
	int j;

	pagefault_disable();

	while(n) {
		/*
		 * Read bytes_to_read bytes at a time, and look for the terminator. Should be fast
		 * since the copy_from_user is optimized for the processor
		 */
		if(n < bytes_to_read)
			bytes_to_read = n;

		if(!ppm_access_ok(VERIFY_READ, from, bytes_to_read)) {
			res = -1;
			goto strncpy_end;
		}

		if(__copy_from_user_inatomic(to, from, bytes_to_read)) {
			/*
			 * Page fault
			 */
			res = -1;
			goto strncpy_end;
		}

		n -= bytes_to_read;
		from += bytes_to_read;

		for(j = 0; j < bytes_to_read; ++j) {
			++string_length;

			/* Check if `*to` is the `\0`. */
			if(!*to) {
				res = string_length;
				goto strncpy_end;
			}

			++to;
		}
	}
	/* We read all the `n` bytes. */
	res = string_length;

strncpy_end:
	pagefault_enable();
	return res;
}

int32_t dpi_lookahead_init(void) {
	g_http_options_intval = (*(uint32_t *)HTTP_OPTIONS_STR);
	g_http_get_intval = (*(uint32_t *)HTTP_GET_STR);
	g_http_head_intval = (*(uint32_t *)HTTP_HEAD_STR);
	g_http_post_intval = (*(uint32_t *)HTTP_POST_STR);
	g_http_put_intval = (*(uint32_t *)HTTP_PUT_STR);
	g_http_delete_intval = (*(uint32_t *)HTTP_DELETE_STR);
	g_http_trace_intval = (*(uint32_t *)HTTP_TRACE_STR);
	g_http_connect_intval = (*(uint32_t *)HTTP_CONNECT_STR);
	g_http_resp_intval = (*(uint32_t *)HTTP_RESP_STR);

	return PPM_SUCCESS;
}

inline int sock_getname(struct socket *sock, struct sockaddr *sock_address, int peer) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	/*
	 * Avoid calling sock->ops->getname(), because in certain kernel versions,
	 * the getname functions may take a lock, which violates the limitations of
	 * the RCU lock execution environment which is used by the kernel module.
	 *
	 * An example is the usage of `BPF_CGROUP_RUN_SA_PROG_LOCK` since kernel version `5.8.0`
	 * https://elixir.bootlin.com/linux/v5.8/source/net/ipv4/af_inet.c#L785
	 *
	 * For efficiency, only fill in sockaddr fields actually used by the
	 * kernel module logic; in particular, skip filling in
	 * - sin_zero
	 * - sin6_scope_id
	 * - sin6_flowinfo
	 */
	struct sock *sk = sock->sk;

	switch(sk->sk_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sock_address;
		struct inet_sock *inet = (struct inet_sock *)sk;

		sin->sin_family = AF_INET;
		if(peer) {
			sin->sin_port = inet->inet_dport;
			sin->sin_addr.s_addr = inet->inet_daddr;
		} else {
			uint32_t addr = inet->inet_rcv_saddr;
			if(!addr) {
				addr = inet->inet_saddr;
			}
			sin->sin_port = inet->inet_sport;
			sin->sin_addr.s_addr = addr;
		}
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sock_address;
		struct inet_sock *inet = (struct inet_sock *)sk;
		struct ipv6_pinfo *np = (struct ipv6_pinfo *)inet->pinet6;

		sin->sin6_family = AF_INET6;
		if(peer) {
			sin->sin6_port = inet->inet_dport;
			sin->sin6_addr = sk->sk_v6_daddr;
		} else {
			sin->sin6_addr = sk->sk_v6_rcv_saddr;
			if(ipv6_addr_any(&sin->sin6_addr)) {
				sin->sin6_addr = np->saddr;
			}
			sin->sin6_port = inet->inet_sport;
		}
		break;
	}

	case AF_UNIX: {
		struct sockaddr_un *sunaddr = (struct sockaddr_un *)sock_address;
		struct unix_sock *u;

		if(peer)
			sk = ((struct unix_sock *)sk)->peer;

		u = (struct unix_sock *)sk;
		if(u && u->addr) {
			unsigned int len = u->addr->len;
			if(unlikely(len > sizeof(struct sockaddr_storage))) {
				len = sizeof(struct sockaddr_storage);
			}
			memcpy(sunaddr, u->addr->name, len);
		} else {
			sunaddr->sun_family = AF_UNIX;
			sunaddr->sun_path[0] = 0;
			// The first byte to 0 can be confused with an `abstract socket address` for this reason
			// we put also the second byte to 0 to comunicate to the caller that the address is not
			// valid.
			sunaddr->sun_path[1] = 0;
		}
		break;
	}

	default:
		return -ENOTCONN;
	}

	return 0;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	int ret = sock->ops->getname(sock, sock_address, peer);
	if(ret >= 0)
		ret = 0;
	return ret;
#else
	int sockaddr_len;
	return sock->ops->getname(sock, sock_address, &sockaddr_len, peer);
#endif
}

/**
 * Compute the snaplen for the arguments.
 *
 * The snaplen is the amount of argument data returned along with the event.
 * Normally, the driver performs a dynamic calculation to figure out snaplen
 * per-event. However, if this calculation is disabled
 * (i.e. args->consumer->do_dynamic_snaplen == false), the snaplen will always
 * be args->consumer->snaplen.
 *
 * If dynamic snaplen is enabled, here's how the calculation works:
 *
 * 1. If the event is a write to /dev/null, it gets a special snaplen because
 *    writes to /dev/null is a backdoor method for inserting special events
 *    into the event stream.
 * 2. If the event is NOT a socket operation, return args->consumer->snaplen.
 * 3. If the sending port OR destination port falls within the fullcapture port
 *    range specified by the user, return 16000.
 * 4. Protocol detection. A number of applications are detected heuristically
 *    and given a longer snaplen (2000). These applications are MYSQL, Postgres,
 *    HTTP, mongodb, and statsd.
 * 5. If none of the above apply, return args->consumer->snaplen.
 */
inline uint32_t compute_snaplen(struct event_filler_arguments *args,
                                char *buf,
                                uint32_t lookahead_size) {
	uint32_t res = args->consumer->snaplen;
	int err = 0;
	struct socket *sock = NULL;
	struct sock *sk = NULL;
	uint16_t port_local = 0, port_remote = 0, socket_family = 0, min_port = 0, max_port = 0;

	if(!args->consumer->do_dynamic_snaplen)
		return res;

	// We set this in the previous syscall-specific logic
	if(args->fd == -1)
		return res;

	sock = sockfd_lookup(args->fd, &err);
	if(!sock)
		return res;

	sk = sock->sk;
	if(!sk)
		goto done;

	socket_family = sk->sk_family;
	if(socket_family == AF_INET || socket_family == AF_INET6) {
		struct inet_sock *inet = (struct inet_sock *)sk;
		struct sockaddr *sockaddr = NULL;
		struct sockaddr_in sockaddr_in = {};
		struct sockaddr_in6 sockaddr_in6 = {};

// Kernel 2.6.33 renamed `inet->sport` into `inet->inet_sport`
// https://elixir.bootlin.com/linux/v2.6.33/source/include/net/inet_sock.h#L126
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
		port_local = ntohs(inet->inet_sport);
		// In recent kernels `inet_dport` is just an alias for `sk.__sk_common.skc_dport`
		port_remote = ntohs(inet->inet_dport);
#else
		// Unsupported kernel versions.
		goto done;
#endif

		switch(args->event_type) {
		case PPME_SOCKET_SENDTO_X:
		case PPME_SOCKET_RECVFROM_X:
			// Reading directly from this could cause a page fault.
			// That's why we WILL copy its content into the stack with `ppm_copy_from_user`.
			sockaddr = (struct sockaddr *)args->args[4];
			break;

		case PPME_SOCKET_RECVMSG_X:
		case PPME_SOCKET_SENDMSG_X: {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
			struct user_msghdr mh = {};
#else
			struct msghdr mh = {};
#endif

#ifdef CONFIG_COMPAT
			if(args->compat) {
				struct compat_msghdr compat_mh = {};
				if(likely(ppm_copy_from_user(&compat_mh,
				                             (const void *)compat_ptr(args->args[1]),
				                             sizeof(compat_mh)) == 0)) {
					sockaddr = (struct sockaddr *)compat_ptr(compat_mh.msg_name);
				}
				// in any case we break the switch.
				break;
			}
#endif
			if(likely(ppm_copy_from_user(&mh, (const void *)args->args[1], sizeof(mh)) == 0)) {
				sockaddr = (struct sockaddr *)mh.msg_name;
			}
		} break;

		default:
			break;
		}

		if(port_remote == 0 && sockaddr != NULL) {
			if(socket_family == AF_INET) {
				if(ppm_copy_from_user(&sockaddr_in, sockaddr, sizeof(struct sockaddr_in)) == 0) {
					port_remote = ntohs(sockaddr_in.sin_port);
				}
			} else {
				if(ppm_copy_from_user(&sockaddr_in6, sockaddr, sizeof(struct sockaddr_in6)) == 0) {
					port_remote = ntohs(sockaddr_in6.sin6_port);
				}
			}
		}
	}

	min_port = args->consumer->fullcapture_port_range_start;
	max_port = args->consumer->fullcapture_port_range_end;
	if(max_port > 0 && (in_port_range(port_local, min_port, max_port) ||
	                    in_port_range(port_remote, min_port, max_port))) {
		res = res > SNAPLEN_FULLCAPTURE_PORT ? res : SNAPLEN_FULLCAPTURE_PORT;
		goto done;
	} else if(port_remote == args->consumer->statsd_port) {
		res = res > SNAPLEN_EXTENDED ? res : SNAPLEN_EXTENDED;
		goto done;
	} else if(port_remote == PPM_PORT_DNS) {
		res = res > SNAPLEN_DNS_UDP ? res : SNAPLEN_DNS_UDP;
		goto done;
	} else if((port_local == PPM_PORT_MYSQL || port_remote == PPM_PORT_MYSQL) &&
	          lookahead_size >= 5) {
		if((buf[0] == 3 || buf[1] == 3 || buf[2] == 3 || buf[3] == 3 || buf[4] == 3) ||
		   (buf[2] == 0 && buf[3] == 0)) {
			res = res > SNAPLEN_EXTENDED ? res : SNAPLEN_EXTENDED;
			goto done;
		}
	} else if((port_local == PPM_PORT_POSTGRES || port_remote == PPM_PORT_POSTGRES) &&
	          lookahead_size >= 7) {
		if((buf[0] == 'Q' && buf[1] == 0) ||              /* SimpleQuery command */
		   (buf[0] == 'P' && buf[1] == 0) ||              /* Prepare statement command */
		   (buf[4] == 0 && buf[5] == 3 && buf[6] == 0) || /* startup command */
		   (buf[0] == 'E' && buf[1] == 0)                 /* error or execute command */
		) {
			res = res > SNAPLEN_EXTENDED ? res : SNAPLEN_EXTENDED;
			goto done;
		}
	} else if((port_local == PPM_PORT_MONGODB || port_remote == PPM_PORT_MONGODB) ||
	          (lookahead_size >= 16 &&
	           (*(int32_t *)(buf + 12) == 1 || /* matches header */
	            *(int32_t *)(buf + 12) == 2001 || *(int32_t *)(buf + 12) == 2002 ||
	            *(int32_t *)(buf + 12) == 2003 || *(int32_t *)(buf + 12) == 2004 ||
	            *(int32_t *)(buf + 12) == 2005 || *(int32_t *)(buf + 12) == 2006 ||
	            *(int32_t *)(buf + 12) == 2007))) {
		res = res > SNAPLEN_EXTENDED ? res : SNAPLEN_EXTENDED;
		goto done;
	} else if(lookahead_size >= 5) {
		if(*(uint32_t *)buf == g_http_get_intval || *(uint32_t *)buf == g_http_post_intval ||
		   *(uint32_t *)buf == g_http_put_intval || *(uint32_t *)buf == g_http_delete_intval ||
		   *(uint32_t *)buf == g_http_trace_intval || *(uint32_t *)buf == g_http_connect_intval ||
		   *(uint32_t *)buf == g_http_options_intval ||
		   ((*(uint32_t *)buf == g_http_resp_intval) && (buf[4] == '/'))) {
			res = res > SNAPLEN_EXTENDED ? res : SNAPLEN_EXTENDED;
			goto done;
		}
	}
done:
	sockfd_put(sock);
	return res;
}

int push_empty_param(struct event_filler_arguments *args) {
	uint16_t *psize = (uint16_t *)(args->buffer + args->curarg * sizeof(uint16_t));

	if(unlikely(args->curarg >= args->nargs)) {
		pr_err("(%u)val_to_ring: too many arguments for event #%u, type=%u, curarg=%u, nargs=%u "
		       "tid:%u\n",
		       smp_processor_id(),
		       args->nevents,
		       (uint32_t)args->event_type,
		       args->curarg,
		       args->nargs,
		       current->pid);
		memory_dump(args->buffer - sizeof(struct ppm_evt_hdr), 32);
		ASSERT(0);
		return PPM_FAILURE_BUG;
	}

	/* We push 0 in the length array */
	*psize = 0;

	/* We increment the current argument */
	args->curarg++;
	return PPM_SUCCESS;
}

/*
 * NOTES:
 * - val_len is ignored for everything other than PT_BYTEBUF.
 * - fromuser is ignored for numeric types
 * - dyn_idx is ignored for everything other than PT_DYN
 */
int val_to_ring(struct event_filler_arguments *args,
                uint64_t val,
                uint32_t val_len,
                bool fromuser,
                uint8_t dyn_idx) {
	const struct ppm_param_info *param_info;
	int len = -1;
	uint16_t *psize = (uint16_t *)(args->buffer + args->curarg * sizeof(uint16_t));
	uint32_t max_arg_size = args->arg_data_size;

	if(unlikely(args->curarg >= args->nargs)) {
		pr_err("(%u)val_to_ring: too many arguments for event #%u, type=%u, curarg=%u, nargs=%u "
		       "tid:%u\n",
		       smp_processor_id(),
		       args->nevents,
		       (uint32_t)args->event_type,
		       args->curarg,
		       args->nargs,
		       current->pid);
		memory_dump(args->buffer - sizeof(struct ppm_evt_hdr), 32);
		ASSERT(0);
		return PPM_FAILURE_BUG;
	}

	if(unlikely(args->arg_data_size == 0))
		return PPM_FAILURE_BUFFER_FULL;

	if(max_arg_size > PPM_MAX_ARG_SIZE)
		max_arg_size = PPM_MAX_ARG_SIZE;

	param_info = &(g_event_info[args->event_type].params[args->curarg]);
	if(param_info->type == PT_DYN && param_info->info != NULL) {
		const struct ppm_param_info *dyn_params;

		if(unlikely(dyn_idx >= param_info->ninfo)) {
			ASSERT(0);
			return PPM_FAILURE_BUG;
		}

		dyn_params = (const struct ppm_param_info *)param_info->info;

		param_info = &dyn_params[dyn_idx];
		if(likely(max_arg_size >= sizeof(uint8_t))) {
			*(uint8_t *)(args->buffer + args->arg_data_offset) = dyn_idx;
			len = sizeof(uint8_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}
		args->arg_data_offset += len;
		args->arg_data_size -= len;
		max_arg_size -= len;
		*psize = (uint16_t)len;
	} else {
		*psize = 0;
	}

	switch(param_info->type) {
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		if(unlikely(val == 0)) {
			/* Send an empty param when we have a null pointer `val==0` */
			len = 0;
			break;
		}

		if(fromuser) {
			len = ppm_strncpy_from_user(args->buffer + args->arg_data_offset,
			                            (const char __user *)(unsigned long)val,
			                            max_arg_size);

			if(unlikely(len < 0)) {
				len = 0;
				break;
			}
			/* Two possible cases here:
			 *
			 * 1. `len < max_arg_size`, the terminator is always there, and `len` takes it into
			 * account, so we need to do nothing. We just push a `\0` to an empty byte to avoid an
			 * if case.
			 *
			 * 2. `len == max_arg_size`, the terminator is not there but we cannot push an
			 * additional char for this reason we overwrite the last char and we don't increment
			 * `len`.
			 */
			*(char *)(args->buffer + args->arg_data_offset + max_arg_size - 1) = '\0';
		} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 3, 0)
			// strscpy is available since kernel 4.3.0:
			// https://github.com/torvalds/linux/commit/30035e45753b708e7d47a98398500ca005e02b86
			len = (int)strscpy(args->buffer + args->arg_data_offset,
			                   (const char *)(unsigned long)val,
			                   max_arg_size);
			/* WARNING: `strscpy` returns the length of the string it creates or -E2BIG in case
			 * the resulting string would not fit inside the destination string.
			 * (see https://elixir.bootlin.com/linux/latest/source/lib/string.c#L122 and
			 * https://lwn.net/Articles/659214/)
			 *
			 * The copied string is always null terminated but the returned `len` doesn't
			 * take account for it.
			 *
			 * Two possible cases here:
			 *
			 * 1. `len < max_arg_size`, the terminator is always there, but `len` doesn't take it
			 * into account, so we need to increment the `len`.
			 *
			 * 2. `len == -E2BIG`, the source string is >= than `max_arg_size`. `strscpy` copied
			 *    `max_arg_size - 1` and added the `\0` at the end, so our final copied `len` is
			 * `max_arg_size`.
			 */
			if(len == -E2BIG) {
				len = max_arg_size;
			} else {
				len++;
			}
#else
			// Use old `strlcpy`.
			len = (int)strlcpy(args->buffer + args->arg_data_offset,
			                   (const char *)(unsigned long)val,
			                   max_arg_size);
			/* WARNING: `strlcpy` returns the length of the string it tries to create
			 * so `len` could also be greater than `max_arg_size`, but please note that the copied
			 * charbuf is at max `max_arg_size` (where the last byte is used for the `\0`).
			 * The copied string is always `\0` terminated but the returned `len` doesn't
			 * take into consideration the `\0` like `strlen()` function.
			 *
			 * Two possible cases here:
			 *
			 * 1. `len < max_arg_size`, the terminator is always there, but `len` doesn't take it
			 * into account, so we need to increment the `len`. Note that if the source string has
			 * exactly `max_arg_size` characters the returned `len` is `max_arg_size-1` so we need
			 * to do `len++` to obtain the copied size.
			 *
			 * 2. `len >= max_arg_size`, the source string is greater than `max_arg_size`. `strlcpy`
			 * copied `max_arg_size - 1` and added the `\0` at the end, so our final copied `len` is
			 * `max_arg_size` we have just to resize it and we have done.
			 */
			if(++len >= max_arg_size) {
				len = max_arg_size;
			}
#endif
		}
		break;

	case PT_BYTEBUF:
		if(likely(val != 0 && val_len)) {
			if(fromuser) {
				/*
				 * Copy the lookahead portion of the buffer that we will use DPI-based
				 * snaplen calculation
				 */
				uint32_t dpi_lookahead_size = DPI_LOOKAHEAD_SIZE;

				if(dpi_lookahead_size > val_len)
					dpi_lookahead_size = val_len;

				if(unlikely(dpi_lookahead_size >= max_arg_size))
					return PPM_FAILURE_BUFFER_FULL;

				/* Returns the number of bytes NOT read. */
				len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset,
				                              (const void __user *)(unsigned long)val,
				                              dpi_lookahead_size);

				if(unlikely(len != 0)) {
					goto send_empty_bytebuf_param;
				}

				/*
				 * Check if there's more to copy
				 */
				if(likely((dpi_lookahead_size != val_len))) {
					/*
					 * Calculate the snaplen
					 */
					if(likely(args->enforce_snaplen)) {
						uint32_t sl = args->consumer->snaplen;

						sl = compute_snaplen(args,
						                     args->buffer + args->arg_data_offset,
						                     dpi_lookahead_size);
						if(val_len > sl)
							val_len = sl;
					}

					if(unlikely((val_len) >= max_arg_size))
						val_len = max_arg_size;

					if(val_len > dpi_lookahead_size) {
						len = (int)ppm_copy_from_user(
						        args->buffer + args->arg_data_offset + dpi_lookahead_size,
						        (const uint8_t __user *)(unsigned long)val + dpi_lookahead_size,
						        val_len - dpi_lookahead_size);

						if(unlikely(len != 0)) {
							goto send_empty_bytebuf_param;
						}
					}
				}

				len = val_len;
			} else {
				if(likely(args->enforce_snaplen)) {
					uint32_t sl = compute_snaplen(args, (char *)(unsigned long)val, val_len);
					if(val_len > sl)
						val_len = sl;
				}

				if(unlikely(val_len >= max_arg_size))
					return PPM_FAILURE_BUFFER_FULL;

				memcpy(args->buffer + args->arg_data_offset, (void *)(unsigned long)val, val_len);

				len = val_len;
			}
			/* If we arrive here we have something to send. */
			break;
		}
		/* Send an empty param in all these cases:
		 * - we have a null pointer `val==0` or `val_len==0`.
		 * - we have read `0` bytes.
		 * - we faced an error while reading.
		 */
	send_empty_bytebuf_param:
		len = 0;
		break;

	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
		if(likely(val != 0)) {
			if(unlikely(val_len >= max_arg_size))
				return PPM_FAILURE_BUFFER_FULL;

			if(fromuser) {
				len = (int)ppm_copy_from_user(args->buffer + args->arg_data_offset,
				                              (const void __user *)(unsigned long)val,
				                              val_len);

				if(unlikely(len != 0)) {
					goto send_empty_sock_param;
				}

				len = val_len;
			} else {
				memcpy(args->buffer + args->arg_data_offset, (void *)(unsigned long)val, val_len);

				len = val_len;
			}
			/* If we arrive here we have something to send. */
			break;
		}

	send_empty_sock_param:
		len = 0;
		break;

	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		if(likely(max_arg_size >= sizeof(uint8_t))) {
			*(uint8_t *)(args->buffer + args->arg_data_offset) = (uint8_t)val;
			len = sizeof(uint8_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_UINT16:
	case PT_SYSCALLID:
		if(likely(max_arg_size >= sizeof(uint16_t))) {
			*(uint16_t *)(args->buffer + args->arg_data_offset) = (uint16_t)val;
			len = sizeof(uint16_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_FLAGS32:
	case PT_UINT32:
	case PT_MODE:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
	case PT_ENUMFLAGS32:
		if(likely(max_arg_size >= sizeof(uint32_t))) {
			*(uint32_t *)(args->buffer + args->arg_data_offset) = (uint32_t)val;
			len = sizeof(uint32_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_UINT64:
		if(likely(max_arg_size >= sizeof(uint64_t))) {
			*(uint64_t *)(args->buffer + args->arg_data_offset) = (uint64_t)val;
			len = sizeof(uint64_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT8:
		if(likely(max_arg_size >= sizeof(int8_t))) {
			*(int8_t *)(args->buffer + args->arg_data_offset) = (int8_t)(long)val;
			len = sizeof(int8_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT16:
		if(likely(max_arg_size >= sizeof(int16_t))) {
			*(int16_t *)(args->buffer + args->arg_data_offset) = (int16_t)(long)val;
			len = sizeof(int16_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT32:
		if(likely(max_arg_size >= sizeof(int32_t))) {
			*(int32_t *)(args->buffer + args->arg_data_offset) = (int32_t)(long)val;
			len = sizeof(int32_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	case PT_INT64:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		if(likely(max_arg_size >= sizeof(int64_t))) {
			*(int64_t *)(args->buffer + args->arg_data_offset) = (int64_t)(long)val;
			len = sizeof(int64_t);
		} else {
			return PPM_FAILURE_BUFFER_FULL;
		}

		break;
	default:
		ASSERT(0);
		pr_err("val_to_ring: invalid argument type %d. Event %u (%s) might have less parameters "
		       "than what has been declared in nparams\n",
		       (int)g_event_info[args->event_type].params[args->curarg].type,
		       (uint32_t)args->event_type,
		       g_event_info[args->event_type].name);
		return PPM_FAILURE_BUG;
	}

	ASSERT(len <= PPM_MAX_ARG_SIZE);
	ASSERT(len <= (int)max_arg_size);

	*psize += (uint16_t)len;
	args->curarg++;
	args->arg_data_offset += len;
	args->arg_data_size -= len;

	return PPM_SUCCESS;
}

/*
static struct socket *ppm_sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
    struct file *file;
    struct socket *sock;

    *err = -EBADF;
    file = fget_light(fd, fput_needed);
    if (file) {
        sock = sock_from_file(file, err);
        if (sock)
            return sock;
        fput_light(file, *fput_needed);
    }
    return NULL;
}
*/

static void unix_socket_path(char *dest, const char *path, size_t size) {
	if(path == NULL) {
		dest[0] = '\0';
		return;
	}

	if(path[0] == '\0') {
		/* Please note exceptions in the `sun_path`:
		 * Taken from: https://man7.org/linux/man-pages/man7/unix.7.html
		 *
		 * An `abstract socket address` is distinguished (from a
		 * pathname socket) by the fact that sun_path[0] is a null byte
		 * ('\0').
		 *
		 * So in this case, we need to skip the initial `\0`.
		 */
		snprintf(dest, size - 1, "%s", path + 1);
	} else {
		snprintf(dest,
		         size,
		         "%s",
		         path); /* we assume this will be smaller than (targetbufsize - (1 + 8 + 8)) */
	}
}

/*
 * Convert a sockaddr into our address representation and copy it to
 * targetbuf
 */
uint16_t pack_addr(struct sockaddr *usrsockaddr,
                   int ulen,
                   char *targetbuf,
                   uint16_t targetbufsize) {
	uint32_t ip;
	uint16_t port;
	sa_family_t family = usrsockaddr->sa_family;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	struct sockaddr_un *usrsockaddr_un;
	uint16_t size;
	char *dest;

	switch(family) {
	case AF_INET:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		ip = usrsockaddr_in->sin_addr.s_addr;
		port = ntohs(usrsockaddr_in->sin_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 2; /* family + ip + port */

		*targetbuf = socket_family_to_scap((uint8_t)family);
		*(uint32_t *)(targetbuf + 1) = ip;
		*(uint16_t *)(targetbuf + 5) = port;

		break;
	case AF_INET6:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		port = ntohs(usrsockaddr_in6->sin6_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 2; /* family + ip + port */

		*targetbuf = socket_family_to_scap((uint8_t)family);
		memcpy(targetbuf + 1, usrsockaddr_in6->sin6_addr.s6_addr, 16);
		*(uint16_t *)(targetbuf + 17) = port;

		break;
	case AF_UNIX:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

		/*
		 * Put a 0 at the end of struct sockaddr_un because
		 * the user might not have considered it in the length
		 */
		if(ulen == sizeof(struct sockaddr_storage))
			*(((char *)usrsockaddr_un) + ulen - 1) = 0;
		else
			*(((char *)usrsockaddr_un) + ulen) = 0;

		/*
		 * Pack the data into the target buffer
		 */
		size = 1;

		*targetbuf = socket_family_to_scap((uint8_t)family);

		dest = targetbuf + 1;
		unix_socket_path(dest, usrsockaddr_un->sun_path, UNIX_PATH_MAX);

		size += (uint16_t)strlen(dest) + 1;

		break;
	default:
		size = 0;
		break;
	}

	return size;
}

/*
 * Convert a connection tuple into our tuple representation and copy it to
 * targetbuf. Return the tuple size in case of success; 0 otherwise.
 */
uint16_t fd_to_socktuple(int fd,
                         struct sockaddr *usrsockaddr,
                         int ulen,
                         bool use_userdata,
                         bool is_inbound,
                         char *targetbuf,
                         uint16_t targetbufsize) {
	int err = 0;
	sa_family_t family;
	uint32_t sip;
	uint32_t dip;
	uint8_t *sip6;
	uint8_t *dip6;
	uint16_t sport;
	uint16_t dport;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	uint16_t size;
	struct sockaddr_storage sock_address = {};
	struct sockaddr_storage peer_address = {};
	struct socket *sock;
	char *dest;
	struct unix_sock *us;
	char *us_name = NULL;
	struct sock *speer;
	struct sockaddr_un *usrsockaddr_un;

	/*
	 * Get the socket from the fd
	 * NOTE: sockfd_lookup() locks the socket, so we don't need to worry when we dig in it
	 */
	sock = sockfd_lookup(fd, &err);

	if(unlikely(!sock || !(sock->sk))) {
		/*
		 * This usually happens if the call failed without being able to establish a connection,
		 * i.e. if it didn't return something like SE_EINPROGRESS.
		 */
		if(sock)
			sockfd_put(sock);
		return 0;
	}
	err = sock_getname(sock, (struct sockaddr *)&sock_address, 0);
	ASSERT(err == 0);

	family = sock->sk->sk_family;

	/*
	 * Extract and pack the info, based on the family
	 */
	switch(family) {
	case AF_INET:
		if(!use_userdata) {
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
			if(err == 0) {
				if(is_inbound) {
					sip = ((struct sockaddr_in *)&peer_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *)&peer_address)->sin_port);
					dip = ((struct sockaddr_in *)&sock_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *)&sock_address)->sin_port);
				} else {
					sip = ((struct sockaddr_in *)&sock_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *)&sock_address)->sin_port);
					dip = ((struct sockaddr_in *)&peer_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *)&peer_address)->sin_port);
				}
			} else {
				sip = 0;
				sport = 0;
				dip = 0;
				dport = 0;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in
			 */
			usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

			if(is_inbound) {
				/* To take peer address info we try to use the kernel where possible.
				 * TCP allows us to obtain the right information, while the kernel doesn't fill
				 * `sk->__sk_common.skc_daddr` for UDP connection.
				 * Instead of having a custom logic for each protocol we try to read from
				 * kernel structs and if we don't find valid data we fallback to userspace
				 * structs.
				 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
				sport = ntohs(sock->sk->__sk_common.skc_dport);
				if(sport != 0) {
					/* We can read from the kernel */
					sip = sock->sk->__sk_common.skc_daddr;
				} else
#endif
				{
					sip = usrsockaddr_in->sin_addr.s_addr;
					sport = ntohs(usrsockaddr_in->sin_port);
				}
				dip = ((struct sockaddr_in *)&sock_address)->sin_addr.s_addr;
				dport = ntohs(((struct sockaddr_in *)&sock_address)->sin_port);
			} else {
				sip = ((struct sockaddr_in *)&sock_address)->sin_addr.s_addr;
				sport = ntohs(((struct sockaddr_in *)&sock_address)->sin_port);
				dip = usrsockaddr_in->sin_addr.s_addr;
				dport = ntohs(usrsockaddr_in->sin_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 4 + 2 + 2; /* family + sip + dip + sport + dport */

		*targetbuf = socket_family_to_scap((uint8_t)family);
		*(uint32_t *)(targetbuf + 1) = sip;
		*(uint16_t *)(targetbuf + 5) = sport;
		*(uint32_t *)(targetbuf + 7) = dip;
		*(uint16_t *)(targetbuf + 11) = dport;

		break;
	case AF_INET6:
		if(!use_userdata) {
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
			ASSERT(err == 0);

			if(is_inbound) {
				sip6 = ((struct sockaddr_in6 *)&peer_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *)&peer_address)->sin6_port);
				dip6 = ((struct sockaddr_in6 *)&sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *)&sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *)&sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *)&sock_address)->sin6_port);
				dip6 = ((struct sockaddr_in6 *)&peer_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *)&peer_address)->sin6_port);
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in6
			 */
			usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

			if(is_inbound) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
				sport = ntohs(sock->sk->__sk_common.skc_dport);
				if(sport != 0) {
					/* We can read from the kernel */
					sip6 = sock->sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8;
				} else
#endif
				{
					/* Fallback to userspace struct */
					sip6 = usrsockaddr_in6->sin6_addr.s6_addr;
					sport = ntohs(usrsockaddr_in6->sin6_port);
				}
				dip6 = ((struct sockaddr_in6 *)&sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *)&sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *)&sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *)&sock_address)->sin6_port);
				dip6 = usrsockaddr_in6->sin6_addr.s6_addr;
				dport = ntohs(usrsockaddr_in6->sin6_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 16 + 2 + 2; /* family + sip + dip + sport + dport */

		*targetbuf = socket_family_to_scap((uint8_t)family);
		memcpy(targetbuf + 1, sip6, 16);
		*(uint16_t *)(targetbuf + 17) = sport;
		memcpy(targetbuf + 19, dip6, 16);
		*(uint16_t *)(targetbuf + 35) = dport;

		break;
	case AF_UNIX:
		/*
		 * Retrieve the addresses
		 */
		us = unix_sk(sock->sk);
		speer = us->peer;

		*targetbuf = socket_family_to_scap(family);

		if(is_inbound) {
			*(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)us;
			*(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)speer;
			us_name = ((struct sockaddr_un *)&sock_address)->sun_path;
		} else {
			*(uint64_t *)(targetbuf + 1) = (uint64_t)(unsigned long)speer;
			*(uint64_t *)(targetbuf + 1 + 8) = (uint64_t)(unsigned long)us;
			err = sock_getname(sock, (struct sockaddr *)&peer_address, 1);
			ASSERT(err == 0);
			us_name = ((struct sockaddr_un *)&peer_address)->sun_path;
		}

		// `us_name` should contain the socket path extracted from the kernel if we cannot retrieve
		// it we can fallback to the user-provided address
		// Note that we check the second byte of `us_name`, see `sock_getname` for more details.
		// Some times `usrsockaddr` is provided as a NULL pointer, checking `use_userdata` should be
		// enough but just to be sure we check also `usrsockaddr != NULL`
		if((!us_name || (us_name[0] == '\0' && us_name[1] == '\0')) && usrsockaddr != NULL) {
			usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

			/*
			 * Put a 0 at the end of struct sockaddr_un because
			 * the user might not have considered it in the length
			 */
			if(ulen == sizeof(struct sockaddr_storage))
				*(((char *)usrsockaddr_un) + ulen - 1) = 0;
			else
				*(((char *)usrsockaddr_un) + ulen) = 0;

			if(is_inbound)
				us_name = ((struct sockaddr_un *)&sock_address)->sun_path;
			else
				us_name = usrsockaddr_un->sun_path;
		}
		size = 1 + 8 + 8;
		dest = targetbuf + size;
		unix_socket_path(dest, us_name, UNIX_PATH_MAX);
		size += strlen(dest) + 1;
		break;
	default:
		size = 0;
		break;
	}

	/*
	 * Digging finished. We can release the fd.
	 */
	sockfd_put(sock);

	return size;
}

int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr) {
	if(unlikely(ulen < 0 || ulen > sizeof(struct sockaddr_storage)))
		return -EINVAL;

	if(unlikely(ulen == 0))
		return 0;

	if(unlikely(ppm_copy_from_user(kaddr, uaddr, ulen)))
		return -EFAULT;

	return 0;
}

/*
 * Parses the list of buffers of a xreadv or xwritev call, and pushes the size
 * (and optionally the data) to the ring.
 */
int32_t parse_readv_writev_bufs(struct event_filler_arguments *args,
                                const struct iovec __user *iovsrc,
                                unsigned long iovcnt,
                                int64_t retval,
                                int flags) {
	int32_t res;
	const struct iovec *iov;
	uint64_t copylen;
	uint32_t j;
	uint64_t size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	uint32_t targetbuflen = STR_STORAGE_SIZE;
	unsigned long val;
	uint32_t notcopied_len;
	size_t tocopy_len;

	copylen = iovcnt * sizeof(struct iovec);

	if(unlikely(iovcnt >= 0xffffffff))
		return PPM_FAILURE_BUFFER_FULL;

	if(unlikely(copylen >= STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	if(unlikely(ppm_copy_from_user(args->str_storage, iovsrc, copylen)))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if(flags & PRB_FLAG_PUSH_SIZE) {
		for(j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if((flags & PRB_FLAG_IS_WRITE) == 0)
			if(size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		CHECK_RES(res);
	}

	/*
	 * data
	 */
	if(flags & PRB_FLAG_PUSH_DATA) {
		if(retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
			val = args->args[0];
			args->fd = (int)val;

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for(j = 0; j < iovcnt; j++) {
				if((flags & PRB_FLAG_IS_WRITE) == 0) {
					if(bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (size_t)retval - bufsize);
					tocopy_len = min(tocopy_len, (size_t)targetbuflen - bufsize - 1);
				} else {
					tocopy_len = min(iov[j].iov_len, targetbuflen - bufsize - 1);
				}

				notcopied_len =
				        (int)ppm_copy_from_user(targetbuf + bufsize, iov[j].iov_base, tocopy_len);

				if(unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if(tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			args->enforce_snaplen = true;

			res = val_to_ring(args, (unsigned long)targetbuf, bufsize, false, 0);
			CHECK_RES(res);
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			CHECK_RES(res);
		}
	}

	return PPM_SUCCESS;
}

#ifdef CONFIG_COMPAT
/*
 * Parses the list of buffers of a xreadv or xwritev call, and pushes the size
 * (and optionally the data) to the ring.
 */
int32_t compat_parse_readv_writev_bufs(struct event_filler_arguments *args,
                                       const struct compat_iovec __user *iovsrc,
                                       unsigned long iovcnt,
                                       int64_t retval,
                                       int flags) {
	int32_t res;
	const struct compat_iovec *iov;
	uint64_t copylen;
	uint32_t j;
	uint64_t size = 0;
	unsigned long bufsize;
	char *targetbuf = args->str_storage;
	uint32_t targetbuflen = STR_STORAGE_SIZE;
	unsigned long val;
	uint32_t notcopied_len;
	compat_size_t tocopy_len;

	copylen = iovcnt * sizeof(struct compat_iovec);

	if(unlikely(iovcnt >= 0xffffffff))
		return PPM_FAILURE_BUFFER_FULL;

	if(unlikely(copylen >= STR_STORAGE_SIZE))
		return PPM_FAILURE_BUFFER_FULL;

	if(unlikely(ppm_copy_from_user(args->str_storage, iovsrc, copylen)))
		return PPM_FAILURE_INVALID_USER_MEMORY;

	iov = (const struct compat_iovec *)(args->str_storage);

	targetbuf += copylen;
	targetbuflen -= copylen;

	/*
	 * Size
	 */
	if(flags & PRB_FLAG_PUSH_SIZE) {
		for(j = 0; j < iovcnt; j++)
			size += iov[j].iov_len;

		/*
		 * Size is the total size of the buffers provided by the user. The number of
		 * received bytes can be smaller
		 */
		if((flags & PRB_FLAG_IS_WRITE) == 0)
			if(size > retval)
				size = retval;

		res = val_to_ring(args, size, 0, false, 0);
		CHECK_RES(res);
	}

	/*
	 * data
	 */
	if(flags & PRB_FLAG_PUSH_DATA) {
		if(retval > 0 && iovcnt > 0) {
			/*
			 * Retrieve the FD. It will be used for dynamic snaplen calculation.
			 */
			val = args->args[0];
			args->fd = (int)val;

			/*
			 * Merge the buffers
			 */
			bufsize = 0;

			for(j = 0; j < iovcnt; j++) {
				if((flags & PRB_FLAG_IS_WRITE) == 0) {
					if(bufsize >= retval) {
						ASSERT(bufsize >= retval);

						/*
						 * Copied all the data even if we haven't reached the
						 * end of the buffer.
						 * Copy must stop here.
						 */
						break;
					}

					tocopy_len = min(iov[j].iov_len, (compat_size_t)((size_t)retval - bufsize));
					tocopy_len = min(tocopy_len, (compat_size_t)(targetbuflen - bufsize - 1));
				} else {
					tocopy_len = min(iov[j].iov_len, (compat_size_t)(targetbuflen - bufsize - 1));
				}

				notcopied_len = (int)ppm_copy_from_user(targetbuf + bufsize,
				                                        compat_ptr(iov[j].iov_base),
				                                        tocopy_len);

				if(unlikely(notcopied_len != 0)) {
					/*
					 * This means we had a page fault. Skip this event.
					 */
					return PPM_FAILURE_INVALID_USER_MEMORY;
				}

				bufsize += tocopy_len;

				if(tocopy_len != iov[j].iov_len) {
					/*
					 * No space left in the args->str_storage buffer.
					 * Copy must stop here.
					 */
					break;
				}
			}

			args->enforce_snaplen = true;

			res = val_to_ring(args, (unsigned long)targetbuf, bufsize, false, 0);
			CHECK_RES(res);
		} else {
			res = val_to_ring(args, 0, 0, false, 0);
			CHECK_RES(res);
		}
	}

	return PPM_SUCCESS;
}
#endif /* CONFIG_COMPAT */

/*
 * STANDARD FILLERS
 */

/*
 * AUTOFILLER
 * In simple cases in which extracting an event is just a matter of moving the
 * arguments to the buffer, this filler can be used instead of writing a
 * filler function.
 * The arguments to extract are be specified in g_ppm_events.
 */
int f_sys_autofill(struct event_filler_arguments *args) {
	int res;
	unsigned long val;
	uint32_t j;
	int64_t retval;

	const struct ppm_event_entry *evinfo = &g_ppm_events[args->event_type];
	ASSERT(evinfo->n_autofill_args <= PPM_MAX_AUTOFILL_ARGS);

	for(j = 0; j < evinfo->n_autofill_args; j++) {
		if(evinfo->autofill_args[j].id >= 0) {
			val = args->args[evinfo->autofill_args[j].id];
			res = val_to_ring(args, val, 0, true, 0);
			CHECK_RES(res);
		} else if(evinfo->autofill_args[j].id == AF_ID_RETVAL) {
			/*
			 * Return value
			 */
			retval = (int64_t)(long)syscall_get_return_value(current, args->regs);
			res = val_to_ring(args, retval, 0, false, 0);
			CHECK_RES(res);
		} else if(evinfo->autofill_args[j].id == AF_ID_USEDEFAULT) {
			/*
			 * Default Value
			 */
			res = val_to_ring(args, evinfo->autofill_args[j].default_val, 0, false, 0);
			CHECK_RES(res);
		} else {
			ASSERT(false);
		}
	}

	return add_sentinel(args);
}
