// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef EVENTS_H_
#define EVENTS_H_

/* To know about __NR_socketcall */
#include <asm/unistd.h>
#include "ppm_consumer.h"
#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#include "ppm_events_public.h"

/*
 * Various crap that a callback might need
 */
struct fault_data_t {
	unsigned long address;
	struct pt_regs *regs;
	unsigned long error_code;
};

struct event_filler_arguments {
	ppm_consumer_t *consumer;
	char *buffer; /* the buffer that will be filled with the data */
	uint32_t buffer_size; /* the space in the ring buffer available for this event */
	uint32_t syscall_id; /* the system call ID */
#ifdef PPM_ENABLE_SENTINEL
	uint32_t sentinel;
#endif
	uint32_t nevents;
	uint32_t curarg;
	uint32_t nargs;
	uint32_t arg_data_offset;
	uint32_t arg_data_size;
	ppm_event_code event_type;	/* the event type */
	/* Eventually convert this to an event_info union and move all the
	 * below per-event params in this union, it's not good to waste kernel
	 * stack since all this stuff is always exclusive
	 */
	struct pt_regs *regs; /* the registers containing the call arguments */
	struct task_struct *sched_prev; /* for context switch events, the task that is being scheduled out */
	struct task_struct *sched_next; /* for context switch events, the task that is being scheduled in */

#ifdef CAPTURE_SCHED_PROC_FORK
	struct task_struct *child; /* for sched_process_fork events, this is the child task */
#endif

	char *str_storage; /* String storage. Size is one page. */
	unsigned long args[6];
	bool compat;
	int fd; /* Passed by some of the fillers to val_to_ring to compute the snaplen dynamically */
	bool enforce_snaplen;
	int signo; /* Signal number */
	__kernel_pid_t spid; /* PID of source process */
	__kernel_pid_t dpid; /* PID of destination process */
	struct fault_data_t fault_data; /* For page faults */
};

extern const struct ppm_event_entry g_ppm_events[];

/*
 * HTTP markers
 */
#define HTTP_GET_STR "GET "
#define HTTP_OPTIONS_STR "OPTI"
#define HTTP_HEAD_STR "HEAD"
#define HTTP_POST_STR "POST"
#define HTTP_PUT_STR "PUT "
#define HTTP_DELETE_STR "DELE"
#define HTTP_TRACE_STR "TRAC"
#define HTTP_CONNECT_STR "CONN"
#define HTTP_RESP_STR "HTTP"

/*
 * Functions
 */
int32_t dpi_lookahead_init(void);
int32_t push_empty_param(struct event_filler_arguments *args);
int32_t val_to_ring(struct event_filler_arguments *args, uint64_t val, uint32_t val_len, bool fromuser, uint8_t dyn_idx);
uint16_t pack_addr(struct sockaddr *usrsockaddr, int ulen, char *targetbuf, uint16_t targetbufsize);
uint16_t fd_to_socktuple(int fd, struct sockaddr *usrsockaddr, int ulen, bool use_userdata, bool is_inbound, char *targetbuf, uint16_t targetbufsize);
int addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr *kaddr);
int32_t parse_readv_writev_bufs(struct event_filler_arguments *args, const struct iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags);

#ifdef CONFIG_COMPAT
int32_t compat_parse_readv_writev_bufs(struct event_filler_arguments *args, const struct compat_iovec __user *iovsrc, unsigned long iovcnt, int64_t retval, int flags);
#endif

static inline int add_sentinel(struct event_filler_arguments *args)
{
#ifdef PPM_ENABLE_SENTINEL
	if (likely(args->arg_data_size >= sizeof(uint32_t))) {
		*(uint32_t *)(args->buffer + args->arg_data_offset) = args->sentinel;
		args->arg_data_offset += 4;
		args->arg_data_size -= 4;
		return PPM_SUCCESS;
	}
	return PPM_FAILURE_BUFFER_FULL;
#else
	return PPM_SUCCESS;
#endif
}

#endif /* EVENTS_H_ */
