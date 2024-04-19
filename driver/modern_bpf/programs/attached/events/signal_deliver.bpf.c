// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: `/include/trace/events/signal.h`
 *	 TP_PROTO(int sig, struct kernel_siginfo *info, struct k_sigaction *ka)
 */
SEC("tp_btf/signal_deliver")
int BPF_PROG(signal_deliver,
	     int sig, struct kernel_siginfo *info, struct k_sigaction *ka)
{
	if(sampling_logic(ctx, PPME_SIGNALDELIVER_E, MODERN_BPF_TRACEPOINT))
	{
		return 0;
	}

	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, SIGNAL_DELIVER_SIZE, PPME_SIGNALDELIVER_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Try to find the source pid */
	pid_t spid = 0;

	if(info != NULL)
	{
		switch(sig)
		{
		case SIGKILL:
			spid = info->_sifields._kill._pid;
			break;

		case SIGTERM:
		case SIGHUP:
		case SIGINT:
		case SIGTSTP:
		case SIGQUIT:
		{
			int si_code = info->si_code;
			if(si_code == SI_USER ||
			   si_code == SI_QUEUE ||
			   si_code <= 0)
			{
				/* This is equivalent to `info->si_pid` where
			 * `si_pid` is a macro `_sifields._kill._pid`
				 */
				spid = info->_sifields._kill._pid;
			}
			break;
		}

		case SIGCHLD:
			spid = info->_sifields._sigchld._pid;
			break;

		default:
			spid = 0;
			break;
		}

		if(sig >= SIGRTMIN && sig <= SIGRTMAX)
		{
			spid = info->_sifields._rt._pid;
		}
	}

	/* Parameter 1: spid (type: PT_PID) */
	ringbuf__store_u64(&ringbuf, (int64_t)spid);

	/* Parameter 2: dpid (type: PT_PID) */
	ringbuf__store_u64(&ringbuf, (int64_t)bpf_get_current_pid_tgid() & 0xffffffff);

	/* Parameter 3: sig (type: PT_SIGTYPE) */
	ringbuf__store_u8(&ringbuf, (uint8_t)sig);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}
