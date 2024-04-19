// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(pipe2_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PIPE2_E_SIZE, PPME_SYSCALL_PIPE2_E))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(pipe2_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, ctx, PIPE2_X_SIZE, PPME_SYSCALL_PIPE2_X))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	ringbuf__store_s64(&ringbuf, ret);

	int32_t pipefd[2] = {-1, -1};
	/* This is a pointer to the vector with the 2 file descriptors. */
	unsigned long fd_vector_pointer = extract__syscall_argument(regs, 0);
	if(bpf_probe_read_user((void *)pipefd, sizeof(pipefd), (void *)fd_vector_pointer) != 0)
	{
		pipefd[0] = -1;
		pipefd[1] = -1;
	}

	/* Parameter 2: fd1 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (int64_t)pipefd[0]);

	/* Parameter 3: fd2 (type: PT_FD) */
	ringbuf__store_s64(&ringbuf, (int64_t)pipefd[1]);

	uint64_t ino = 0;
	/* On success, pipe returns `0` */
	if(ret == 0)
	{
		extract__ino_from_fd(pipefd[0], &ino);
	}

	/* Parameter 4: ino (type: PT_UINT64) */
	ringbuf__store_u64(&ringbuf, ino);

	/* Parameter 5: flags (type: PT_FLAGS32) */
	int32_t flags = extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, pipe2_flags_to_scap(flags));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
