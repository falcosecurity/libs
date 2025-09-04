// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(preadv_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PREADV_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	if(ret > 0) {
		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, (uint32_t)ret);

		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		dynamic_snaplen_args snaplen_args = {
		        .only_port_range = true,
		        .evt_type = PPME_SYSCALL_PREADV_X,
		};
		uint16_t snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, &snaplen_args);
		if(snaplen > ret) {
			snaplen = ret;
		}

		unsigned long iov_pointer = extract__syscall_argument(regs, 1);
		unsigned long iov_cnt = extract__syscall_argument(regs, 2);

		//* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_iovec_data_param(auxmap, iov_pointer, iov_cnt, snaplen);
	} else {
		/* Parameter 2: size (type: PT_UINT32) */
		auxmap__store_u32_param(auxmap, 0);

		/* Parameter 3: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 4: fd (type: PT_FD) */
	int64_t fd = (int64_t)(int32_t)extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, fd);

	/* Parameter 5: pos (type: PT_UINT64) */
	uint64_t pos = (uint64_t)extract__syscall_argument(regs, 3);
	auxmap__store_u64_param(auxmap, pos);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
