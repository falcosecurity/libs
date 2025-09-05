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
int BPF_PROG(pread64_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_PREAD_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	if(ret > 0) {
		/* We read the minimum between `snaplen` and what we really
		 * have in the buffer.
		 */
		dynamic_snaplen_args snaplen_args = {
		        .only_port_range = false,
		        .evt_type = PPME_SYSCALL_PREAD_X,
		};
		uint16_t snaplen = maps__get_snaplen();
		apply_dynamic_snaplen(regs, &snaplen, &snaplen_args);
		if(snaplen > ret) {
			snaplen = ret;
		}

		/* Parameter 2: data (type: PT_BYTEBUF) */
		unsigned long data_ptr = extract__syscall_argument(regs, 1);
		auxmap__store_bytebuf_param(auxmap, data_ptr, snaplen, USER);
	} else {
		/* Parameter 2: data (type: PT_BYTEBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/* Parameter 3: fd (type: PT_FD) */
	int32_t fd = (int32_t)extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, (int64_t)fd);

	/* Parameter 4: size (type: PT_UINT32) */
	uint32_t size = (uint32_t)extract__syscall_argument(regs, 2);
	auxmap__store_u32_param(auxmap, (uint32_t)size);

	/* Parameter 5: pos (type: PT_UINT64) */
	uint64_t pos = (uint64_t)extract__syscall_argument(regs, 3);
	auxmap__store_u64_param(auxmap, pos);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
