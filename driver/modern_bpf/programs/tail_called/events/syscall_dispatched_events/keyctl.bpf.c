// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2026 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(keyctl_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_KEYCTL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: operation (type: PT_ENUMFLAGS32) */
	uint32_t operation = (uint32_t)keyctl_operation_to_scap(extract__syscall_argument(regs, 0));
	auxmap__store_u32_param(auxmap, operation);

	if(!keyctl_operation_supports_arg2(operation)) {
		/* Operations like SESSION_TO_PARENT don't define arg2. */
		auxmap__store_empty_param(auxmap);
		auxmap__store_s64_param(auxmap, 0);
	} else {
		unsigned long arg2 = extract__syscall_argument(regs, 1);

		if(operation == PPM_KEYCTL_JOIN_SESSION_KEYRING) {
			/* Parameter 3: arg2_str (type: PT_CHARBUF) — char* keyring name */
			auxmap__store_charbuf_param(auxmap, arg2, MAX_PATH, USER);
			/* Parameter 4: arg2_int (type: PT_INT64) */
			auxmap__store_s64_param(auxmap, 0);
		} else {
			/* Parameter 3: arg2_str (type: PT_CHARBUF) — empty, arg2 is a raw non-string value */
			auxmap__store_empty_param(auxmap);
			/* Parameter 4: arg2_int (type: PT_INT64) */
			auxmap__store_s64_param(auxmap, arg2);
		}
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
