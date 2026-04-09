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
	uint32_t op = (uint32_t)keyctl_operation_to_scap(extract__syscall_argument(regs, 0));
	auxmap__store_u32_param(auxmap, op);

	/* Parameters 3-6: arg2, arg3, arg4, arg5 (all PT_DYN) */
	unsigned long arg2 = 0;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	switch(op) {
	case PPM_KEYCTL_SESSION_TO_PARENT:
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_JOIN_SESSION_KEYRING:
		/* arg2 = const char *name */
		arg2 = extract__syscall_argument(regs, 1);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_REVOKE:
	case PPM_KEYCTL_CLEAR:
	case PPM_KEYCTL_SET_REQKEY_KEYRING:
	case PPM_KEYCTL_ASSUME_AUTHORITY:
	case PPM_KEYCTL_INVALIDATE:
		arg2 = extract__syscall_argument(regs, 1);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_GET_KEYRING_ID:
	case PPM_KEYCTL_SETPERM:
	case PPM_KEYCTL_LINK:
	case PPM_KEYCTL_UNLINK:
	case PPM_KEYCTL_SET_TIMEOUT:
	case PPM_KEYCTL_GET_PERSISTENT:
	case PPM_KEYCTL_CAPABILITIES:
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_UPDATE:
	case PPM_KEYCTL_CHOWN:
	case PPM_KEYCTL_DESCRIBE:
	case PPM_KEYCTL_READ:
	case PPM_KEYCTL_NEGATE:
	case PPM_KEYCTL_GET_SECURITY:
	case PPM_KEYCTL_WATCH_KEY:
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		arg4 = extract__syscall_argument(regs, 3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_RESTRICT_KEYRING:
		/* arg3 = const char *type, arg4 = const char *restriction */
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		arg4 = extract__syscall_argument(regs, 3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_PKEY_QUERY:
		/* arg3 = 0 (reserved), arg4 = const char *info */
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		arg4 = extract__syscall_argument(regs, 3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	case PPM_KEYCTL_SEARCH:
		/* arg3 = const char *type, arg4 = const char *description */
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		arg4 = extract__syscall_argument(regs, 3);
		arg5 = extract__syscall_argument(regs, 4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg5);
		break;
	case PPM_KEYCTL_INSTANTIATE:
	case PPM_KEYCTL_REJECT:
	case PPM_KEYCTL_INSTANTIATE_IOV:
	case PPM_KEYCTL_DH_COMPUTE:
	case PPM_KEYCTL_MOVE:
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		arg4 = extract__syscall_argument(regs, 3);
		arg5 = extract__syscall_argument(regs, 4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg5);
		break;
	case PPM_KEYCTL_PKEY_ENCRYPT:
	case PPM_KEYCTL_PKEY_DECRYPT:
	case PPM_KEYCTL_PKEY_SIGN:
	case PPM_KEYCTL_PKEY_VERIFY:
		/* arg3 = const char *info, arg4 = data pointer */
		arg2 = extract__syscall_argument(regs, 1);
		arg3 = extract__syscall_argument(regs, 2);
		arg4 = extract__syscall_argument(regs, 3);
		arg5 = extract__syscall_argument(regs, 4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg2);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_CHARBUF, arg3);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg4);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, arg5);
		break;
	default:
		bpf_printk("unsupported keyctl op %lu", op);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		auxmap__store_keyctl_param(auxmap, PPM_KEYCTL_IDX_INT64, 0);
		break;
	}

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
