/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(fsconfig_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, FSCONFIG_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_FSCONFIG_E, FSCONFIG_E_SIZE);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	// Here we have no parameters to collect.

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(fsconfig_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_FSCONFIG_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: ret (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: fd (type: PT_FD) */
    /* This is the file-system fd */
	s32 fd = (s32)extract__syscall_argument(regs, 0);
	auxmap__store_s64_param(auxmap, (s64)fd);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	u32 cmd = (u32)extract__syscall_argument(regs, 1);
	cmd = fsconfig_cmds_to_scap(cmd);
	auxmap__store_u32_param(auxmap, cmd);

	/* Parameter 4: key (type: PT_CHARBUF) */
	unsigned long key = (unsigned long)extract__syscall_argument(regs, 2);
	auxmap__store_charbuf_param(auxmap, key, USER);

	s32 aux = (s32)extract__syscall_argument(regs, 4);

	unsigned long value;
	/* see https://elixir.bootlin.com/linux/latest/source/fs/fsopen.c#L271 */
	switch (cmd)
	{
	case PPM_FSCONFIG_SET_FLAG:
		// Only key must be set
		/*
		 * Force-set NULL as both value_ptr and value_str,
		 * because we don't know what to expect from a read.
		 */
		auxmap__store_empty_param(auxmap);
		auxmap__store_empty_param(auxmap);
		break;
	case PPM_FSCONFIG_SET_STRING:
		// value is a NUL-terminated string; aux is 0
		value = (unsigned long)extract__syscall_argument(regs, 3);
		/*
		 * value -> string
		 * Push empty value_ptr
		 * Push value_str
		 */
		auxmap__store_empty_param(auxmap);
		auxmap__store_charbuf_param(auxmap, value, USER);
		break;
	case PPM_FSCONFIG_SET_BINARY:
		// value points to a blob; aux is its size
		value = (unsigned long)extract__syscall_argument(regs, 3);
		/*
		 * value -> bytebuf
		 * push value_ptr
		 * push empty value_str
		 */
		auxmap__store_bytebuf_param(auxmap, value, aux, USER);
		auxmap__store_empty_param(auxmap);
		break;
	case PPM_FSCONFIG_SET_PATH:
	case PPM_FSCONFIG_SET_PATH_EMPTY:
		// value is a NUL-terminated string; aux is a fd
		value = (unsigned long)extract__syscall_argument(regs, 3);
		/*
		 * Push empty value_ptr
		 * Push value_str
		 */
		auxmap__store_empty_param(auxmap);
		auxmap__store_charbuf_param(auxmap, value, USER);
		break;
	case PPM_FSCONFIG_SET_FD:
		// value must be NULL; aux is a fd
		/*
		 * Force-set NULL as both value_ptr and value_str,
		 * because we don't know what to expect from a read.
		 */
		auxmap__store_empty_param(auxmap);
		auxmap__store_empty_param(auxmap);
		break;
	case PPM_FSCONFIG_CMD_CREATE:
	case PPM_FSCONFIG_CMD_RECONFIGURE:
		// key, value and aux should be 0
		/*
		 * Force-set NULL as both value_ptr and value_str,
		 * because we don't know what to expect from a read.
		 */
		auxmap__store_empty_param(auxmap);
		auxmap__store_empty_param(auxmap);
		break;
	}

	auxmap__store_s32_param(auxmap, aux);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
