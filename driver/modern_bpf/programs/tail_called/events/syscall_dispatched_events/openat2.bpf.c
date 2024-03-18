// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(openat2_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT2_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: dirfd (type: PT_FD) */
	int32_t dirfd = (int32_t)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD)
	{
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)dirfd);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* the `open_how` struct is defined since kernel version 5.6 */
	unsigned long open_how_pointer = extract__syscall_argument(regs, 2);
	struct open_how how = {0};
	bpf_probe_read_user((void *)&how, bpf_core_type_size(struct open_how), (void *)open_how_pointer);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, open_flags_to_scap(how.flags));

	/* Parameter 4: mode (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, open_modes_to_scap(how.flags, how.mode));

	/* Parameter 5: resolve (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, openat2_resolve_to_scap(how.resolve));

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

SEC("tp_btf/sys_exit")
int BPF_PROG(openat2_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_OPENAT2_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: fd (type: PT_FD) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: dirfd (type: PT_FD) */
	int32_t dirfd = (int32_t)extract__syscall_argument(regs, 0);
	if(dirfd == AT_FDCWD)
	{
		dirfd = PPM_AT_FDCWD;
	}
	auxmap__store_s64_param(auxmap, (int64_t)dirfd);

	/* Parameter 3: name (type: PT_FSRELPATH) */
	unsigned long path_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

	/* the `open_how` struct is defined since kernel version 5.6 */
	unsigned long open_how_pointer = extract__syscall_argument(regs, 2);
	struct open_how how = {0};
	bpf_probe_read_user((void *)&how, bpf_core_type_size(struct open_how), (void *)open_how_pointer);

	/* Parameter 4: flags (type: PT_FLAGS32) */
	uint32_t flags = open_flags_to_scap(how.flags);
	/* update flags if file is created */
	flags |= extract__fmode_created_from_fd(ret);

	auxmap__store_u32_param(auxmap, flags);

	/* Parameter 5: mode (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, open_modes_to_scap(how.flags, how.mode));

	/* Parameter 6: resolve (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, openat2_resolve_to_scap(how.resolve));

	dev_t dev = 0;
	uint64_t ino = 0;

	if(ret > 0)
	{
		extract__dev_and_ino_from_fd(ret, &dev, &ino);
	}

	/* Parameter 7: dev (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, dev);

	/* Parameter 8: ino (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
