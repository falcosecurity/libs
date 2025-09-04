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
int BPF_PROG(quotactl_x, struct pt_regs *regs, long ret) {
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap) {
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_QUOTACTL_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* Parameter 2: special (type: PT_CHARBUF) */
	/* The special argument is a pointer to a null-terminated string
	 * containing the pathname of the (mounted) block special device for
	 * the filesystem being manipulated.
	 */
	unsigned long special_pointer = extract__syscall_argument(regs, 1);
	auxmap__store_charbuf_param(auxmap, special_pointer, MAX_PATH, USER);

	uint32_t cmd = (uint32_t)extract__syscall_argument(regs, 0);
	uint16_t scap_cmd = quotactl_cmd_to_scap(cmd);

	/* The `addr` argument is the address of an optional, command-
	 * specific data structure that is copied in or out of the system.
	 * The interpretation of `addr` is given with each cmd.
	 */
	unsigned long addr_pointer = extract__syscall_argument(regs, 3);

	/* We get `quotafilepath` only for `QUOTAON` command. */
	if(scap_cmd == PPM_Q_QUOTAON) {
		/* Parameter 3: quotafilepath (type: PT_CHARBUF) */
		auxmap__store_charbuf_param(auxmap, addr_pointer, MAX_PATH, USER);
	} else {
		/* Parameter 3: quotafilepath (type: PT_CHARBUF) */
		auxmap__store_empty_param(auxmap);
	}

	/* We extract the `struct if_dqblk` if possible. */
	uint64_t dqb_bhardlimit = 0;
	uint64_t dqb_bsoftlimit = 0;
	uint64_t dqb_curspace = 0;
	uint64_t dqb_ihardlimit = 0;
	uint64_t dqb_isoftlimit = 0;
	uint64_t dqb_btime = 0;
	uint64_t dqb_itime = 0;

	if(bpf_core_type_exists(struct if_dqblk) &&
	   (scap_cmd == PPM_Q_GETQUOTA || scap_cmd == PPM_Q_SETQUOTA)) {
		struct if_dqblk dqblk = {0};
		bpf_probe_read_user((void *)&dqblk,
		                    bpf_core_type_size(struct if_dqblk),
		                    (void *)addr_pointer);

		/* Please note that `dqblk` struct could be filled with values different from `0`,
		 * even if these values are not valid, so we need to explicitly send `0`.
		 */
		if(dqblk.dqb_valid & QIF_BLIMITS) {
			dqb_bhardlimit = dqblk.dqb_bhardlimit;
			dqb_bsoftlimit = dqblk.dqb_bsoftlimit;
		}

		if(dqblk.dqb_valid & QIF_SPACE) {
			dqb_curspace = dqblk.dqb_curspace;
		}

		if(dqblk.dqb_valid & QIF_ILIMITS) {
			dqb_ihardlimit = dqblk.dqb_ihardlimit;
			dqb_isoftlimit = dqblk.dqb_isoftlimit;
		}

		if(dqblk.dqb_valid & QIF_BTIME) {
			dqb_btime = dqblk.dqb_btime;
		}

		if(dqblk.dqb_valid & QIF_ITIME) {
			dqb_itime = dqblk.dqb_itime;
		}
	}

	/* Parameter 4: dqb_bhardlimit (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, dqb_bhardlimit);

	/* Parameter 5: dqb_bsoftlimit (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, dqb_bsoftlimit);

	/* Parameter 6: dqb_curspace (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, dqb_curspace);

	/* Parameter 7: dqb_ihardlimit (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, dqb_ihardlimit);

	/* Parameter 8: dqb_isoftlimit (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, dqb_isoftlimit);

	/* Parameter 9: dqb_btime (type: PT_RELTIME) */
	auxmap__store_u64_param(auxmap, dqb_btime);

	/* Parameter 10: dqb_itime (type: PT_RELTIME) */
	auxmap__store_u64_param(auxmap, dqb_itime);

	uint64_t dqi_bgrace = 0;
	uint64_t dqi_igrace = 0;
	uint64_t dqi_flags = 0;

	if(bpf_core_type_exists(struct if_dqinfo) &&
	   (scap_cmd == PPM_Q_GETINFO || scap_cmd == PPM_Q_SETINFO)) {
		struct if_dqinfo dqinfo = {0};
		bpf_probe_read_user((void *)&dqinfo,
		                    bpf_core_type_size(struct if_dqinfo),
		                    (void *)addr_pointer);

		if(dqinfo.dqi_valid & IIF_BGRACE) {
			dqi_bgrace = dqinfo.dqi_bgrace;
		}

		if(dqinfo.dqi_valid & IIF_IGRACE) {
			/* Parameter 12: dqi_igrace (type: PT_RELTIME) */
			dqi_igrace = dqinfo.dqi_igrace;
		}

		if(dqinfo.dqi_valid & IIF_FLAGS) {
			/* Parameter 13: dqi_flags (type: PT_FLAGS8) */
			dqi_flags = dqinfo.dqi_flags;
		}
	}

	/* Parameter 11: dqi_bgrace (type: PT_RELTIME) */
	auxmap__store_u64_param(auxmap, dqi_bgrace);

	/* Parameter 12: dqi_igrace (type: PT_RELTIME) */
	auxmap__store_u64_param(auxmap, dqi_igrace);

	/* Parameter 13: dqi_flags (type: PT_FLAGS8) */
	auxmap__store_u8_param(auxmap, dqi_flags);

	/* Parameter 14: quota_fmt_out (type: PT_FLAGS8) */
	uint32_t quota_fmt_out = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_GETFMT) {
		uint32_t quota_fmt_out_tmp = 0;
		bpf_probe_read_user(&quota_fmt_out_tmp, sizeof(quota_fmt_out_tmp), (void *)addr_pointer);
		quota_fmt_out = quotactl_fmt_to_scap(quota_fmt_out_tmp);
	}
	auxmap__store_u8_param(auxmap, quota_fmt_out);

	/* Parameter 15: cmd (type: PT_FLAGS16) */
	auxmap__store_u16_param(auxmap, scap_cmd);

	/* Parameter 16: type (type: PT_FLAGS8) */
	auxmap__store_u8_param(auxmap, quotactl_type_to_scap(cmd));

	/* Parameter 17: id (type: PT_UINT32) */
	uint32_t id = (uint32_t)extract__syscall_argument(regs, 2);
	if(scap_cmd != PPM_Q_GETQUOTA && scap_cmd != PPM_Q_SETQUOTA && scap_cmd != PPM_Q_XGETQUOTA &&
	   scap_cmd != PPM_Q_XSETQLIM) {
		/* In this case `id` don't represent a `userid` or a `groupid` */
		auxmap__store_u32_param(auxmap, 0);
	} else {
		auxmap__store_u32_param(auxmap, id);
	}

	/* Parameter 18: quota_fmt (type: PT_FLAGS8) */
	uint8_t quota_fmt = PPM_QFMT_NOT_USED;
	if(scap_cmd == PPM_Q_QUOTAON) {
		quota_fmt = quotactl_fmt_to_scap(id);
	}
	auxmap__store_u8_param(auxmap, quota_fmt);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
