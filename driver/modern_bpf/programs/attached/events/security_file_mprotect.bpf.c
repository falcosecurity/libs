// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

/*=============================== ENTER EVENT ===========================*/

#include <helpers/interfaces/variable_size_event.h>
#include <helpers/extract/extract_from_kernel.h>

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect,
	     struct vm_area_struct *vma,
	     unsigned long reqprot,
	     unsigned long prot,
	     int ret)
{
        struct auxiliary_map *auxmap = auxmap__get();
        if(!auxmap)
        {
                return 0;
        }

        auxmap__preload_event_header(auxmap, PPME_LSM_SECURITY_FILE_MPROTECT_E);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* Parameter 1: vm_start (PT_UINT64) */
	unsigned long vm_start = extract__vm_start(vma);
	auxmap__store_u64_param(auxmap, vm_start);

	/* Parameter 2: vm_end (PT_UINT64) */
	unsigned long vm_end = extract__vm_end(vma);
	auxmap__store_u64_param(auxmap, vm_end);

	/* Parameter 3: reqprot (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, reqprot);

	/* Parameter 4: prot (type: PT_FLAGS32)*/
	auxmap__store_u32_param(auxmap, prot);

	/*=============================== COLLECT PARAMETERS  ===========================*/
	//auxmap__submit_event(auxmap, ctx);

	return 0;
}

/*=============================== EXIT EVENT ===========================*/
