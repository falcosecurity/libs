/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(security_file_mprotect_e,
	     struct pt_regs *regs,
	     long id)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_SECURITY_FILE_MPROTECT_E);

    /*=============================== COLLECT PARAMETERS  ===========================*/

    /* Copy struct vm_area_struct */
    unsigned long vma_pointer = extract__syscall_argument(regs, 1);
    struct vm_area_struct vma;
    bpf_probe_read_user((void *)&vma, sizeof(struct vm_area_struct), (void *)vma_pointer);


	/* Parameter 1: vm_start (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, vma.vm_start);

    /* Parameter 2: vm_end (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, vma.vm_end);

    unsigned long start_code = 0;
    unsigned long end_code = 0;
    unsigned long start_data = 0;
    unsigned long end_data = 0;
    unsigned long start_brk = 0;
    unsigned long end_brk = 0;
    unsigned long start_stack = 0;
    if (vma.vm_mm) {
        start_code = vma.vm_mm->start_code;
        end_code = vma.vm_mm->end_code;
        start_data = vma.vm_mm->start_data;
        end_data = vma.vm_mm->end_data;
        start_brk = vma.vm_mm->start_brk;
        end_brk = vma.vm_mm->brk;
        start_stack = vma.vm_mm->start_stack;
    }

    /* Parameter 3: start_code (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, start_code);

    /* Parameter 4: end_code (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, end_code)

    /* Parameter 5: start_data (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, start_data);

    /* Parameter 6: end_data (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, end_data);

    /* Parameter 7: start_brk (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, start_brk);

    /* Parameter 8: end_brk (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, end_brk);

    /* Parameter 9: start_stack (type: PT_UINT64) */
    auxmap__store_u64_param(auxmap, start_stack);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}
