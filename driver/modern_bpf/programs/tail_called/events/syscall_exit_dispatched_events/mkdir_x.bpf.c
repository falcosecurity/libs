#include "../../../../helpers/interfaces/variable_size_event.h"

SEC("tp_btf/sys_exit")
int BPF_PROG(mkdir_x,
	     struct pt_regs *regs,
	     long ret)
{
	struct auxiliary_map *auxmap = auxmap__get();
	if(!auxmap)
	{
		return 0;
	}

	auxmap__preload_event_header(auxmap, PPME_SYSCALL_MKDIR_2_X);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* 1° Parameter: res (type: PT_ERRNO) */
	auxmap__store_s64_param(auxmap, ret);

	/* 2° Parameter: path (type: PT_FSPATH) */
	unsigned long path_pointer = extract__syscall_argument(regs, 0);
	auxmap__store_charbuf_param(auxmap, path_pointer);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	auxmap__finalize_event_header(auxmap);

	auxmap__submit_event(auxmap);

	return 0;
}