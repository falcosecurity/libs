#include <helpers/interfaces/fixed_size_event.h>
#include <helpers/interfaces/variable_size_event.h>

/*=============================== ENTER EVENT ===========================*/

SEC("tp_btf/sys_enter")
int BPF_PROG(mkdir_e,
	     struct pt_regs *regs,
	     long id)
{
	struct ringbuf_struct ringbuf;
	if(!ringbuf__reserve_space(&ringbuf, MKDIR_E_SIZE))
	{
		return 0;
	}

	ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_MKDIR_2_E, MKDIR_E_SIZE);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	/* 1° Parameter: mode (type: PT_UINT32) */
	u32 mode = (u32)extract__syscall_argument(regs, 1);
	ringbuf__store_u32(&ringbuf, mode);

	/*=============================== COLLECT PARAMETERS  ===========================*/

	ringbuf__submit_event(&ringbuf);

	return 0;
}

/*=============================== ENTER EVENT ===========================*/

/*=============================== EXIT EVENT ===========================*/

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

/*=============================== EXIT EVENT ===========================*/
