#include <helpers/interfaces/fixed_size_event.h>

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