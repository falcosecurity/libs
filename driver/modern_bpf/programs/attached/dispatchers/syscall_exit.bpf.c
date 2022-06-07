#include <helpers/interfaces/syscalls_dispatcher.h>
#include <helpers/interfaces/attached_programs.h>

/* From linux tree: /include/trace/events/syscall.h
 * TP_PROTO(struct pt_regs *regs, long ret),
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(dispatch_syscall_exit_events,
	     struct pt_regs *regs,
	     long ret)
{
	u32 syscall_id = syscalls_dispatcher__get_syscall_id(regs);

	/* The `syscall-id` can refer to both 64-bit and 32-bit architectures.
	 * Right now we filter only 64-bit syscalls, all the 32-bit syscalls
	 * will be dropped with `syscalls_dispatcher__check_32bit_syscalls`.
	 *
	 * If the syscall is not interesting we drop it.
	 */
	if(!syscalls_dispatcher__64bit_interesting_syscall(syscall_id))
	{
		return 0;
	}

	if(!attached_programs__capture_enabled())
	{
		return 0;
	}

	if(syscalls_dispatcher__check_32bit_syscalls())
	{
		return 0;
	}

	bpf_tail_call(ctx, &syscall_exit_tail_table, syscall_id);

	return 0;
}