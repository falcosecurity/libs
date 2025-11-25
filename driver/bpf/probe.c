// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#include "quirks.h"

#include <generated/utsrelease.h>
#include <uapi/linux/bpf.h>
#if __has_include(<asm/rwonce.h>)
#include <asm/rwonce.h>
#endif

#include "driver_config.h"
#include "ppm_events_public.h"
#include "bpf_helpers.h"
#include "types.h"
#include "maps.h"
#include "plumbing_helpers.h"
#include "ring_helpers.h"
#include "filler_helpers.h"
#include "fillers.h"
#include "builtins.h"

#define __NR_ia32_socketcall 102

BPF_PROBE("raw_syscalls/", sys_enter, sys_enter_args) {
	long id = bpf_syscall_get_nr(ctx);
	if(id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

	if(bpf_in_ia32_syscall()) {
		// Right now we support 32-bit emulation only on x86.
		// We try to convert the 32-bit id into the 64-bit one.
#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
		id = convert_ia32_to_64(id);
		// Syscalls defined only on 32 bits are dropped here.
		if(id == -1) {
			return 0;
		}
#else
		// Unsupported arch
		return 0;
#endif
	}

	// This program is used only for system calls requiring enter events generation for TOCTOU
	// mitigation. For any other system call, just return.
	switch(id) {
#ifdef __NR_connect
	case __NR_connect:
		break;
#endif  // __NR_connect
#ifdef __NR_creat
	case __NR_creat:
		break;
#endif  // __NR_creat
#ifdef __NR_open
	case __NR_open:
		break;
#endif  // __NR_open
#ifdef __NR_openat
	case __NR_openat:
		break;
#endif  // __NR_openat
#ifdef __NR_openat2
	case __NR_openat2:
		break;
#endif  // __NR_openat2
	default:
		return 0;
	}

	if(!is_syscall_interesting(id)) {
		return 0;
	}

	const struct syscall_evt_pair *sc_evt = get_syscall_info(id);
	if(!sc_evt) {
		return 0;
	}

	if(unlikely((sc_evt->flags & UF_USED) == 0)) {
		bpf_printk(
		        "event associated to syscall ID %ld doesn't have an UF_USED flag. This is a bug, "
		        "as the sys_enter dispatcher is meant only for calling fillers for system calls "
		        "supporting TOCTOU mitigation through enter event generation",
		        id);
		return 0;
	}
	ppm_event_code evt_type = sc_evt->enter_event_type;
	int drop_flags = sc_evt->flags;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	call_filler(ctx, ctx, evt_type, drop_flags, -1);
#else
	/* Duplicated here to avoid verifier madness */
	struct sys_enter_args stack_ctx;

	memcpy(stack_ctx.args, ctx->args, sizeof(ctx->args));
	if(stash_args(stack_ctx.args))
		return 0;

	call_filler(ctx, &stack_ctx, evt_type, drop_flags, -1);
#endif
	return 0;
}

BPF_PROBE("raw_syscalls/", sys_exit, sys_exit_args) {
	const struct syscall_evt_pair *sc_evt = NULL;
	ppm_event_code evt_type = -1;
	int drop_flags = 0;
	long id = 0;
	bool enabled = false;
	struct scap_bpf_settings *settings = 0;
	long retval = 0;
	int socketcall_syscall_id = -1;

	id = bpf_syscall_get_nr(ctx);
	if(id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

	if(bpf_in_ia32_syscall()) {
#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
		if(id == __NR_ia32_socketcall) {
			socketcall_syscall_id = __NR_ia32_socketcall;
		} else {
			/*
			 * When a process does execve from 64bit to 32bit, TS_COMPAT is marked true
			 * but the id of the syscall is __NR_execve, so to correctly parse it we need to
			 * use 64bit syscall table. On 32bit __NR_execve is equal to __NR_ia32_oldolduname
			 * which is a very old syscall, not used anymore by most applications
			 */
#ifdef __NR_execveat
			if(id != __NR_execve && id != __NR_execveat)
#else
			if(id != __NR_execve)
#endif
			{
				id = convert_ia32_to_64(id);
				if(id == -1) {
					return 0;
				}
			}
		}
#else
		// Unsupported arch
		return 0;
#endif
	} else {
#ifdef __NR_socketcall
		socketcall_syscall_id = __NR_socketcall;
#endif
	}

	if(id == socketcall_syscall_id) {
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
		bool is_syscall_return = false;
		int return_code = convert_network_syscalls(ctx, &is_syscall_return);
		if(return_code == -1) {
			// Wrong SYS_ argument passed. Drop the syscall.
			return 0;
		}
		if(!is_syscall_return) {
			evt_type = return_code;
			drop_flags = UF_USED;
		} else {
			id = return_code;
		}
#else
		// We do not support socketcall when raw tracepoints are not supported.
		return 0;
#endif
	}

	if(evt_type == -1) {
		enabled = is_syscall_interesting(id);
		if(!enabled) {
			return 0;
		}
		sc_evt = get_syscall_info(id);
		if(!sc_evt)
			return 0;

		if(sc_evt->flags & UF_USED) {
			evt_type = sc_evt->exit_event_type;
			drop_flags = sc_evt->flags;
		} else {
			evt_type = PPME_GENERIC_X;
			drop_flags = UF_ALWAYS_DROP;
		}
	}

	settings = get_bpf_settings();
	if(!settings)
		return 0;

	// Drop failed syscalls if necessary
	if(settings->drop_failed) {
		retval = bpf_syscall_get_retval(ctx);
		if(retval < 0) {
			return 0;
		}
	}

	if(bpf_drop_syscall_exit_events(ctx, evt_type))
		return 0;

	call_filler(ctx, ctx, evt_type, drop_flags, socketcall_syscall_id);
	return 0;
}

BPF_PROBE("sched/", sched_process_exit, sched_process_exit_args) {
	ppm_event_code evt_type;
	struct task_struct *task;
	unsigned int flags;

	task = (struct task_struct *)bpf_get_current_task();

	flags = _READ(task->flags);
	if(flags & PF_KTHREAD)
		return 0;

	evt_type = PPME_PROCEXIT_1_E;

	call_filler(ctx, ctx, evt_type, UF_NEVER_DROP, -1);
	return 0;
}

BPF_PROBE("sched/", sched_switch, sched_switch_args) {
	ppm_event_code evt_type;

	evt_type = PPME_SCHEDSWITCH_6_E;

	call_filler(ctx, ctx, evt_type, UF_ALWAYS_DROP, -1);
	return 0;
}

#ifdef CAPTURE_PAGE_FAULTS
static __always_inline int bpf_page_fault(struct page_fault_args *ctx) {
	ppm_event_code evt_type;

	evt_type = PPME_PAGE_FAULT_E;

	call_filler(ctx, ctx, evt_type, UF_ALWAYS_DROP, -1);
	return 0;
}

BPF_PROBE("exceptions/", page_fault_user, page_fault_args) {
	return bpf_page_fault(ctx);
}

BPF_PROBE("exceptions/", page_fault_kernel, page_fault_args) {
	return bpf_page_fault(ctx);
}
#endif

BPF_PROBE("signal/", signal_deliver, signal_deliver_args) {
	ppm_event_code evt_type;

	evt_type = PPME_SIGNALDELIVER_E;

	call_filler(ctx, ctx, evt_type, UF_ALWAYS_DROP, -1);
	return 0;
}

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
__bpf_section(TP_NAME "sched/sched_process_fork&1") int bpf_sched_process_fork(
        struct sched_process_fork_args *ctx) {
	ppm_event_code evt_type;
	struct sys_stash_args args;
	unsigned long *argsp;

	argsp = __unstash_args(ctx->parent_pid);
	if(!argsp)
		return 0;

	memcpy(&args, argsp, sizeof(args));

	__stash_args(ctx->child_pid, args.args);

	return 0;
}
#endif

/*
 * This tracepoint generates `execve` exit events for both successful `execve` and `execveat` system
 * calls. Event related to system calls failures, for both system calls, are generated by
 * `proc_startupdate` filler. This architectural choice is motivated by the fact that the kernel
 * haven't consistently called the correct tracepoint for `execve` and `execveat` calls on all
 * architectures:
 * - on `x86_64`, a successful `execveat` call is identified as `execve`, and a failing one is
 * identified as `execveat`
 * - on `aarch64`, till version 5.18 (actually, the fix was back-ported up to 5.15:
 *   https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-5.15.y&id=42eede3ae05bbf32cb0d87940b466ec5a76aca3f),
 *   neither successful `execve`s nor successful `execveat`s used to trigger the `sys_exit` (see
 *   https://www.spinics.net/lists/linux-trace/msg01001.html) tracepoint; only failing ones have
 *   always triggered the correct behaviour
 * - on `s390x`, each call correctly triggers `sys_exit` tracepoint and is correctly identified as
 *   `execve` and `execveat`
 * Indeed, the `sched/sched_process_exec` is correctly triggered on all architectures for successful
 * calls. Moreover, failing calls correctly trigger the `sys_exit` tracepoint, and are correctly
 * associated to the right syscall number. In the past, this design was applied just for `aarch64`,
 * but since it works consistently on all architectures, its application was extended. The only
 * issue seems to be that now we generates `execve` exit events for both `execve` and `execveat` if
 * the call is successful: this is not a big problem, because even with the previous implementation
 * we weren't able to generate any `execveat` exit event on both `x86_64` and `aarch64` for this
 * scenario.
 */
BPF_PROBE("sched/", sched_process_exec, sched_process_exec_args) {
	struct scap_bpf_settings *settings;
	/* We will always send an execve exit event. */
	ppm_event_code event_type = PPME_SYSCALL_EXECVE_19_X;

	/* We are not interested in kernel threads. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int flags = _READ(task->flags);
	if(flags & PF_KTHREAD) {
		return 0;
	}

	/* Reset the tail context in the CPU state map. */
	uint32_t cpu = bpf_get_smp_processor_id();
	struct scap_bpf_per_cpu_state *state = get_local_state(cpu);
	if(!state) {
		return 0;
	}

	settings = get_bpf_settings();
	if(!settings) {
		return 0;
	}
	uint64_t ts = settings->boot_time + bpf_ktime_get_boot_ns();
	reset_tail_ctx(state, event_type, ts);
	++state->n_evts;

	int filler_code = PPM_FILLER_sched_prog_exec;
	bpf_tail_call(ctx, &tail_map, filler_code);
	bpf_printk("Can't tail call filler 'sched_proc_exec' evt=%d, filler=%d\n",
	           event_type,
	           filler_code);
	return 0;
}

#ifdef CAPTURE_SCHED_PROC_FORK
__bpf_section("raw_tracepoint/sched_process_fork&2") int bpf_sched_process_fork(
        struct sched_process_fork_raw_args *ctx) {
	struct scap_bpf_settings *settings;
	/* We will always send a clone exit event. */
	ppm_event_code event_type = PPME_SYSCALL_CLONE_20_X;

	/* We are not interested in kernel threads. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int flags = _READ(task->flags);
	if(flags & PF_KTHREAD) {
		return 0;
	}

	/* Reset the tail context in the CPU state map. */
	uint32_t cpu = bpf_get_smp_processor_id();
	struct scap_bpf_per_cpu_state *state = get_local_state(cpu);
	if(!state) {
		return 0;
	}

	settings = get_bpf_settings();
	if(!settings) {
		return 0;
	}
	uint64_t ts = settings->boot_time + bpf_ktime_get_boot_ns();
	reset_tail_ctx(state, event_type, ts);
	++state->n_evts;

	int filler_code = PPM_FILLER_sched_prog_fork;
	bpf_tail_call(ctx, &tail_map, filler_code);
	bpf_printk("Can't tail call filler 'sched_proc_fork' evt=%d, filler=%d\n",
	           event_type,
	           filler_code);
	return 0;
}
#endif /* CAPTURE_SCHED_PROC_FORK */

char kernel_ver[] __bpf_section("kernel_version") = UTS_RELEASE;

char __license[] __bpf_section("license") = "Dual MIT/GPL";

char probe_ver[] __bpf_section("probe_version") = DRIVER_VERSION;

char probe_commit[] __bpf_section("build_commit") = DRIVER_COMMIT;

uint64_t probe_api_ver __bpf_section("api_version") = PPM_API_CURRENT_VERSION;

uint64_t probe_schema_ver __bpf_section("schema_version") = PPM_SCHEMA_CURRENT_VERSION;
