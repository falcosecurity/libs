/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#include "quirks.h"

#include <generated/utsrelease.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/sched.h>

#include "../driver_config.h"
#include "../ppm_events_public.h"
#include "bpf_helpers.h"
#include "types.h"
#include "maps.h"
#include "plumbing_helpers.h"
#include "ring_helpers.h"
#include "filler_helpers.h"
#include "fillers.h"
#include "builtins.h"
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
#define BPF_PROBE(prefix, event, type)			\
__bpf_section(TP_NAME #event)				\
int bpf_##event(struct type *ctx)
#else
#define BPF_PROBE(prefix, event, type)			\
__bpf_section(TP_NAME prefix #event)			\
int bpf_##event(struct type *ctx)
#endif

#define BPF_KPROBE(event)				\
__bpf_section(KP_NAME #event)				\
int bpf_kp_##event(struct pt_regs *ctx)

#define BPF_KRET_PROBE(event)				\
__bpf_section(KRET_NAME #event)				\
int bpf_kret_##event(struct pt_regs *ctx)

BPF_PROBE("raw_syscalls/", sys_enter, sys_enter_args)
{
	const struct syscall_evt_pair *sc_evt;
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	int drop_flags;
	long id;

	if (bpf_in_ia32_syscall())
		return 0;

	id = bpf_syscall_get_nr(ctx);
	if (id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;
#ifdef CPU_ANALYSIS
	enum offcpu_type type = get_syscall_type((int)id);
	u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&type_map, &tid, &type, BPF_ANY);
#endif
	sc_evt = get_syscall_info(id);
	if (!sc_evt)
		return 0;

	if (sc_evt->flags & UF_USED) {
		evt_type = sc_evt->enter_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_E;
		drop_flags = UF_ALWAYS_DROP;
	}

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	call_filler(ctx, ctx, evt_type, settings, drop_flags);
#else
	/* Duplicated here to avoid verifier madness */
	struct sys_enter_args stack_ctx;

	memcpy(stack_ctx.args, ctx->args, sizeof(ctx->args));
	if (stash_args(stack_ctx.args))
		return 0;

	call_filler(ctx, &stack_ctx, evt_type, settings, drop_flags);
#endif
	return 0;
}

BPF_PROBE("raw_syscalls/", sys_exit, sys_exit_args)
{
	const struct syscall_evt_pair *sc_evt;
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	int drop_flags;
	long id;

	if (bpf_in_ia32_syscall())
		return 0;

	id = bpf_syscall_get_nr(ctx);
	if (id < 0 || id >= SYSCALL_TABLE_SIZE)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;
#ifdef CPU_ANALYSIS
	u32 tid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&type_map, &tid);
#endif
	if (!settings->capture_enabled)
		return 0;

	sc_evt = get_syscall_info(id);
	if (!sc_evt)
		return 0;

	if (sc_evt->flags & UF_USED) {
		evt_type = sc_evt->exit_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_X;
		drop_flags = UF_ALWAYS_DROP;
	}

	call_filler(ctx, ctx, evt_type, settings, drop_flags);
	return 0;
}

BPF_PROBE("sched/", sched_process_exit, sched_process_exit_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	struct task_struct *task;
	unsigned int flags;

	task = (struct task_struct *)bpf_get_current_task();

	flags = _READ(task->flags);
	if (flags & PF_KTHREAD)
		return 0;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_PROCEXIT_1_E;
#ifdef CPU_ANALYSIS
	// perf out
	u32 tid = _READ(task->pid);
	if (prepare_filler(ctx, ctx, PPME_CPU_ANALYSIS_E, settings, 0)) {
		bpf_cpu_analysis(ctx, tid);
	}
	clear_map(tid);
#endif
	call_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP);
	return 0;
}

#ifndef CPU_ANALYSIS
BPF_PROBE("sched/", sched_switch, sched_switch_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_SCHEDSWITCH_6_E;

	call_filler(ctx, ctx, evt_type, settings, 0);
	return 0;
}
#endif

#ifdef CPU_ANALYSIS
#define FILTER (tid != 0)
#define MINBLOCK_US 1
#define MAXBLOCK_US ((1UL << 48) - 1)

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
BPF_PROBE("sched/", sched_switch, sched_switch_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type = PPME_CPU_ANALYSIS_E;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	if (evt_type < PPM_EVENT_MAX && !settings->events_mask[evt_type]) {
		return 0;
	}

	struct task_struct *p = (struct task_struct *) ctx->prev;
	struct task_struct *n = (struct task_struct *) ctx->next;
	u32 tid = _READ(p->pid);
	u32 pid = _READ(p->tgid);
	u64 ts, *tsp;
	if (FILTER) {
		if (_READ(p->state) == TASK_RUNNING) {
			u64 ts = bpf_ktime_get_ns();
			bpf_map_update_elem(&cpu_runq, &pid, &ts, BPF_ANY);
		}
		// record previous thread (current) sleep time
		ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&off_start_ts, &tid, &ts, BPF_ANY);

		// calculate oncpu time, sleep time - &on_start_ts
		// p is the focus thread, it switch off
		u64 *on_ts;
		on_ts = bpf_map_lookup_elem(&on_start_ts, &tid);
		if (on_ts != 0) {
			u64 delta = ts - *on_ts;
			u64 delta_us = delta / 1000; // convert to us
			bpf_map_delete_elem(&on_start_ts, &tid);
			if ((delta_us >= MINBLOCK_US) && (delta_us <= MAXBLOCK_US)) {
				if (check_filter(pid)) {
					record_cputime_and_out(ctx, settings, pid, tid, *on_ts, delta, 1);
					// aggregate(pid, tid, *on_ts, delta, 1);
				}
			}
		}
	}
	// get the next thread's start time
	tid = _READ(n->pid);
	pid = _READ(n->tgid);
	if (!(FILTER))
		return 0;

	// record oncpu start time
	u64 on_ts = bpf_ktime_get_ns();
	// record on start time
	bpf_map_update_elem(&on_start_ts, &tid, &on_ts, BPF_ANY);

	tsp = bpf_map_lookup_elem(&off_start_ts, &tid);
	if (tsp != 0) {
		u64 off_ts = *tsp;
		bpf_map_delete_elem(&off_start_ts, &tid);
		// calculate current thread's off delta time
		u64 delta = on_ts - off_ts;
		u64 delta_us = delta / 1000;
		if ((delta_us >= MINBLOCK_US) && (delta_us <= MAXBLOCK_US)) {
			if (check_filter(pid)) {
				u64 *rq_ts = bpf_map_lookup_elem(&cpu_runq, &tid);
				u64 rq_la = 0;
				if (rq_ts != 0) {
					if (on_ts > *rq_ts)
						rq_la = (on_ts - *rq_ts) / 1000;
					bpf_map_delete_elem(&cpu_runq, &tid);
				}
				record_cputime(ctx, settings, pid, tid, off_ts, rq_la, delta, 0);
				// aggregate(pid, tid, off_ts, delta, 0);
			}
		}
	}
	return 0;
}
#else
BPF_KPROBE(finish_task_switch)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	struct task_struct *p = (struct task_struct *) ctx->si;
	u32 tid = _READ(p->pid);
	u32 pid = _READ(p->tgid);
	u64 ts, *tsp;
	if (FILTER) {
		if (_READ(p->state) == TASK_RUNNING) {
			u64 ts = bpf_ktime_get_ns();
			bpf_map_update_elem(&cpu_runq, &pid, &ts, BPF_ANY);
		}
		// record previous thread (current) sleep time
		ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&off_start_ts, &tid, &ts, BPF_ANY);

		// calculate oncpu time, sleep time - &on_start_ts
		// p is the focus thread, it switch off
		u64 *on_ts;
		on_ts = bpf_map_lookup_elem(&on_start_ts, &tid);
		if (on_ts != 0) {
			u64 delta = ts - *on_ts;
			u64 delta_us = delta / 1000; // convert to us
			bpf_map_delete_elem(&on_start_ts, &tid);
			if ((delta_us >= MINBLOCK_US) && (delta_us <= MAXBLOCK_US)) {
				if (check_filter(pid)) {
					record_cputime_and_out(ctx, settings, pid, tid, *on_ts, delta, 1);
					// aggregate(pid, tid, *on_ts, delta, 1);
				}
			}
		}
	}
	// get the next thread's start time
	struct task_struct *n = (struct task_struct *)bpf_get_current_task();

	tid = _READ(n->pid);
	pid = _READ(n->tgid);
	if (!(FILTER))
		return 0;

	// record oncpu start time
	u64 on_ts = bpf_ktime_get_ns();
	// record on start time
	bpf_map_update_elem(&on_start_ts, &tid, &on_ts, BPF_ANY);

	tsp = bpf_map_lookup_elem(&off_start_ts, &tid);
	if (tsp != 0) {
		u64 off_ts = *tsp;
		bpf_map_delete_elem(&off_start_ts, &tid);
		// calculate current thread's off delta time
		u64 delta = on_ts - off_ts;
		u64 delta_us = delta / 1000;
		if ((delta_us >= MINBLOCK_US) && (delta_us <= MAXBLOCK_US)) {
			if (check_filter(pid)) {
				u64 *rq_ts = bpf_map_lookup_elem(&cpu_runq, &tid);
				u64 rq_la = 0;
				if (rq_ts != 0) {
					if (on_ts > *rq_ts)
						rq_la = (on_ts - *rq_ts) / 1000;
					bpf_map_delete_elem(&cpu_runq, &tid);
				}
				record_cputime(ctx, settings, pid, tid, off_ts, rq_la, delta, 0);
				// aggregate(pid, tid, off_ts, delta, 0);
			}
		}
	}
	return 0;
}
#endif
static __always_inline int bpf_trace_enqueue(struct sched_process_exit_args *ctx)
{
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	struct task_struct *p = (struct task_struct *) ctx->p;
	u32 pid = _READ(p->pid);
#else
	u32 pid = ctx->pid;
#endif

	if (pid == 0)
		return 0;
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&cpu_runq, &pid, &ts, BPF_ANY);
	return 0;
}
BPF_PROBE("sched/", sched_wakeup_new, sched_process_exit_args)
{
	return bpf_trace_enqueue(ctx);
}
BPF_PROBE("sched/", sched_wakeup, sched_process_exit_args)
{
	return bpf_trace_enqueue(ctx);
}
#endif

static __always_inline int bpf_page_fault(struct page_fault_args *ctx)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->page_faults)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_PAGE_FAULT_E;

	call_filler(ctx, ctx, evt_type, settings, UF_ALWAYS_DROP);
	return 0;
}

BPF_PROBE("exceptions/", page_fault_user, page_fault_args)
{
	return bpf_page_fault(ctx);
}

BPF_PROBE("exceptions/", page_fault_kernel, page_fault_args)
{
	return bpf_page_fault(ctx);
}

BPF_PROBE("signal/", signal_deliver, signal_deliver_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_SIGNALDELIVER_E;

	call_filler(ctx, ctx, evt_type, settings, UF_ALWAYS_DROP);
	return 0;
}

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
__bpf_section(TP_NAME "sched/sched_process_fork")
int bpf_sched_process_fork(struct sched_process_fork_args *ctx)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	struct sys_stash_args args;
	unsigned long *argsp;

	settings = get_bpf_settings();
	if (!settings)
		return 0;

	if (!settings->capture_enabled)
		return 0;

	argsp = __unstash_args(ctx->parent_pid);
	if (!argsp)
		return 0;

	memcpy(&args, argsp, sizeof(args));

	__stash_args(ctx->child_pid, args.args);

	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
BPF_PROBE("net/", net_dev_start_xmit, net_dev_start_xmit_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;
	if (!settings->capture_enabled)
		return 0;
	if (!settings->skb_capture)
		return 0;

	struct sk_buff *skb;
	char dev_name[16] = {0};

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	skb = ctx->skb;
	bpf_probe_read((void *)dev_name, 16, ctx->dev->name);
#else
	skb = (struct sk_buff*) ctx->skbaddr;
	TP_DATA_LOC_READ(dev_name, name, 16);
#endif

	if(check_skb(skb, dev_name, settings->if_name) < 0)
		return 0;

	evt_type = PPME_NET_DEV_XMIT_E;

	call_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP);
	return 0;
}
#endif
/*
BPF_PROBE("net/", netif_receive_skb, netif_receive_skb_args)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;
	if (!settings->capture_enabled)
		return 0;
	if (!settings->skb_capture)
		return 0;

	struct sk_buff *skb;
	char dev_name[16] = {0};

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	skb = ctx->skb;
	struct net_device *dev;
	dev = _READ(skb->dev);
	bpf_probe_read((void *)dev_name, 16, dev->name);
#else
	skb = (struct sk_buff*) ctx->skbaddr;
	TP_DATA_LOC_READ(dev_name, name, 16);
#endif

	if(check_skb(skb, dev_name, settings->if_name) < 0)
		return 0;

	evt_type = PPME_NETIF_RECEIVE_SKB_E;

	call_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP);
	return 0;
}
*/

BPF_KPROBE(tcp_drop)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;

	evt_type = PPME_TCP_DROP_E;
	if(prepare_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP)) {
		bpf_tcp_drop_kprobe_e(ctx);
	}

	return 0;
}

BPF_KPROBE(tcp_rcv_established)
{
	u16 sport = 0;
	u16 dport = 0;
	u32 saddr = 0;
	u32 daddr = 0;
	u16 family = 0;
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;
	struct sock *sk = (struct sock *)_READ(ctx->di);
	struct tcp_sock *ts = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);

	bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_dport);
	bpf_probe_read(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
	bpf_probe_read(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

	struct tuple tp = {0};
	tp.daddr = daddr;
	tp.dport = dport;
	tp.saddr = saddr;
	tp.sport = sport;
	tp.family = family;
	tp.pad = 1;
	if(ntohs(sport) == 22 || ntohs(dport) == 22 || ntohs(sport) == 0 || ntohs(dport) == 0) {
		return 0;
	}

	struct statistics *st = bpf_map_lookup_elem(&rtt_static_map, &tp);
	if (!st) {
		struct statistics new_st = {0};
		new_st.last_time = bpf_ktime_get_ns();
		int ret = bpf_map_update_elem(&rtt_static_map, &tp, &new_st, BPF_NOEXIST);
	} else {
		if (bpf_ktime_get_ns() - st->last_time > 5000000000) {
			st->last_time = bpf_ktime_get_ns();
			evt_type = PPME_TCP_RCV_ESTABLISHED_E;
			if(prepare_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP)) {
				bpf_rtt_kprobe_e(ctx);
			}
		}
	}
	return 0;
}


BPF_KPROBE(tcp_close)
{
	u16 sport = 0;
	u16 dport = 0;
	u32 saddr = 0;
	u32 daddr = 0;
	u16 family = 0;
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;

	struct sock *sk = (struct sock *)_READ(ctx->di);
	struct tcp_sock *ts = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);

	bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_dport);
	bpf_probe_read(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
	bpf_probe_read(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

	struct tuple tp = {0};
	tp.daddr = daddr;
	tp.dport = dport;
	tp.saddr = saddr;
	tp.sport = sport;
	tp.family = family;
	tp.pad = 1;

	int res = bpf_map_delete_elem(&rtt_static_map, &tp);

	if(ntohs(sport)==22||ntohs(dport)==22||ntohs(sport)==0||ntohs(dport)==0){
		return 0;
	}
	evt_type = PPME_TCP_CLOSE_E;
	if(prepare_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP)){
		bpf_rtt_kprobe_e(ctx);
	}

	return 0;
}


BPF_KPROBE(tcp_retransmit_skb)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;

	evt_type = PPME_TCP_RETRANCESMIT_SKB_E;
	if(prepare_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP)){
		bpf_tcp_retransmit_skb_kprobe_e(ctx);
	}

	return 0;
}
BPF_KPROBE(tcp_connect)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;

	struct sock *sk = (struct sock *)_READ(ctx->di);
	const struct inet_sock *inet = inet_sk(sk);

	u16 sport = 0;
	u16 dport = 0;
	u32 saddr = 0;
	u32 daddr = 0;
	u16 family = 0;

	bpf_probe_read(&sport, sizeof(sport), (void *)&inet->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), (void *)&inet->inet_dport);
	bpf_probe_read(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
	bpf_probe_read(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

	struct tuple tp = {0};
	tp.daddr = daddr;
	tp.dport = dport;
	tp.saddr = saddr;
	tp.sport = sport;
	tp.family = family;
	tp.pad = 1;

	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;
	int ret = bpf_map_update_elem(&stash_tuple_map, &id, &tp, BPF_ANY);

	return 0;
}

BPF_KRET_PROBE(tcp_connect)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;

	evt_type = PPME_TCP_CONNECT_X;
	if(prepare_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP)){
		bpf_tcp_connect_kprobe_x(ctx);
	}

	return 0;
}

BPF_KPROBE(tcp_set_state)
{
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;
	struct sock *sk = (struct sock *)_READ(ctx->di);
	u16 family = 0;
	bpf_probe_read(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);
	if(family != AF_INET)
		return 0;

	const struct inet_sock *inet = inet_sk(sk);
	u8 old_state = 0;
	bpf_probe_read(&old_state, sizeof(old_state), (void *)&sk->sk_state);
	int new_state = _READ(ctx->si);
	if(old_state == 1 || new_state == 1){
		evt_type = PPME_TCP_SET_STATE_E;
		if(prepare_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP)){
			bpf_tcp_set_state_kprobe_e(ctx);
		}
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
BPF_PROBE("tcp/", tcp_send_reset, tcp_reset_args){
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;
	if (!settings->capture_enabled)
		return 0;

	evt_type = PPME_TCP_SEND_RESET_E;

	call_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP);

	return 0;
}

BPF_PROBE("tcp/", tcp_receive_reset, tcp_reset_args){
	struct sock *sk;
	struct sysdig_bpf_settings *settings;
	enum ppm_event_type evt_type;
	settings = get_bpf_settings();
	if (!settings)
		return 0;
	if (!settings->capture_enabled)
		return 0;
	evt_type = PPME_TCP_RECEIVE_RESET_E;

	call_filler(ctx, ctx, evt_type, settings, UF_NEVER_DROP);

	return 0;
}
#endif

#ifdef CPU_ANALYSIS
BPF_KPROBE(sock_recvmsg) {
	u32 tid = bpf_get_current_pid_tgid();

	if (!(FILTER))
		return 0;
	// update to NET
	enum offcpu_type type = NET;
	bpf_map_update_elem(&type_map, &tid, &type, BPF_ANY);
	return 0;
}
BPF_KPROBE(sock_sendmsg) {
	u32 tid = bpf_get_current_pid_tgid();

	if (!(FILTER))
		return 0;
	// update to NET
	enum offcpu_type type = NET;
	bpf_map_update_elem(&type_map, &tid, &type, BPF_ANY);
	return 0;
}
#endif
char kernel_ver[] __bpf_section("kernel_version") = UTS_RELEASE;

char __license[] __bpf_section("license") = "GPL";

char probe_ver[] __bpf_section("probe_version") = PROBE_VERSION;
