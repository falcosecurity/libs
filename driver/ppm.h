/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_H_
#define PPM_H_

/*
 * Our Own ASSERT implementation, so we can easily switch among BUG_ON, WARN_ON and nothing
 */
#ifndef UDIG

#include <linux/time.h>
#include "ppm_consumer.h"

#ifdef _DEBUG
#define ASSERT(expr) WARN_ON(!(expr))
#else
#define ASSERT(expr)
#endif /* _DEBUG */

#endif /* UDIG */

#include "capture_macro.h"
#define PPM_NULL_RDEV MKDEV(1, 3)

typedef u64 nanoseconds;

/* This is an auxiliary struct we use in setsockopt
 * when `__kernel_timex_timeval` struct is not defined.
 */
struct __aux_timeval {
	long long int tv_sec;
	long long int tv_usec;
};

/*
 * The ring descriptor.
 * We have one of these for each CPU.
 */
struct ppm_ring_buffer_context {
	bool cpu_online;
	bool open;
	struct ppm_ring_buffer_info *info;
	char *buffer;
	nanoseconds last_print_time;
	u32 nevents;
#ifndef UDIG
	atomic_t preempt_count;
#endif	
	char *str_storage;	/* String storage. Size is one page. */
};

#define STR_STORAGE_SIZE PAGE_SIZE

typedef unsigned long syscall_arg_t;

/*
 * Global functions
 *
 * These are analogous to get_user(), copy_from_user() and strncpy_from_user(),
 * but they can't sleep, barf on page fault or be preempted
 */
#define ppm_get_user(x, ptr) (ppm_copy_from_user(&x, ptr, sizeof(x)) ? -EFAULT : 0)
#ifndef UDIG
unsigned long ppm_copy_from_user(void *to, const void __user *from, unsigned long n);
long ppm_strncpy_from_user(char *to, const char __user *from, unsigned long n);
#endif // UDIG

/*
 * Global tables
 */

#ifdef CONFIG_MIPS
  #define SYSCALL_TABLE_ID0 __NR_Linux
#elif defined CONFIG_ARM
  #define SYSCALL_TABLE_ID0 __NR_SYSCALL_BASE
#elif defined CONFIG_X86 || defined CONFIG_SUPERH
  #define SYSCALL_TABLE_ID0 0
#elif defined CONFIG_PPC64
  #define SYSCALL_TABLE_ID0 0
#elif defined CONFIG_S390
  #define SYSCALL_TABLE_ID0 0
#elif defined CONFIG_ARM64
  #define SYSCALL_TABLE_ID0 0
#endif

extern const struct syscall_evt_pair g_syscall_table[];
extern const struct ppm_event_info g_event_info[];

#if defined(CONFIG_X86_64) && defined(CONFIG_IA32_EMULATION)
extern const struct syscall_evt_pair g_syscall_ia32_table[];
#endif

#ifndef UDIG
extern void ppm_syscall_get_arguments(struct task_struct *task, struct pt_regs *regs, unsigned long *args);
#endif

#define NS_TO_SEC(_ns) ((_ns) / 1000000000)
#define MORE_THAN_ONE_SECOND_AHEAD(_ns1, _ns2) ((_ns1) - (_ns2) > 1000000000)
#define SECOND_IN_NS 1000000000
#define USECOND_IN_NS 1000

// used in main.c, ppm_events.c and ppm_fillers.c so include it just once here
#ifdef __KERNEL__
#include <linux/version.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#include "ppm_syscall.h"
#endif
#endif

#endif /* PPM_H_ */
