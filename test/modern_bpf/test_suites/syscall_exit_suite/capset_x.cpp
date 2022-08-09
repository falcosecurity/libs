#include "../../event_class/event_class.h"

#ifdef __NR_capset

#include <sys/capability.h>

#ifndef CAP_PERFMON
	#define CAP_PERFMON 38
#endif

#ifndef CAP_BPF
	#define CAP_BPF 39
#endif

#ifndef CAP_CHECKPOINT_RESTORE
	#define CAP_CHECKPOINT_RESTORE 40
#endif

/* This helper is a copy of the one you can find in `driver/ppm_flag_helpers.h`.
 * Right now we cannot directly include it, let's see if we need other helpers
 * from this file, in that case, we can think of splitting it.
 */
uint64_t capabilities_to_scap(unsigned long caps)
{
	uint64_t res = 0;

#ifdef CAP_CHOWN
	if(caps & (1UL << CAP_CHOWN))
		res |= PPM_CAP_CHOWN;
#endif
#ifdef CAP_DAC_OVERRIDE
	if(caps & (1UL << CAP_DAC_OVERRIDE))
		res |= PPM_CAP_DAC_OVERRIDE;
#endif
#ifdef CAP_DAC_READ_SEARCH
	if(caps & (1UL << CAP_DAC_READ_SEARCH))
		res |= PPM_CAP_DAC_READ_SEARCH;
#endif
#ifdef CAP_FOWNER
	if(caps & (1UL << CAP_FOWNER))
		res |= PPM_CAP_FOWNER;
#endif
#ifdef CAP_FSETID
	if(caps & (1UL << CAP_FSETID))
		res |= PPM_CAP_FSETID;
#endif
#ifdef CAP_KILL
	if(caps & (1UL << CAP_KILL))
		res |= PPM_CAP_KILL;
#endif
#ifdef CAP_SETGID
	if(caps & (1UL << CAP_SETGID))
		res |= PPM_CAP_SETGID;
#endif
#ifdef CAP_SETUID
	if(caps & (1UL << CAP_SETUID))
		res |= PPM_CAP_SETUID;
#endif
#ifdef CAP_SETPCAP
	if(caps & (1UL << CAP_SETPCAP))
		res |= PPM_CAP_SETPCAP;
#endif
#ifdef CAP_LINUX_IMMUTABLE
	if(caps & (1UL << CAP_LINUX_IMMUTABLE))
		res |= PPM_CAP_LINUX_IMMUTABLE;
#endif
#ifdef CAP_NET_BIND_SERVICE
	if(caps & (1UL << CAP_NET_BIND_SERVICE))
		res |= PPM_CAP_NET_BIND_SERVICE;
#endif
#ifdef CAP_NET_BROADCAST
	if(caps & (1UL << CAP_NET_BROADCAST))
		res |= PPM_CAP_NET_BROADCAST;
#endif
#ifdef CAP_NET_ADMIN
	if(caps & (1UL << CAP_NET_ADMIN))
		res |= PPM_CAP_NET_ADMIN;
#endif
#ifdef CAP_NET_RAW
	if(caps & (1UL << CAP_NET_RAW))
		res |= PPM_CAP_NET_RAW;
#endif
#ifdef CAP_IPC_LOCK
	if(caps & (1UL << CAP_IPC_LOCK))
		res |= PPM_CAP_IPC_LOCK;
#endif
#ifdef CAP_IPC_OWNER
	if(caps & (1UL << CAP_IPC_OWNER))
		res |= PPM_CAP_IPC_OWNER;
#endif
#ifdef CAP_SYS_MODULE
	if(caps & (1UL << CAP_SYS_MODULE))
		res |= PPM_CAP_SYS_MODULE;
#endif
#ifdef CAP_SYS_RAWIO
	if(caps & (1UL << CAP_SYS_RAWIO))
		res |= PPM_CAP_SYS_RAWIO;
#endif
#ifdef CAP_SYS_CHROOT
	if(caps & (1UL << CAP_SYS_CHROOT))
		res |= PPM_CAP_SYS_CHROOT;
#endif
#ifdef CAP_SYS_PTRACE
	if(caps & (1UL << CAP_SYS_PTRACE))
		res |= PPM_CAP_SYS_PTRACE;
#endif
#ifdef CAP_SYS_PACCT
	if(caps & (1UL << CAP_SYS_PACCT))
		res |= PPM_CAP_SYS_PACCT;
#endif
#ifdef CAP_SYS_ADMIN
	if(caps & (1UL << CAP_SYS_ADMIN))
		res |= PPM_CAP_SYS_ADMIN;
#endif
#ifdef CAP_SYS_BOOT
	if(caps & (1UL << CAP_SYS_BOOT))
		res |= PPM_CAP_SYS_BOOT;
#endif
#ifdef CAP_SYS_NICE
	if(caps & (1UL << CAP_SYS_NICE))
		res |= PPM_CAP_SYS_NICE;
#endif
#ifdef CAP_SYS_RESOURCE
	if(caps & (1UL << CAP_SYS_RESOURCE))
		res |= PPM_CAP_SYS_RESOURCE;
#endif
#ifdef CAP_SYS_TIME
	if(caps & (1UL << CAP_SYS_TIME))
		res |= PPM_CAP_SYS_TIME;
#endif
#ifdef CAP_SYS_TTY_CONFIG
	if(caps & (1UL << CAP_SYS_TTY_CONFIG))
		res |= PPM_CAP_SYS_TTY_CONFIG;
#endif
#ifdef CAP_MKNOD
	if(caps & (1UL << CAP_MKNOD))
		res |= PPM_CAP_MKNOD;
#endif
#ifdef CAP_LEASE
	if(caps & (1UL << CAP_LEASE))
		res |= PPM_CAP_LEASE;
#endif
#ifdef CAP_AUDIT_WRITE
	if(caps & (1UL << CAP_AUDIT_WRITE))
		res |= PPM_CAP_AUDIT_WRITE;
#endif
#ifdef CAP_AUDIT_CONTROL
	if(caps & (1UL << CAP_AUDIT_CONTROL))
		res |= PPM_CAP_AUDIT_CONTROL;
#endif
#ifdef CAP_SETFCAP
	if(caps & (1UL << CAP_SETFCAP))
		res |= PPM_CAP_SETFCAP;
#endif
#ifdef CAP_MAC_OVERRIDE
	if(caps & (1UL << CAP_MAC_OVERRIDE))
		res |= PPM_CAP_MAC_OVERRIDE;
#endif
#ifdef CAP_MAC_ADMIN
	if(caps & (1UL << CAP_MAC_ADMIN))
		res |= PPM_CAP_MAC_ADMIN;
#endif
#ifdef CAP_SYSLOG
	if(caps & (1UL << CAP_SYSLOG))
		res |= PPM_CAP_SYSLOG;
#endif
#ifdef CAP_WAKE_ALARM
	if(caps & (1UL << CAP_WAKE_ALARM))
		res |= PPM_CAP_WAKE_ALARM;
#endif
#ifdef CAP_BLOCK_SUSPEND
	if(caps & (1UL << CAP_BLOCK_SUSPEND))
		res |= PPM_CAP_BLOCK_SUSPEND;
#endif
#ifdef CAP_AUDIT_READ
	if(caps & (1UL << CAP_AUDIT_READ))
		res |= PPM_CAP_AUDIT_READ;
#endif
#ifdef CAP_PERFMON
	if(caps & (1UL << CAP_PERFMON))
		res |= PPM_CAP_PERFMON;
#endif
#ifdef CAP_BPF
	if(caps & (1UL << CAP_BPF))
		res |= PPM_CAP_BPF;
#endif
#ifdef CAP_CHECKPOINT_RESTORE
	if(caps & (1UL << CAP_CHECKPOINT_RESTORE))
		res |= PPM_CAP_CHECKPOINT_RESTORE;
#endif

	return res;
}

TEST(SyscallExit, capsetX)
{
	auto evt_test = new event_test(__NR_capset, EXIT_EVENT);

	evt_test->enable_capture();

	/*=============================== TRIGGER SYSCALL ===========================*/

	/* In this test we don't want to modify the capabilities of the actual process
	 * so as a first step we will get the actual capabilities of the process and
	 * after it we will call `capset` with empty params just to trigger the BPF
	 * program. In case of failure, the capset exit event returns the actual
	 * capabilities of the process, in this way we can assert them against the ones
	 * we have retrieved from the previous `capget` call.
	 */

	/* On kernels >= 5.8 the suggested version should be `_LINUX_CAPABILITY_VERSION_3` */
	struct __user_cap_header_struct header = {0};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	cap_user_header_t hdrp = &header;
	cap_user_data_t datap = data;

	/* Prepare the header. */
	header.pid = 0; /* `0` means the pid of the actual process. */
	header.version = _LINUX_CAPABILITY_VERSION_3;

	assert_syscall_state(SYSCALL_SUCCESS, "capget", syscall(__NR_capget, hdrp, datap), EQUAL, 0);

	assert_syscall_state(SYSCALL_FAILURE, "capset", syscall(__NR_capset, NULL, NULL));
	int64_t errno_value = -errno;

	/*=============================== TRIGGER SYSCALL ===========================*/

	evt_test->disable_capture();

	evt_test->assert_event_presence();

	if(HasFatalFailure())
	{
		return;
	}

	evt_test->parse_event();

	evt_test->assert_header();

	/*=============================== ASSERT PARAMETERS  ===========================*/

	/* Parameter 1: res (type: PT_ERRNO) */
	evt_test->assert_numeric_param(1, (int64_t)errno_value);

	/* Parameter 2: cap_inheritable (type: PT_UINT64) */
	evt_test->assert_numeric_param(2, (uint64_t)capabilities_to_scap(((unsigned long)data[1].inheritable << 32) | data[0].inheritable));

	/* Parameter 3: cap_permitted (type: PT_UINT64) */
	evt_test->assert_numeric_param(3, (uint64_t)capabilities_to_scap(((unsigned long)data[1].permitted << 32) | data[0].permitted));

	/* Parameter 4: cap_effective (type: PT_UINT64) */
	evt_test->assert_numeric_param(4, (uint64_t)capabilities_to_scap(((unsigned long)data[1].effective << 32) | data[0].effective));

	/*=============================== ASSERT PARAMETERS  ===========================*/

	evt_test->assert_num_params_pushed(4);
}
#endif
