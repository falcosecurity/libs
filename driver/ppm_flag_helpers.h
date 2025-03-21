// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef PPM_FLAG_HELPERS_H_
#define PPM_FLAG_HELPERS_H_

/* The ASSERT is defined in other files that we don't
 * want to inlcude with the modern probe. `ppm.h`
 */
#ifdef __USE_VMLINUX__
#define ASSERT(expr)
#endif

#ifdef __KERNEL__
#include <linux/mman.h>
#include <linux/futex.h>
#include <linux/ptrace.h>
#include <linux/capability.h>
#include <linux/eventpoll.h>
#include <linux/prctl.h>
#include <linux/splice.h>
#ifdef __NR_finit_module
#include <uapi/linux/module.h>
#endif
#include "ppm.h"
#ifdef __NR_memfd_create
#include <uapi/linux/memfd.h>
#endif
#ifdef __NR_io_uring_register
#include <uapi/linux/io_uring.h>
#endif
#ifdef __NR_umount2
#include <linux/fs.h>
#endif
#endif  // ifndef __KERNEL__

#ifndef __always_inline
#define __always_inline inline
#endif

// When this file is included in userspace
#if !defined(__KERNEL__) && !defined(__USE_VMLINUX__)
#include <linux/futex.h>
#include <linux/dqblk_xfs.h>
#endif

#define PPM_MS_MGC_MSK 0xffff0000
#define PPM_MS_MGC_VAL 0xC0ED0000

/* Check if the res is different from `PPM_SUCCESS` */
#define CHECK_RES(x)                 \
	if(unlikely(x != PPM_SUCCESS)) { \
		return x;                    \
	}

static __always_inline uint32_t open_flags_to_scap(uint32_t flags) {
	uint32_t res = 0;

	switch(flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
	case O_WRONLY:
		res |= PPM_O_WRONLY;
		break;
	case O_RDWR:
		res |= PPM_O_RDWR;
		break;
	default:
		res |= PPM_O_RDONLY;
		break;
	}

	if(flags & O_CREAT)
		res |= PPM_O_CREAT;
#ifdef O_TMPFILE
	if(flags & O_TMPFILE)
		res |= PPM_O_TMPFILE;
#endif

	if(flags & O_APPEND)
		res |= PPM_O_APPEND;

#ifdef O_DSYNC
	if(flags & O_DSYNC)
		res |= PPM_O_DSYNC;
#endif

	if(flags & O_EXCL)
		res |= PPM_O_EXCL;

#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;
#endif

#ifdef O_SYNC
	if(flags & O_SYNC)
		res |= PPM_O_SYNC;
#endif

	if(flags & O_TRUNC)
		res |= PPM_O_TRUNC;

#ifdef O_DIRECT
	if(flags & O_DIRECT)
		res |= PPM_O_DIRECT;
#endif

#ifdef O_DIRECTORY
	if(flags & O_DIRECTORY)
		res |= PPM_O_DIRECTORY;
#endif

#ifdef O_LARGEFILE
	if(flags & O_LARGEFILE)
		res |= PPM_O_LARGEFILE;
#endif

#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif

	return res;
}

static __always_inline uint32_t open_modes_to_scap(unsigned long flags, unsigned long modes) {
// This file is used also in userspace so we cannot use `KERNEL_VERSION` macro without an ifdef
#ifdef __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	unsigned long flags_mask = O_CREAT | O_TMPFILE;
#else
	unsigned long flags_mask = O_CREAT;
#endif
#else
	unsigned long flags_mask = O_CREAT | O_TMPFILE;
#endif

	uint32_t res = 0;

	if((flags & flags_mask) == 0)
		return res;

	if(modes & S_IRUSR)
		res |= PPM_S_IRUSR;

	if(modes & S_IWUSR)
		res |= PPM_S_IWUSR;

	if(modes & S_IXUSR)
		res |= PPM_S_IXUSR;

	/*
	 * PPM_S_IRWXU == S_IRUSR | S_IWUSR | S_IXUSR
	 */

	if(modes & S_IRGRP)
		res |= PPM_S_IRGRP;

	if(modes & S_IWGRP)
		res |= PPM_S_IWGRP;

	if(modes & S_IXGRP)
		res |= PPM_S_IXGRP;

	/*
	 * PPM_S_IRWXG == S_IRGRP | S_IWGRP | S_IXGRP
	 */

	if(modes & S_IROTH)
		res |= PPM_S_IROTH;

	if(modes & S_IWOTH)
		res |= PPM_S_IWOTH;

	if(modes & S_IXOTH)
		res |= PPM_S_IXOTH;

	/*
	 * PPM_S_IRWXO == S_IROTH | S_IWOTH | S_IXOTH
	 */

	if(modes & S_ISUID)
		res |= PPM_S_ISUID;

	if(modes & S_ISGID)
		res |= PPM_S_ISGID;

	if(modes & S_ISVTX)
		res |= PPM_S_ISVTX;

	return res;
}

static __always_inline uint32_t openat2_resolve_to_scap(unsigned long flags) {
	uint32_t res = 0;
#ifdef RESOLVE_NO_XDEV
	if(flags & RESOLVE_NO_XDEV)
		res |= PPM_RESOLVE_NO_XDEV;
#endif

#ifdef RESOLVE_NO_MAGICLINKS
	if(flags & RESOLVE_NO_MAGICLINKS)
		res |= PPM_RESOLVE_NO_MAGICLINKS;
#endif

#ifdef RESOLVE_NO_SYMLINKS
	if(flags & RESOLVE_NO_SYMLINKS)
		res |= PPM_RESOLVE_NO_SYMLINKS;
#endif

#ifdef RESOLVE_BENEATH
	if(flags & RESOLVE_BENEATH)
		res |= PPM_RESOLVE_BENEATH;
#endif

#ifdef RESOLVE_IN_ROOT
	if(flags & RESOLVE_IN_ROOT)
		res |= PPM_RESOLVE_IN_ROOT;
#endif

#ifdef RESOLVE_CACHED
	if(flags & RESOLVE_CACHED)
		res |= PPM_RESOLVE_CACHED;
#endif
	return res;
}

static __always_inline uint32_t io_uring_setup_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;

#ifdef IORING_SETUP_IOPOLL
	if(flags & IORING_SETUP_IOPOLL)
		res |= PPM_IORING_SETUP_IOPOLL;
#endif

#ifdef IORING_SETUP_SQPOLL
	if(flags & IORING_SETUP_SQPOLL)
		res |= PPM_IORING_SETUP_SQPOLL;
#endif

#ifdef IORING_SQ_NEED_WAKEUP
	if(flags & IORING_SQ_NEED_WAKEUP)
		res |= PPM_IORING_SQ_NEED_WAKEUP;
#endif

#ifdef IORING_SETUP_SQ_AFF
	if(flags & IORING_SETUP_SQ_AFF)
		res |= PPM_IORING_SETUP_SQ_AFF;
#endif

#ifdef IORING_SETUP_CQSIZE
	if(flags & IORING_SETUP_CQSIZE)
		res |= PPM_IORING_SETUP_CQSIZE;
#endif

#ifdef IORING_SETUP_CLAMP
	if(flags & IORING_SETUP_CLAMP)
		res |= PPM_IORING_SETUP_CLAMP;
#endif

#ifdef IORING_SETUP_ATTACH_WQ
	if(flags & IORING_SETUP_ATTACH_WQ)
		res |= PPM_IORING_SETUP_ATTACH_WQ;
#endif

#ifdef IORING_SETUP_R_DISABLED
	if(flags & IORING_SETUP_R_DISABLED)
		res |= PPM_IORING_SETUP_R_DISABLED;
#endif
	return res;
}

static __always_inline uint32_t io_uring_setup_feats_to_scap(unsigned long flags) {
	uint32_t res = 0;

#ifdef IORING_FEAT_SINGLE_MMAP
	if(flags & IORING_FEAT_SINGLE_MMAP)
		res |= PPM_IORING_FEAT_SINGLE_MMAP;
#endif

#ifdef IORING_FEAT_NODROP
	if(flags & IORING_FEAT_NODROP)
		res |= PPM_IORING_FEAT_NODROP;
#endif

#ifdef IORING_FEAT_SUBMIT_STABLE
	if(flags & IORING_FEAT_SUBMIT_STABLE)
		res |= PPM_IORING_FEAT_SUBMIT_STABLE;
#endif

#ifdef IORING_FEAT_RW_CUR_POS
	if(flags & IORING_FEAT_RW_CUR_POS)
		res |= PPM_IORING_FEAT_RW_CUR_POS;
#endif

#ifdef IORING_FEAT_CUR_PERSONALITY
	if(flags & IORING_FEAT_CUR_PERSONALITY)
		res |= PPM_IORING_FEAT_CUR_PERSONALITY;
#endif

#ifdef IORING_FEAT_FAST_POLL
	if(flags & IORING_FEAT_FAST_POLL)
		res |= PPM_IORING_FEAT_FAST_POLL;
#endif

#ifdef IORING_FEAT_POLL_32BITS
	if(flags & IORING_FEAT_POLL_32BITS)
		res |= PPM_IORING_FEAT_POLL_32BITS;
#endif

#ifdef IORING_FEAT_SQPOLL_NONFIXED
	if(flags & IORING_FEAT_SQPOLL_NONFIXED)
		res |= PPM_IORING_FEAT_SQPOLL_NONFIXED;
#endif

#ifdef IORING_FEAT_ENTER_EXT_ARG
	if(flags & IORING_FEAT_ENTER_EXT_ARG)
		res |= PPM_IORING_FEAT_ENTER_EXT_ARG;
#endif

#ifdef IORING_FEAT_NATIVE_WORKERS
	if(flags & IORING_FEAT_NATIVE_WORKERS)
		res |= PPM_IORING_FEAT_NATIVE_WORKERS;
#endif

#ifdef IORING_FEAT_RSRC_TAGS
	if(flags & IORING_FEAT_RSRC_TAGS)
		res |= PPM_IORING_FEAT_RSRC_TAGS;
#endif
	return res;
}

static __always_inline uint32_t io_uring_enter_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;

#ifdef IORING_ENTER_GETEVENTS
	if(flags & IORING_ENTER_GETEVENTS)
		res |= PPM_IORING_ENTER_GETEVENTS;
#endif

#ifdef IORING_ENTER_SQ_WAKEUP
	if(flags & IORING_ENTER_SQ_WAKEUP)
		res |= PPM_IORING_ENTER_SQ_WAKEUP;
#endif

#ifdef IORING_ENTER_SQ_WAIT
	if(flags & IORING_ENTER_SQ_WAIT)
		res |= PPM_IORING_ENTER_SQ_WAIT;
#endif

#ifdef IORING_ENTER_EXT_ARG
	if(flags & IORING_ENTER_EXT_ARG)
		res |= PPM_IORING_ENTER_EXT_ARG;
#endif
	return res;
}

static __always_inline uint32_t io_uring_register_opcodes_to_scap(unsigned long flags) {
	/*
	 * io_uring_register opcodes are defined via enum in io_uring.h.
	 * It is userspace API (thus stable) and arch independent.
	 * Therefore we map them 1:1; if any unmapped flag arrives,
	 * we will just print its value to userspace without mapping it to a string flag.
	 * We then need to append new flags to both flags_table and ppm_events_public PPM_ flags.
	 */
	return flags;
}

/* Here we don't define new flags for `inotify` since under the hood it uses the open flags.
 *
 * `/include/uapi/linux/inotify.h` from kernel source tree.
 *
 *  #define IN_CLOEXEC O_CLOEXEC
 *  #define IN_NONBLOCK O_NONBLOCK
 */
static __always_inline uint16_t inotify_init1_flags_to_scap(int32_t flags) {
	uint16_t res = 0;

	/* We need to explicitly handle the negative case otherwise `-1` will match all `flags & ...` */
	if(flags < 0) {
		return res;
	}

#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;
#endif

#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif

	return res;
}

/* Here we don't define new flags for `eventfd2` since under the hood it uses the open flags.
 *
 * `/include/linux/eventd.h` from kernel source tree.
 *
 *  #define EFD_SEMAPHORE (1 << 0)  <---  we don't catch this flag right now.
 *  #define EFD_CLOEXEC O_CLOEXEC
 *  #define EFD_NONBLOCK O_NONBLOCK
 */
static __always_inline uint16_t eventfd2_flags_to_scap(int32_t flags) {
	uint16_t res = 0;

	/* We need to explicitly handle the negative case otherwise `-1` will match all `flags & ...` */
	if(flags < 0) {
		return res;
	}

#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;
#endif

#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif

	return res;
}

/* Here we don't define new flags for `signalfd4` since under the hood it uses the open flags.
 *
 * `/include/uapi/linux/signalfd.h` from kernel source tree.
 *
 *  #define SFD_CLOEXEC O_CLOEXEC
 *  #define SFD_NONBLOCK O_NONBLOCK
 */
static __always_inline uint16_t signalfd4_flags_to_scap(int32_t flags) {
	uint16_t res = 0;

	/* We need to explicitly handle the negative case otherwise `-1` will match all `flags & ...` */
	if(flags < 0) {
		return res;
	}

#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;
#endif

#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif

	return res;
}

static __always_inline uint32_t clone_flags_to_scap(int flags) {
	uint32_t res = 0;

	if(flags & CLONE_FILES)
		res |= PPM_CL_CLONE_FILES;

	if(flags & CLONE_FS)
		res |= PPM_CL_CLONE_FS;

#ifdef CLONE_IO
	if(flags & CLONE_IO)
		res |= PPM_CL_CLONE_IO;
#endif

#ifdef CLONE_NEWIPC
	if(flags & CLONE_NEWIPC)
		res |= PPM_CL_CLONE_NEWIPC;
#endif

#ifdef CLONE_NEWNET
	if(flags & CLONE_NEWNET)
		res |= PPM_CL_CLONE_NEWNET;
#endif

#ifdef CLONE_NEWNS
	if(flags & CLONE_NEWNS)
		res |= PPM_CL_CLONE_NEWNS;
#endif

#ifdef CLONE_NEWPID
	if(flags & CLONE_NEWPID)
		res |= PPM_CL_CLONE_NEWPID;
#endif

#ifdef CLONE_NEWUTS
	if(flags & CLONE_NEWUTS)
		res |= PPM_CL_CLONE_NEWUTS;
#endif

	if(flags & CLONE_PARENT_SETTID)
		res |= PPM_CL_CLONE_PARENT_SETTID;

	if(flags & CLONE_PARENT)
		res |= PPM_CL_CLONE_PARENT;

	if(flags & CLONE_PTRACE)
		res |= PPM_CL_CLONE_PTRACE;

	if(flags & CLONE_SIGHAND)
		res |= PPM_CL_CLONE_SIGHAND;

	if(flags & CLONE_SYSVSEM)
		res |= PPM_CL_CLONE_SYSVSEM;

	if(flags & CLONE_THREAD)
		res |= PPM_CL_CLONE_THREAD;

	if(flags & CLONE_UNTRACED)
		res |= PPM_CL_CLONE_UNTRACED;

	if(flags & CLONE_VM)
		res |= PPM_CL_CLONE_VM;

#ifdef CLONE_NEWUSER
	if(flags & CLONE_NEWUSER)
		res |= PPM_CL_CLONE_NEWUSER;
#endif

	if(flags & CLONE_CHILD_CLEARTID)
		res |= PPM_CL_CLONE_CHILD_CLEARTID;

	if(flags & CLONE_CHILD_SETTID)
		res |= PPM_CL_CLONE_CHILD_SETTID;

	if(flags & CLONE_SETTLS)
		res |= PPM_CL_CLONE_SETTLS;

#ifdef CLONE_STOPPED
	if(flags & CLONE_STOPPED)
		res |= PPM_CL_CLONE_STOPPED;
#endif

	if(flags & CLONE_VFORK)
		res |= PPM_CL_CLONE_VFORK;

#ifdef CLONE_NEWCGROUP
	if(flags & CLONE_NEWCGROUP)
		res |= PPM_CL_CLONE_NEWCGROUP;
#endif

	return res;
}

static __always_inline uint8_t socket_family_to_scap(uint8_t family) {
	if(family == AF_INET)
		return PPM_AF_INET;
	else if(family == AF_INET6)
		return PPM_AF_INET6;
	else if(family == AF_UNIX)
		return PPM_AF_UNIX;
#ifdef AF_NETLINK
	else if(family == AF_NETLINK)
		return PPM_AF_NETLINK;
#endif
#ifdef AF_PACKET
	else if(family == AF_PACKET)
		return PPM_AF_PACKET;
#endif
#ifdef AF_UNSPEC
	else if(family == AF_UNSPEC)
		return PPM_AF_UNSPEC;
#endif
#ifdef AF_AX25
	else if(family == AF_AX25)
		return PPM_AF_AX25;
#endif
#ifdef AF_IPX
	else if(family == AF_IPX)
		return PPM_AF_IPX;
#endif
#ifdef AF_APPLETALK
	else if(family == AF_APPLETALK)
		return PPM_AF_APPLETALK;
#endif
#ifdef AF_NETROM
	else if(family == AF_NETROM)
		return PPM_AF_NETROM;
#endif
#ifdef AF_BRIDGE
	else if(family == AF_BRIDGE)
		return PPM_AF_BRIDGE;
#endif
#ifdef AF_ATMPVC
	else if(family == AF_ATMPVC)
		return PPM_AF_ATMPVC;
#endif
#ifdef AF_X25
	else if(family == AF_X25)
		return PPM_AF_X25;
#endif
#ifdef AF_ROSE
	else if(family == AF_ROSE)
		return PPM_AF_ROSE;
#endif
#ifdef AF_DECnet
	else if(family == AF_DECnet)
		return PPM_AF_DECnet;
#endif
#ifdef AF_NETBEUI
	else if(family == AF_NETBEUI)
		return PPM_AF_NETBEUI;
#endif
#ifdef AF_SECURITY
	else if(family == AF_SECURITY)
		return PPM_AF_SECURITY;
#endif
#ifdef AF_KEY
	else if(family == AF_KEY)
		return PPM_AF_KEY;
#endif
#ifdef AF_ROUTE
	else if(family == AF_ROUTE)
		return PPM_AF_ROUTE;
#endif
#ifdef AF_ASH
	else if(family == AF_ASH)
		return PPM_AF_ASH;
#endif
#ifdef AF_ECONET
	else if(family == AF_ECONET)
		return PPM_AF_ECONET;
#endif
#ifdef AF_ATMSVC
	else if(family == AF_ATMSVC)
		return PPM_AF_ATMSVC;
#endif
#ifdef AF_RDS
	else if(family == AF_RDS)
		return PPM_AF_RDS;
#endif
#ifdef AF_SNA
	else if(family == AF_SNA)
		return PPM_AF_SNA;
#endif
#ifdef AF_IRDA
	else if(family == AF_IRDA)
		return PPM_AF_IRDA;
#endif
#ifdef AF_PPPOX
	else if(family == AF_PPPOX)
		return PPM_AF_PPPOX;
#endif
#ifdef AF_WANPIPE
	else if(family == AF_WANPIPE)
		return PPM_AF_WANPIPE;
#endif
#ifdef AF_LLC
	else if(family == AF_LLC)
		return PPM_AF_LLC;
#endif
#ifdef AF_CAN
	else if(family == AF_CAN)
		return PPM_AF_CAN;
#endif
#ifdef AF_TIPC
	else if(family == AF_TIPC)
		return PPM_AF_TIPC;
#endif
#ifdef AF_BLUETOOTH
	else if(family == AF_BLUETOOTH)
		return PPM_AF_BLUETOOTH;
#endif
#ifdef AF_IUCV
	else if(family == AF_IUCV)
		return PPM_AF_IUCV;
#endif
#ifdef AF_RXRPC
	else if(family == AF_RXRPC)
		return PPM_AF_RXRPC;
#endif
#ifdef AF_ISDN
	else if(family == AF_ISDN)
		return PPM_AF_ISDN;
#endif
#ifdef AF_PHONET
	else if(family == AF_PHONET)
		return PPM_AF_PHONET;
#endif
#ifdef AF_IEEE802154
	else if(family == AF_IEEE802154)
		return PPM_AF_IEEE802154;
#endif
#ifdef AF_CAIF
	else if(family == AF_CAIF)
		return PPM_AF_CAIF;
#endif
#ifdef AF_ALG
	else if(family == AF_ALG)
		return PPM_AF_ALG;
#endif
#ifdef AF_NFC
	else if(family == AF_NFC)
		return PPM_AF_NFC;
#endif
	else {
		ASSERT(false);
		return PPM_AF_UNSPEC;
	}
}

static __always_inline uint32_t prot_flags_to_scap(int prot) {
	uint32_t res = 0;

	if(prot & PROT_READ)
		res |= PPM_PROT_READ;

	if(prot & PROT_WRITE)
		res |= PPM_PROT_WRITE;

	if(prot & PROT_EXEC)
		res |= PPM_PROT_EXEC;

#ifdef PROT_SEM
	if(prot & PROT_SEM)
		res |= PPM_PROT_SEM;
#endif

	if(prot & PROT_GROWSDOWN)
		res |= PPM_PROT_GROWSDOWN;

	if(prot & PROT_GROWSUP)
		res |= PPM_PROT_GROWSUP;

#ifdef PROT_SAO
	if(prot & PROT_SAO)
		res |= PPM_PROT_SAO;
#endif

	return res;
}

static __always_inline uint32_t mmap_flags_to_scap(int flags) {
	uint32_t res = 0;

	if(flags & MAP_SHARED)
		res |= PPM_MAP_SHARED;

	if(flags & MAP_PRIVATE)
		res |= PPM_MAP_PRIVATE;

	if(flags & MAP_FIXED)
		res |= PPM_MAP_FIXED;

	if(flags & MAP_ANONYMOUS)
		res |= PPM_MAP_ANONYMOUS;

#ifdef MAP_32BIT
	if(flags & MAP_32BIT)
		res |= PPM_MAP_32BIT;
#endif

#ifdef MAP_RENAME
	if(flags & MAP_RENAME)
		res |= PPM_MAP_RENAME;
#endif

	if(flags & MAP_NORESERVE)
		res |= PPM_MAP_NORESERVE;

	if(flags & MAP_POPULATE)
		res |= PPM_MAP_POPULATE;

	if(flags & MAP_NONBLOCK)
		res |= PPM_MAP_NONBLOCK;

	if(flags & MAP_GROWSDOWN)
		res |= PPM_MAP_GROWSDOWN;

	if(flags & MAP_DENYWRITE)
		res |= PPM_MAP_DENYWRITE;

	if(flags & MAP_EXECUTABLE)
		res |= PPM_MAP_EXECUTABLE;

#ifdef MAP_INHERIT
	if(flags & MAP_INHERIT)
		res |= PPM_MAP_INHERIT;
#endif

	if(flags & MAP_FILE)
		res |= PPM_MAP_FILE;

	if(flags & MAP_LOCKED)
		res |= PPM_MAP_LOCKED;

	return res;
}

static __always_inline uint8_t fcntl_cmd_to_scap(unsigned long cmd) {
	switch(cmd) {
	case F_DUPFD:
		return PPM_FCNTL_F_DUPFD;
	case F_GETFD:
		return PPM_FCNTL_F_GETFD;
	case F_SETFD:
		return PPM_FCNTL_F_SETFD;
	case F_GETFL:
		return PPM_FCNTL_F_GETFL;
	case F_SETFL:
		return PPM_FCNTL_F_SETFL;
	case F_GETLK:
		return PPM_FCNTL_F_GETLK;
	case F_SETLK:
		return PPM_FCNTL_F_SETLK;
	case F_SETLKW:
		return PPM_FCNTL_F_SETLKW;
	case F_SETOWN:
		return PPM_FCNTL_F_SETOWN;
	case F_GETOWN:
		return PPM_FCNTL_F_GETOWN;
	case F_SETSIG:
		return PPM_FCNTL_F_SETSIG;
	case F_GETSIG:
		return PPM_FCNTL_F_GETSIG;
// In userspace we don't want to include these flags to avoid duplicate values.
#if !defined(CONFIG_64BIT) && (defined(__KERNEL__) || defined(__USE_VMLINUX__))
	case F_GETLK64:
		return PPM_FCNTL_F_GETLK64;
	case F_SETLK64:
		return PPM_FCNTL_F_SETLK64;
	case F_SETLKW64:
		return PPM_FCNTL_F_SETLKW64;
#endif
#ifdef F_SETOWN_EX
	case F_SETOWN_EX:
		return PPM_FCNTL_F_SETOWN_EX;
#endif
#ifdef F_GETOWN_EX
	case F_GETOWN_EX:
		return PPM_FCNTL_F_GETOWN_EX;
#endif
	case F_SETLEASE:
		return PPM_FCNTL_F_SETLEASE;
	case F_GETLEASE:
		return PPM_FCNTL_F_GETLEASE;
	case F_CANCELLK:
		return PPM_FCNTL_F_CANCELLK;
#ifdef F_DUPFD_CLOEXEC
	case F_DUPFD_CLOEXEC:
		return PPM_FCNTL_F_DUPFD_CLOEXEC;
#endif
	case F_NOTIFY:
		return PPM_FCNTL_F_NOTIFY;
#ifdef F_SETPIPE_SZ
	case F_SETPIPE_SZ:
		return PPM_FCNTL_F_SETPIPE_SZ;
#endif
#ifdef F_GETPIPE_SZ
	case F_GETPIPE_SZ:
		return PPM_FCNTL_F_GETPIPE_SZ;
#endif
#ifdef F_OFD_GETLK
	case F_OFD_GETLK:
		return PPM_FCNTL_F_OFD_GETLK;
#endif
#ifdef F_OFD_SETLK
	case F_OFD_SETLK:
		return PPM_FCNTL_F_OFD_SETLK;
#endif
#ifdef F_OFD_SETLKW
	case F_OFD_SETLKW:
		return PPM_FCNTL_F_OFD_SETLKW;
#endif
	default:
		return PPM_FCNTL_UNKNOWN;
	}
}

static __always_inline uint8_t sockopt_level_to_scap(int level) {
	switch(level) {
	case SOL_SOCKET:
		return PPM_SOCKOPT_LEVEL_SOL_SOCKET;
#ifdef SOL_TCP
	case SOL_TCP:
		return PPM_SOCKOPT_LEVEL_SOL_TCP;
#endif
	default:
		/* no ASSERT as there are legitimate other levels we don't just support yet */
		return PPM_SOCKOPT_LEVEL_UNKNOWN;
	}
}

static __always_inline uint8_t sockopt_optname_to_scap(int level, int optname) {
	if(level != SOL_SOCKET) {
		/* no ASSERT as there are legitimate other levels we don't just support yet */
		return PPM_SOCKOPT_LEVEL_UNKNOWN;
	}
	switch(optname) {
#ifdef SO_DEBUG
	case SO_DEBUG:
		return PPM_SOCKOPT_SO_DEBUG;
#endif
#ifdef SO_REUSEADDR
	case SO_REUSEADDR:
		return PPM_SOCKOPT_SO_REUSEADDR;
#endif
#ifdef SO_TYPE
	case SO_TYPE:
		return PPM_SOCKOPT_SO_TYPE;
#endif
#ifdef SO_ERROR
	case SO_ERROR:
		return PPM_SOCKOPT_SO_ERROR;
#endif
#ifdef SO_DONTROUTE
	case SO_DONTROUTE:
		return PPM_SOCKOPT_SO_DONTROUTE;
#endif
#ifdef SO_BROADCAST
	case SO_BROADCAST:
		return PPM_SOCKOPT_SO_BROADCAST;
#endif
#ifdef SO_SNDBUF
	case SO_SNDBUF:
		return PPM_SOCKOPT_SO_SNDBUF;
#endif
#ifdef SO_RCVBUF
	case SO_RCVBUF:
		return PPM_SOCKOPT_SO_RCVBUF;
#endif
#ifdef SO_SNDBUFFORCE
	case SO_SNDBUFFORCE:
		return PPM_SOCKOPT_SO_SNDBUFFORCE;
#endif
#ifdef SO_RCVBUFFORCE
	case SO_RCVBUFFORCE:
		return PPM_SOCKOPT_SO_RCVBUFFORCE;
#endif
#ifdef SO_KEEPALIVE
	case SO_KEEPALIVE:
		return PPM_SOCKOPT_SO_KEEPALIVE;
#endif
#ifdef SO_OOBINLINE
	case SO_OOBINLINE:
		return PPM_SOCKOPT_SO_OOBINLINE;
#endif
#ifdef SO_NO_CHECK
	case SO_NO_CHECK:
		return PPM_SOCKOPT_SO_NO_CHECK;
#endif
#ifdef SO_PRIORITY
	case SO_PRIORITY:
		return PPM_SOCKOPT_SO_PRIORITY;
#endif
#ifdef SO_LINGER
	case SO_LINGER:
		return PPM_SOCKOPT_SO_LINGER;
#endif
#ifdef SO_BSDCOMPAT
	case SO_BSDCOMPAT:
		return PPM_SOCKOPT_SO_BSDCOMPAT;
#endif
#ifdef SO_REUSEPORT
	case SO_REUSEPORT:
		return PPM_SOCKOPT_SO_REUSEPORT;
#endif
#ifdef SO_PASSCRED
	case SO_PASSCRED:
		return PPM_SOCKOPT_SO_PASSCRED;
#endif
#ifdef SO_PEERCRED
	case SO_PEERCRED:
		return PPM_SOCKOPT_SO_PEERCRED;
#endif
#ifdef SO_RCVLOWAT
	case SO_RCVLOWAT:
		return PPM_SOCKOPT_SO_RCVLOWAT;
#endif
#ifdef SO_SNDLOWAT
	case SO_SNDLOWAT:
		return PPM_SOCKOPT_SO_SNDLOWAT;
#endif
/* We use this workaround to avoid 2 switch cases with the same value.
 * An `elif` approach is not enough if `SO_RCVTIMEO` is not defined.
 * In this case we have only `SO_RCVTIMEO_OLD` and `SO_RCVTIMEO_NEW` so
 * we couldn't be able to detect the right flag value, for example:
 * `SO_RCVTIMEO_OLD` is defined so we compile only this branch, but
 * actual value of `SO_RCVTIMEO` is `SO_RCVTIMEO_NEW`.
 * https://github.com/torvalds/linux/commit/a9beb86ae6e55bd92f38453c8623de60b8e5a308
 */
#ifdef SO_RCVTIMEO
	case SO_RCVTIMEO:
		return PPM_SOCKOPT_SO_RCVTIMEO;
#endif
#if(defined(SO_RCVTIMEO_OLD) && !defined(SO_RCVTIMEO)) || \
        (defined(SO_RCVTIMEO_OLD) && (SO_RCVTIMEO_OLD != SO_RCVTIMEO))
	case SO_RCVTIMEO_OLD:
		return PPM_SOCKOPT_SO_RCVTIMEO;
#endif
#if(defined(SO_RCVTIMEO_NEW) && !defined(SO_RCVTIMEO)) || \
        (defined(SO_RCVTIMEO_NEW) && (SO_RCVTIMEO_NEW != SO_RCVTIMEO))
	case SO_RCVTIMEO_NEW:
		return PPM_SOCKOPT_SO_RCVTIMEO;
#endif
/* Look at `SO_RCVTIMEO` */
#ifdef SO_SNDTIMEO
	case SO_SNDTIMEO:
		return PPM_SOCKOPT_SO_SNDTIMEO;
#endif
#if(defined(SO_SNDTIMEO_OLD) && !defined(SO_SNDTIMEO)) || \
        (defined(SO_SNDTIMEO_OLD) && (SO_SNDTIMEO_OLD != SO_SNDTIMEO))
	case SO_SNDTIMEO_OLD:
		return PPM_SOCKOPT_SO_SNDTIMEO;
#endif
#if(defined(SO_SNDTIMEO_NEW) && !defined(SO_SNDTIMEO)) || \
        (defined(SO_SNDTIMEO_NEW) && (SO_SNDTIMEO_NEW != SO_SNDTIMEO))
	case SO_SNDTIMEO_NEW:
		return PPM_SOCKOPT_SO_SNDTIMEO;
#endif
#ifdef SO_SECURITY_AUTHENTICATION
	case SO_SECURITY_AUTHENTICATION:
		return PPM_SOCKOPT_SO_SECURITY_AUTHENTICATION;
#endif
#ifdef SO_SECURITY_ENCRYPTION_TRANSPORT
	case SO_SECURITY_ENCRYPTION_TRANSPORT:
		return PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_TRANSPORT;
#endif
#ifdef SO_SECURITY_ENCRYPTION_NETWORK
	case SO_SECURITY_ENCRYPTION_NETWORK:
		return PPM_SOCKOPT_SO_SECURITY_ENCRYPTION_NETWORK;
#endif
#ifdef SO_BINDTODEVICE
	case SO_BINDTODEVICE:
		return PPM_SOCKOPT_SO_BINDTODEVICE;
#endif
#ifdef SO_ATTACH_FILTER
	case SO_ATTACH_FILTER:
		return PPM_SOCKOPT_SO_ATTACH_FILTER;
#endif
#ifdef SO_DETACH_FILTER
	case SO_DETACH_FILTER:
		return PPM_SOCKOPT_SO_DETACH_FILTER;
#endif
#ifdef SO_PEERNAME
	case SO_PEERNAME:
		return PPM_SOCKOPT_SO_PEERNAME;
#endif
#ifdef SO_TIMESTAMP
	case SO_TIMESTAMP:
		return PPM_SOCKOPT_SO_TIMESTAMP;
#endif
#ifdef SO_ACCEPTCONN
	case SO_ACCEPTCONN:
		return PPM_SOCKOPT_SO_ACCEPTCONN;
#endif
#ifdef SO_PEERSEC
	case SO_PEERSEC:
		return PPM_SOCKOPT_SO_PEERSEC;
#endif
#ifdef SO_PASSSEC
	case SO_PASSSEC:
		return PPM_SOCKOPT_SO_PASSSEC;
#endif
#ifdef SO_TIMESTAMPNS
	case SO_TIMESTAMPNS:
		return PPM_SOCKOPT_SO_TIMESTAMPNS;
#endif
#ifdef SO_MARK
	case SO_MARK:
		return PPM_SOCKOPT_SO_MARK;
#endif
#ifdef SO_TIMESTAMPING
	case SO_TIMESTAMPING:
		return PPM_SOCKOPT_SO_TIMESTAMPING;
#endif
#ifdef SO_PROTOCOL
	case SO_PROTOCOL:
		return PPM_SOCKOPT_SO_PROTOCOL;
#endif
#ifdef SO_DOMAIN
	case SO_DOMAIN:
		return PPM_SOCKOPT_SO_DOMAIN;
#endif
#ifdef SO_RXQ_OVFL
	case SO_RXQ_OVFL:
		return PPM_SOCKOPT_SO_RXQ_OVFL;
#endif
#ifdef SO_WIFI_STATUS
	case SO_WIFI_STATUS:
		return PPM_SOCKOPT_SO_WIFI_STATUS;
#endif
#ifdef SO_PEEK_OFF
	case SO_PEEK_OFF:
		return PPM_SOCKOPT_SO_PEEK_OFF;
#endif
#ifdef SO_NOFCS
	case SO_NOFCS:
		return PPM_SOCKOPT_SO_NOFCS;
#endif
#ifdef SO_LOCK_FILTER
	case SO_LOCK_FILTER:
		return PPM_SOCKOPT_SO_LOCK_FILTER;
#endif
#ifdef SO_SELECT_ERR_QUEUE
	case SO_SELECT_ERR_QUEUE:
		return PPM_SOCKOPT_SO_SELECT_ERR_QUEUE;
#endif
#ifdef SO_BUSY_POLL
	case SO_BUSY_POLL:
		return PPM_SOCKOPT_SO_BUSY_POLL;
#endif
#ifdef SO_MAX_PACING_RATE
	case SO_MAX_PACING_RATE:
		return PPM_SOCKOPT_SO_MAX_PACING_RATE;
#endif
#ifdef SO_BPF_EXTENSIONS
	case SO_BPF_EXTENSIONS:
		return PPM_SOCKOPT_SO_BPF_EXTENSIONS;
#endif
#ifdef SO_INCOMING_CPU
	case SO_INCOMING_CPU:
		return PPM_SOCKOPT_SO_INCOMING_CPU;
#endif
#ifdef SO_ATTACH_BPF
	case SO_ATTACH_BPF:
		return PPM_SOCKOPT_SO_ATTACH_BPF;
#endif
#ifdef SO_PEERGROUPS
	case SO_PEERGROUPS:
		return PPM_SOCKOPT_SO_PEERGROUPS;
#endif
#ifdef SO_MEMINFO
	case SO_MEMINFO:
		return PPM_SOCKOPT_SO_MEMINFO;
#endif
#ifdef SO_COOKIE
	case SO_COOKIE:
		return PPM_SOCKOPT_SO_COOKIE;
#endif
#ifdef __BPF_TRACING__
	case INT_MAX:
		// forcefully disable switch jump table (clang-5 bug?)
		// Basically, when labels values are similar AND the switch has many labels,
		// compiler tends to build a jump table as optimization.
		// This breaks with eBPF, and in our Makefile we already have the -fno-jump-tables;
		// most probably clang5 had some kind of bug that caused -O2 mode to still use jump tables.
		// Let's add a "very distant" label value to forcefully disable jump table.
		//
		// DO NOT merge with below default case
		// otherwise this label will be skipped by compiler.
		ASSERT(false);
		return PPM_SOCKOPT_UNKNOWN;
#endif
	default:
		ASSERT(false);
		return PPM_SOCKOPT_UNKNOWN;
	}
}

/* XXX this is very basic for the moment, we'll need to improve it */
static __always_inline uint16_t poll_events_to_scap(short revents) {
	uint16_t res = 0;

	if(revents & POLLIN)
		res |= PPM_POLLIN;

	if(revents & POLLPRI)
		res |= PPM_POLLPRI;

	if(revents & POLLOUT)
		res |= PPM_POLLOUT;

	if(revents & POLLRDHUP)
		res |= PPM_POLLRDHUP;

	if(revents & POLLERR)
		res |= PPM_POLLERR;

	if(revents & POLLHUP)
		res |= PPM_POLLHUP;

	if(revents & POLLNVAL)
		res |= PPM_POLLNVAL;

	if(revents & POLLRDNORM)
		res |= PPM_POLLRDNORM;

	if(revents & POLLRDBAND)
		res |= PPM_POLLRDBAND;

	if(revents & POLLWRNORM)
		res |= PPM_POLLWRNORM;

	if(revents & POLLWRBAND)
		res |= PPM_POLLWRBAND;

	return res;
}

static __always_inline uint16_t futex_op_to_scap(unsigned long op) {
	uint16_t res = 0;
	unsigned long flt_op = op & 127;

	if(flt_op == FUTEX_WAIT)
		res = PPM_FU_FUTEX_WAIT;
	else if(flt_op == FUTEX_WAKE)
		res = PPM_FU_FUTEX_WAKE;
	else if(flt_op == FUTEX_FD)
		res = PPM_FU_FUTEX_FD;
	else if(flt_op == FUTEX_REQUEUE)
		res = PPM_FU_FUTEX_REQUEUE;
	else if(flt_op == FUTEX_CMP_REQUEUE)
		res = PPM_FU_FUTEX_CMP_REQUEUE;
	else if(flt_op == FUTEX_WAKE_OP)
		res = PPM_FU_FUTEX_WAKE_OP;
	else if(flt_op == FUTEX_LOCK_PI)
		res = PPM_FU_FUTEX_LOCK_PI;
	else if(flt_op == FUTEX_UNLOCK_PI)
		res = PPM_FU_FUTEX_UNLOCK_PI;
	else if(flt_op == FUTEX_TRYLOCK_PI)
		res = PPM_FU_FUTEX_TRYLOCK_PI;
#ifdef FUTEX_WAIT_BITSET
	else if(flt_op == FUTEX_WAIT_BITSET)
		res = PPM_FU_FUTEX_WAIT_BITSET;
#endif
#ifdef FUTEX_WAKE_BITSET
	else if(flt_op == FUTEX_WAKE_BITSET)
		res = PPM_FU_FUTEX_WAKE_BITSET;
#endif
#ifdef FUTEX_WAIT_REQUEUE_PI
	else if(flt_op == FUTEX_WAIT_REQUEUE_PI)
		res = PPM_FU_FUTEX_WAIT_REQUEUE_PI;
#endif
#ifdef FUTEX_CMP_REQUEUE_PI
	else if(flt_op == FUTEX_CMP_REQUEUE_PI)
		res = PPM_FU_FUTEX_CMP_REQUEUE_PI;
#endif

	if(op & FUTEX_PRIVATE_FLAG)
		res |= PPM_FU_FUTEX_PRIVATE_FLAG;

#ifdef FUTEX_CLOCK_REALTIME
	if(op & FUTEX_CLOCK_REALTIME)
		res |= PPM_FU_FUTEX_CLOCK_REALTIME;
#endif
	return res;
}

static __always_inline uint32_t access_flags_to_scap(unsigned flags) {
	uint32_t res = 0;

	if(flags == 0 /*F_OK*/) {
		res = PPM_F_OK;
	} else {
#if defined(__KERNEL__) || defined(__USE_VMLINUX__)
		if(flags & MAY_EXEC)
			res |= PPM_X_OK;
		if(flags & MAY_READ)
			res |= PPM_R_OK;
		if(flags & MAY_WRITE)
			res |= PPM_W_OK;
#else  // in userspace
		if(flags & X_OK)
			res |= PPM_X_OK;
		if(flags & R_OK)
			res |= PPM_R_OK;
		if(flags & W_OK)
			res |= PPM_W_OK;
#endif
	}

	return res;
}

static __always_inline u8 rlimit_resource_to_scap(uint32_t resource) {
	switch(resource) {
	case RLIMIT_CPU:
		return PPM_RLIMIT_CPU;
	case RLIMIT_FSIZE:
		return PPM_RLIMIT_FSIZE;
	case RLIMIT_DATA:
		return PPM_RLIMIT_DATA;
	case RLIMIT_STACK:
		return PPM_RLIMIT_STACK;
	case RLIMIT_CORE:
		return PPM_RLIMIT_CORE;
	case RLIMIT_RSS:
		return PPM_RLIMIT_RSS;
	case RLIMIT_NPROC:
		return PPM_RLIMIT_NPROC;
	case RLIMIT_NOFILE:
		return PPM_RLIMIT_NOFILE;
	case RLIMIT_MEMLOCK:
		return PPM_RLIMIT_MEMLOCK;
	case RLIMIT_AS:
		return PPM_RLIMIT_AS;
	case RLIMIT_LOCKS:
		return PPM_RLIMIT_LOCKS;
	case RLIMIT_SIGPENDING:
		return PPM_RLIMIT_SIGPENDING;
	case RLIMIT_MSGQUEUE:
		return PPM_RLIMIT_MSGQUEUE;
	case RLIMIT_NICE:
		return PPM_RLIMIT_NICE;
	case RLIMIT_RTPRIO:
		return PPM_RLIMIT_RTPRIO;
#ifdef RLIMIT_RTTIME
	case RLIMIT_RTTIME:
		return PPM_RLIMIT_RTTIME;
#endif
	default:
		return PPM_RLIMIT_UNKNOWN;
	}
}

static __always_inline uint16_t shutdown_how_to_scap(unsigned long how) {
	if(how == SHUT_RD)
		return PPM_SHUT_RD;
	else if(how == SHUT_WR)
		return PPM_SHUT_WR;
	else if(how == SHUT_RDWR)
		return PPM_SHUT_RDWR;
	return PPM_SHUT_UNKNOWN;
}

static __always_inline uint64_t lseek_whence_to_scap(unsigned long whence) {
	uint64_t res = 0;

	if(whence == SEEK_SET)
		res = PPM_SEEK_SET;
	else if(whence == SEEK_CUR)
		res = PPM_SEEK_CUR;
	else if(whence == SEEK_END)
		res = PPM_SEEK_END;

	return res;
}

static __always_inline uint16_t semop_flags_to_scap(short flags) {
	uint16_t res = 0;

	if(flags & IPC_NOWAIT)
		res |= PPM_IPC_NOWAIT;

	if(flags & SEM_UNDO)
		res |= PPM_SEM_UNDO;

	return res;
}

static __always_inline uint32_t pf_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;

	/* Page fault error codes don't seem to be clearly defined in header
	 * files throughout the kernel except in some emulation modes (e.g. kvm)
	 * which we can't assume to exist, so I just took the definitions from
	 * the x86 manual. If we end up supporting another arch for page faults,
	 * refactor this.
	 */
	if(flags & 0x1)
		res |= PPM_PF_PROTECTION_VIOLATION;
	else
		res |= PPM_PF_PAGE_NOT_PRESENT;

	if(flags & 0x2)
		res |= PPM_PF_WRITE_ACCESS;
	else
		res |= PPM_PF_READ_ACCESS;

	if(flags & 0x4)
		res |= PPM_PF_USER_FAULT;
	else
		res |= PPM_PF_SUPERVISOR_FAULT;

	if(flags & 0x8)
		res |= PPM_PF_RESERVED_PAGE;

	if(flags & 0x10)
		res |= PPM_PF_INSTRUCTION_FETCH;

	return res;
}

static __always_inline uint32_t flock_flags_to_scap(int flags) {
	uint32_t res = 0;

	if(flags & LOCK_EX)
		res |= PPM_LOCK_EX;

	if(flags & LOCK_SH)
		res |= PPM_LOCK_SH;

	if(flags & LOCK_UN)
		res |= PPM_LOCK_UN;

	if(flags & LOCK_NB)
		res |= PPM_LOCK_NB;

	return res;
}

static __always_inline uint8_t quotactl_type_to_scap(unsigned long cmd) {
	switch(cmd & SUBCMDMASK) {
	case USRQUOTA:
		return PPM_USRQUOTA;
	case GRPQUOTA:
		return PPM_GRPQUOTA;
	}
	return 0;
}

static __always_inline uint16_t quotactl_cmd_to_scap(unsigned long cmd) {
	uint16_t res;

	switch(cmd >> SUBCMDSHIFT) {
	case Q_SYNC:
		res = PPM_Q_SYNC;
		break;
	case Q_QUOTAON:
		res = PPM_Q_QUOTAON;
		break;
	case Q_QUOTAOFF:
		res = PPM_Q_QUOTAOFF;
		break;
	case Q_GETFMT:
		res = PPM_Q_GETFMT;
		break;
	case Q_GETINFO:
		res = PPM_Q_GETINFO;
		break;
	case Q_SETINFO:
		res = PPM_Q_SETINFO;
		break;
	case Q_GETQUOTA:
		res = PPM_Q_GETQUOTA;
		break;
	case Q_SETQUOTA:
		res = PPM_Q_SETQUOTA;
		break;
	/*
	 *  XFS specific
	 */
	case Q_XQUOTAON:
		res = PPM_Q_XQUOTAON;
		break;
	case Q_XQUOTAOFF:
		res = PPM_Q_XQUOTAOFF;
		break;
	case Q_XGETQUOTA:
		res = PPM_Q_XGETQUOTA;
		break;
	case Q_XSETQLIM:
		res = PPM_Q_XSETQLIM;
		break;
	case Q_XGETQSTAT:
		res = PPM_Q_XGETQSTAT;
		break;
	case Q_XQUOTARM:
		res = PPM_Q_XQUOTARM;
		break;
	case Q_XQUOTASYNC:
		res = PPM_Q_XQUOTASYNC;
		break;
	default:
		res = 0;
	}
	return res;
}

static __always_inline uint8_t quotactl_fmt_to_scap(unsigned long fmt) {
	switch(fmt) {
	case QFMT_VFS_OLD:
		return PPM_QFMT_VFS_OLD;
	case QFMT_VFS_V0:
		return PPM_QFMT_VFS_V0;
#ifdef QFMT_VFS_V1
	case QFMT_VFS_V1:
		return PPM_QFMT_VFS_V1;
#endif
	default:
		return PPM_QFMT_NOT_USED;
	}
}

static __always_inline uint32_t semget_flags_to_scap(unsigned flags) {
	uint32_t res = 0;

	if(flags & IPC_CREAT)
		res |= PPM_IPC_CREAT;

	if(flags & IPC_EXCL)
		res |= PPM_IPC_EXCL;

	return res;
}

static __always_inline uint32_t semctl_cmd_to_scap(unsigned cmd) {
	switch(cmd) {
	case IPC_STAT:
		return PPM_IPC_STAT;
	case IPC_SET:
		return PPM_IPC_SET;
	case IPC_RMID:
		return PPM_IPC_RMID;
	case IPC_INFO:
		return PPM_IPC_INFO;
	case SEM_INFO:
		return PPM_SEM_INFO;
	case SEM_STAT:
		return PPM_SEM_STAT;
	case GETALL:
		return PPM_GETALL;
	case GETNCNT:
		return PPM_GETNCNT;
	case GETPID:
		return PPM_GETPID;
	case GETVAL:
		return PPM_GETVAL;
	case GETZCNT:
		return PPM_GETZCNT;
	case SETALL:
		return PPM_SETALL;
	case SETVAL:
		return PPM_SETVAL;
#ifdef __BPF_TRACING__
	// forcefully disable switch jump table, see sockopt_optname_to_scap() for more info
	case INT_MAX:
		return 0;
#endif
	}
	return 0;
}

static __always_inline uint16_t ptrace_requests_to_scap(unsigned long req) {
	switch(req) {
#ifdef PTRACE_SINGLEBLOCK
	case PTRACE_SINGLEBLOCK:
		return PPM_PTRACE_SINGLEBLOCK;
#endif
#ifdef PTRACE_SYSEMU_SINGLESTEP
	case PTRACE_SYSEMU_SINGLESTEP:
		return PPM_PTRACE_SYSEMU_SINGLESTEP;
#endif

#ifdef PTRACE_SYSEMU
	case PTRACE_SYSEMU:
		return PPM_PTRACE_SYSEMU;
#endif
#ifdef PTRACE_ARCH_PRCTL
	case PTRACE_ARCH_PRCTL:
		return PPM_PTRACE_ARCH_PRCTL;
#endif
#ifdef PTRACE_SET_THREAD_AREA
	case PTRACE_SET_THREAD_AREA:
		return PPM_PTRACE_SET_THREAD_AREA;
#endif
#ifdef PTRACE_GET_THREAD_AREA
	case PTRACE_GET_THREAD_AREA:
		return PPM_PTRACE_GET_THREAD_AREA;
#endif
#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
		return PPM_PTRACE_OLDSETOPTIONS;
#endif
#ifdef PTRACE_SETFPXREGS
	case PTRACE_SETFPXREGS:
		return PPM_PTRACE_SETFPXREGS;
#endif
#ifdef PTRACE_GETFPXREGS
	case PTRACE_GETFPXREGS:
		return PPM_PTRACE_GETFPXREGS;
#endif
#ifdef PTRACE_SETFPREGS
	case PTRACE_SETFPREGS:
		return PPM_PTRACE_SETFPREGS;
#endif
#ifdef PTRACE_GETFPREGS
	case PTRACE_GETFPREGS:
		return PPM_PTRACE_GETFPREGS;
#endif
#ifdef PTRACE_SETREGS
	case PTRACE_SETREGS:
		return PPM_PTRACE_SETREGS;
#endif
#ifdef PTRACE_GETREGS
	case PTRACE_GETREGS:
		return PPM_PTRACE_GETREGS;
#endif
#ifdef PTRACE_SETSIGMASK
	case PTRACE_SETSIGMASK:
		return PPM_PTRACE_SETSIGMASK;
#endif
#ifdef PTRACE_GETSIGMASK
	case PTRACE_GETSIGMASK:
		return PPM_PTRACE_GETSIGMASK;
#endif
#ifdef PTRACE_PEEKSIGINFO
	case PTRACE_PEEKSIGINFO:
		return PPM_PTRACE_PEEKSIGINFO;
#endif
#ifdef PTRACE_LISTEN
	case PTRACE_LISTEN:
		return PPM_PTRACE_LISTEN;
#endif
#ifdef PTRACE_INTERRUPT
	case PTRACE_INTERRUPT:
		return PPM_PTRACE_INTERRUPT;
#endif
#ifdef PTRACE_SEIZE
	case PTRACE_SEIZE:
		return PPM_PTRACE_SEIZE;
#endif
#ifdef PTRACE_SETREGSET
	case PTRACE_SETREGSET:
		return PPM_PTRACE_SETREGSET;
#endif
#ifdef PTRACE_GETREGSET
	case PTRACE_GETREGSET:
		return PPM_PTRACE_GETREGSET;
#endif
	case PTRACE_SETSIGINFO:
		return PPM_PTRACE_SETSIGINFO;
	case PTRACE_GETSIGINFO:
		return PPM_PTRACE_GETSIGINFO;
	case PTRACE_GETEVENTMSG:
		return PPM_PTRACE_GETEVENTMSG;
	case PTRACE_SETOPTIONS:
		return PPM_PTRACE_SETOPTIONS;
	case PTRACE_SYSCALL:
		return PPM_PTRACE_SYSCALL;
	case PTRACE_DETACH:
		return PPM_PTRACE_DETACH;
	case PTRACE_ATTACH:
		return PPM_PTRACE_ATTACH;
	case PTRACE_SINGLESTEP:
		return PPM_PTRACE_SINGLESTEP;
	case PTRACE_KILL:
		return PPM_PTRACE_KILL;
	case PTRACE_CONT:
		return PPM_PTRACE_CONT;
#ifdef PTRACE_POKEUSR
	case PTRACE_POKEUSR:
		return PPM_PTRACE_POKEUSR;
#endif
	case PTRACE_POKEDATA:
		return PPM_PTRACE_POKEDATA;
	case PTRACE_POKETEXT:
		return PPM_PTRACE_POKETEXT;
#ifdef PTRACE_PEEKUSR
	case PTRACE_PEEKUSR:
		return PPM_PTRACE_PEEKUSR;
#endif
	case PTRACE_PEEKDATA:
		return PPM_PTRACE_PEEKDATA;
	case PTRACE_PEEKTEXT:
		return PPM_PTRACE_PEEKTEXT;
	case PTRACE_TRACEME:
		return PPM_PTRACE_TRACEME;
	default:
		return PPM_PTRACE_UNKNOWN;
	}
}

static __always_inline uint32_t execveat_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;

#ifdef AT_EMPTY_PATH
	if(flags & AT_EMPTY_PATH)
		res |= PPM_EXVAT_AT_EMPTY_PATH;
#endif

#ifdef AT_SYMLINK_NOFOLLOW
	if(flags & AT_SYMLINK_NOFOLLOW)
		res |= PPM_EXVAT_AT_SYMLINK_NOFOLLOW;
#endif

	return res;
}

static __always_inline uint32_t fsconfig_cmds_to_scap(uint32_t cmd) {
	/*
	 * fsconfig opcodes are defined via enum in uapi/linux/mount.h.
	 * It is userspace API (thus stable) and arch-independent.
	 * Therefore we map them 1:1; if any unmapped flag arrives,
	 * we will just print its value to userspace without mapping it to a string flag.
	 * We then need to append new flags to both flags_table and ppm_events_public PPM_ flags.
	 */
	return cmd;
}

static __always_inline uint32_t mlockall_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;
#ifdef MCL_CURRENT
	if(flags & MCL_CURRENT)
		res |= PPM_MLOCKALL_MCL_CURRENT;
#endif
#ifdef MCL_FUTURE
	if(flags & MCL_FUTURE)
		res |= PPM_MLOCKALL_MCL_FUTURE;
#endif
#ifdef MCL_ONFAULT
	if(flags & MCL_ONFAULT)
		res |= PPM_MLOCKALL_MCL_ONFAULT;
#endif
	return res;
}

static __always_inline uint32_t mlock2_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;
#ifdef MLOCK_ONFAULT
	if(flags & MLOCK_ONFAULT)
		res |= PPM_MLOCK_ONFAULT;
#endif
	return res;
}

static __always_inline uint32_t memfd_create_flags_to_scap(uint32_t flags) {
	uint32_t res = 0;
#ifdef MFD_CLOEXEC
	if(flags & MFD_CLOEXEC)
		res |= PPM_MFD_CLOEXEC;
#endif
#ifdef MFD_ALLOW_SEALING
	if(flags & MFD_ALLOW_SEALING)
		res |= PPM_MFD_ALLOW_SEALING;
#endif
#ifdef MFD_HUGETLB
	if(flags & MFD_HUGETLB)
		res |= PPM_MFD_HUGETLB;
#endif
	return res;
}

static __always_inline uint32_t unlinkat_flags_to_scap(int32_t flags) {
	uint32_t res = 0;

	if(flags & AT_REMOVEDIR)
		res |= PPM_AT_REMOVEDIR;

	return res;
}

static __always_inline uint32_t linkat_flags_to_scap(int32_t flags) {
	uint32_t res = 0;

	if(flags & AT_SYMLINK_FOLLOW)
		res |= PPM_AT_SYMLINK_FOLLOW;

#ifdef AT_EMPTY_PATH
	if(flags & AT_EMPTY_PATH)
		res |= PPM_AT_EMPTY_PATH;
#endif

	return res;
}

static __always_inline uint32_t newfstatat_flags_to_scap(int32_t flags) {
	uint32_t res = 0;

	/* AT_SYMLINK_NOFOLLOW was introduced in kernel 2.6.16, we don't need to check if it's defined
	 */
	if(flags & AT_SYMLINK_NOFOLLOW)
		res |= PPM_AT_SYMLINK_NOFOLLOW;

#ifdef AT_EMPTY_PATH
	if(flags & AT_EMPTY_PATH)
		res |= PPM_AT_EMPTY_PATH;
#endif

#ifdef AT_NO_AUTOMOUNT
	if(flags & AT_NO_AUTOMOUNT)
		res |= PPM_AT_NO_AUTOMOUNT;
#endif

	return res;
}

static __always_inline uint32_t chmod_mode_to_scap(unsigned long modes) {
	uint32_t res = 0;
	if(modes & S_IRUSR)
		res |= PPM_S_IRUSR;

	if(modes & S_IWUSR)
		res |= PPM_S_IWUSR;

	if(modes & S_IXUSR)
		res |= PPM_S_IXUSR;

	/*
	 * PPM_S_IRWXU == S_IRUSR | S_IWUSR | S_IXUSR
	 */

	if(modes & S_IRGRP)
		res |= PPM_S_IRGRP;

	if(modes & S_IWGRP)
		res |= PPM_S_IWGRP;

	if(modes & S_IXGRP)
		res |= PPM_S_IXGRP;

	/*
	 * PPM_S_IRWXG == S_IRGRP | S_IWGRP | S_IXGRP
	 */

	if(modes & S_IROTH)
		res |= PPM_S_IROTH;

	if(modes & S_IWOTH)
		res |= PPM_S_IWOTH;

	if(modes & S_IXOTH)
		res |= PPM_S_IXOTH;

	/*
	 * PPM_S_IRWXO == S_IROTH | S_IWOTH | S_IXOTH
	 */

	if(modes & S_ISUID)
		res |= PPM_S_ISUID;

	if(modes & S_ISGID)
		res |= PPM_S_ISGID;

	if(modes & S_ISVTX)
		res |= PPM_S_ISVTX;

	return res;
}

static __always_inline uint32_t umount2_flags_to_scap(int flags) {
	uint32_t res = 0;

#ifdef MNT_FORCE
	if(flags & MNT_FORCE)
		res |= PPM_MNT_FORCE;
#endif
#ifdef MNT_DETACH
	if(flags & MNT_DETACH)
		res |= PPM_MNT_DETACH;
#endif
#ifdef MNT_EXPIRE
	if(flags & MNT_EXPIRE)
		res |= PPM_MNT_EXPIRE;
#endif
#ifdef UMOUNT_NOFOLLOW
	if(flags & UMOUNT_NOFOLLOW)
		res |= PPM_UMOUNT_NOFOLLOW;
#endif
	return res;
}

static __always_inline uint32_t fchownat_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;

#ifdef AT_SYMLINK_FOLLOW
	if(flags & AT_SYMLINK_FOLLOW)
		res |= PPM_AT_SYMLINK_FOLLOW;
#endif

#ifdef AT_EMPTY_PATH
	if(flags & AT_EMPTY_PATH)
		res |= PPM_AT_EMPTY_PATH;
#endif

	return res;
}

static __always_inline uint64_t capabilities_to_scap(unsigned long caps) {
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

static __always_inline uint32_t dup3_flags_to_scap(int flags) {
	uint32_t res = 0;
#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif
	return res;
}

static __always_inline uint32_t pipe2_flags_to_scap(int32_t flags) {
	uint32_t res = 0;

	/* We need to explicitly handle the negative case otherwise `-1` will match all `flags & ...` */
	if(flags < 0) {
		return res;
	}

#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif
#ifdef O_DIRECT
	if(flags & O_DIRECT)
		res |= PPM_O_DIRECT;
#endif
#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;
#endif
	return res;
}

static __always_inline uint32_t epoll_create1_flags_to_scap(uint32_t flags) {
	uint32_t res = 0;
#ifdef EPOLL_CLOEXEC
	if(flags & EPOLL_CLOEXEC)
		res |= PPM_EPOLL_CLOEXEC;
#endif
	return res;
}

static __always_inline uint32_t splice_flags_to_scap(uint32_t flags) {
	uint32_t res = 0;
#ifdef SPLICE_F_MOVE
	if(flags & SPLICE_F_MOVE)
		res |= PPM_SPLICE_F_MOVE;
#endif
#ifdef SPLICE_F_NONBLOCK
	if(flags & SPLICE_F_NONBLOCK)
		res |= PPM_SPLICE_F_NONBLOCK;
#endif
#ifdef SPLICE_F_MORE
	if(flags & SPLICE_F_MORE)
		res |= PPM_SPLICE_F_MORE;
#endif
#ifdef SPLICE_F_GIFT
	if(flags & SPLICE_F_GIFT)
		res |= PPM_SPLICE_F_GIFT;
#endif
	return res;
}

static __always_inline uint32_t pidfd_open_flags_to_scap(uint32_t flags) {
	uint32_t res = 0;
// See https://elixir.bootlin.com/linux/v5.10.185/source/include/uapi/linux/pidfd.h#L10
#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_PIDFD_NONBLOCK;
#endif
	return res;
}

#ifdef OVERLAYFS_SUPER_MAGIC
#define PPM_OVERLAYFS_SUPER_MAGIC OVERLAYFS_SUPER_MAGIC
#else
#define PPM_OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif

static __always_inline uint32_t prctl_options_to_scap(int options) {
	return (uint32_t)options;
}

static __always_inline uint32_t finit_module_flags_to_scap(int32_t flags) {
	int32_t res = 0;
#ifdef MODULE_INIT_IGNORE_MODVERSIONS
	if(flags & MODULE_INIT_IGNORE_MODVERSIONS)
		res |= PPM_MODULE_INIT_IGNORE_MODVERSIONS;
#endif

#ifdef MODULE_INIT_IGNORE_VERMAGIC
	if(flags & MODULE_INIT_IGNORE_VERMAGIC)
		res |= PPM_MODULE_INIT_IGNORE_VERMAGIC;
#endif

#ifdef MODULE_INIT_COMPRESSED_FILE
	if(flags & MODULE_INIT_COMPRESSED_FILE)
		res |= PPM_MODULE_INIT_COMPRESSED_FILE;
#endif

	return res;
}

static __always_inline uint32_t mknod_mode_to_scap(uint32_t modes) {
	uint32_t res = chmod_mode_to_scap(modes);

	/*
	 * mknod modes
	 */

#ifdef S_IFMT
	switch(modes & S_IFMT) {
#ifdef S_IFSOCK
	case S_IFSOCK:
		res |= PPM_S_IFSOCK;
		break;
#endif
#ifdef S_IFREG
	// Zero file type is equivalent to type S_IFREG.
	case 0:
	case S_IFREG:
		res |= PPM_S_IFREG;
		break;
#endif
#ifdef S_IFBLK
	case S_IFBLK:
		res |= PPM_S_IFBLK;
		break;
#endif
#ifdef S_IFCHR
	case S_IFCHR:
		res |= PPM_S_IFCHR;
		break;
#endif
#ifdef S_IFIFO
	case S_IFIFO:
		res |= PPM_S_IFIFO;
		break;
#endif
	default:
		break;
	}
#endif

	return res;
}

static __always_inline uint32_t bpf_cmd_to_scap(unsigned long cmd) {
	/*
	 * bpf opcodes are defined via enum in uapi/linux/bpf.h.
	 * It is userspace API (thus stable) and arch-independent.
	 * Therefore we map them 1:1; if any unmapped flag arrives,
	 * we will just print its value to userspace without mapping it to a string flag.
	 * We then need to append new flags to both flags_table and ppm_events_public PPM_ flags.
	 */

	return cmd;
}

static __always_inline uint32_t delete_module_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;
#ifdef O_NONBLOCK
	if(flags & O_NONBLOCK)
		res |= PPM_DELETE_MODULE_O_NONBLOCK;
#endif
#ifdef O_TRUNC
	if(flags & O_TRUNC)
		res |= PPM_DELETE_MODULE_O_TRUNC;
#endif
	return res;
}

#endif /* PPM_FLAG_HELPERS_H_ */
