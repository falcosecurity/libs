#pragma once

#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <sys/quota.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/file.h>

#define ASSERT assert
#define F_CANCELLK 1024 + 5

#ifndef QFMT_VFS_OLD
#define	QFMT_VFS_OLD 1
#define	QFMT_VFS_V0 2
#define QFMT_OCFS2 3
#define	QFMT_VFS_V1 4
#endif

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t

#ifndef UDIG
#define UNDEF_UDIG
#define UDIG
#endif

#include "../../driver/ppm_flag_helpers.h"

#ifdef UNDEF_UDIG
#undef UDIG
#undef UNDEF_UDIG
#endif
