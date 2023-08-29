#pragma once

#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#if !defined(__EMSCRIPTEN__) && !defined(_WIN32)
#include <sys/quota.h>
#include <sys/ptrace.h>
#if !defined(__APPLE__)
#include <sys/prctl.h>
#endif //__APPLE__
#endif //__EMSCRIPTEN__ _WIN32
#if !defined(_WIN32)
#include <sys/mman.h>
#include <poll.h>
#include <sys/sem.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sched.h>
#endif //_WIN32

#define ASSERT assert
#ifndef F_CANCELLK
#define F_CANCELLK (1024 + 5)
#endif

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

#if defined(__linux__)
#include "../../driver/ppm_flag_helpers.h"
#endif

#ifdef UNDEF_UDIG
#undef UDIG
#undef UNDEF_UDIG
#endif
