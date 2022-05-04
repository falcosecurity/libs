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

#define ASSERT assert
#define F_CANCELLK 1024 + 5

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
