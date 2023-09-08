// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#if defined(__TARGET_ARCH_x86)
#include "x86_64/vmlinux.h"
#elif defined(__TARGET_ARCH_arm64)
#include "aarch64/vmlinux.h"
#elif defined(__TARGET_ARCH_s390)
#include "s390x/vmlinux.h"
#elif defined(__TARGET_ARCH_powerpc)
#include "ppc64le/vmlinux.h"
#endif
