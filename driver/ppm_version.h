// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef PPM_VERSION_H_
#define PPM_VERSION_H_

#include <linux/version.h>

/**
 * for RHEL kernels, export the release code (which is equal to e.g.
 * RHEL_RELEASE_CODE(8, 1)) under our own name.
 * For other kernels, just use zeros.
 *
 * We need macros that are always defined to use in preprocessor directives
 * to express the required kernel version in a single expression, without
 * a multiline #ifdef soup.
 */
#ifdef RHEL_RELEASE_CODE
#define PPM_RHEL_RELEASE_CODE RHEL_RELEASE_CODE
#define PPM_RHEL_RELEASE_VERSION(x,y) RHEL_RELEASE_VERSION(x,y)
#else
#define PPM_RHEL_RELEASE_CODE 0
#define PPM_RHEL_RELEASE_VERSION(x,y) 0
#endif

#endif /* PPM_VERSION_H_ */
