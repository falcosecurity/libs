// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include "ppm_tp.h"

const char *kmod_prog_names[] = {
#define X(name, path) path,
	KMOD_PROGS
#undef X
};
