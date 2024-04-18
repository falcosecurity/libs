// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2023 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef __SYSTYPE_COMPACT_H__
#define __SYSTYPE_COMPACT_H__

/* If WIFEXITED(STATUS), the low-order 8 bits of the status.  */
#define __WEXITSTATUS(status) (((status)&0xff00) >> 8)

/* If WIFSIGNALED(STATUS), the terminating signal.  */
#define __WTERMSIG(status) ((status)&0x7f)

/* Nonzero if STATUS indicates termination by a signal.  */
#define __WIFSIGNALED(status) \
	(((signed char)(((status)&0x7f) + 1) >> 1) > 0)

/* Nonzero if STATUS indicates the child dumped core.  */
#define __WCOREDUMP(status) ((status)&__WCOREFLAG)

#define __WCOREFLAG 0x80

#endif /* __SYSTYPE_COMPACT_H__ */
