/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#include "unistd32.h"

#if defined(__KERNEL__) && defined(CONFIG_IA32_EMULATION)

#define g_syscall_table g_syscall_ia32_table

#include "syscall_table.c"

#endif
