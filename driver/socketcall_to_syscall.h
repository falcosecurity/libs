/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef SOCKETCALL_TO_SYSCALL_H
#define SOCKETCALL_TO_SYSCALL_H

/* We obtain an UNRESOLVED_SOCKETCALL code
 * when a syscall is just defined through the socket call code
 * but not in the system.
 *
 * ----- s390x
 * - `SYS_ACCEPT` is defined but `__NR_accept` is not defined
 *
 * ----- x86 with CONFIG_IA32_EMULATION
 * - `SYS_ACCEPT` is defined but `__NR_accept` is not defined
 * - `SYS_SEND` is defined but `__NR_send` is not defined
 * - `SYS_RECV` is defined but `__NR_recv` is not defined
 */
// #define UNRESOLVED_SOCKETCALL -1

int socketcall_code_to_syscall_code(int socketcall_code, int socketcall_syscall_id);

#endif /* SOCKETCALL_TO_SYSCALL_H */
