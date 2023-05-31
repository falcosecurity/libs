/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

#ifndef SOCKETCALL_TO_SYSCALL_H
#define SOCKETCALL_TO_SYSCALL_H

int socketcall_code_to_syscall_code(int socketcall_code, bool* is_syscall_return);

#endif /* SOCKETCALL_TO_SYSCALL_H */
