/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#pragma once

/*!
    \brief Set the Effective User ID only for the current thread

    \return On success, zero is returned.  On error, -1 is returned, and
       errno is set to indicate the error.
 */
static inline int thread_seteuid(uid_t uid)
{
	int result;

	if (uid == (uid_t) ~0) {
		errno = EINVAL;
		return -1;
	}

#ifdef __NR_setresuid32
	result = syscall(SYS_setresuid32, -1, uid, -1);
#else
	result = syscall(SYS_setresuid, -1, uid, -1);
#endif

	return result;
}

/*!
    \brief Set the Effective Group ID only for the current thread

    \return On success, zero is returned.  On error, -1 is returned, and
       errno is set to indicate the error.
 */
static inline int thread_setegid(gid_t gid)
{
	int result;

	if (gid == (gid_t) ~0) {
		errno = EINVAL;
		return -1;
	}

#ifdef __NR_setresgid32
	result = syscall(SYS_setresgid32, -1, gid, -1);
#else
	result = syscall(SYS_setresgid, -1, gid, -1);
#endif

	return result;
}
