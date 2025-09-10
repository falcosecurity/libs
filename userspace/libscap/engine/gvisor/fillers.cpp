// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/un.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>

#include <functional>
#include <unordered_map>
#include <sstream>
#include <string>

#include <json/json.h>

#include <libscap/engine/gvisor/gvisor.h>
#include <libscap/compat/misc.h>
#include <driver/ppm_events_public.h>
#include <libscap/strl.h>

#include <libscap/userspace_flag_helpers.h>

#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

namespace scap_gvisor {
namespace fillers {

// PPME_SYSCALL_CLONE_20_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F7/fdlimit -- hardcoded to 75000
// - F8/pgft_maj -- hardcoded to 0
// - F9/pgft_min -- hardcoded to 0
// - F10/vm_size -- hardcoded to 0
// - F11/vm_rss -- hardcoded to 0
// - F12/vm_swap -- hardcoded to 0
//
// B) Provided by caller, but caller sometimes specifies a hardcoded value
//    due to value not available in native gVisor event:
// - F2/args -- some callers pass in a hardcoded value of empty string
// - F5/ptid -- some callers pass in hardcoded value of 0
// - F15/flags -- some callers pass in hardcoded value of 0
// - F16/uid -- some callers pass in hardcoded value of 0
// - F17/gid -- some callers pass in hardcoded value of 0
int32_t fill_event_clone_20_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t res,
                              const char* exe,
                              scap_const_sized_buffer args,
                              uint64_t tid,
                              uint64_t pid,
                              uint64_t ptid,
                              const char* cwd,
                              const char* comm,
                              scap_const_sized_buffer cgroups,
                              uint32_t flags,
                              uint32_t uid,
                              uint32_t gid,
                              uint64_t vtid,
                              uint64_t vpid,
                              uint64_t pidns_init_start_ts) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_CLONE_20_X,
	                                21,
	                                res,
	                                exe,
	                                args,
	                                tid,
	                                pid,
	                                ptid,
	                                cwd,
	                                75000,  // fdlimit -- INVALID
	                                0,      // pgft_maj -- INVALID
	                                0,      // pgft_min -- INVALID
	                                0,      // vm_size -- INVALID
	                                0,      // vm_rss -- INVALID
	                                0,      // vm_swap -- INVALID
	                                comm,
	                                cgroups,
	                                flags,
	                                uid,
	                                gid,
	                                vtid,
	                                vpid,
	                                pidns_init_start_ts);
}

// PPME_SYSCALL_FORK_20_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F2/args -- hardcoded to empty string
// - F5/ptid -- hardcoded to 0
// - F7/fdlimit -- hardcoded to 75000
// - F8/pgft_maj -- hardcoded to 0
// - F9/pgft_min -- hardcoded to 0
// - F10/vm_size -- hardcoded to 0
// - F11/vm_rss -- hardcoded to 0
// - F12/vm_swap -- hardcoded to 0
int32_t fill_event_fork_20_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             const char* exe,
                             uint64_t tid,
                             uint64_t pid,
                             const char* cwd,
                             const char* comm,
                             scap_const_sized_buffer cgroups,
                             uint32_t uid,
                             uint32_t gid,
                             uint64_t vtid,
                             uint64_t vpid,
                             uint64_t pidns_init_start_ts) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_FORK_20_X,
	                                21,
	                                res,
	                                exe,
	                                scap_const_sized_buffer{"", 0},  // args -- INVALID
	                                tid,
	                                pid,
	                                0,  // ptid -- INVALID
	                                cwd,
	                                75000,  // fdlimit -- INVALID
	                                0,      // pgft_maj -- INVALID
	                                0,      // pgft_min -- INVALID
	                                0,      // vm_size -- INVALID
	                                0,      // vm_rss -- INVALID
	                                0,      // vm_swap -- INVALID
	                                comm,
	                                cgroups,
	                                0,  // flags, hardcoded to 0 just like drivers
	                                uid,
	                                gid,
	                                vtid,
	                                vpid,
	                                pidns_init_start_ts);
}

// PPME_SYSCALL_VFORK_20_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F2/args -- hardcoded to empty string
// - F5/ptid -- hardcoded to 0
// - F7/fdlimit -- hardcoded to 75000
// - F8/pgft_maj -- hardcoded to 0
// - F9/pgft_min -- hardcoded to 0
// - F10/vm_size -- hardcoded to 0
// - F11/vm_rss -- hardcoded to 0
// - F12/vm_swap -- hardcoded to 0
int32_t fill_event_vfork_20_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t res,
                              const char* exe,
                              uint64_t tid,
                              uint64_t pid,
                              const char* cwd,
                              const char* comm,
                              scap_const_sized_buffer cgroups,
                              uint32_t uid,
                              uint32_t gid,
                              uint64_t vtid,
                              uint64_t vpid,
                              uint64_t pidns_init_start_ts) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_VFORK_20_X,
	                                21,
	                                res,
	                                exe,
	                                scap_const_sized_buffer{"", 0},  // args -- INVALID
	                                tid,
	                                pid,
	                                0,  // ptid -- INVALID
	                                cwd,
	                                75000,  // fdlimit -- INVALID
	                                0,      // pgft_maj -- INVALID
	                                0,      // pgft_min -- INVALID
	                                0,      // vm_size -- INVALID
	                                0,      // vm_rss -- INVALID
	                                0,      // vm_swap -- INVALID
	                                comm,
	                                cgroups,
	                                0,  // flags, hardcoded to 0 just like drivers
	                                uid,
	                                gid,
	                                vtid,
	                                vpid,
	                                pidns_init_start_ts);
}

// PPME_SYSCALL_EXECVE_19_E
// Event field validity issues: none
int32_t fill_event_execve_19_e(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               const char* filename) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_EXECVE_19_E,
	                                1,
	                                filename);
}

// PPME_SYSCALL_EXECVE_19_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F5/ptid -- hardcoded to -1
// - F7/fdlimit -- hardcoded to 75000
// - F8/pgft_maj -- hardcoded to 0
// - F9/pgft_min -- hardcoded to 0
// - F10/vm_size -- hardcoded to 0
// - F11/vm_rss -- hardcoded to 0
// - F12/vm_swap -- hardcoded to 0
// - F16/tty -- hardcoded to 0
// - F17/vpgid -- hardcoded to 0
// - F18/loginuid -- hardcoded to UINT32_MAX
// - F19/flags -- hardcoded to 0
// - F20/cap_inheritable -- hardcoded to 0
// - F21/cap_permitted -- hardcoded to 0
// - F22/cap_effective -- hardcoded to 0
// - F23/exe_ino -- hardcoded to 0
// - F24/exe_ino_ctime -- hardcoded to 0
// - F25/exe_ino_mtime -- hardcoded to 0
//
// B) Provided by caller, but caller sometimes specifies a hardcoded value
//    due to value not available in native gVisor event:
// - F26/uid -- some callers pass in hardcoded value of 0
// - F29/gid -- some callers pass in hardcoded value of 0
int32_t fill_event_execve_19_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t res,
                               const char* exe,
                               scap_const_sized_buffer args,
                               uint64_t tid,
                               uint64_t pid,
                               const char* cwd,
                               const char* comm,
                               scap_const_sized_buffer cgroups,
                               scap_const_sized_buffer env,
                               uint32_t uid,
                               uint32_t gid) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_EXECVE_19_X,
	                                30,
	                                res,
	                                exe,
	                                args,
	                                tid,
	                                pid,
	                                -1,     // ptid -- INVALID
	                                cwd,    // cwd
	                                75000,  // fdlimit -- INVALID
	                                0,      // pgft_maj -- INVALID
	                                0,      // pgft_min -- INVALID
	                                0,      // vm_size -- INVALID
	                                0,      // vm_rss -- INVALID
	                                0,      // vm_swap -- INVALID
	                                comm,
	                                cgroups,
	                                env,
	                                0,           // tty -- INVALID
	                                0,           // vpgid -- INVALID
	                                UINT32_MAX,  // loginuid -- INVALID
	                                0,           // flags -- INVALID
	                                0,           // cap_inheritable -- INVALID
	                                0,           // cap_permitted -- INVALID
	                                0,           // cap_effective -- INVALID
	                                0,           // exe_ino -- INVALID
	                                0,           // exe_ino_ctime -- INVALID
	                                0,           // exe_ino_mtime -- INVALID
	                                uid,         // uid
	                                exe,         // trusted_exepath
	                                0,           // pgid -- INVALID
	                                gid          // gid
	);
}

// PPME_SYSCALL_EXECVEAT_E
// Event field validity issues: none
int32_t fill_event_execveat_e(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t dirfd,
                              const char* pathname,
                              uint32_t flags) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_EXECVEAT_E,
	                                3,
	                                dirfd,
	                                pathname,
	                                flags);
}

// PPME_SYSCALL_EXECVEAT_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F5/ptid -- hardcoded to -1
// - F7/fdlimit -- hardcoded to 75000
// - F8/pgft_maj -- hardcoded to 0
// - F9/pgft_min -- hardcoded to 0
// - F10/vm_size -- hardcoded to 0
// - F11/vm_rss -- hardcoded to 0
// - F12/vm_swap -- hardcoded to 0
// - F16/tty -- hardcoded to 0
// - F17/vpgid -- hardcoded to 0
// - F18/loginuid -- hardcoded to UINT32_MAX
// - F19/flags -- hardcoded to 0
// - F20/cap_inheritable -- hardcoded to 0
// - F21/cap_permitted -- hardcoded to 0
// - F22/cap_effective -- hardcoded to 0
// - F23/exe_ino -- hardcoded to 0
// - F24/exe_ino_ctime -- hardcoded to 0
// - F25/exe_ino_mtime -- hardcoded to 0
//
// B) Provided by caller, but caller sometimes specifies a hardcoded value
//    due to value not available in native gVisor event:
// - F26/uid -- some callers pass in hardcoded value of 0
// - F29/gid -- some callers pass in hardcoded value of 0
int32_t fill_event_execveat_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t res,
                              const char* exe,
                              scap_const_sized_buffer args,
                              uint64_t tid,
                              uint64_t pid,
                              const char* cwd,
                              const char* comm,
                              scap_const_sized_buffer cgroups,
                              scap_const_sized_buffer env,
                              uint32_t uid,
                              uint32_t gid) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_EXECVEAT_X,
	                                30,
	                                res,
	                                exe,
	                                args,
	                                tid,
	                                pid,
	                                -1,     // ptid -- INVALID
	                                cwd,    // cwd
	                                75000,  // fdlimit -- INVALID
	                                0,      // pgft_maj -- INVALID
	                                0,      // pgft_min -- INVALID
	                                0,      // vm_size -- INVALID
	                                0,      // vm_rss -- INVALID
	                                0,      // vm_swap -- INVALID
	                                comm,
	                                cgroups,
	                                env,
	                                0,           // tty -- INVALID
	                                0,           // pgid -- INVALID
	                                UINT32_MAX,  // loginuid -- INVALID
	                                0,           // flags -- INVALID
	                                0,           // cap_inheritable -- INVALID
	                                0,           // cap_permitted -- INVALID
	                                0,           // cap_effective -- INVALID
	                                0,           // exe_ino -- INVALID
	                                0,           // exe_ino_ctime -- INVALID
	                                0,           // exe_ino_mtime -- INVALID
	                                uid,         // uid
	                                exe,         // trusted_exepath
	                                0,           // pgid -- INVALID
	                                gid          // gid
	);
}

// PPME_SYSCALL_PROCEXIT_1_E
// Event field validity issues: none
int32_t fill_event_procexit_1_e(scap_sized_buffer scap_buf,
                                size_t* event_size,
                                char* scap_err,
                                uint32_t status,
                                uint32_t ret,
                                uint32_t sig,
                                uint32_t core) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_PROCEXIT_1_E,
	                                4,
	                                status,
	                                ret,
	                                sig,
	                                core);
}

// PPME_SYSCALL_OPEN_E
// Event field validity issues: none
int32_t fill_event_open_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          const char* name,
                          uint32_t flags,
                          uint32_t mode) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_OPEN_E,
	                                3,
	                                name,
	                                flags,
	                                mode);
}

// PPME_SYSCALL_OPEN_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F4/dev -- hardcoded to 0
// - F5/ino -- hardcoded to 0
int32_t fill_event_open_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t fd,
                          const char* name,
                          uint32_t flags,
                          uint32_t mode) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_OPEN_X,
	                                6,
	                                fd,
	                                name,
	                                flags,
	                                mode,
	                                0,   // dev -- INVALID
	                                0);  // ino -- INVALID
}

// PPME_SYSCALL_OPENAT_2_E
// Event field validity issues: none
int32_t fill_event_openat_2_e(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t dirfd,
                              const char* name,
                              uint32_t flags,
                              uint32_t mode) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_OPENAT_2_E,
	                                4,
	                                dirfd,
	                                name,
	                                flags,
	                                mode);
}

// PPME_SYSCALL_OPENAT_2_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F5/dev -- hardcoded to 0
// - F6/ino -- hardcoded to 0
int32_t fill_event_openat_2_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t fd,
                              int64_t dirfd,
                              const char* name,
                              uint32_t flags,
                              uint32_t mode) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_OPENAT_2_X,
	                                7,
	                                fd,
	                                dirfd,
	                                name,
	                                flags,
	                                mode,
	                                0,   // dev -- INVALID
	                                0);  // ino -- INVALID
}

// PPME_SYSCALL_CREAT_E
// Event field validity issues: none
int32_t fill_event_creat_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           const char* name,
                           uint32_t mode) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_CREAT_E,
	                                2,
	                                name,
	                                mode);
}

// PPME_SYSCALL_CREAT_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F3/dev -- hardcoded to 0
// - F4/ino -- hardcoded to 0
int32_t fill_event_creat_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd,
                           const char* name,
                           uint32_t mode) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_CREAT_X,
	                                5,
	                                fd,
	                                name,
	                                mode,
	                                0,   // dev -- INVALID
	                                0);  // ino -- INVALID
}

// PPME_SYSCALL_CLOSE_X
// Event field validity issues: none
int32_t fill_event_close_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t fd) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_CLOSE_X,
	                                2,
	                                res,
	                                fd);
}

// PPME_SYSCALL_READ_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/data -- hardcoded to empty string
int32_t fill_event_read_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t fd,
                          uint32_t size) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_READ_X,
	                                4,
	                                res,
	                                scap_const_sized_buffer{NULL, 0},  // data -- INVALID
	                                fd,
	                                size);
}

// PPME_SYSCALL_PREAD_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/data -- hardcoded to empty string
int32_t fill_event_pread_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t fd,
                           uint32_t size,
                           uint64_t pos) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_PREAD_X,
	                                5,
	                                res,
	                                scap_const_sized_buffer{NULL, 0},  // data -- INVALID
	                                fd,
	                                size,
	                                pos);
}

// PPME_SYSCALL_READV_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F2/data -- hardcoded to empty string
int32_t fill_event_readv_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           uint32_t size,
                           int64_t fd) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_READV_X,
	                                4,
	                                res,
	                                size,
	                                scap_const_sized_buffer{NULL, 0},  // data -- INVALID
	                                fd);
}

// PPME_SYSCALL_PREADV_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F2/data -- hardcoded to empty string
int32_t fill_event_preadv_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint32_t size,
                            int64_t fd,
                            uint64_t pos) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_PREADV_X,
	                                5,
	                                res,
	                                size,
	                                scap_const_sized_buffer{NULL, 0},  // data -- INVALID
	                                fd,
	                                pos);
}

// PPME_SYSCALL_CONNECT_E
// Event field validity issues: none
int32_t fill_event_connect_e(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t fd,
                             scap_const_sized_buffer addr) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_CONNECT_E,
	                                2,
	                                fd,
	                                addr);
}

// PPME_SYSCALL_CONNECT_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F2/tuple -- local address portion hardcoded to 0
int32_t fill_event_connect_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             scap_const_sized_buffer tuple,
                             int64_t fd,
                             scap_const_sized_buffer addr) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_CONNECT_X,
	                                4,
	                                res,
	                                tuple,  // local addr hardcoded 0 -- INVALID
	                                fd,
	                                addr);
}

// PPME_SYSCALL_SOCKET_X
// Event field validity issues: none
int32_t fill_event_socket_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t fd,
                            uint32_t domain,
                            uint32_t type,
                            uint32_t protocol) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_SOCKET_X,
	                                4,
	                                fd,
	                                domain,
	                                type,
	                                protocol);
}

// PPME_SYSCALL_CHDIR_X
// Event field validity issues: none
int32_t fill_event_chdir_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           const char* path) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_CHDIR_X,
	                                2,
	                                res,
	                                path);
}

// PPME_SYSCALL_FCHDIR_X
// Event field validity issues: none
int32_t fill_event_fchdir_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            int64_t fd) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_FCHDIR_X,
	                                2,
	                                res,
	                                fd);
}

// PPME_SYSCALL_SETUID_X
// Event field validity issues: none
int32_t fill_event_setuid_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint32_t uid) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_SETUID_X,
	                                2,
	                                res,
	                                uid);
}

// PPME_SYSCALL_SETGID_X
// Event field validity issues: none
int32_t fill_event_setgid_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint32_t gid) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_SETGID_X,
	                                2,
	                                res,
	                                gid);
}

// PPME_SYSCALL_SETSID_X
// Event field validity issues: none
int32_t fill_event_setsid_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res) {
	return scap_event_encode_params(scap_buf, event_size, scap_err, PPME_SYSCALL_SETSID_X, 1, res);
}

// PPME_SYSCALL_SETRESUID_X
// Event field validity issues: none
int32_t fill_event_setresuid_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t res,
                               uint32_t ruid,
                               uint32_t euid,
                               uint32_t suid) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_SETRESUID_X,
	                                4,
	                                res,
	                                ruid,
	                                euid,
	                                suid);
}

// PPME_SYSCALL_SETRESGID_X
// Event field validity issues: none
int32_t fill_event_setresgid_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t res,
                               uint32_t rgid,
                               uint32_t egid,
                               uint32_t sgid) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_SETRESGID_X,
	                                4,
	                                res,
	                                rgid,
	                                egid,
	                                sgid);
}

// PPME_SYSCALL_PRLIMIT_X
// Event field validity issues: none
int32_t fill_event_prlimit_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             int64_t newcur,
                             int64_t newmax,
                             int64_t oldcur,
                             int64_t oldmax) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_PRLIMIT_X,
	                                5,
	                                res,
	                                newcur,
	                                newmax,
	                                oldcur,
	                                oldmax);
}

// PPME_SYSCALL_PIPE_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F3/ino -- hardcoded to 0
int32_t fill_event_pipe_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t fd1,
                          int64_t fd2) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_PIPE_X,
	                                4,
	                                res,
	                                fd1,
	                                fd2,
	                                0);  // ino -- INVALID
}

// PPME_SYSCALL_FCNTL_X
// Event field validity issues: none
int32_t fill_event_fcntl_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res) {
	return scap_event_encode_params(scap_buf, event_size, scap_err, PPME_SYSCALL_FCNTL_X, 1, res);
}

// PPME_SYSCALL_DUP_1_X
// Event field validity issues: none
int32_t fill_event_dup_1_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t oldfd) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_DUP_1_X,
	                                2,
	                                res,
	                                oldfd);
}

// PPME_SYSCALL_DUP2_X
// Event field validity issues: none
int32_t fill_event_dup2_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t oldfd,
                          int64_t newfd) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_DUP2_X,
	                                3,
	                                res,
	                                oldfd,
	                                newfd);
}

// PPME_SYSCALL_DUP3_X
// Event field validity issues: none
int32_t fill_event_dup3_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t oldfd,
                          int64_t newfd,
                          uint32_t flags) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_DUP3_X,
	                                4,
	                                res,
	                                oldfd,
	                                newfd,
	                                flags);
}

// PPME_SYSCALL_SIGNALFD_X
// Event field validity issues: none
int32_t fill_event_signalfd_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t res,
                              int64_t fd,
                              uint32_t mask,
                              uint8_t flags) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_SIGNALFD_X,
	                                4,
	                                res,
	                                fd,
	                                mask,
	                                flags);
}

// PPME_SYSCALL_CHROOT_X
// Event field validity issues: none
int32_t fill_event_chroot_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            const char* path) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_CHROOT_X,
	                                2,
	                                res,
	                                path);
}

// PPME_SYSCALL_EVENTFD_X
// Event field validity issues: none
int32_t fill_event_eventfd_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res) {
	return scap_event_encode_params(scap_buf, event_size, scap_err, PPME_SYSCALL_EVENTFD_X, 1, res);
}

// PPME_SYSCALL_BIND_X
// Event field validity issues: none
int32_t fill_event_bind_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          scap_const_sized_buffer addr,
                          int64_t fd) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_BIND_X,
	                                3,
	                                res,
	                                addr,
	                                fd);
}

// PPME_SYSCALL_ACCEPT_5_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/tuple -- local address portion hardcoded to 0
// - F2/queuepct -- hardcoded to 0
// - F3/queuelen -- hardcoded to 0
// - F4/queuemax -- hardcoded to 0
int32_t fill_event_accept_5_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t fd,
                              scap_const_sized_buffer tuple) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_ACCEPT_5_X,
	                                5,
	                                fd,
	                                tuple,  // local address portion hardcoded to 0 -- INVALID
	                                0,      // queuepct -- INVALID
	                                0,      // queuelen -- INVALID
	                                0);     // queuemax -- INVALID
}

// PPME_SYSCALL_ACCEPT4_6_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/tuple -- local address portion hardcoded to 0
// - F2/queuepct -- hardcoded to 0
// - F3/queuelen -- hardcoded to 0
// - F4/queuemax -- hardcoded to 0
int32_t fill_event_accept4_6_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t fd,
                               scap_const_sized_buffer tuple,
                               int32_t flags) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_ACCEPT4_6_X,
	                                6,
	                                fd,
	                                tuple,  // local address portion hardcoded to 0 -- INVALID
	                                0,      // queuepct -- INVALID
	                                0,      // queuelen -- INVALID
	                                0,      // queuemax -- INVALID
	                                flags);
}

// PPME_SYSCALL_TIMERFD_CREATE_X
// Event field validity issues: none
int32_t fill_event_timerfd_create_x(scap_sized_buffer scap_buf,
                                    size_t* event_size,
                                    char* scap_err,
                                    int64_t res,
                                    uint8_t clockid,
                                    uint8_t flags) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_TIMERFD_CREATE_X,
	                                3,
	                                res,
	                                clockid,
	                                flags);
}

// PPME_SYSCALL_INOTIFY_INIT_X
// Event field validity issues: none
int32_t fill_event_inotify_init_x(scap_sized_buffer scap_buf,
                                  size_t* event_size,
                                  char* scap_err,
                                  int64_t res,
                                  uint8_t flags) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_INOTIFY_INIT_X,
	                                2,
	                                res,
	                                flags);
}

// PPME_SYSCALL_SOCKETPAIR_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F3/source -- hardcoded to 0
// - F4/peer -- hardcoded to 0
int32_t fill_event_socketpair_x(scap_sized_buffer scap_buf,
                                size_t* event_size,
                                char* scap_err,
                                int64_t res,
                                int64_t fd1,
                                int64_t fd2) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SOCKET_SOCKETPAIR_X,
	                                5,
	                                res,
	                                fd1,
	                                fd2,
	                                0,   // source -- INVALID
	                                0);  // peer -- INVALID
}

// PPME_SYSCALL_WRITE_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/data -- hardcoded to empty string
int32_t fill_event_write_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t fd,
                           uint32_t size) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_WRITE_X,
	                                4,
	                                res,
	                                scap_const_sized_buffer{NULL, 0},
	                                fd,
	                                size);  // data -- INVALID
}

// PPME_SYSCALL_PWRITE_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/data -- hardcoded to empty string
int32_t fill_event_pwrite_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            int64_t fd,
                            uint32_t size,
                            uint64_t pos) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_PWRITE_X,
	                                5,
	                                res,
	                                scap_const_sized_buffer{NULL, 0},
	                                fd,
	                                size,
	                                pos);  // data -- INVALID
}

// PPME_SYSCALL_WRITEV_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/data -- hardcoded to empty string
int32_t fill_event_writev_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            int64_t fd,
                            uint32_t size) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_WRITEV_X,
	                                4,
	                                res,
	                                scap_const_sized_buffer{NULL, 0},  // data -- INVALID
	                                fd,
	                                size);
}

// PPME_SYSCALL_PWRITEV_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/data -- hardcoded to empty string
int32_t fill_event_pwritev_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             int64_t fd,
                             uint32_t size,
                             uint64_t pos) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_PWRITEV_X,
	                                5,
	                                res,
	                                scap_const_sized_buffer{NULL, 0},  // data -- INVALID
	                                fd,
	                                size,
	                                pos);
}

// PPME_SYSCALL_MMAP_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/vm_size -- hardcoded to 0
// - F2/vm_rss -- hardcoded to 0
// - F3/vm_swap -- hardcoded to 0
int32_t fill_event_mmap_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          uint64_t addr,
                          uint64_t length,
                          uint32_t prot,
                          uint32_t flags,
                          int64_t fd,
                          uint64_t offset) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_MMAP_X,
	                                10,
	                                res,
	                                0,  // vm_size -- INVALID
	                                0,  // vm_rss -- INVALID
	                                0,  // vm_swap -- INVALID
	                                addr,
	                                length,
	                                prot,
	                                flags,
	                                fd,
	                                offset);
}

// PPME_SYSCALL_MUNMAP_X
// Event field validity issues:
// A) Always hardcoded due to value not available in native gVisor event:
// - F1/vm_size -- hardcoded to 0
// - F2/vm_rss -- hardcoded to 0
// - F3/vm_swap -- hardcoded to 0
int32_t fill_event_munmap_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint64_t addr,
                            uint64_t length) {
	return scap_event_encode_params(scap_buf,
	                                event_size,
	                                scap_err,
	                                PPME_SYSCALL_MUNMAP_X,
	                                6,
	                                res,
	                                0,  // vm_size -- INVALID
	                                0,  // vm_rss -- INVALID
	                                0,  // vm_swap -- INVALID
	                                addr,
	                                length);
}

}  // namespace fillers
}  // namespace scap_gvisor
