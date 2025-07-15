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

#include <vector>
#include <functional>

#include <libscap/engine/gvisor/gvisor.h>
#include "pkg/sentry/seccheck/points/syscall.pb.h"

namespace scap_gvisor {
namespace fillers {

int32_t fill_event_clone_20_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

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
                              uint64_t pidns_init_start_ts);

int32_t fill_event_fork_20_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

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
                             uint64_t pidns_init_start_ts);

int32_t fill_event_vfork_20_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

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
                              uint64_t pidns_init_start_ts);

int32_t fill_event_execve_19_e(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               const char* filename);

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
                               uint32_t gid);

int32_t fill_event_execveat_e(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t dirfd,
                              const char* pathname,
                              uint32_t flags);

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
                              uint32_t uid);

int32_t fill_event_procexit_1_e(scap_sized_buffer scap_buf,
                                size_t* event_size,
                                char* scap_err,
                                uint32_t status,
                                uint32_t ret,
                                uint32_t sig,
                                uint32_t core);

int32_t fill_event_open_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          const char* name,
                          uint32_t flags,
                          uint32_t mode);

int32_t fill_event_open_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t fd,
                          const char* name,
                          uint32_t flags,
                          uint32_t mode);

int32_t fill_event_openat_2_e(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t dirfd,
                              const char* name,
                              uint32_t flags,
                              uint32_t mode);

int32_t fill_event_openat_2_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t fd,
                              int64_t dirfd,
                              const char* name,
                              uint32_t flags,
                              uint32_t mode);

int32_t fill_event_creat_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           const char* name,
                           uint32_t mode);

int32_t fill_event_creat_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd,
                           const char* name,
                           uint32_t mode);

int32_t fill_event_close_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd);

int32_t fill_event_close_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t fd);

int32_t fill_event_read_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t fd,
                          uint32_t size);

int32_t fill_event_read_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t fd,
                          uint32_t size);

int32_t fill_event_pread_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd,
                           uint32_t size,
                           uint64_t pos);

int32_t fill_event_pread_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t fd,
                           uint32_t size,
                           uint64_t pos);

int32_t fill_event_readv_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd);

int32_t fill_event_readv_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           uint32_t size,
                           int64_t fd);

int32_t fill_event_preadv_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t fd,
                            uint64_t pos);

int32_t fill_event_preadv_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint32_t size,
                            int64_t fd,
                            uint64_t pos);

int32_t fill_event_connect_e(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t fd,
                             scap_const_sized_buffer addr);

int32_t fill_event_connect_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             scap_const_sized_buffer tuple,
                             int64_t fd,
                             scap_const_sized_buffer addr);

int32_t fill_event_socket_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            uint32_t domain,
                            uint32_t type,
                            uint32_t protocol);

int32_t fill_event_socket_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t fd,
                            uint32_t domain,
                            uint32_t type,
                            uint32_t protocol);

int32_t fill_event_chdir_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

int32_t fill_event_chdir_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           const char* path);

int32_t fill_event_fchdir_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t fd);

int32_t fill_event_fchdir_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            int64_t fd);

int32_t fill_event_setuid_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            uint32_t uid);

int32_t fill_event_setuid_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint32_t uid);

int32_t fill_event_setgid_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            uint32_t gid);

int32_t fill_event_setgid_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint32_t gid);

int32_t fill_event_setsid_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

int32_t fill_event_setsid_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res);

int32_t fill_event_setresuid_e(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               uint32_t ruid,
                               uint32_t euid,
                               uint32_t suid);

int32_t fill_event_setresuid_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t res,
                               uint32_t ruid,
                               uint32_t euid,
                               uint32_t suid);

int32_t fill_event_setresgid_e(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               uint32_t rgid,
                               uint32_t egid,
                               uint32_t sgid);

int32_t fill_event_setresgid_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t res,
                               uint32_t rgid,
                               uint32_t egid,
                               uint32_t sgid);

int32_t fill_event_prlimit_e(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t pid,
                             uint8_t resource);

int32_t fill_event_prlimit_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             int64_t newcur,
                             int64_t newmax,
                             int64_t oldcur,
                             int64_t oldmax);

int32_t fill_event_pipe_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

int32_t fill_event_pipe_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t fd1,
                          int64_t fd2);

int32_t fill_event_fcntl_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd,
                           uint8_t cmd);

int32_t fill_event_fcntl_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res);

int32_t fill_event_dup_1_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd);

int32_t fill_event_dup_1_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t oldfd);

int32_t fill_event_dup2_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t fd);

int32_t fill_event_dup2_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t oldfd,
                          int64_t newfd);

int32_t fill_event_dup3_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t fd);

int32_t fill_event_dup3_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          int64_t oldfd,
                          int64_t newfd,
                          uint32_t flags);

int32_t fill_event_signalfd_e(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t fd,
                              uint32_t mask,
                              uint8_t flags);

int32_t fill_event_signalfd_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t res,
                              int64_t fd,
                              uint32_t mask,
                              uint8_t flags);

int32_t fill_event_chroot_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

int32_t fill_event_chroot_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            const char* path);

int32_t fill_event_eventfd_e(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             uint64_t initval,
                             uint32_t flags);

int32_t fill_event_eventfd_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res);

int32_t fill_event_bind_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t fd);

int32_t fill_event_bind_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          scap_const_sized_buffer addr,
                          int64_t fd);

int32_t fill_event_accept_5_e(scap_sized_buffer scap_buf, size_t* event_size, char* scap_err);

int32_t fill_event_accept_5_x(scap_sized_buffer scap_buf,
                              size_t* event_size,
                              char* scap_err,
                              int64_t fd,
                              scap_const_sized_buffer tuple);

int32_t fill_event_accept4_6_e(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int32_t flags);

int32_t fill_event_accept4_6_x(scap_sized_buffer scap_buf,
                               size_t* event_size,
                               char* scap_err,
                               int64_t fd,
                               scap_const_sized_buffer tuple,
                               int32_t flags);

int32_t fill_event_timerfd_create_e(scap_sized_buffer scap_buf,
                                    size_t* event_size,
                                    char* scap_err,
                                    uint8_t clockid,
                                    uint8_t flags);

int32_t fill_event_timerfd_create_x(scap_sized_buffer scap_buf,
                                    size_t* event_size,
                                    char* scap_err,
                                    int64_t res,
                                    uint8_t clockid,
                                    uint8_t flags);

int32_t fill_event_inotify_init_e(scap_sized_buffer scap_buf,
                                  size_t* event_size,
                                  char* scap_err,
                                  uint8_t flags);

int32_t fill_event_inotify_init_x(scap_sized_buffer scap_buf,
                                  size_t* event_size,
                                  char* scap_err,
                                  int64_t res,
                                  uint8_t flags);

int32_t fill_event_socketpair_e(scap_sized_buffer scap_buf,
                                size_t* event_size,
                                char* scap_err,
                                uint32_t domain,
                                uint32_t type,
                                uint32_t proto);

int32_t fill_event_socketpair_x(scap_sized_buffer scap_buf,
                                size_t* event_size,
                                char* scap_err,
                                int64_t res,
                                int64_t fd1,
                                int64_t fd2);

int32_t fill_event_write_e(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t fd,
                           uint32_t size);

int32_t fill_event_write_x(scap_sized_buffer scap_buf,
                           size_t* event_size,
                           char* scap_err,
                           int64_t res,
                           int64_t fd,
                           uint32_t size);

int32_t fill_event_pwrite_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t fd,
                            uint32_t size,
                            uint64_t pos);

int32_t fill_event_pwrite_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            int64_t fd,
                            uint32_t size,
                            uint64_t pos);

int32_t fill_event_writev_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t fd,
                            uint32_t size);

int32_t fill_event_writev_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            int64_t fd,
                            uint32_t size);

int32_t fill_event_pwritev_e(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t fd,
                             uint32_t size,
                             uint64_t pos);

int32_t fill_event_pwritev_x(scap_sized_buffer scap_buf,
                             size_t* event_size,
                             char* scap_err,
                             int64_t res,
                             int64_t fd,
                             uint32_t size,
                             uint64_t pos);

int32_t fill_event_mmap_e(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          uint64_t addr,
                          uint64_t length,
                          uint32_t prot,
                          uint32_t flags,
                          int64_t fd,
                          uint64_t offset);

int32_t fill_event_mmap_x(scap_sized_buffer scap_buf,
                          size_t* event_size,
                          char* scap_err,
                          int64_t res,
                          uint64_t addr,
                          uint64_t length,
                          uint32_t prot,
                          uint32_t flags,
                          int64_t fd,
                          uint64_t offset);

int32_t fill_event_munmap_e(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            uint64_t addr,
                            uint64_t length);

int32_t fill_event_munmap_x(scap_sized_buffer scap_buf,
                            size_t* event_size,
                            char* scap_err,
                            int64_t res,
                            uint64_t addr,
                            uint64_t length);

}  // namespace fillers
}  // namespace scap_gvisor
