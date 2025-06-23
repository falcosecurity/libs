// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <libscap/scap_const.h>
#include <driver/ppm_events_public.h>
#include <converter/table.h>

// We cannot use designated initializers, we need c++20
const std::unordered_map<conversion_key, conversion_info> g_conversion_table = {
        /*====================== CLOSE ======================*/
        {conversion_key{PPME_SYSCALL_CLOSE_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_CLOSE_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== READ ======================*/
        {conversion_key{PPME_SYSCALL_READ_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_READ_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== PREAD ======================*/
        {conversion_key{PPME_SYSCALL_PREAD_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PREAD_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== GETRLIMIT ======================*/
        {conversion_key{PPME_SYSCALL_GETRLIMIT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_GETRLIMIT_X, 3},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SETRLIMIT ======================*/
        {conversion_key{PPME_SYSCALL_SETRLIMIT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETRLIMIT_X, 3},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== BRK ======================*/
        {conversion_key{PPME_SYSCALL_BRK_4_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_BRK_4_X, 4},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== BIND ======================*/
        {conversion_key{PPME_SOCKET_BIND_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_BIND_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SOCKET ======================*/
        {conversion_key{PPME_SOCKET_SOCKET_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_SOCKET_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== LISTEN ======================*/
        {conversion_key{PPME_SOCKET_LISTEN_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_LISTEN_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== ACCEPT ======================*/
        {conversion_key{PPME_SOCKET_ACCEPT_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SOCKET_ACCEPT_X, 3},
         conversion_info()
                 .desired_type(PPME_SOCKET_ACCEPT_5_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},
                         {C_INSTR_FROM_OLD, 1},
                         {C_INSTR_FROM_OLD, 2},
                         {C_INSTR_FROM_DEFAULT, 0},
                         {C_INSTR_FROM_DEFAULT, 0},
                 })},
        {conversion_key{PPME_SOCKET_ACCEPT_5_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        /*====================== WRITE ======================*/
        {conversion_key{PPME_SYSCALL_WRITE_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_WRITE_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== PWRITE ======================*/
        {conversion_key{PPME_SYSCALL_PWRITE_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PWRITE_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== SETRESUID ======================*/
        {conversion_key{PPME_SYSCALL_SETRESUID_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETRESUID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== SETUID ======================*/
        {conversion_key{PPME_SYSCALL_SETUID_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETUID_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== RECV ======================*/
        {conversion_key{PPME_SOCKET_RECV_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_RECV_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_DEFAULT, 0}})},
        /*====================== RECVFROM ======================*/
        {conversion_key{PPME_SOCKET_RECVFROM_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_RECVFROM_X, 3},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== SEND ======================*/
        {conversion_key{PPME_SOCKET_SEND_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_SEND_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_DEFAULT, 0}})},
        /*====================== SENDTO ======================*/
        {conversion_key{PPME_SOCKET_SENDTO_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_SENDTO_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== SHUTDOWN ======================*/
        {conversion_key{PPME_SOCKET_SHUTDOWN_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_SHUTDOWN_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== SOCKETPAIR ======================*/
        {conversion_key{PPME_SOCKET_SOCKETPAIR_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_SOCKETPAIR_X, 5},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== SENDMSG ======================*/
        {conversion_key{PPME_SOCKET_SENDMSG_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_SENDMSG_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== RECVMSG ======================*/
        {conversion_key{PPME_SOCKET_RECVMSG_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_RECVMSG_X, 4},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_DEFAULT, 0}})},
        {conversion_key{PPME_SOCKET_RECVMSG_X, 5},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== EVENTFD ======================*/
        {conversion_key{PPME_SYSCALL_EVENTFD_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_EVENTFD_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== MKDIR ======================*/
        {conversion_key{PPME_SYSCALL_MKDIR_2_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MKDIR_2_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        {conversion_key{PPME_SYSCALL_MKDIR_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MKDIR_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_MKDIR_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0},
                          {C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1}})},
        /*====================== FUTEX ======================*/
        {conversion_key{PPME_SYSCALL_FUTEX_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_FUTEX_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== FSTAT ======================*/
        {conversion_key{PPME_SYSCALL_FSTAT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_FSTAT_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== EPOLL_WAIT ======================*/
        {conversion_key{PPME_SYSCALL_EPOLLWAIT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_EPOLLWAIT_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== POLL ======================*/
        {conversion_key{PPME_SYSCALL_POLL_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_POLL_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 1}})},
        /*====================== LLSEEK ======================*/
        {conversion_key{PPME_SYSCALL_LLSEEK_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_LLSEEK_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== IOCTL ======================*/
        {conversion_key{PPME_SYSCALL_IOCTL_3_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_IOCTL_3_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== MMAP ======================*/
        {conversion_key{PPME_SYSCALL_MMAP_E, 6}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MMAP_X, 4},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2},
                          {C_INSTR_FROM_ENTER, 3},
                          {C_INSTR_FROM_ENTER, 4},
                          {C_INSTR_FROM_ENTER, 5}})},
        /*====================== MMAP2 ======================*/
        {conversion_key{PPME_SYSCALL_MMAP2_E, 6}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MMAP2_X, 4},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2},
                          {C_INSTR_FROM_ENTER, 3},
                          {C_INSTR_FROM_ENTER, 4},
                          {C_INSTR_FROM_ENTER, 5}})},
        /*====================== MUNMAP ======================*/
        {conversion_key{PPME_SYSCALL_MUNMAP_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MUNMAP_X, 4},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== PTRACE ======================*/
        {conversion_key{PPME_SYSCALL_PTRACE_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PTRACE_X, 3},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== FCHDIR ======================*/
        {conversion_key{PPME_SYSCALL_FCHDIR_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_FCHDIR_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== GETDENTS ======================*/
        {conversion_key{PPME_SYSCALL_GETDENTS_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_GETDENTS_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== GETDENTS64 ======================*/
        {conversion_key{PPME_SYSCALL_GETDENTS64_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_GETDENTS64_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SETNS ======================*/
        {conversion_key{PPME_SYSCALL_SETNS_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETNS_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== FLOCK ======================*/
        {conversion_key{PPME_SYSCALL_FLOCK_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_FLOCK_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== SEMOP ======================*/
        {conversion_key{PPME_SYSCALL_SEMOP_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SEMOP_X, 8},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SEMCTL ======================*/
        {conversion_key{PPME_SYSCALL_SEMCTL_E, 4}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SEMCTL_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2},
                          {C_INSTR_FROM_ENTER, 3}})},
        /*====================== PPOLL ======================*/
        {conversion_key{PPME_SYSCALL_PPOLL_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PPOLL_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 1}, {C_INSTR_FROM_ENTER, 2}})},
        /*====================== MOUNT ======================*/
        {conversion_key{PPME_SYSCALL_MOUNT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MOUNT_X, 4},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SEMGET ======================*/
        {conversion_key{PPME_SYSCALL_SEMGET_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SEMGET_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== SETGID ======================*/
        {conversion_key{PPME_SYSCALL_SETGID_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETGID_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SETPGID ======================*/
        {conversion_key{PPME_SYSCALL_SETPGID_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETPGID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== SETRESGID ======================*/
        {conversion_key{PPME_SYSCALL_SETRESGID_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETRESGID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
};
