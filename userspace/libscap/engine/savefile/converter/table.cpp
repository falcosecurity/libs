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
        /*====================== GENERIC ======================*/
        {conversion_key{PPME_GENERIC_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_GENERIC_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
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
        /*====================== LINK ======================*/
        {conversion_key{PPME_SYSCALL_LINK_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_LINK_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_LINK_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0},
                          {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== LINKAT ======================*/
        {conversion_key{PPME_SYSCALL_LINKAT_E, 4}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_LINKAT_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_LINKAT_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},                           // res
                         {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},  // olddir
                         {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY},  // oldpath
                         {C_INSTR_FROM_ENTER, 2, CIF_FALLBACK_TO_EMPTY},  // newdir
                         {C_INSTR_FROM_ENTER, 3, CIF_FALLBACK_TO_EMPTY},  // newpath
                         {C_INSTR_FROM_EMPTY, 0},                         // flags
                 })},
        /*====================== UNLINK ======================*/
        {conversion_key{PPME_SYSCALL_UNLINK_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_UNLINK_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_UNLINK_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0}, {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== UNLINKAT ======================*/
        {conversion_key{PPME_SYSCALL_UNLINKAT_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_UNLINKAT_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_UNLINKAT_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},
                         {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                         {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY},
                         {C_INSTR_FROM_EMPTY, 0},  // flags
                 })},
        /*====================== PREAD ======================*/
        {conversion_key{PPME_SYSCALL_PREAD_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PREAD_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== DUP ======================*/
        {conversion_key{PPME_SYSCALL_DUP_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_DUP_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_DUP_1_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},                           // res
                         {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},  // oldfd
                 })},
        /*====================== SIGNALFD ======================*/
        {conversion_key{PPME_SYSCALL_SIGNALFD_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SIGNALFD_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== KILL ======================*/
        {conversion_key{PPME_SYSCALL_KILL_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_KILL_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== TKILL ======================*/
        {conversion_key{PPME_SYSCALL_TKILL_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_TKILL_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== TGKILL ======================*/
        {conversion_key{PPME_SYSCALL_TGKILL_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_TGKILL_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== NANOSLEEP ======================*/
        {conversion_key{PPME_SYSCALL_NANOSLEEP_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_NANOSLEEP_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== TIMERFD_CREATE ======================*/
        {conversion_key{PPME_SYSCALL_TIMERFD_CREATE_E, 2},
         conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_TIMERFD_CREATE_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== INOTIFY_INIT ======================*/
        {conversion_key{PPME_SYSCALL_INOTIFY_INIT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_INOTIFY_INIT_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== GETRLIMIT ======================*/
        {conversion_key{PPME_SYSCALL_GETRLIMIT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_GETRLIMIT_X, 3},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SETRLIMIT ======================*/
        {conversion_key{PPME_SYSCALL_SETRLIMIT_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETRLIMIT_X, 3},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== PRLIMIT ======================*/
        {conversion_key{PPME_SYSCALL_PRLIMIT_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PRLIMIT_X, 5},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== FCNTL ======================*/
        {conversion_key{PPME_SYSCALL_FCNTL_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_FCNTL_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== BRK ======================*/
        {conversion_key{PPME_SYSCALL_BRK_1_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_BRK_1_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_BRK_4_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},                           // res
                         {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},  // vm_size
                         {C_INSTR_FROM_EMPTY},                            // vm_rss
                         {C_INSTR_FROM_EMPTY},                            // vm_swap
                         {C_INSTR_FROM_EMPTY},                            // addr
                 })},
        {conversion_key{PPME_SYSCALL_BRK_4_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_BRK_4_X, 4},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== EXECVE ======================*/
        {conversion_key{PPME_SYSCALL_EXECVE_8_E, 0},
         conversion_info().desired_type(PPME_SYSCALL_EXECVE_13_E).action(C_ACTION_CHANGE_TYPE)},
        {conversion_key{PPME_SYSCALL_EXECVE_8_X, 8},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_13_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_EMPTY, 0},  // pgft_maj
                         {C_INSTR_FROM_EMPTY, 0},  // pgft_min
                         {C_INSTR_FROM_EMPTY, 0},  // vm_size
                         {C_INSTR_FROM_EMPTY, 0},  // vm_rss
                         {C_INSTR_FROM_EMPTY, 0},  // vm_swap
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_13_E, 0},
         conversion_info().desired_type(PPME_SYSCALL_EXECVE_14_E).action(C_ACTION_CHANGE_TYPE)},
        {conversion_key{PPME_SYSCALL_EXECVE_13_X, 13},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_14_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_EMPTY, 0},  // env
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_14_E, 0},
         conversion_info().desired_type(PPME_SYSCALL_EXECVE_15_E).action(C_ACTION_CHANGE_TYPE)},
        {conversion_key{PPME_SYSCALL_EXECVE_14_X, 14},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_15_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_EMPTY, 0},  // comm
                         {C_INSTR_FROM_OLD, 13},   // env
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_15_E, 0},
         conversion_info().desired_type(PPME_SYSCALL_EXECVE_16_E).action(C_ACTION_CHANGE_TYPE)},
        {conversion_key{PPME_SYSCALL_EXECVE_15_X, 15},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_16_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_OLD, 13},   // comm
                         {C_INSTR_FROM_EMPTY, 0},  // cgroups
                         {C_INSTR_FROM_OLD, 14},   // env
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_16_E, 0},
         conversion_info().desired_type(PPME_SYSCALL_EXECVE_17_E).action(C_ACTION_CHANGE_TYPE)},
        {conversion_key{PPME_SYSCALL_EXECVE_16_X, 16},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_17_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_OLD, 13},   // comm
                         {C_INSTR_FROM_OLD, 14},   // cgroups
                         {C_INSTR_FROM_OLD, 15},   // env
                         {C_INSTR_FROM_EMPTY, 0},  // tty
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_17_E, 0},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_18_E)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // filename
        {conversion_key{PPME_SYSCALL_EXECVE_17_X, 17},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_18_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},   // res
                         {C_INSTR_FROM_OLD, 1},   // exe
                         {C_INSTR_FROM_OLD, 2},   // args
                         {C_INSTR_FROM_OLD, 3},   // tid
                         {C_INSTR_FROM_OLD, 4},   // pid
                         {C_INSTR_FROM_OLD, 5},   // ptid
                         {C_INSTR_FROM_OLD, 6},   // cwd
                         {C_INSTR_FROM_OLD, 7},   // fdlimit
                         {C_INSTR_FROM_OLD, 8},   // pgft_maj
                         {C_INSTR_FROM_OLD, 9},   // pgft_min
                         {C_INSTR_FROM_OLD, 10},  // vm_size
                         {C_INSTR_FROM_OLD, 11},  // vm_rss
                         {C_INSTR_FROM_OLD, 12},  // vm_swap
                         {C_INSTR_FROM_OLD, 13},  // comm
                         {C_INSTR_FROM_OLD, 14},  // cgroups
                         {C_INSTR_FROM_OLD, 15},  // env
                         {C_INSTR_FROM_OLD, 16},  // tty
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_18_E, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_19_E)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0}})},  // filename
        {conversion_key{PPME_SYSCALL_EXECVE_18_X, 17},
         conversion_info()
                 .desired_type(PPME_SYSCALL_EXECVE_19_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_OLD, 13},   // comm
                         {C_INSTR_FROM_OLD, 14},   // cgroups
                         {C_INSTR_FROM_OLD, 15},   // env
                         {C_INSTR_FROM_OLD, 16},   // tty
                         {C_INSTR_FROM_EMPTY, 0},  // vpgid
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 18},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // loginuid
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 19},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // flags
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 20},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({
                         {C_INSTR_FROM_EMPTY, 0},  // cap_inheritable
                         {C_INSTR_FROM_EMPTY, 0},  // cap_permitted
                         {C_INSTR_FROM_EMPTY, 0},  // cap_effective
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 23},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({
                         {C_INSTR_FROM_EMPTY, 0},  // exe_ino
                         {C_INSTR_FROM_EMPTY, 0},  // exe_ino_ctime
                         {C_INSTR_FROM_EMPTY, 0},  // exe_ino_mtime
                 })},
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 26},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // uid
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 27},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // trusted_exepath
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 28},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // pgid
        {conversion_key{PPME_SYSCALL_EXECVE_19_X, 29},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // gid
        /*====================== CLONE ======================*/
        {conversion_key{PPME_SYSCALL_CLONE_11_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_CLONE_11_X, 11},
         conversion_info()
                 .desired_type(PPME_SYSCALL_CLONE_16_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_EMPTY, 0},  // pgft_maj
                         {C_INSTR_FROM_EMPTY, 0},  // pgft_min
                         {C_INSTR_FROM_EMPTY, 0},  // vm_size
                         {C_INSTR_FROM_EMPTY, 0},  // vm_rss
                         {C_INSTR_FROM_EMPTY, 0},  // vm_swap
                         {C_INSTR_FROM_OLD, 8},    // flags
                         {C_INSTR_FROM_OLD, 9},    // uid
                         {C_INSTR_FROM_OLD, 10},   // gid
                 })},
        {conversion_key{PPME_SYSCALL_CLONE_16_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_CLONE_16_X, 16},
         conversion_info()
                 .desired_type(PPME_SYSCALL_CLONE_17_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_EMPTY, 0},  // comm
                         {C_INSTR_FROM_OLD, 13},   // flags
                         {C_INSTR_FROM_OLD, 14},   // uid
                         {C_INSTR_FROM_OLD, 15},   // gid
                 })},
        {conversion_key{PPME_SYSCALL_CLONE_17_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_CLONE_17_X, 17},
         conversion_info()
                 .desired_type(PPME_SYSCALL_CLONE_20_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_OLD, 13},   // comm
                         {C_INSTR_FROM_EMPTY, 0},  // cgroups
                         {C_INSTR_FROM_OLD, 14},   // flags
                         {C_INSTR_FROM_OLD, 15},   // uid
                         {C_INSTR_FROM_OLD, 16},   // gid
                         {C_INSTR_FROM_EMPTY, 0},  // vtid
                         {C_INSTR_FROM_EMPTY, 0},  // vpid
                 })},
        {conversion_key{PPME_SYSCALL_CLONE_20_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_CLONE_20_X, 20},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // pidns_init_start_ts
        /*====================== BIND ======================*/
        {conversion_key{PPME_SOCKET_BIND_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_BIND_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== CONNECT ======================*/
        {conversion_key{PPME_SOCKET_CONNECT_E, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_DEFAULT, 0}})},
        {conversion_key{PPME_SOCKET_CONNECT_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_CONNECT_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        {conversion_key{PPME_SOCKET_CONNECT_X, 3},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 1}})},
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
        /*====================== READV ======================*/
        {conversion_key{PPME_SYSCALL_READV_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_READV_X, 3},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== WRITEV ======================*/
        {conversion_key{PPME_SYSCALL_WRITEV_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_WRITEV_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== PREADV ======================*/
        {conversion_key{PPME_SYSCALL_PREADV_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PREADV_X, 3},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== PWRITEV ======================*/
        {conversion_key{PPME_SYSCALL_PWRITEV_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PWRITEV_X, 2},
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
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 2, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== SETUID ======================*/
        {conversion_key{PPME_SYSCALL_SETUID_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETUID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
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
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
        {conversion_key{PPME_SYSCALL_MKDIR_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MKDIR_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_MKDIR_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0},
                          {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== RMDIR ======================*/
        {conversion_key{PPME_SYSCALL_RMDIR_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_RMDIR_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_RMDIR_2_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0}, {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== UNSHARE ======================*/
        {conversion_key{PPME_SYSCALL_UNSHARE_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_UNSHARE_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
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
        /*====================== LSEEK ======================*/
        {conversion_key{PPME_SYSCALL_LSEEK_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_LSEEK_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== LLSEEK ======================*/
        {conversion_key{PPME_SYSCALL_LLSEEK_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_LLSEEK_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== IOCTL ======================*/
        {conversion_key{PPME_SYSCALL_IOCTL_2_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_IOCTL_2_X, 1},
         conversion_info()
                 .desired_type(PPME_SYSCALL_IOCTL_3_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},                           // res
                         {C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},  // fd
                         {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY},  // request
                         {C_INSTR_FROM_EMPTY},                            // argument
                 })},
        {conversion_key{PPME_SYSCALL_IOCTL_3_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_IOCTL_3_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({
                         {C_INSTR_FROM_ENTER, 0},  // fd
                         {C_INSTR_FROM_ENTER, 1},  // request
                         {C_INSTR_FROM_ENTER, 2},  // argument
                 })},
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
        /*====================== SPLICE ======================*/
        {conversion_key{PPME_SYSCALL_SPLICE_E, 4}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SPLICE_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2},
                          {C_INSTR_FROM_ENTER, 3}})},
        /*====================== PTRACE ======================*/
        {conversion_key{PPME_SYSCALL_PTRACE_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_PTRACE_X, 0},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0},
                          {C_INSTR_FROM_EMPTY, 0},
                          {C_INSTR_FROM_EMPTY, 0}})},
        {conversion_key{PPME_SYSCALL_PTRACE_X, 3},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== FORK ======================*/
        {conversion_key{PPME_SYSCALL_FORK_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_FORK_X, 16},
         conversion_info()
                 .desired_type(PPME_SYSCALL_FORK_17_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_EMPTY, 0},  // comm
                         {C_INSTR_FROM_OLD, 13},   // flags
                         {C_INSTR_FROM_OLD, 14},   // uid
                         {C_INSTR_FROM_OLD, 15},   // gid
                 })},
        {conversion_key{PPME_SYSCALL_FORK_17_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_FORK_17_X, 17},
         conversion_info()
                 .desired_type(PPME_SYSCALL_FORK_20_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_OLD, 13},   // comm
                         {C_INSTR_FROM_EMPTY, 0},  // cgroups
                         {C_INSTR_FROM_OLD, 14},   // flags
                         {C_INSTR_FROM_OLD, 15},   // uid
                         {C_INSTR_FROM_OLD, 16},   // gid
                         {C_INSTR_FROM_EMPTY, 0},  // vtid
                         {C_INSTR_FROM_EMPTY, 0},  // vpid
                 })},
        {conversion_key{PPME_SYSCALL_FORK_20_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_FORK_20_X, 20},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // pidns_init_start_ts
        /*====================== VFORK ======================*/
        {conversion_key{PPME_SYSCALL_VFORK_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_VFORK_X, 16},
         conversion_info()
                 .desired_type(PPME_SYSCALL_VFORK_17_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_EMPTY, 0},  // comm
                         {C_INSTR_FROM_OLD, 13},   // flags
                         {C_INSTR_FROM_OLD, 14},   // uid
                         {C_INSTR_FROM_OLD, 15},   // gid
                 })},
        {conversion_key{PPME_SYSCALL_VFORK_17_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_VFORK_17_X, 17},
         conversion_info()
                 .desired_type(PPME_SYSCALL_VFORK_20_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},    // res
                         {C_INSTR_FROM_OLD, 1},    // exe
                         {C_INSTR_FROM_OLD, 2},    // args
                         {C_INSTR_FROM_OLD, 3},    // tid
                         {C_INSTR_FROM_OLD, 4},    // pid
                         {C_INSTR_FROM_OLD, 5},    // ptid
                         {C_INSTR_FROM_OLD, 6},    // cwd
                         {C_INSTR_FROM_OLD, 7},    // fdlimit
                         {C_INSTR_FROM_OLD, 8},    // pgft_maj
                         {C_INSTR_FROM_OLD, 9},    // pgft_min
                         {C_INSTR_FROM_OLD, 10},   // vm_size
                         {C_INSTR_FROM_OLD, 11},   // vm_rss
                         {C_INSTR_FROM_OLD, 12},   // vm_swap
                         {C_INSTR_FROM_OLD, 13},   // comm
                         {C_INSTR_FROM_EMPTY, 0},  // cgroups
                         {C_INSTR_FROM_OLD, 14},   // flags
                         {C_INSTR_FROM_OLD, 15},   // uid
                         {C_INSTR_FROM_OLD, 16},   // gid
                         {C_INSTR_FROM_EMPTY, 0},  // vtid
                         {C_INSTR_FROM_EMPTY, 0},  // vpid
                 })},
        {conversion_key{PPME_SYSCALL_VFORK_20_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_VFORK_20_X, 20},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // pidns_init_start_ts
        /*====================== SENDFILE ======================*/
        {conversion_key{PPME_SYSCALL_SENDFILE_E, 4}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SENDFILE_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 3}})},
        /*====================== QUOTACTL ======================*/
        {conversion_key{PPME_SYSCALL_QUOTACTL_E, 4}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_QUOTACTL_X, 14},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2},
                          {C_INSTR_FROM_ENTER, 3}})},
        /*====================== FCHDIR ======================*/
        {conversion_key{PPME_SYSCALL_FCHDIR_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_FCHDIR_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
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
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
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
        /*====================== UMOUNT ======================*/
        {conversion_key{PPME_SYSCALL_UMOUNT_E, 1}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_UMOUNT_X, 2},
         conversion_info()
                 .desired_type(PPME_SYSCALL_UMOUNT_1_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({
                         {C_INSTR_FROM_OLD, 0},  // res
                         {C_INSTR_FROM_OLD, 1},  // name
                 })},
        /*====================== SEMGET ======================*/
        {conversion_key{PPME_SYSCALL_SEMGET_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SEMGET_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== ACCESS ======================*/
        {conversion_key{PPME_SYSCALL_ACCESS_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_ACCESS_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SETGID ======================*/
        {conversion_key{PPME_SYSCALL_SETGID_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETGID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== SETPGID ======================*/
        {conversion_key{PPME_SYSCALL_SETPGID_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETPGID_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETPGID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== SECCOMP ======================*/
        {conversion_key{PPME_SYSCALL_SECCOMP_E, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_DEFAULT, 0}})},
        {conversion_key{PPME_SYSCALL_SECCOMP_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SECCOMP_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
        /*====================== MPROTECT ======================*/
        {conversion_key{PPME_SYSCALL_MPROTECT_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_MPROTECT_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== EXECVEAT ======================*/
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 19},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // flags
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 20},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({
                         {C_INSTR_FROM_EMPTY, 0},  // cap_inheritable
                         {C_INSTR_FROM_EMPTY, 0},  // cap_permitted
                         {C_INSTR_FROM_EMPTY, 0},  // cap_effective
                 })},
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 23},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({
                         {C_INSTR_FROM_EMPTY, 0},  // exe_ino
                         {C_INSTR_FROM_EMPTY, 0},  // exe_ino_ctime
                         {C_INSTR_FROM_EMPTY, 0},  // exe_ino_mtime
                 })},
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 26},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // uid
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 27},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // trusted_exepath
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 28},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // pgid
        {conversion_key{PPME_SYSCALL_EXECVEAT_X, 29},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_EMPTY, 0}})},  // gid
        /*====================== COPY_FILE_RANGE ======================*/
        {conversion_key{PPME_SYSCALL_COPY_FILE_RANGE_E, 3},
         conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_COPY_FILE_RANGE_X, 3},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0},
                          {C_INSTR_FROM_ENTER, 1},
                          {C_INSTR_FROM_ENTER, 2}})},
        /*====================== CLONE3 ======================*/
        {conversion_key{PPME_SYSCALL_CLONE3_E, 0}, conversion_info().action(C_ACTION_SKIP)},
        {conversion_key{PPME_SYSCALL_CLONE3_X, 20},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_EMPTY, 0}})},  // pidns_init_start_ts
        /*====================== EPOLL_CREATE ======================*/
        {conversion_key{PPME_SYSCALL_EPOLL_CREATE_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_EPOLL_CREATE_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== EPOLL_CREATE1 ======================*/
        {conversion_key{PPME_SYSCALL_EPOLL_CREATE1_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_EPOLL_CREATE1_X, 1},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SETRESGID ======================*/
        {conversion_key{PPME_SYSCALL_SETRESGID_E, 3}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SETRESGID_X, 1},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 1, CIF_FALLBACK_TO_EMPTY},
                          {C_INSTR_FROM_ENTER, 2, CIF_FALLBACK_TO_EMPTY}})},
        /*====================== ACCEPT4 ======================*/
        {conversion_key{PPME_SOCKET_ACCEPT4_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_ACCEPT4_X, 3},
         conversion_info()
                 .desired_type(PPME_SOCKET_ACCEPT4_6_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0},
                          {C_INSTR_FROM_OLD, 1},
                          {C_INSTR_FROM_OLD, 2},
                          {C_INSTR_FROM_DEFAULT, 0},
                          {C_INSTR_FROM_DEFAULT, 0},
                          {C_INSTR_FROM_ENTER, 0}})},
        {conversion_key{PPME_SOCKET_ACCEPT4_5_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_ACCEPT4_5_X, 5},
         conversion_info()
                 .desired_type(PPME_SOCKET_ACCEPT4_6_X)
                 .action(C_ACTION_CHANGE_TYPE)
                 .instrs({{C_INSTR_FROM_OLD, 0},
                          {C_INSTR_FROM_OLD, 1},
                          {C_INSTR_FROM_OLD, 2},
                          {C_INSTR_FROM_OLD, 3},
                          {C_INSTR_FROM_OLD, 4},
                          {C_INSTR_FROM_ENTER, 0}})},
        {conversion_key{PPME_SOCKET_ACCEPT4_6_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SOCKET_ACCEPT4_6_X, 5},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== UMOUNT2 ======================*/
        {conversion_key{PPME_SYSCALL_UMOUNT2_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_UMOUNT2_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== EVENTFD2 ======================*/
        {conversion_key{PPME_SYSCALL_EVENTFD2_E, 1}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_EVENTFD2_X, 2},
         conversion_info().action(C_ACTION_ADD_PARAMS).instrs({{C_INSTR_FROM_ENTER, 0}})},
        /*====================== SIGNALFD4 ======================*/
        {conversion_key{PPME_SYSCALL_SIGNALFD4_E, 2}, conversion_info().action(C_ACTION_STORE)},
        {conversion_key{PPME_SYSCALL_SIGNALFD4_X, 2},
         conversion_info()
                 .action(C_ACTION_ADD_PARAMS)
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})},
};
