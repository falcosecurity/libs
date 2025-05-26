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
                 .instrs({{C_INSTR_FROM_ENTER, 0}, {C_INSTR_FROM_ENTER, 1}})}};
