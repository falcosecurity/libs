// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#pragma once

/**
 * @brief Attaches only the syscall_exit_dispatcher.
 * @return `0` on success, `errno` in case of error.
 */
int attach_syscall_exit_dispatcher();

/**
 * @brief Detach only the syscall_exit_dispatcher.
 * @return `0` on success, `errno` in case of error.
 */
int detach_syscall_exit_dispatcher();

/**
 * @brief Attaches only the sched_process_exit tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_sched_proc_exit();

/**
 * @brief Detach only the sched_process_exit tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_sched_proc_exit();

/**
 * @brief Attaches only the sched_switch tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_sched_switch();

/**
 * @brief Detach only the sched_switch tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_sched_switch();

/**
 * @brief Attaches only the sched_proc_exec tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_sched_proc_exec();

/**
 * @brief Detach only the sched_proc_exec tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_sched_proc_exec();

/**
 * @brief Attaches only the sched_proc_fork tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_sched_proc_fork();

/**
 * @brief Detach only the sched_proc_fork tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_sched_proc_fork();

/**
 * @brief Attaches only the page_fault_user tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_page_fault_user();

/**
 * @brief Detach only the page_fault_user tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_page_fault_user();

/**
 * @brief Attaches only the page_fault_kernel tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_page_fault_kernel();

/**
 * @brief Detach only the page_fault_kernel tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_page_fault_kernel();

/**
 * @brief Attaches only the signal_deliver tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int attach_signal_deliver();

/**
 * @brief Detach only the signal_deliver tracepoint.
 * @return `0` on success, `errno` in case of error.
 */
int detach_signal_deliver();

/*
 * @brief Attaches only the connect TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int attach_connect_toctou_mitigation_progs();

/**
 * @brief Detach only the connect TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int detach_connect_toctou_mitigation_progs();

/**
 * @brief Attaches only the creat TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int attach_creat_toctou_mitigation_progs();

/**
 * @brief Detach only the creat TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int detach_creat_toctou_mitigation_progs();

/**
 * @brief Attaches only the open TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int attach_open_toctou_mitigation_progs();

/**
 * @brief Detach only the open TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int detach_open_toctou_mitigation_progs();

/**
 * @brief Attaches only the openat TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int attach_openat_toctou_mitigation_progs();

/**
 * @brief Detach only the openat TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int detach_openat_toctou_mitigation_progs();

/**
 * @brief Attaches only the openat2 TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int attach_openat2_toctou_mitigation_progs();

/**
 * @brief Detach only the openat2 TOCTOU mitigation programs.
 * @return `0` on success, `errno` in case of error.
 */
int detach_openat2_toctou_mitigation_progs();
