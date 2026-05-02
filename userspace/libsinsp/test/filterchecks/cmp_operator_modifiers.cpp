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

// End-to-end filtercheck tests for every comparator × modifier combination.
//
// proc.name is a single-value string field (PT_CHARBUF). For a single extracted value v:
//   oneof  : true iff exactly one extracted value satisfies in_rhs(v)   — same as anyof for one
//   value anyof  : true iff at least one extracted value satisfies in_rhs(v)  — same as oneof for
//   one value allof  : true iff every extracted value satisfies in_rhs(v)         — same as oneof
//   for one value
//
// in_rhs semantics (given RHS set R):
//   CO_EQ/CO_CONTAINS/etc. : ∃ r∈R : v op r  — v satisfies op against some element of R
//   CO_NE                  : ∀ r∈R : v ≠ r   — v is not equal to any element of R (membership
//   negation) CO_REGEX               : ∃ r∈R : r matches v  — any regex pattern in R matches v
//
// Multi-value modifier semantics (oneof=exactly-one / anyof=at-least-one / allof=all) are
// exercised against mock filter checks in filter_compiler.ut.cpp.

#include <helpers/threads_helpers.h>

// ── == ───────────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_eq) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	// oneof: field value must be in the RHS set
	EXPECT_TRUE(eval_filter(evt, "proc.name == oneof (myexe, bash)"));
	EXPECT_TRUE(eval_filter(evt, "proc.name == oneof (myexe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name == oneof (bash, sh)"));

	// anyof: identical semantics to oneof for a single-value field
	EXPECT_TRUE(eval_filter(evt, "proc.name == anyof (myexe, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name == anyof (bash, sh)"));

	// allof: field must equal ALL listed values (only possible with a single distinct value)
	EXPECT_TRUE(eval_filter(evt, "proc.name == allof (myexe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name == allof (myexe, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name == allof (bash, sh)"));
}

// ── != ───────────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_ne) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	// in_rhs for !=: v ∉ RHS (not equal to any element)
	EXPECT_TRUE(eval_filter(evt, "proc.name != oneof (bash, sh)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name != oneof (myexe, bash)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name != anyof (bash, sh)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name != anyof (myexe, bash)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name != allof (bash, sh)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name != allof (myexe, bash)"));
}

// ── contains ─────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_contains) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name contains oneof (myex, bash)"));
	EXPECT_TRUE(eval_filter(evt, "proc.name contains oneof (exe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name contains oneof (bash, sh)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name contains anyof (myex, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name contains anyof (bash, sh)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name contains allof (my, exe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name contains allof (myex, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name contains allof (bash, sh)"));
}

// ── icontains ────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_icontains) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name icontains oneof (MYEX, BASH)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name icontains oneof (BASH, SH)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name icontains anyof (MYEX, BASH)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name icontains anyof (BASH, SH)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name icontains allof (MY, EXE)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name icontains allof (MYEX, BASH)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name icontains allof (BASH, SH)"));
}

// ── startswith ───────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_startswith) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name startswith oneof (my, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name startswith oneof (bash, sh)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name startswith anyof (my, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name startswith anyof (bash, sh)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name startswith allof (my, mye)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name startswith allof (my, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name startswith allof (bash, sh)"));
}

// ── endswith ─────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_endswith) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name endswith oneof (exe, sh)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name endswith oneof (sh, bash)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name endswith anyof (exe, sh)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name endswith anyof (sh, bash)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name endswith allof (exe, yexe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name endswith allof (exe, sh)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name endswith allof (sh, bash)"));
}

// ── glob ─────────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_glob) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name glob oneof (my*, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name glob oneof (bash, sh*)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name glob anyof (my*, bash)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name glob anyof (bash, sh*)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name glob allof (my*, *exe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name glob allof (bash, sh*)"));
}

// ── iglob ─────────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_iglob) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name iglob oneof (MY*, BASH)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name iglob oneof (BASH, SH*)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name iglob anyof (MY*, BASH)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name iglob anyof (BASH, SH*)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name iglob allof (MY*, *EXE)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name iglob allof (BASH, SH*)"));
}

// ── regex ─────────────────────────────────────────────────────────────────────

TEST_F(sinsp_with_test_input, FILTERCHECK_MOD_regex) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_execve_enter_and_exit_event(0,
	                                                 INIT_TID,
	                                                 INIT_TID,
	                                                 INIT_PID,
	                                                 INIT_PTID,
	                                                 "/myexe",
	                                                 "myexe");

	EXPECT_TRUE(eval_filter(evt, "proc.name regex oneof (my.*, b.*)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name regex oneof (b.*, sh.*)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name regex anyof (my.*, b.*)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name regex anyof (b.*, sh.*)"));

	EXPECT_TRUE(eval_filter(evt, "proc.name regex allof (my.*, .*exe)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name regex allof (my.*, b.*)"));
	EXPECT_FALSE(eval_filter(evt, "proc.name regex allof (b.*, sh.*)"));
}
