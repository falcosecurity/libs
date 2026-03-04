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

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define LABEL_FMT "%-25s"

static void print_charbuff_array(const char *label, const char *buf, const size_t buf_size) {
	printf(LABEL_FMT " ", label);
	const char *buf_end = buf + buf_size;

	while(buf < buf_end) {
		printf("%s ", buf);
		buf += strlen(buf) + 1;
	}
	putchar('\n');
}

void scap_print_threadinfo(const scap_threadinfo *tinfo) {
	if(!tinfo) {
		printf("----------------------- THREADINFO (NULL)\n");
		return;
	}

	printf("----------------------- THREADINFO\n");
	printf(LABEL_FMT
	       " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 "\n" LABEL_FMT
	       " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 "\n" LABEL_FMT
	       " %-20" PRId64 " " LABEL_FMT " %-20" PRId64 " " LABEL_FMT " %-20" PRIu32 "\n" LABEL_FMT
	       " %-20" PRIu32 " " LABEL_FMT " %-20" PRId32 " " LABEL_FMT " %-20" PRIu32 "\n" LABEL_FMT
	       " %-20" PRId64 " " LABEL_FMT " %-20" PRIu32 " " LABEL_FMT " %-20d\n" LABEL_FMT
	       " %-20" PRIu16 " " LABEL_FMT " %-20" PRIu16 " " LABEL_FMT " %-20d\n" LABEL_FMT
	       " %-20d " LABEL_FMT " %-20d " LABEL_FMT " %-20d\n" LABEL_FMT " %-20" PRIu32 " " LABEL_FMT
	       " %-20" PRIu32 " " LABEL_FMT " %-20" PRIu32 "\n" LABEL_FMT " %-20" PRIu64 " " LABEL_FMT
	       " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 "\n" LABEL_FMT " 0x%-18" PRIx64 " " LABEL_FMT
	       " 0x%-18" PRIx64 " " LABEL_FMT " 0x%-18" PRIx64 "\n" LABEL_FMT " 0x%-18" PRIx64
	       " " LABEL_FMT " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 "\n" LABEL_FMT " %-20" PRIu64
	       " " LABEL_FMT " %-20" PRIu64 " " LABEL_FMT " %-20" PRIu64 "\n" LABEL_FMT
	       " %s\n" LABEL_FMT " %s\n" LABEL_FMT " %s\n" LABEL_FMT " %s\n" LABEL_FMT " %s\n",
	       "tid:",
	       tinfo->tid,
	       "pid:",
	       tinfo->pid,
	       "ptid:",
	       tinfo->ptid,
	       "sid:",
	       tinfo->sid,
	       "vpgid:",
	       tinfo->vpgid,
	       "pgid:",
	       tinfo->pgid,
	       "vtid:",
	       tinfo->vtid,
	       "vpid:",
	       tinfo->vpid,
	       "uid:",
	       tinfo->uid,
	       "gid:",
	       tinfo->gid,
	       "loginuid:",
	       (int32_t)tinfo->loginuid,
	       "tty:",
	       tinfo->tty,
	       "fdlimit:",
	       tinfo->fdlimit,
	       "flags:",
	       tinfo->flags,
	       "filtered_out:",
	       tinfo->filtered_out,
	       "args_len:",
	       tinfo->args_len,
	       "env_len:",
	       tinfo->env_len,
	       "exe_writable:",
	       tinfo->exe_writable,
	       "exe_upper_layer:",
	       tinfo->exe_upper_layer,
	       "exe_lower_layer:",
	       tinfo->exe_lower_layer,
	       "exe_from_memfd:",
	       tinfo->exe_from_memfd,
	       "vmsize_kb:",
	       tinfo->vmsize_kb,
	       "vmrss_kb:",
	       tinfo->vmrss_kb,
	       "vmswap_kb:",
	       tinfo->vmswap_kb,
	       "pfmajor:",
	       tinfo->pfmajor,
	       "pfminor:",
	       tinfo->pfminor,
	       "clone_ts:",
	       tinfo->clone_ts,
	       "cap_permitted:",
	       tinfo->cap_permitted,
	       "cap_effective:",
	       tinfo->cap_effective,
	       "cap_inheritable:",
	       tinfo->cap_inheritable,
	       "exe_ino:",
	       tinfo->exe_ino,
	       "exe_ino_ctime:",
	       tinfo->exe_ino_ctime,
	       "exe_ino_mtime:",
	       tinfo->exe_ino_mtime,
	       "exe_ino_..._clone_ts:",
	       tinfo->exe_ino_ctime_duration_clone_ts,
	       "exe_ino_..._pidns_start:",
	       tinfo->exe_ino_ctime_duration_pidns_start,
	       "pidns_init_start_ts:",
	       tinfo->pidns_init_start_ts,
	       "comm:",
	       tinfo->comm,
	       "exe:",
	       tinfo->exe,
	       "exepath:",
	       tinfo->exepath,
	       "cwd:",
	       tinfo->cwd,
	       "root:",
	       tinfo->root);
	print_charbuff_array("args:", tinfo->args, tinfo->args_len);
	print_charbuff_array("env:", tinfo->env, tinfo->env_len);
	print_charbuff_array("cgroups:", tinfo->cgroups.path, tinfo->cgroups.len);
	printf("----------------------- \n");
}
