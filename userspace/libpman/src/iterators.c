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

#include <driver/ppm_events_public.h>
#include <driver/ppm_param_helpers.h>
#include <libpman.h>
#include <libscap/scap.h>
#include <libscap/strl.h>
#include <libscap/scap_likely.h>
#include <libscap/strerror.h>

#include <state.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>

#ifdef BPF_ITERATOR_DEBUG

#if defined(BPF_ITERATOR_DEBUG_RAW) || defined(BPF_ITERATOR_DEBUG_PARSED)

#include <libscap/scap_print.h>

#ifdef BPF_ITERATOR_DEBUG_RAW
#define DEBUG_PRINT_EVENT(evt_ptr) scap_print_event(evt_ptr, PRINT_FULL)
#endif  // BPF_ITERATOR_DEBUG_RAW

#ifdef BPF_ITERATOR_DEBUG_PARSED
#define DEBUG_PRINT_THREADINFO(tinfo_ptr) scap_print_threadinfo(tinfo_ptr)
#define DEBUG_PRINT_FDINFO(fdinfo_ptr) scap_print_fdinfo(fdinfo_ptr)
#endif  // BPF_ITERATOR_DEBUG_PARSED

#endif  // defined(BPF_ITERATOR_DEBUG_RAW) || defined(BPF_ITERATOR_DEBUG_PARSED)

#endif  // BPF_ITERATOR_DEBUG

#ifndef DEBUG_PRINT_EVENT
#define DEBUG_PRINT_EVENT(evt_ptr)
#endif

#ifndef DEBUG_PRINT_THREADINFO
#define DEBUG_PRINT_THREADINFO(tinfo_ptr)
#endif

#ifndef DEBUG_PRINT_FDINFO
#define DEBUG_PRINT_FDINFO(fdinfo_ptr)
#endif

///////////////////////////////////////////////////////////////////////////////
// GENERIC PARSING LOGIC HELPERS
///////////////////////////////////////////////////////////////////////////////

static void get_evt_pid_tid(const struct ppm_evt_hdr *evt, uint32_t *pid_out, uint32_t *tid_out) {
	const uint64_t tgid_pid = evt->tid;
	*pid_out = (uint32_t)(tgid_pid >> 32);
	*tid_out = (uint32_t)tgid_pid;
}

static int32_t check_evt_params(const struct ppm_evt_hdr *evt,
                                const scap_const_sized_buffer *evt_params,
                                const uint32_t params_num,
                                char *error) {
	const struct ppm_event_info *evt_info = &scap_get_event_info_table()[evt->type];
	const uint32_t expected_params_num = evt_info->nparams;
	if(scap_unlikely(params_num < expected_params_num)) {
		return scap_errprintf(
		        error,
		        0,
		        "unexpected number of parameters for event '%s' (%d): expected %d, got %d",
		        evt_info->name,
		        evt->type,
		        expected_params_num,
		        params_num);
	}

	const size_t len_size =
	        evt_info->flags & EF_LARGE_PAYLOAD ? sizeof(uint32_t) : sizeof(uint16_t);

	for(int i = 0; i < expected_params_num; i++) {
		const struct ppm_param_info *param = &evt_info->params[i];
		const size_t actual_param_len = evt_params[i].size;
		uint32_t min_param_len = 0;
		int res = ppm_param_min_len_from_type(param->type, &min_param_len);
		if(scap_unlikely(res < 0)) {
			return scap_errprintf(error,
			                      0,
			                      "bug: unexpected error while getting the minimum length for "
			                      "parameter %d of type %d in event '%s' (%d): %d",
			                      i,
			                      param->type,
			                      evt_info->name,
			                      evt->type,
			                      res);
		}

		uint32_t max_param_len = 0;
		res = ppm_param_max_len_from_type(param->type, len_size, &max_param_len);
		if(scap_unlikely(res < 0)) {
			return scap_errprintf(error,
			                      0,
			                      "bug: unexpected error while getting the maximum length for "
			                      "parameter %d of type %d in event '%s' (%d): %d",
			                      i,
			                      param->type,
			                      evt_info->name,
			                      evt->type,
			                      res);
		}

		if(scap_unlikely(actual_param_len < min_param_len || actual_param_len > max_param_len)) {
			return scap_errprintf(
			        error,
			        0,
			        "unexpected size for parameter %d of type %d in event '%s' (%d): expected "
			        "range [%u; %u], got %lu",
			        i,
			        param->type,
			        evt_info->name,
			        evt->type,
			        min_param_len,
			        max_param_len,
			        actual_param_len);
		}
	}
	return SCAP_SUCCESS;
}

#define COPY_PARAM(dst, param_ptr) memcpy(&(dst), (param_ptr)->buf, sizeof(dst))

static void u64_from_u32_param(uint64_t *dest, const scap_const_sized_buffer *param) {
	uint32_t tmp;
	COPY_PARAM(tmp, param);
	*dest = (uint64_t)tmp;
}

static void i64_from_u32_param(int64_t *dest, const scap_const_sized_buffer *param) {
	uint32_t tmp;
	COPY_PARAM(tmp, param);
	*dest = (int64_t)tmp;
}

static void path_from_fspath_param(void *dest_buff,
                                   const size_t dest_buff_size,
                                   const scap_const_sized_buffer *param) {
	if(param->size > 0) {
		strlcpy(dest_buff, param->buf, dest_buff_size);
	} else {
		((char *)dest_buff)[0] = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
// TASK EVENT HANDLER LOGIC
///////////////////////////////////////////////////////////////////////////////

static void tinfo_exe_and_args_from_argv_param(scap_threadinfo *tinfo,
                                               const scap_const_sized_buffer *param) {
	const char *buff = param->buf;
	const size_t buff_size = param->size;
	if(buff_size == 0) {
		tinfo->exe[0] = 0;
		tinfo->args[0] = 0;
		tinfo->args_len = 0;
		return;
	}

	const size_t n = strlcpy(tinfo->exe, buff, sizeof(tinfo->exe));
	const size_t argv0_size = n + 1 < buff_size ? n + 1 : buff_size;  // `+ 1` to include '\0'.
	tinfo->args_len = buff_size - argv0_size;
	if(tinfo->args_len > 0) {
		memcpy(tinfo->args, buff + argv0_size, tinfo->args_len);
		tinfo->args[tinfo->args_len - 1] = 0;
	} else {
		tinfo->args[0] = 0;
		tinfo->args_len = 0;
	}
}

static void tinfo_flags_from_flags_param(scap_threadinfo *tinfo,
                                         const scap_const_sized_buffer *param) {
	uint32_t flags;
	memcpy(&flags, param->buf, sizeof(flags));
	tinfo->exe_writable = (flags & PPM_EXE_WRITABLE) != 0;
	tinfo->exe_upper_layer = (flags & PPM_EXE_UPPER_LAYER) != 0;
	tinfo->exe_lower_layer = (flags & PPM_EXE_LOWER_LAYER) != 0;
	tinfo->exe_from_memfd = (flags & PPM_EXE_FROM_MEMFD) != 0;
}

static void tinfo_env_from_env_param(scap_threadinfo *tinfo, const scap_const_sized_buffer *param) {
	const char *buff = param->buf;
	const size_t buff_size = param->size;
	if(buff_size == 0) {
		tinfo->env[0] = 0;
		tinfo->env_len = 0;
		return;
	}

	const size_t env_size = buff_size <= sizeof(tinfo->env) ? buff_size : sizeof(tinfo->env);
	memcpy(&tinfo->env, buff, env_size);
	// The following is needed when the actual size is capped to `sizeof(tinfo->env)`.
	tinfo->env[env_size - 1] = 0;
	tinfo->env_len = env_size;
}

static void tinfo_cgroups_from_cgroups_param(scap_threadinfo *tinfo,
                                             const scap_const_sized_buffer *param) {
	const char *buff = param->buf;
	const size_t buff_size = param->size;
	struct scap_cgroup_set *cgroups = &tinfo->cgroups;
	if(buff_size == 0) {
		cgroups->path[0] = 0;
		cgroups->len = 0;
		return;
	}

	const size_t cgroups_size =
	        buff_size <= sizeof(cgroups->path) ? buff_size : sizeof(cgroups->path);
	memcpy(&cgroups->path, buff, cgroups_size);
	// The following is needed when the actual size is capped to `sizeof(cgroups->path)`.
	cgroups->path[cgroups_size - 1] = 0;
	cgroups->len = cgroups_size;
}

static void tinfo_from_task_evt(scap_threadinfo *tinfo,
                                const uint32_t pid,
                                const uint32_t tid,
                                const scap_const_sized_buffer *evt_params) {
	tinfo->tid = (uint64_t)tid;
	tinfo->pid = (uint64_t)pid;
	u64_from_u32_param(&tinfo->ptid, &evt_params[0]);                                // ppid
	u64_from_u32_param(&tinfo->sid, &evt_params[3]);                                 // sid
	u64_from_u32_param(&tinfo->vpgid, &evt_params[2]);                               // vpgid
	u64_from_u32_param(&tinfo->pgid, &evt_params[1]);                                // pgid
	path_from_fspath_param(tinfo->comm, sizeof(tinfo->comm), &evt_params[4]);        // comm
	tinfo_exe_and_args_from_argv_param(tinfo, &evt_params[5]);                       // argv
	path_from_fspath_param(tinfo->exepath, sizeof(tinfo->exepath), &evt_params[6]);  // exepath
	tinfo_flags_from_flags_param(tinfo, &evt_params[7]);                             // flags
	tinfo_env_from_env_param(tinfo, &evt_params[8]);                                 // env
	path_from_fspath_param(tinfo->cwd, sizeof(tinfo->cwd), &evt_params[9]);          // cwd
	COPY_PARAM(tinfo->fdlimit, &evt_params[10]);                                     // fdlimit
	// The following logic is copied from `userspace/libscap/linux/scap_procs.c`, and while it is
	// reliable for `PPM_CL_CLONE_THREAD`, it is not for `PPM_CL_CLONE_FILES`. We should directly
	// take this information in kernel.
	tinfo->flags = tinfo->tid == tinfo->pid ? 0 : PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES;
	COPY_PARAM(tinfo->uid, &evt_params[11]);              // euid
	COPY_PARAM(tinfo->gid, &evt_params[12]);              // egid
	COPY_PARAM(tinfo->cap_permitted, &evt_params[13]);    // cap_permitted
	COPY_PARAM(tinfo->cap_effective, &evt_params[14]);    // cap_effective
	COPY_PARAM(tinfo->cap_inheritable, &evt_params[15]);  // cap_inheritable
	COPY_PARAM(tinfo->exe_ino, &evt_params[16]);          // exe_ino_num
	COPY_PARAM(tinfo->exe_ino_ctime, &evt_params[17]);    // exe_ino_ctime
	COPY_PARAM(tinfo->exe_ino_mtime, &evt_params[18]);    // exe_ino_mtime
	// `exe_ino_ctime_duration_clone_ts` and `exe_ino_ctime_duration_pidns_start` are implicitely
	// set to 0 in `userspace/libscap/linux/scap_procs.c`. We should take this information in
	// kernel.
	tinfo->exe_ino_ctime_duration_clone_ts = 0;
	tinfo->exe_ino_ctime_duration_pidns_start = 0;
	COPY_PARAM(tinfo->vmsize_kb, &evt_params[19]);             // vm_size
	COPY_PARAM(tinfo->vmrss_kb, &evt_params[20]);              // vm_rss
	COPY_PARAM(tinfo->vmswap_kb, &evt_params[21]);             // vm_swap
	COPY_PARAM(tinfo->pfmajor, &evt_params[22]);               // pgft_maj
	COPY_PARAM(tinfo->pfminor, &evt_params[23]);               // pgft_min
	i64_from_u32_param(&tinfo->vtid, &evt_params[25]);         // vpid
	i64_from_u32_param(&tinfo->vpid, &evt_params[24]);         // vtgid
	COPY_PARAM(tinfo->pidns_init_start_ts, &evt_params[26]);   // pidns_init_start_ts
	tinfo_cgroups_from_cgroups_param(tinfo, &evt_params[27]);  // cgroups
	path_from_fspath_param(tinfo->root, sizeof(tinfo->root), &evt_params[28]);  // root
	COPY_PARAM(tinfo->clone_ts, &evt_params[29]);                               // start_time
	COPY_PARAM(tinfo->tty, &evt_params[30]);                                    // tty
	COPY_PARAM(tinfo->loginuid, &evt_params[31]);                               // loginuid
}

static void handle_task_evt(const struct ppm_evt_hdr *evt,
                            const scap_const_sized_buffer *evt_params,
                            const struct scap_fetch_callbacks *callbacks,
                            scap_threadinfo **tinfo_out,
                            const scap_sized_buffer *cb_err_buff) {
	uint32_t pid, tid;
	get_evt_pid_tid(evt, &pid, &tid);

	scap_threadinfo tinfo = {};
	tinfo_from_task_evt(&tinfo, pid, tid, evt_params);

	DEBUG_PRINT_THREADINFO(&tinfo);

	const int32_t res = callbacks->proc_entry_cb(callbacks->ctx,
	                                             cb_err_buff->buf,
	                                             (int64_t)tid,
	                                             &tinfo,
	                                             NULL,
	                                             tinfo_out);
	if(scap_unlikely(res != SCAP_SUCCESS)) {
		pman_print_msgf(FALCOSECURITY_LOG_SEV_DEBUG,
		                "process entry callback failed with error code %d for thread (pid: %u, "
		                "tid: %u): %.*s",
		                res,
		                pid,
		                tid,
		                (int)cb_err_buff->size,
		                (char *)cb_err_buff->buf);
	}
}

///////////////////////////////////////////////////////////////////////////////
// BOOTSTRAP AND ROUTING LOGIC
///////////////////////////////////////////////////////////////////////////////

// Select the logic that must be used to handle an event.
enum evt_handler_selector {
	EHS_TASK,
};

static int32_t fetch_evts(const int iter_fd,
                          const enum evt_handler_selector selector,
                          const struct scap_fetch_callbacks *callbacks,
                          scap_threadinfo **tinfo,
                          char *error) {
	// Stack buffer to accommodate at least one event at the time.
	char buff[MAX_ITER_EVENT_SIZE];
	size_t bytes_in_buff = 0;

	// Buffer used to store any error resulting from callback invocation.
	char cb_err[256] = {0};
	const scap_sized_buffer cb_err_buff = {&cb_err, sizeof(cb_err)};

	while(true) {
		const ssize_t bytes_read =
		        read(iter_fd, buff + bytes_in_buff, sizeof(buff) - bytes_in_buff);
		if(bytes_read < 0) {
			if(errno == EAGAIN || errno == EINTR) {  // Re-attempt upon signal.
				continue;
			}
			return scap_errprintf(error, errno, "failed to read from iter FD %d", iter_fd);
		}
		if(bytes_read == 0) {
			return SCAP_SUCCESS;
		}
		bytes_in_buff += bytes_read;

		char *data_start = buff;
		const char *data_end = buff + bytes_in_buff;

		while(true) {
			const size_t data_len = data_end - data_start;
			if(data_len < sizeof(struct ppm_evt_hdr)) {
				break;
			}

			const struct ppm_evt_hdr *evt = (struct ppm_evt_hdr *)data_start;
			const size_t evt_len = evt->len;
			if(data_len < evt_len) {
				break;
			}

			DEBUG_PRINT_EVENT(evt);

			scap_const_sized_buffer evt_params[PPM_MAX_EVENT_PARAMS];
			// note: we let `scap_event_decode_params()' believe `evt_params` is a
			// `scap_sized_buffer` array instead of `scap_const_sized_buffer` one, so that it can
			// write into it.
			const uint32_t params_num =
			        scap_event_decode_params(evt, (scap_sized_buffer *)&evt_params);
			const int32_t res = check_evt_params(evt, evt_params, params_num, error);
			if(scap_unlikely(res != SCAP_SUCCESS)) {
				return res;
			}

			cb_err[0] = 0;
			switch(selector) {
			case EHS_TASK:
				handle_task_evt(evt, evt_params, callbacks, tinfo, &cb_err_buff);
				break;
			default:
				return scap_errprintf(error, 0, "bug: unknown event handler selector %d", selector);
			}

			data_start += evt_len;
		}

		// Apply shifting logic to move the truncated event (if any) at the beginning of the buffer.
		// note: this remove from the buffer any processed data, that is data in the range
		// [buff, buff+processed_data_len]).
		// note: the shift is not applied if we haven't processed any data in this iteration.
		const size_t processed_data_len = data_start - buff;
		const size_t buff_unprocessed_data_len = bytes_in_buff - processed_data_len;
		if(buff_unprocessed_data_len > 0 && processed_data_len > 0) {
			memmove(buff, buff + processed_data_len, buff_unprocessed_data_len);
		}

		bytes_in_buff = buff_unprocessed_data_len;

		// Do not allow for unprocessed data with size is bigger than the maximum allowed size for
		// an iterator event.
		if(bytes_in_buff >= MAX_ITER_EVENT_SIZE) {
			return scap_errprintf(
			        error,
			        0,
			        "%lu bytes left on the buffer while the maximum allowed event size is %d bytes",
			        bytes_in_buff,
			        MAX_ITER_EVENT_SIZE);
		}
	}
}

struct prog_info {
	struct bpf_link **link;
	const struct bpf_program *prog;
	const char *name;
	enum evt_handler_selector selector;
};

static int32_t fetch(const struct prog_info *prog_info,
                     const struct scap_fetch_callbacks *callbacks,
                     const int pid_filter,
                     const int tid_filter,
                     scap_threadinfo **tinfo,
                     char *error) {
	if(pid_filter != 0 && tid_filter != 0) {
		return scap_errprintf(error,
		                      0,
		                      "bug: wrong configuration: pid_filter (%d) and tid_filter (%d) "
		                      "cannot be both non-zero",
		                      pid_filter,
		                      tid_filter);
	}

	// The program must not be already attached.
	if(*prog_info->link) {
		return scap_errprintf(error,
		                      0,
		                      "'%s' program is unexpectedly already attached",
		                      prog_info->name);
	}

	errno = 0;
	int32_t res = SCAP_SUCCESS;
	int iter_fd = -1;

	// Attach the program.
	LIBBPF_OPTS(bpf_iter_attach_opts, opts);
	union bpf_iter_link_info linfo;
	memset(&linfo, 0, sizeof(linfo));
	linfo.task.pid = pid_filter;  // If the pid is set to zero, no filtering logic is applied.
	linfo.task.tid = tid_filter;  // If the tid is set to zero, no filtering logic is applied.
	opts.link_info = &linfo;
	opts.link_info_len = sizeof(linfo);
	*prog_info->link = bpf_program__attach_iter(prog_info->prog, &opts);
	if(!*prog_info->link) {
		res = scap_errprintf(error, errno, "failed to attach the '%s' program", prog_info->name);
		goto cleanup;
	}

	// Create the iter FD.
	iter_fd = bpf_iter_create(bpf_link__fd(*prog_info->link));
	if(iter_fd < 0) {
		res = scap_errprintf(error,
		                     errno,
		                     "failed to create iter FD for '%s' program",
		                     prog_info->name);
		goto cleanup;
	}

	res = fetch_evts(iter_fd, prog_info->selector, callbacks, tinfo, error);

cleanup:
	if(iter_fd >= 0 && close(iter_fd) < 0) {
		pman_print_errorf("failed to close iter FD for `%s` program", prog_info->name);
	}
	if(*prog_info->link && bpf_link__destroy(*prog_info->link)) {
		pman_print_errorf("failed to detach the `%s` program", prog_info->name);
	}
	*prog_info->link = NULL;
	return res;
}

static void fill_dump_task_prog_info(struct prog_info *info) {
	info->link = &g_state.skel->links.dump_task;
	info->prog = g_state.skel->progs.dump_task;
	info->name = "dump_task";
	info->selector = EHS_TASK;
}

int32_t pman_iter_fetch_task(const struct scap_fetch_callbacks *callbacks,
                             const uint32_t tid,
                             scap_threadinfo **tinfo,
                             char *error) {
#ifndef BPF_ITERATOR_SUPPORT
	return SCAP_NOT_SUPPORTED;
#else
	if(!g_state.is_tasks_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	struct prog_info prog_info;
	fill_dump_task_prog_info(&prog_info);
	return fetch(&prog_info, callbacks, 0, tid, tinfo, error);
#endif
}

int32_t pman_iter_fetch_tasks(const struct scap_fetch_callbacks *callbacks, char *error) {
#ifndef BPF_ITERATOR_SUPPORT
	return SCAP_NOT_SUPPORTED;
#else
	if(!g_state.is_tasks_dumping_supported) {
		return SCAP_NOT_SUPPORTED;
	}

	struct prog_info prog_info;
	fill_dump_task_prog_info(&prog_info);
	return fetch(&prog_info, callbacks, 0, 0, NULL, error);
#endif
}

int32_t pman_iter_fetch_proc_file(const struct scap_fetch_callbacks *callbacks,
                                  const uint32_t pid,
                                  const uint32_t fd,
                                  char *error) {
#ifndef BPF_ITERATOR_SUPPORT
	return SCAP_NOT_SUPPORTED;
#else
	// todo(ekoops): add support here.
	return SCAP_NOT_SUPPORTED;
#endif
}

int32_t pman_iter_fetch_proc_files(const struct scap_fetch_callbacks *callbacks,
                                   const uint32_t pid,
                                   const bool must_fetch_sockets,
                                   uint64_t *num_files_fetched,
                                   char *error) {
#ifndef BPF_ITERATOR_SUPPORT
	return SCAP_NOT_SUPPORTED;
#else
	// todo(ekoops): add support here.
	return SCAP_NOT_SUPPORTED;
#endif
}

int32_t pman_iter_fetch_procs_files(const struct scap_fetch_callbacks *callbacks, char *error) {
#ifndef BPF_ITERATOR_SUPPORT
	return SCAP_NOT_SUPPORTED;
#else
	// todo(ekoops): add support here.
	return SCAP_NOT_SUPPORTED;
#endif
}
