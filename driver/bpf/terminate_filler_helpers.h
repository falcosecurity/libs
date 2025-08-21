#pragma once
#include "types.h"
#include "ppm_events_public.h"

static __always_inline int __bpf_terminate_filler() {
	struct scap_bpf_per_cpu_state *state;

	state = get_local_state(bpf_get_smp_processor_id());
	if(!state)
		return 0;

	switch(state->tail_ctx.prev_res) {
	case PPM_SUCCESS:
		break;
	case PPM_FAILURE_BUFFER_FULL:
		bpf_printk("PPM_FAILURE_BUFFER_FULL event=%d curarg=%d\n",
		           state->tail_ctx.evt_type,
		           state->tail_ctx.curarg);
		if(state->n_drops_buffer != ULLONG_MAX) {
			++state->n_drops_buffer;
		}
		switch(state->tail_ctx.evt_type) {
		// enter
		case PPME_SYSCALL_OPEN_E:
		case PPME_SYSCALL_CREAT_E:
		case PPME_SYSCALL_OPENAT_2_E:
		case PPME_SYSCALL_OPENAT2_E:
		case PPME_SYSCALL_OPEN_BY_HANDLE_AT_E:
			if(state->n_drops_buffer_open_enter != ULLONG_MAX) {
				++state->n_drops_buffer_open_enter;
			}
			break;
		case PPME_SYSCALL_DUP_E:
		case PPME_SYSCALL_CHMOD_E:
		case PPME_SYSCALL_FCHMOD_E:
		case PPME_SYSCALL_FCHMODAT_E:
		case PPME_SYSCALL_CHOWN_E:
		case PPME_SYSCALL_LCHOWN_E:
		case PPME_SYSCALL_FCHOWN_E:
		case PPME_SYSCALL_FCHOWNAT_E:
		case PPME_SYSCALL_LINK_2_E:
		case PPME_SYSCALL_LINKAT_2_E:
		case PPME_SYSCALL_MKDIR_2_E:
		case PPME_SYSCALL_MKDIRAT_E:
		case PPME_SYSCALL_MOUNT_E:
		case PPME_SYSCALL_UMOUNT_1_E:
		case PPME_SYSCALL_UMOUNT2_E:
		case PPME_SYSCALL_RENAME_E:
		case PPME_SYSCALL_RENAMEAT_E:
		case PPME_SYSCALL_RENAMEAT2_E:
		case PPME_SYSCALL_RMDIR_2_E:
		case PPME_SYSCALL_SYMLINK_E:
		case PPME_SYSCALL_SYMLINKAT_E:
		case PPME_SYSCALL_UNLINK_2_E:
		case PPME_SYSCALL_UNLINKAT_2_E:
			if(state->n_drops_buffer_dir_file_enter != ULLONG_MAX) {
				++state->n_drops_buffer_dir_file_enter;
			}
			break;
		case PPME_SYSCALL_CLONE_20_E:
		case PPME_SYSCALL_CLONE3_E:
		case PPME_SYSCALL_FORK_20_E:
		case PPME_SYSCALL_VFORK_20_E:
			if(state->n_drops_buffer_clone_fork_enter != ULLONG_MAX) {
				++state->n_drops_buffer_clone_fork_enter;
			}
			break;
		case PPME_SYSCALL_EXECVE_19_E:
		case PPME_SYSCALL_EXECVEAT_E:
			if(state->n_drops_buffer_execve_enter != ULLONG_MAX) {
				++state->n_drops_buffer_execve_enter;
			}
			break;
		case PPME_SOCKET_CONNECT_E:
			if(state->n_drops_buffer_connect_enter != ULLONG_MAX) {
				++state->n_drops_buffer_connect_enter;
			}
			break;
		case PPME_SYSCALL_BPF_2_E:
		case PPME_SYSCALL_SETPGID_E:
		case PPME_SYSCALL_PTRACE_E:
		case PPME_SYSCALL_SECCOMP_E:
		case PPME_SYSCALL_SETNS_E:
		case PPME_SYSCALL_SETRESGID_E:
		case PPME_SYSCALL_SETRESUID_E:
		case PPME_SYSCALL_SETSID_E:
		case PPME_SYSCALL_UNSHARE_E:
		case PPME_SYSCALL_CAPSET_E:
			if(state->n_drops_buffer_other_interest_enter != ULLONG_MAX) {
				++state->n_drops_buffer_other_interest_enter;
			}
			break;
		case PPME_PROCEXIT_1_E:
			if(state->n_drops_buffer_proc_exit != ULLONG_MAX) {
				++state->n_drops_buffer_proc_exit;
			}
			break;
		// exit
		case PPME_SYSCALL_OPEN_X:
		case PPME_SYSCALL_CREAT_X:
		case PPME_SYSCALL_OPENAT_2_X:
		case PPME_SYSCALL_OPENAT2_X:
		case PPME_SYSCALL_OPEN_BY_HANDLE_AT_X:
			if(state->n_drops_buffer_open_exit != ULLONG_MAX) {
				++state->n_drops_buffer_open_exit;
			}
			break;
		case PPME_SYSCALL_DUP_X:
		case PPME_SYSCALL_CHMOD_X:
		case PPME_SYSCALL_FCHMOD_X:
		case PPME_SYSCALL_FCHMODAT_X:
		case PPME_SYSCALL_CHOWN_X:
		case PPME_SYSCALL_LCHOWN_X:
		case PPME_SYSCALL_FCHOWN_X:
		case PPME_SYSCALL_FCHOWNAT_X:
		case PPME_SYSCALL_LINK_2_X:
		case PPME_SYSCALL_LINKAT_2_X:
		case PPME_SYSCALL_MKDIR_2_X:
		case PPME_SYSCALL_MKDIRAT_X:
		case PPME_SYSCALL_MOUNT_X:
		case PPME_SYSCALL_UMOUNT_1_X:
		case PPME_SYSCALL_UMOUNT2_X:
		case PPME_SYSCALL_RENAME_X:
		case PPME_SYSCALL_RENAMEAT_X:
		case PPME_SYSCALL_RENAMEAT2_X:
		case PPME_SYSCALL_RMDIR_2_X:
		case PPME_SYSCALL_SYMLINK_X:
		case PPME_SYSCALL_SYMLINKAT_X:
		case PPME_SYSCALL_UNLINK_2_X:
		case PPME_SYSCALL_UNLINKAT_2_X:
			if(state->n_drops_buffer_dir_file_exit != ULLONG_MAX) {
				++state->n_drops_buffer_dir_file_exit;
			}
			break;
		case PPME_SYSCALL_CLONE_20_X:
		case PPME_SYSCALL_CLONE3_X:
		case PPME_SYSCALL_FORK_20_X:
		case PPME_SYSCALL_VFORK_20_X:
			if(state->n_drops_buffer_clone_fork_exit != ULLONG_MAX) {
				++state->n_drops_buffer_clone_fork_exit;
			}
			break;
		case PPME_SYSCALL_EXECVE_19_X:
		case PPME_SYSCALL_EXECVEAT_X:
			if(state->n_drops_buffer_execve_exit != ULLONG_MAX) {
				++state->n_drops_buffer_execve_exit;
			}
			break;
		case PPME_SOCKET_CONNECT_X:
			if(state->n_drops_buffer_connect_exit != ULLONG_MAX) {
				++state->n_drops_buffer_connect_exit;
			}
			break;
		case PPME_SYSCALL_BPF_2_X:
		case PPME_SYSCALL_SETPGID_X:
		case PPME_SYSCALL_PTRACE_X:
		case PPME_SYSCALL_SECCOMP_X:
		case PPME_SYSCALL_SETNS_X:
		case PPME_SYSCALL_SETRESGID_X:
		case PPME_SYSCALL_SETRESUID_X:
		case PPME_SYSCALL_SETSID_X:
		case PPME_SYSCALL_UNSHARE_X:
		case PPME_SYSCALL_CAPSET_X:
			if(state->n_drops_buffer_other_interest_exit != ULLONG_MAX) {
				++state->n_drops_buffer_other_interest_exit;
			}
			break;
		case PPME_SYSCALL_CLOSE_X:
			if(state->n_drops_buffer_close_exit != ULLONG_MAX) {
				++state->n_drops_buffer_close_exit;
			}
			break;
		default:
			break;
		}
		break;
	case PPM_FAILURE_INVALID_USER_MEMORY:
		bpf_printk("PPM_FAILURE_INVALID_USER_MEMORY event=%d curarg=%d\n",
		           state->tail_ctx.evt_type,
		           state->tail_ctx.curarg);
		if(state->n_drops_pf != ULLONG_MAX) {
			++state->n_drops_pf;
		}
		break;
	case PPM_FAILURE_BUG:
		bpf_printk("PPM_FAILURE_BUG event=%d curarg=%d\n",
		           state->tail_ctx.evt_type,
		           state->tail_ctx.curarg);
		if(state->n_drops_bug != ULLONG_MAX) {
			++state->n_drops_bug;
		}
		break;
	case PPM_SKIP_EVENT:
		break;
	case PPM_FAILURE_FRAME_SCRATCH_MAP_FULL:
		bpf_printk("PPM_FAILURE_FRAME_SCRATCH_MAP_FULL event=%d curarg=%d\n",
		           state->tail_ctx.evt_type,
		           state->tail_ctx.curarg);
		if(state->n_drops_scratch_map != ULLONG_MAX) {
			++state->n_drops_scratch_map;
		}
		break;
	default:
		bpf_printk("Unknown filler res=%d event=%d curarg=%d\n",
		           state->tail_ctx.prev_res,
		           state->tail_ctx.evt_type,
		           state->tail_ctx.curarg);
		break;
	}

	release_local_state(state);
	return 0;
}
