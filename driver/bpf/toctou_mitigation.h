#pragma once
#include "terminate_filler_helpers.h"

// Notice: "ttm" stands for "TOCTOU mitigation".

#define __NR_ia32_connect 362
#define __NR_ia32_creat 8
#define __NR_ia32_open 5
#define __NR_ia32_openat 295
#define __NR_ia32_openat2 437

/* This can only be called from ia-32 TOCTOU mitigation programs (kprobe programs). */
static __always_inline int call_ia32_ttm_filler_wrapper(struct pt_regs *ctx, long syscall_id) {
#if !defined(CONFIG_X86_64) || !defined(CONFIG_IA32_EMULATION)
	return 0;
#else
	if(syscall_id < 0 || syscall_id >= SYSCALL_TABLE_SIZE) {
		return 0;
	}

	if(syscall_id == __NR_ia32_socketcall) {
		// We do not support socketcall when in programs other than raw tracepoints ones.
		return 0;
	}

	// We try to convert the 32-bit id into the 64-bit one.
	syscall_id = convert_ia32_to_64(syscall_id);
	// Syscalls defined only on 32 bits are dropped here.
	if(syscall_id == -1) {
		return 0;
	}

	if(!is_syscall_interesting(syscall_id)) {
		return 0;
	}

	const struct syscall_evt_pair *sc_evt = get_syscall_info(syscall_id);
	if(!sc_evt)
		return 0;

	ppm_event_code evt_type;
	int drop_flags;
	if(sc_evt->flags & UF_USED) {
		evt_type = sc_evt->enter_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_E;
		drop_flags = UF_ALWAYS_DROP;
	}

	call_ia32_ttm_filler(ctx, ctx, evt_type, drop_flags);
	return 0;
#endif
}

/* This can only be called from 64 bit TOCTOU mitigation programs (tracepoint programs). */
static __always_inline int call_64bit_ttm_filler_wrapper(void *ctx, long syscall_id) {
	if(syscall_id < 0 || syscall_id >= SYSCALL_TABLE_SIZE) {
		return 0;
	}

#ifdef __NR_socketcall
	int socketcall_syscall_id = __NR_socketcall;
#else
	int socketcall_syscall_id = -1;
#endif

	/* We do not support socketcall on tracepoints. */
	if(syscall_id == socketcall_syscall_id) {
		return 0;
	}

	if(!is_syscall_interesting(syscall_id)) {
		return 0;
	}

	const struct syscall_evt_pair *sc_evt = get_syscall_info(syscall_id);
	if(!sc_evt)
		return 0;

	ppm_event_code evt_type;
	int drop_flags;
	if(sc_evt->flags & UF_USED) {
		evt_type = sc_evt->enter_event_type;
		drop_flags = sc_evt->flags;
	} else {
		evt_type = PPME_GENERIC_E;
		drop_flags = UF_ALWAYS_DROP;
	}

	call_64bit_ttm_filler(ctx, ctx, evt_type, drop_flags, socketcall_syscall_id);
	return 0;
}

#define TTM_ENTER_FILLER_RAW(x) \
	__bpf_section("tracepoint/filler/toctou/" #x) static __always_inline int bpf_ttm_##x(void *ctx)

#define TTM_ENTER_PROBE(tp_name, prog_name, ctx_type)                                   \
	__bpf_section("tracepoint/syscalls/sys_enter_" #tp_name) static __always_inline int \
	        bpf_ttm_##prog_name(ctx_type *ctx) {                                        \
		return call_64bit_ttm_filler_wrapper(ctx, ctx->__syscall_nr);                   \
	}                                                                                   \
                                                                                        \
	static __always_inline int __bpf_ttm_filler_##prog_name(struct filler_data *data);  \
                                                                                        \
	__bpf_section("tracepoint/filler/toctou/" #prog_name) static __always_inline int    \
	        bpf_ttm_filler_##prog_name(ctx_type *ctx) {                                 \
		struct filler_data data = {0};                                                  \
		int res = init_filler_data(ctx, &data, false);                                  \
		if(res == PPM_SUCCESS) {                                                        \
			if(!data.state->tail_ctx.len) {                                             \
				write_evt_hdr(&data);                                                   \
			}                                                                           \
			res = __bpf_ttm_filler_##prog_name(&data);                                  \
		}                                                                               \
                                                                                        \
		if(res == PPM_SUCCESS) {                                                        \
			res = push_evt_frame(ctx, &data);                                           \
		}                                                                               \
		if(data.state) {                                                                \
			data.state->tail_ctx.prev_res = res;                                        \
		}                                                                               \
		bpf_tail_call(ctx, &ttm_tail_map, PPM_FILLER_terminate_filler);                 \
		bpf_printk("Can't tail call terminate TOCTOU mitigation filler\n");             \
		return 0;                                                                       \
	}                                                                                   \
                                                                                        \
	static __always_inline int __bpf_ttm_filler_##prog_name(struct filler_data *data)

#define TTM_IA32_ENTER_FILLER_RAW(x)                                          \
	__bpf_section("kprobe/filler/ia32_toctou/" #x) static __always_inline int \
	        bpf_ia32_ttm_filler_##x(struct pt_regs *ctx)

/* This is a simplified version of the macro PT_REGS_SYSCALL_REGS exported by the kernel: taking
 * into account the architecture the probe supports, it is enough to define it this way. The
 * "CUSTOM_" prefix is used to avoid confusion with the real macro. */
#define CUSTOM_PT_REGS_SYSCALL_REGS(ctx) \
	((struct pt_regs *)bpf_syscall_get_argument_from_regs(ctx, 0))

#define TTM_IA32_ENTER_PROBE(sc_name, sc_id, prog_name)                                         \
	__bpf_section("kprobe/__ia32_compat_sys_" #sc_name) static __always_inline int              \
	        bpf_ttm_ia32_compat_##prog_name(struct pt_regs *ctx) {                              \
		return call_ia32_ttm_filler_wrapper(ctx, sc_id);                                        \
	}                                                                                           \
                                                                                                \
	__bpf_section("kprobe/__ia32_sys_" #sc_name) static __always_inline int                     \
	        bpf_ttm_ia32_##prog_name(struct pt_regs *ctx) {                                     \
		return call_ia32_ttm_filler_wrapper(ctx, sc_id);                                        \
	}                                                                                           \
                                                                                                \
	static __always_inline int __bpf_ia32_ttm_filler_##prog_name(struct filler_data *data,      \
	                                                             struct pt_regs *regs);         \
                                                                                                \
	__bpf_section("kprobe/filler/ia32_toctou/" #prog_name) int bpf_ia32_ttm_filler_##prog_name( \
	        struct pt_regs *ctx) {                                                              \
		struct filler_data data = {0};                                                          \
		int res = init_filler_data(ctx, &data, false);                                          \
		if(res == PPM_SUCCESS) {                                                                \
			if(!data.state->tail_ctx.len) {                                                     \
				write_evt_hdr(&data);                                                           \
			}                                                                                   \
			res = __bpf_ia32_ttm_filler_##prog_name(&data, CUSTOM_PT_REGS_SYSCALL_REGS(ctx));   \
		}                                                                                       \
                                                                                                \
		if(res == PPM_SUCCESS) {                                                                \
			res = push_evt_frame(ctx, &data);                                                   \
		}                                                                                       \
		if(data.state) {                                                                        \
			data.state->tail_ctx.prev_res = res;                                                \
		}                                                                                       \
		bpf_tail_call(ctx, &ia32_ttm_tail_map, PPM_FILLER_terminate_filler);                    \
		bpf_printk("Can't tail call ia-32 terminate TOCTOU mitigation filler\n");               \
		return 0;                                                                               \
	}                                                                                           \
                                                                                                \
	static __always_inline int __bpf_ia32_ttm_filler_##prog_name(struct filler_data *data,      \
	                                                             struct pt_regs *regs)

/*================================ CONNECT ================================*/

static __always_inline int submit_connect_enter_event(struct filler_data *data,
                                                      int64_t fd,
                                                      struct sockaddr __user *usrsockaddr,
                                                      unsigned long usrsockaddr_len) {
	/* Parameter 1: fd (type: PT_FD) */
	int res = bpf_push_s64_to_ring(data, fd);
	CHECK_RES(res);

	long addr_size = 0;
	if(usrsockaddr != NULL && usrsockaddr_len != 0) {
		struct sockaddr *ksockaddr = (struct sockaddr *)data->tmp_scratch;
		/* Copy the address into kernel memory. */
		res = bpf_addr_to_kernel(usrsockaddr, usrsockaddr_len, ksockaddr);
		if(likely(res >= 0)) {
			/* Convert the fd into socket endpoint information. */
			addr_size = bpf_pack_addr(data, ksockaddr, usrsockaddr_len);
		}
	}

	/* Parameter 2: addr (type: PT_SOCKADDR) */
	data->curarg_already_on_frame = true;
	return bpf_val_to_ring_len(data, 0, addr_size);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_connect/format
struct sys_enter_connect_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t fd;
	uint64_t uservaddr;
	uint64_t addrlen;
};

TTM_ENTER_PROBE(connect, sys_connect_e, struct sys_enter_connect_args) {
	struct sys_enter_connect_args *ctx = data->ctx;

	int64_t fd = (int64_t)(int32_t)ctx->fd;
	struct sockaddr __user *usrsockaddr = (struct sockaddr __user *)ctx->uservaddr;
	unsigned long usrsockaddr_len = (unsigned long)ctx->addrlen;

	return submit_connect_enter_event(data, fd, usrsockaddr, usrsockaddr_len);
}

TTM_IA32_ENTER_PROBE(connect, __NR_ia32_connect, sys_connect_e) {
	int64_t fd = (int64_t)(int32_t)bpf_syscall_get_argument_from_regs(regs, 0);
	struct sockaddr __user *usrsockaddr =
	        (struct sockaddr __user *)bpf_syscall_get_argument_from_regs(regs, 1);
	unsigned long usrsockaddr_len = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 2);

	return submit_connect_enter_event(data, fd, usrsockaddr, usrsockaddr_len);
}

/*================================ CONNECT ================================*/

/*================================ CREAT ================================*/

static __always_inline int submit_creat_enter_event(struct filler_data *data,
                                                    unsigned long filename_pointer,
                                                    unsigned long mode) {
	/* Parameter 1: name (type: PT_FSPATH) */
	int res = bpf_val_to_ring_mem(data, filename_pointer, USER);
	CHECK_RES(res);

	/* Parameter 2: mode (type: PT_UINT32) */
	uint32_t scap_mode = open_modes_to_scap(O_CREAT, mode);
	return bpf_push_u32_to_ring(data, scap_mode);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_creat/format
struct sys_enter_creat_args {
	uint64_t pad;

	uint32_t __syscall_nr;
	uint64_t filename;
	uint64_t mode;
};

TTM_ENTER_PROBE(creat, sys_creat_e, struct sys_enter_creat_args) {
	struct sys_enter_creat_args *ctx = data->ctx;

	unsigned long filename_pointer = (unsigned long)ctx->filename;
	unsigned long mode = (unsigned long)ctx->mode;

	return submit_creat_enter_event(data, filename_pointer, mode);
}

TTM_IA32_ENTER_PROBE(creat, __NR_ia32_creat, sys_creat_e) {
	unsigned long filename_pointer = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 0);
	unsigned long mode = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 1);

	return submit_creat_enter_event(data, filename_pointer, mode);
}

/*================================ CREAT ================================*/

/*================================ OPEN ================================*/

static __always_inline int submit_open_enter_event(struct filler_data *data,
                                                   unsigned long filename_pointer,
                                                   uint32_t flags,
                                                   uint32_t mode) {
	/* Parameter 1: name (type: PT_FSPATH) */
	int res = bpf_val_to_ring(data, filename_pointer);
	CHECK_RES(res);

	/* Parameter 2: flags (type: PT_FLAGS32) */
	uint32_t scap_flags = open_flags_to_scap(flags);
	res = bpf_push_u32_to_ring(data, scap_flags);
	CHECK_RES(res);

	/* Parameter 3: mode (type: PT_UINT32) */
	uint32_t scap_mode = open_modes_to_scap(flags, mode);
	return bpf_push_u32_to_ring(data, scap_mode);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_open/format
struct sys_enter_open_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t filename;
	uint64_t flags;
	uint64_t mode;
};

TTM_ENTER_PROBE(open, sys_open_e, struct sys_enter_open_args) {
	struct sys_enter_open_args *ctx = data->ctx;

	unsigned long filename = (unsigned long)ctx->filename;
	uint32_t original_flags = (uint32_t)ctx->flags;
	uint32_t mode = (uint32_t)ctx->mode;

	return submit_open_enter_event(data, filename, original_flags, mode);
}

TTM_IA32_ENTER_PROBE(open, __NR_ia32_open, sys_open_e) {
	unsigned long filename = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 0);
	uint32_t flags = (uint32_t)bpf_syscall_get_argument_from_regs(regs, 1);
	uint32_t mode = (uint32_t)bpf_syscall_get_argument_from_regs(regs, 2);

	return submit_open_enter_event(data, filename, flags, mode);
}

/*================================ OPEN ================================*/

/*================================ OPENAT ================================*/

static __always_inline int submit_openat_enter_event(struct filler_data *data,
                                                     int64_t dir_fd,
                                                     unsigned long filename_pointer,
                                                     unsigned long flags,
                                                     unsigned long mode) {
	/* Parameter 1: dirfd (type: PT_FD) */
	if(dir_fd == AT_FDCWD) {
		dir_fd = PPM_AT_FDCWD;
	}
	int res = bpf_push_s64_to_ring(data, dir_fd);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	res = bpf_val_to_ring(data, filename_pointer);
	CHECK_RES(res);

	/* Parameter 3: flags (type: PT_FLAGS32) */
	uint32_t scap_flags = open_flags_to_scap(flags);
	res = bpf_push_u32_to_ring(data, scap_flags);
	CHECK_RES(res);

	/* Parameter 4: mode (type: PT_UINT32) */
	uint32_t scap_mode = open_modes_to_scap(flags, mode);

	return bpf_push_u32_to_ring(data, scap_mode);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
struct sys_enter_openat_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t flags;
	uint64_t mode;
};

TTM_ENTER_PROBE(openat, sys_openat_e, struct sys_enter_openat_args) {
	struct sys_enter_openat_args *ctx = data->ctx;

	int64_t dir_fd = (int64_t)(int32_t)ctx->dfd;
	unsigned long filename_pointer = (unsigned long)ctx->filename;
	unsigned long flags = (unsigned long)ctx->flags;
	unsigned long mode = (unsigned long)ctx->mode;

	return submit_openat_enter_event(data, dir_fd, filename_pointer, flags, mode);
}

TTM_IA32_ENTER_PROBE(openat, __NR_ia32_openat, sys_openat_e) {
	int64_t dir_fd = (int64_t)(int32_t)bpf_syscall_get_argument_from_regs(regs, 0);
	unsigned long filename_pointer = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 1);
	unsigned long flags = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 2);
	unsigned long mode = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 3);

	return submit_openat_enter_event(data, dir_fd, filename_pointer, flags, mode);
}

/*================================ OPENAT ================================*/

/*================================ OPENAT2 ================================*/

static __always_inline int submit_openat2_enter_event(struct filler_data *data,
                                                      int64_t dir_fd,
                                                      unsigned long filename_pointer,
                                                      unsigned long open_how_pointer) {
	/* Parameter 1: dirfd (type: PT_FD) */
	if(dir_fd == AT_FDCWD) {
		dir_fd = PPM_AT_FDCWD;
	}
	int res = bpf_push_s64_to_ring(data, dir_fd);
	CHECK_RES(res);

	/* Parameter 2: name (type: PT_FSRELPATH) */
	res = bpf_val_to_ring(data, filename_pointer);
	CHECK_RES(res);

#ifdef __NR_openat2
	struct open_how how = {0};
	if(bpf_probe_read_user(&how, sizeof(struct open_how), (void *)open_how_pointer)) {
		return PPM_FAILURE_INVALID_USER_MEMORY;
	}
	uint32_t flags = open_flags_to_scap(how.flags);
	uint32_t mode = open_modes_to_scap(how.flags, how.mode);
	uint32_t resolve = openat2_resolve_to_scap(how.resolve);
#else
	uint32_t flags = 0;
	uint32_t mode = 0;
	uint32_t resolve = 0;
#endif

	/* Parameter 3: flags (type: PT_FLAGS32) */
	res = bpf_push_u32_to_ring(data, flags);
	CHECK_RES(res);

	/* Parameter 4: mode (type: PT_UINT32) */
	res = bpf_push_u32_to_ring(data, mode);
	CHECK_RES(res);

	/* Parameter 5: resolve (type: PT_FLAGS32) */
	return bpf_push_u32_to_ring(data, resolve);
}

// This struct is defined according to the following format file:
// /sys/kernel/tracing/events/syscalls/sys_enter_openat2/format
struct sys_enter_openat2_args {
	uint64_t pad1;

	uint32_t __syscall_nr;
	uint32_t pad2;
	uint64_t dfd;
	uint64_t filename;
	uint64_t how;
	uint64_t usize;
};

TTM_ENTER_PROBE(openat2, sys_openat2_e, struct sys_enter_openat2_args) {
	struct sys_enter_openat2_args *ctx = data->ctx;

	int64_t dir_fd = (int64_t)(int32_t)ctx->dfd;
	unsigned long filename_pointer = (unsigned long)ctx->filename;
	unsigned long open_how_pointer = (unsigned long)ctx->how;

	return submit_openat2_enter_event(data, dir_fd, filename_pointer, open_how_pointer);
}

TTM_IA32_ENTER_PROBE(openat2, __NR_ia32_openat2, sys_openat2_e) {
	int64_t dir_fd = (int64_t)(int32_t)bpf_syscall_get_argument_from_regs(regs, 0);
	unsigned long filename_pointer = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 1);
	unsigned long open_how_pointer = (unsigned long)bpf_syscall_get_argument_from_regs(regs, 2);

	return submit_openat2_enter_event(data, dir_fd, filename_pointer, open_how_pointer);
}

/*================================ OPENAT2 ================================*/

TTM_ENTER_FILLER_RAW(terminate_filler) {
	return __bpf_terminate_filler();
}

TTM_IA32_ENTER_FILLER_RAW(terminate_filler) {
	return __bpf_terminate_filler();
}

#undef TTM_ENTER_FILLER_RAW
#undef TTM_IA32_ENTER_FILLER_RAW
#undef TTM_ENTER_PROBE
#undef TTM_IA32_ENTER_PROBE
#undef CUSTOM_PT_REGS_SYSCALL_REGS
