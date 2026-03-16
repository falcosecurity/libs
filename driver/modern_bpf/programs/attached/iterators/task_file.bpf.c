// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Copyright (C) 2026 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#include <helpers/interfaces/variable_size_event.h>

static int dump_pipe(struct seq_file *seq,
                     uint64_t tgid_pid,
                     uint32_t fd,
                     struct file *file,
                     struct inode *inode) {
	// Unnamed pipes live in pipefs, while named ones live elsewhere. Check the fs magic to
	// determine the pipe type.
	unsigned long fs_magic = extract__fs_magic_from_inode(inode);
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_PIPE_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: path (type: PT_FSPATH) */
	if(fs_magic == PIPEFS_MAGIC) {
		struct dentry *dentry = extract__dentry_from_file(file);
		const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
		auxmap__store_charbuf_param(auxmap, (unsigned long)name, MAX_PATH, KERNEL);
	} else {
		auxmap__store_d_path(auxmap, &file->f_path);
	}
	/* Parameter 3: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_memfd_file(struct seq_file *seq,
                           uint64_t tgid_pid,
                           uint32_t fd,
                           struct file *file,
                           struct inode *inode) {
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_MEMFD_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: path (type: PT_FSPATH) */
	auxmap__store_d_path(auxmap, &file->f_path);
	/* Parameter 3: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_regular_or_device_file(struct seq_file *seq,
                                       uint64_t tgid_pid,
                                       uint32_t fd,
                                       struct file *file,
                                       struct inode *inode) {
	uint32_t flags = BPF_CORE_READ(file, f_flags);
	uint32_t scap_flags = (uint32_t)open_flags_to_scap(flags);
	struct mount *mnt = extract__mount_from_file(file);
	uint32_t mnt_id = (uint32_t)BPF_CORE_READ(mnt, mnt_id);
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_REGULAR_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: path (type: PT_FSPATH) */
	auxmap__store_d_path(auxmap, &file->f_path);
	/* Parameter 3: flags (type: PT_FLAGS32) */
	auxmap__store_u32_param(auxmap, scap_flags);
	/* Parameter 4: mnt_id (type: PT_UINT32) */
	auxmap__store_u32_param(auxmap, mnt_id);
	/* Parameter 5: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_directory(struct seq_file *seq,
                          uint64_t tgid_pid,
                          uint32_t fd,
                          struct file *file,
                          struct inode *inode) {
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_DIRECTORY_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: path (type: PT_FSPATH) */
	auxmap__store_d_path(auxmap, &file->f_path);
	/* Parameter 3: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int skip_socket_dump(uint64_t tgid_pid, uint32_t fd) {
	uint32_t tgid = (uint32_t)(tgid_pid >> 32);
	uint32_t pid = (uint32_t)tgid_pid;
	bpf_printk("skipped socket file as socket fetching is disabled: tgid=%u, pid=%u, fd=%u",
	           tgid,
	           pid,
	           fd);
	return 0;
}

static __always_inline int dump_inet_socket(struct seq_file *seq,
                                            uint64_t tgid_pid,
                                            uint32_t fd,
                                            struct sock *sk,
                                            uint16_t sk_type,
                                            uint16_t sk_proto,
                                            struct inode *inode) {
	uint32_t local_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
	uint16_t local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	uint32_t remote_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
	uint16_t remote_port = ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_SOCKET_INET_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: sk_type (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_type);
	/* Parameter 3: sk_proto (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_proto);
	/* Parameter 4: local_ip (type: PT_IPV4ADDR) */
	auxmap__store_u32_param(auxmap, local_ip);
	/* Parameter 5: local_port (type: PT_PORT) */
	auxmap__store_u16_param(auxmap, local_port);
	/* Parameter 6: remote_ip (type: PT_IPV4ADDR) */
	auxmap__store_u32_param(auxmap, remote_ip);
	/* Parameter 7: remote_port (type: PT_PORT) */
	auxmap__store_u16_param(auxmap, remote_port);
	/* Parameter 8: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int dump_inet6_socket(struct seq_file *seq,
                                             uint64_t tgid_pid,
                                             uint32_t fd,
                                             struct sock *sk,
                                             uint16_t sk_type,
                                             uint16_t sk_proto,
                                             struct inode *inode) {
	struct in6_addr local_ip;
	BPF_CORE_READ_INTO(&local_ip, sk, __sk_common.skc_v6_rcv_saddr);
	uint16_t local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
	struct in6_addr remote_ip;
	BPF_CORE_READ_INTO(&remote_ip, sk, __sk_common.skc_v6_daddr);
	uint32_t remote_port = ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_SOCKET_INET6_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: sk_type (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_type);
	/* Parameter 3: sk_proto (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_proto);
	/* Parameter 4: local_ip (type: PT_IPV6ADDR) */
	auxmap__store_ipv6_addr_param(auxmap, (uint32_t *)&local_ip);
	/* Parameter 5: local_port (type: PT_PORT) */
	auxmap__store_u16_param(auxmap, local_port);
	/* Parameter 6: remote_ip (type: PT_IPV6ADDR) */
	auxmap__store_ipv6_addr_param(auxmap, (uint32_t *)&remote_ip);
	/* Parameter 7: remote_port (type: PT_PORT) */
	auxmap__store_u16_param(auxmap, remote_port);
	/* Parameter 8: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int dump_unix_socket(struct seq_file *seq,
                                            uint64_t tgid_pid,
                                            uint32_t fd,
                                            struct sock *sk,
                                            uint16_t sk_type,
                                            uint16_t sk_proto,
                                            struct inode *inode) {
	struct unix_sock *un_sk = (struct unix_sock *)sk;
	// note: path here is a pointer to a stack-allocated array created by BPF_CORE_READ
	// implementation.
	char *path = BPF_CORE_READ(un_sk, addr, name[0].sun_path);
	int max_path_len = MAX_UNIX_SOCKET_PATH;
	if(path[0] == '\0') {
		// Abstract sockets are identified by a path beginning with a '\0' byte
		// (https://man7.org/linux/man-pages/man7/unix.7.html). Skip it to point to the beginning of
		// the real path.
		path++;
		max_path_len--;
	}
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_SOCKET_UNIX_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: sk_type (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_type);
	/* Parameter 3: sk_proto (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_proto);
	/* Parameter 4: sk_pointer (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, (uint64_t)un_sk);
	/* Parameter 5: sun_path (type: PT_FSPATH) */
	auxmap__store_charbuf_param(auxmap, (unsigned long)path, max_path_len, KERNEL);
	/* Parameter 6: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int dump_netlink_socket(struct seq_file *seq,
                                               uint64_t tgid_pid,
                                               uint32_t fd,
                                               struct sock *sk,
                                               uint16_t sk_type,
                                               uint16_t sk_proto,
                                               struct inode *inode) {
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_SOCKET_NETLINK_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: sk_type (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_type);
	/* Parameter 3: sk_proto (type: PT_UINT16) */
	auxmap__store_u16_param(auxmap, sk_proto);
	/* Parameter 4: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static int dump_socket(struct seq_file *seq,
                       uint64_t tgid_pid,
                       uint32_t fd,
                       struct file *file,
                       struct inode *inode) {
	if(!dump_task_file__must_dump_sockets) {
		return skip_socket_dump(tgid_pid, fd);
	}

	struct socket *sock = extract__socket_from_file(file);
	if(!sock) {
		return 0;
	}

	struct sock *sk = BPF_CORE_READ(sock, sk);
	if(!sk) {
		return 0;
	}

	uint16_t sk_family = BPF_CORE_READ(sk, __sk_common.skc_family);
	uint16_t sk_type = BPF_CORE_READ(sk, sk_type);
	uint16_t sk_proto = BPF_CORE_READ(sk, sk_protocol);

	switch(sk_family) {
	case AF_INET:
		return dump_inet_socket(seq, tgid_pid, fd, sk, sk_type, sk_proto, inode);
	case AF_INET6:
		return dump_inet6_socket(seq, tgid_pid, fd, sk, sk_type, sk_proto, inode);
	case AF_UNIX:
		return dump_unix_socket(seq, tgid_pid, fd, sk, sk_type, sk_proto, inode);
	case AF_NETLINK:
		return dump_netlink_socket(seq, tgid_pid, fd, sk, sk_type, sk_proto, inode);
	}
	return 0;
}

// The following are DJB2 hashes (i.e.: hash = 5381; foreach c: hash = ((hash << 5) + hash) + c;)
// used by `classify_anon_inode_file()` to quickly classify an anon inode file based on the has of
// its name.
#define HASH_EVENTFD 4283080137UL      // [eventfd]
#define HASH_EVENTPOLL 4247027542UL    // [eventpoll]
#define HASH_INOTIFY 2668889575UL      // inotify
#define HASH_SIGNALFD 3769938309UL     // [signalfd]
#define HASH_TIMERFD 7753960UL         // [timerfd]
#define HASH_IO_URING 2266470649UL     // [io_uring]
#define HASH_USERFAULTFD 3373497826UL  // [userfaultfd]
#define HASH_PIDFD 1838784100UL        // [pidfd]
#define HASH_BPF_MAP 2283598536UL      // bpf-map
#define HASH_BPF_PROG 2344434050UL     // bpf-prog
#define HASH_BPF_LINK 2344280472UL     // bpf-link
#define HASH_BPF_ITER 2403480400UL     // bpf_iter
#define HASH_PERF_EVENT 915066027UL    // [perf_event]

// This only works for strings shorter than 16 characters (excluding the trailing NUL byte).
static __always_inline uint32_t djb2_hash(const char *str) {
	uint32_t hash = 5381;
#pragma unroll
	for(int i = 0; i < 16; i++) {
		char c = str[i];
		if(c == '\0') {
			break;
		}
		hash = ((hash << 5) + hash) + c;
	}
	return hash;
}

static __always_inline enum anon_inode_fd_type classify_anon_inode_file(struct dentry *dentry) {
	const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
	if(!name_ptr) {
		return ANON_INODE_FD_TYPE_UNKNOWN;
	}

	// Classify the anon inode file based on the hash of its name.
	char name[32];
	if(bpf_probe_read_kernel_str(name, sizeof(name), name_ptr) < 0) {
		return ANON_INODE_FD_TYPE_UNKNOWN;
	}

	uint32_t hash = djb2_hash(name);
	switch(hash) {
	case HASH_EVENTFD:
		return ANON_INODE_FD_TYPE_EVENTFD;
	case HASH_EVENTPOLL:
		return ANON_INODE_FD_TYPE_EVENTPOLL;
	case HASH_INOTIFY:
		return ANON_INODE_FD_TYPE_INOTIFY;
	case HASH_SIGNALFD:
		return ANON_INODE_FD_TYPE_SIGNALFD;
	case HASH_TIMERFD:
		return ANON_INODE_FD_TYPE_TIMERFD;
	case HASH_IO_URING:
		return ANON_INODE_FD_TYPE_IO_URING;
	case HASH_USERFAULTFD:
		return ANON_INODE_FD_TYPE_USERFAULTFD;
	case HASH_PIDFD:
		return ANON_INODE_FD_TYPE_PIDFD;
	case HASH_BPF_MAP:
		return ANON_INODE_FD_TYPE_BPF_MAP;
	case HASH_BPF_PROG:
		return ANON_INODE_FD_TYPE_BPF_PROG;
	case HASH_BPF_LINK:
		return ANON_INODE_FD_TYPE_BPF_LINK;
	case HASH_BPF_ITER:
		return ANON_INODE_FD_TYPE_BPF_ITER;
	case HASH_PERF_EVENT:
		return ANON_INODE_FD_TYPE_PERF_EVENT;
	default:
		return ANON_INODE_FD_TYPE_UNKNOWN;
	}
}

static int dump_anon_inode_file(struct seq_file *seq,
                                uint64_t tgid_pid,
                                uint32_t fd,
                                struct file *file,
                                struct inode *inode) {
	uint64_t inode_fs_magic = (uint64_t)extract__fs_magic_from_inode(inode);
	enum anon_inode_fd_type fd_type;
	if(inode_fs_magic == PID_FS_MAGIC) {
		fd_type = ANON_INODE_FD_TYPE_PIDFD;
	} else {
		struct dentry *dentry = extract__dentry_from_file(file);
		fd_type = classify_anon_inode_file(dentry);
	}
	uint64_t ino_num = extract__ino_from_inode(inode);

	struct auxiliary_map *auxmap = auxmap_iter__get();
	if(!auxmap) {
		return 0;
	}

	auxmap_iter__preload_event_header(auxmap, tgid_pid, PPME_ITER_TASK_FILE_ANON_INODE_E);

	/* Parameter 1: fd (type: PT_FD32) */
	auxmap__store_s32_param(auxmap, (int32_t)fd);
	/* Parameter 2: fd_type (type: PT_FLAGS8) */
	auxmap__store_u8_param(auxmap, fd_type);
	/* Parameter 3: path (type: PT_FSPATH) */
	// Push the path just for anon inode files we failed to classify.
	if(fd_type == ANON_INODE_FD_TYPE_UNKNOWN) {
		auxmap__store_d_path(auxmap, &file->f_path);
	} else {
		auxmap__store_empty_param(auxmap);
	}
	/* Parameter 4: ino_num (type: PT_UINT64) */
	auxmap__store_u64_param(auxmap, ino_num);

	auxmap_iter__finalize_event_header(auxmap);
	auxmap_iter__submit_event(auxmap, seq);
	return 0;
}

static __always_inline int handle_unsupported_file(struct seq_file *seq,
                                                   uint64_t tgid_pid,
                                                   uint32_t fd,
                                                   umode_t i_mode,
                                                   uint64_t inode_fs_magic) {
	uint32_t tgid = (uint32_t)(tgid_pid >> 32);
	uint32_t pid = (uint32_t)tgid_pid;
	bpf_printk("unsupported file type: tgid=%u, pid=%u, fd=%u", tgid, pid, fd);
	bpf_printk("\t|- i_mode=%x, inode_fs_magic=%lu", i_mode, inode_fs_magic);
	return 0;
}

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx) {
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	__u32 fd = ctx->fd;
	if(!task || !file) {
		return 0;
	}

	// We are not interested in this file if the filtering logic is on and it requires dumping a
	// file with a different file descriptor.
	if(dump_task_file__fd_filter >= 0 && fd != (__u32)dump_task_file__fd_filter) {
		return 0;
	}

	uint32_t task_flags = 0;
	READ_TASK_FIELD_INTO(&task_flags, task, flags);

	// We are not interested in kernel threads.
	if(task_flags & PF_KTHREAD) {
		return 0;
	}

	pid_t tgid = extract__task_xid_nr(task, PIDTYPE_TGID);
	pid_t pid = extract__task_xid_nr(task, PIDTYPE_PID);
	if(tgid != pid) {
		return 0;
	}

	uint64_t tgid_pid = (uint64_t)tgid << 32 | (uint64_t)pid;

	struct inode *inode = extract__inode_from_file(file);
	if(!inode) {
		return 0;
	}

	// Try to classify based on file inode mode.
	umode_t i_mode = BPF_CORE_READ(inode, i_mode);
	switch(i_mode & S_IFMT) {
	case S_IFIFO:
		return dump_pipe(seq, tgid_pid, fd, file, inode);
	case S_IFREG:
		if(extract__exe_from_memfd(file)) {
			return dump_memfd_file(seq, tgid_pid, fd, file, inode);
		}
		/* fall through */
	case S_IFBLK:
	case S_IFCHR:
	case S_IFLNK:
		return dump_regular_or_device_file(seq, tgid_pid, fd, file, inode);
	case S_IFDIR:
		return dump_directory(seq, tgid_pid, fd, file, inode);
	case S_IFSOCK:
		return dump_socket(seq, tgid_pid, fd, file, inode);
	default:
		break;
	}

	// Try to classify based on filesystem magic.
	uint64_t inode_fs_magic = (uint64_t)extract__fs_magic_from_inode(inode);
	switch(inode_fs_magic) {
	case ANON_INODE_FS_MAGIC:
	case PID_FS_MAGIC:  // In kernels >= 6.9, pid fd files have their own pseudo-filesystem.
		return dump_anon_inode_file(seq, tgid_pid, fd, file, inode);
	case DMA_BUF_MAGIC:  // No support currently provided.
	default:
		return handle_unsupported_file(seq, tgid_pid, fd, i_mode, inode_fs_magic);
	}
}
