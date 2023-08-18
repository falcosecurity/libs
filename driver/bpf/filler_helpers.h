/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __FILLER_HELPERS_H
#define __FILLER_HELPERS_H

#include <linux/compat.h>
#include <net/compat.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/af_unix.h>
#include <linux/in.h>
#include <linux/fdtable.h>
#include <linux/net.h>

#include "../ppm_flag_helpers.h"
#include "builtins.h"
#include "missing_definitions.h"

/* Helper used to please the verifier with operations on the number of arguments */
#define SAFE_ARG_NUMBER(x) x & (PPM_MAX_EVENT_PARAMS - 1)

/* This enum is used to tell our helpers if they have to
 * read from kernel or user memory.
 */
enum read_memory
{
	USER = 0,
	KERNEL = 1,
};

static __always_inline bool in_port_range(uint16_t port, uint16_t min, uint16_t max)
{
	return port >= min && port <= max;
}

static __always_inline struct file *bpf_fget(int fd)
{
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdt;
	int max_fds;
	struct file **fds;
	struct file *fil;

	task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return NULL;

	files = _READ(task->files);
	if (!files)
		return NULL;

	fdt = _READ(files->fdt);
	if (!fdt)
		return NULL;

	max_fds = _READ(fdt->max_fds);
	if (fd >= max_fds)
		return NULL;

	fds = _READ(fdt->fd);
	fil = _READ(fds[fd]);

	return fil;
}

static __always_inline u32 bpf_get_fd_fmode_created(int fd)
{
	if(fd < 0)
    {
        return 0;
    }

/* FMODE_CREATED flag was introduced in kernel 4.19 and it's not present in earlier versions */
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 19, 0)
    struct file *file;
    file = bpf_fget(fd);
    if(file)
    {
        fmode_t fmode = _READ(file->f_mode);
        if (fmode & FMODE_CREATED)
            return PPM_O_F_CREATED;
    }
#endif
    return 0;
}

/* In this kernel version the instruction limit was bumped from 131072 to 1000000.
 * For this reason we use different values of `MAX_NUM_COMPONENTS`
 * according to the kernel version.
 */
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
#define MAX_NUM_COMPONENTS 48
#else
#define MAX_NUM_COMPONENTS 24
#endif

/* We must always leave at least 4096 bytes free in our tmp scratch space
 * to please the verifier since we set the max component len to 4096 bytes.
 * We start writing our exepath from half of the tmp scratch space. The
 * whole space is 256 KB, we start at 128 KB.
 *
 *       128 KB           128 KB (Free space to please the verifier)
 * |----------------|----------------|
 *                  ^
 *                  |
 *        We start here and write backward
 *        as we find components of the path
 *
 * As a bitmask we use `SAFE_TMP_SCRATCH_ACCESS` (128*1024 - 1).
 * This helps the verifier to understand that our offset never overcomes
 * 128 KB.
 */
#define MAX_COMPONENT_LEN 4096
#define MAX_TMP_SCRATCH_LEN (SCRATCH_SIZE >> 1)
#define SAFE_TMP_SCRATCH_ACCESS(x) (x) & (MAX_TMP_SCRATCH_LEN - 1)

/* Please note: Kernel 5.10 introduced a new bpf_helper called `bpf_d_path`
 * to extract a file path starting from a struct* file but it can be used only
 * with specific hooks:
 *
 * https://github.com/torvalds/linux/blob/e0dccc3b76fb35bb257b4118367a883073d7390e/kernel/trace/bpf_trace.c#L915-L929.
 *
 * So we need to do it by hand emulating its behavior.
 * This brings some limitations:
 * 1. the number of path components is limited to `MAX_NUM_COMPONENTS`.
 * 2. we cannot use locks so we can face race conditions during the path reconstruction.
 * 3. reconstructed path could be slightly different from the one returned by `d_path`.
 *    See pseudo_filesystem prefixes or the " (deleted)" suffix.
 *
 * Take a look at the research that led to this implementation:
 * https://github.com/falcosecurity/libs/issues/1111
 */
static __always_inline char *bpf_d_path_approx(struct filler_data *data, struct path *path)
{
	struct path f_path = {};
	bpf_probe_read_kernel(&f_path, sizeof(struct path), path);
	struct dentry *dentry = f_path.dentry;
	struct vfsmount *vfsmnt = f_path.mnt;
	struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
	struct mount *mnt_parent_p = NULL;
	bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *), &(mnt_p->mnt_parent));
	struct dentry *mnt_root_p = NULL;
	bpf_probe_read_kernel(&mnt_root_p, sizeof(struct dentry *), &(vfsmnt->mnt_root));

	/* This is the max length of the buffer in which we will write the full path. */
	u32 max_buf_len = MAX_TMP_SCRATCH_LEN;

	/* Populated inside the loop */
	struct dentry *d_parent = NULL;
	struct qstr d_name = {};
	u32 current_off = 0;
	int effective_name_len = 0;
	char slash = '/';
	char terminator = '\0';

#pragma unroll
	for(int i = 0; i < MAX_NUM_COMPONENTS; i++)
	{
		bpf_probe_read_kernel(&d_parent, sizeof(struct dentry *), &(dentry->d_parent));
		if(dentry == d_parent && dentry != mnt_root_p)
		{
			/* We reached the root (dentry == d_parent)
			 * but not the mount root...there is something weird, stop here.
			 */
			break;
		}

		if(dentry == mnt_root_p)
		{
			if(mnt_p != mnt_parent_p)
			{
				/* We reached root, but not global root - continue with mount point path */
				bpf_probe_read_kernel(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
				bpf_probe_read_kernel(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
				bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
				vfsmnt = &mnt_p->mnt;
				bpf_probe_read_kernel(&mnt_root_p, sizeof(struct dentry *), &(vfsmnt->mnt_root));
				continue;
			}
			else
			{
				/* We have the full path, stop here */
				break;
			}
		}

		/* Get the dentry name */
		bpf_probe_read_kernel(&d_name, sizeof(struct qstr), &(dentry->d_name));

		/* +1 for the terminator that is not considered in d_name.len.
		 * Reserve space for the name trusting the len
		 * written in `qstr` struct
		 */
		current_off = max_buf_len - (d_name.len + 1);

		effective_name_len =
			bpf_probe_read_kernel_str(&(data->tmp_scratch[SAFE_TMP_SCRATCH_ACCESS(current_off)]),
						  MAX_COMPONENT_LEN, (void *)d_name.name);

		/* This check shouldn't be necessary, right now we
		 * keep it just to be extra safe. Unfortunately, it causes
		 * verifier issues on s390x (5.15.0-75-generic Ubuntu s390x)
		 */
#ifndef CONFIG_S390
		if(effective_name_len <= 1)
		{
			/* If effective_name_len is 0 or 1 we have an error
			 * (path can't be null nor an empty string)
			 */
			break;
		}
#endif
		/* 1. `max_buf_len -= 1` point to the `\0` of the just written name.
		 * 2. We replace it with a `/`. Note that we have to use `bpf_probe_read_kernel`
		 *    to please some old verifiers like (Oracle Linux 4.14).
		 * 3. Then we set `max_buf_len` to the last written char.
		 */
		max_buf_len -= 1;
		bpf_probe_read_kernel(&(data->tmp_scratch[SAFE_TMP_SCRATCH_ACCESS(max_buf_len)]), 1, &slash);
		max_buf_len -= (effective_name_len - 1);

		dentry = d_parent;
	}

	if(max_buf_len == MAX_TMP_SCRATCH_LEN)
	{
		/* memfd files have no path in the filesystem so we never decremented the `max_buf_len` */
		bpf_probe_read_kernel(&d_name, sizeof(struct qstr), &(dentry->d_name));
		bpf_probe_read_kernel_str(&(data->tmp_scratch[0]), MAX_COMPONENT_LEN, (void *)d_name.name);
		return data->tmp_scratch;
	}

	/* Add leading slash */
	max_buf_len -= 1;
	bpf_probe_read_kernel(&(data->tmp_scratch[SAFE_TMP_SCRATCH_ACCESS(max_buf_len)]), 1, &slash);

	/* Null terminate the path string.
	 * Replace the first `/` we added in the loop with `\0`
	 */
	bpf_probe_read_kernel(&(data->tmp_scratch[SAFE_TMP_SCRATCH_ACCESS(MAX_TMP_SCRATCH_LEN - 1)]), 1, &terminator);

	return &(data->tmp_scratch[SAFE_TMP_SCRATCH_ACCESS(max_buf_len)]);
}

static __always_inline struct socket *bpf_sockfd_lookup(struct filler_data *data,
							int fd)
{
	struct file *file;
	const struct file_operations *fop;
	struct socket *sock;

	if (!data->settings->socket_file_ops)
		return NULL;

	file = bpf_fget(fd);
	if (!file)
		return NULL;

	fop = _READ(file->f_op);
	if (fop != data->settings->socket_file_ops)
		return NULL;

	sock = _READ(file->private_data);
	return sock;
}

static __always_inline unsigned long bpf_encode_dev(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static __always_inline void bpf_get_fd_dev_ino(int fd, unsigned long *dev, unsigned long *ino)
{
	struct super_block *sb;
	struct inode *inode;
	struct file *file;
	dev_t kdev;

	if (fd < 0)
		return;

	file = bpf_fget(fd);
	if (!file)
		return;

	inode = _READ(file->f_inode);
	if (!inode)
		return;

	sb = _READ(inode->i_sb);
	if (!sb)
		return;

	kdev = _READ(sb->s_dev);
	*dev = bpf_encode_dev(kdev);

	*ino = _READ(inode->i_ino);
}

static __always_inline bool bpf_ipv6_addr_any(const struct in6_addr *a)
{
	const unsigned long *ul = (const unsigned long *)a;

	return (ul[0] | ul[1]) == 0UL;
}

static __always_inline bool bpf_getsockname(struct socket *sock,
					    struct sockaddr_storage *addr,
					    int peer)
{
	struct sock *sk;
	sa_family_t family;

	sk = _READ(sock->sk);
	if (!sk)
		return false;

	family = _READ(sk->sk_family);

	switch (family) {
	case AF_INET:
	{
		struct inet_sock *inet	= (struct inet_sock *)sk;
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;

		sin->sin_family = AF_INET;
		if (peer) {
			sin->sin_port = _READ(inet->inet_dport);
			sin->sin_addr.s_addr = _READ(inet->inet_daddr);
		} else {
			u32 addr = _READ(inet->inet_rcv_saddr);

			if (!addr)
				addr = _READ(inet->inet_saddr);
			sin->sin_port = _READ(inet->inet_sport);
			sin->sin_addr.s_addr = addr;
		}

		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)addr;
		struct inet_sock *inet = (struct inet_sock *)sk;
		struct ipv6_pinfo {
			struct in6_addr saddr;
		};
		struct ipv6_pinfo *np = (struct ipv6_pinfo *)_READ(inet->pinet6);

		sin->sin6_family = AF_INET6;
		if (peer) {
			sin->sin6_port = _READ(inet->inet_dport);
			sin->sin6_addr = _READ(sk->sk_v6_daddr);
		} else {
			sin->sin6_addr = _READ(sk->sk_v6_rcv_saddr);
			if (bpf_ipv6_addr_any(&sin->sin6_addr))
				sin->sin6_addr = _READ(np->saddr);
			sin->sin6_port = _READ(inet->inet_sport);
		}

		break;
	}
	case AF_UNIX:
	{
		struct sockaddr_un *sunaddr = (struct sockaddr_un *)addr;
		struct unix_sock *u;
		struct unix_address *addr;

		if (peer)
			sk = _READ(((struct unix_sock *)sk)->peer);

		u = (struct unix_sock *)sk;
		addr = _READ(u->addr);
		if (!addr) {
			sunaddr->sun_family = AF_UNIX;
			sunaddr->sun_path[0] = 0;
		} else {
			unsigned int len = _READ(addr->len);

			if (len > sizeof(struct sockaddr_storage))
				len = sizeof(struct sockaddr_storage);

#ifdef BPF_FORBIDS_ZERO_ACCESS
			if (len > 0)
				bpf_probe_read_kernel(sunaddr, ((len - 1) & 0xff) + 1, addr->name);
#else
			bpf_probe_read_kernel(sunaddr, len, addr->name);
#endif
		}

		break;
	}
	default:
		return false;
	}

	return true;
}

static __always_inline int bpf_addr_to_kernel(void *uaddr, int ulen,
					      struct sockaddr *kaddr)
{
	int len = ulen & 0xfff;	/* required by BPF verifier */

	if (len < 0 || len > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (len == 0)
		return 0;

#ifdef BPF_FORBIDS_ZERO_ACCESS
	if (bpf_probe_read_user(kaddr, ((len - 1) & 0xff) + 1, uaddr))
#else
	if (bpf_probe_read_user(kaddr, len & 0xff, uaddr))
#endif
		return -EFAULT;

	return 0;
}

#define get_buf(x) data->buf[(data->state->tail_ctx.curoff + (x)) & SCRATCH_SIZE_HALF]

static __always_inline u32 bpf_compute_snaplen(struct filler_data *data,
					       u32 lookahead_size)
{
	struct sockaddr_storage *sock_address;
	struct sockaddr_storage *peer_address;
	u32 res = data->settings->snaplen;
	struct socket *sock;
	struct sock *sk;
	u16 sport;
	u16 dport;

	if (data->settings->tracers_enabled &&
	    data->state->tail_ctx.evt_type == PPME_SYSCALL_WRITE_X) {
		struct file *fil;
		struct inode *f_inode;
		dev_t i_rdev;

		fil = bpf_fget(data->fd);
		if (!fil)
			return res;

		f_inode = _READ(fil->f_inode);
		if (!f_inode)
			return res;

		i_rdev = _READ(f_inode->i_rdev);
		if (i_rdev == PPM_NULL_RDEV)
			return SNAPLEN_TRACERS_ENABLED;
	}

	if (!data->settings->do_dynamic_snaplen)
		return res;

	if (data->fd == -1)
		return res;

	sock = bpf_sockfd_lookup(data, data->fd);
	if (!sock)
		return res;

	sock_address = (struct sockaddr_storage *)data->tmp_scratch;
	peer_address = (struct sockaddr_storage *)data->tmp_scratch + 1;

	if (!bpf_getsockname(sock, sock_address, 0))
		return res;

	if (data->state->tail_ctx.evt_type == PPME_SOCKET_SENDTO_X) {
		unsigned long val;
		struct sockaddr *usrsockaddr;

		usrsockaddr = (struct sockaddr *)bpf_syscall_get_argument(data, 4);

		if (!usrsockaddr) {
			if (!bpf_getsockname(sock, peer_address, 1))
				return res;
		} else {
			int addrlen = bpf_syscall_get_argument(data, 5);

			if (addrlen != 0) {
				if (bpf_addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)peer_address))
					return res;
			} else if (!bpf_getsockname(sock, peer_address, 1)) {
				return res;
			}
		}
	} else if (data->state->tail_ctx.evt_type == PPME_SOCKET_SENDMSG_X) {
		struct sockaddr *usrsockaddr;
		struct user_msghdr mh;
		unsigned long val;
		int addrlen;

		val = bpf_syscall_get_argument(data, 1);
		if (bpf_probe_read_user(&mh, sizeof(mh), (void *)val)) {
			usrsockaddr = NULL;
			addrlen = 0;
		} else {
			usrsockaddr = (struct sockaddr *)mh.msg_name;
			addrlen = mh.msg_namelen;
		}

		if (usrsockaddr && addrlen != 0) {
			if (bpf_addr_to_kernel(usrsockaddr, addrlen, (struct sockaddr *)peer_address))
				return res;
		} else if (!bpf_getsockname(sock, peer_address, 1)) {
			return res;
		}
	} else if (!bpf_getsockname(sock, peer_address, 1)) {
		return res;
	}

	sk = _READ(sock->sk);
	if (!sk)
		return res;

	sa_family_t family = _READ(sk->sk_family);

	if (family == AF_INET) {
		sport = ntohs(((struct sockaddr_in *)sock_address)->sin_port);
		dport = ntohs(((struct sockaddr_in *)peer_address)->sin_port);
	} else if (family == AF_INET6) {
		sport = ntohs(((struct sockaddr_in6 *)sock_address)->sin6_port);
		dport = ntohs(((struct sockaddr_in6 *)peer_address)->sin6_port);
	} else {
		sport = 0;
		dport = 0;
	}

	uint16_t min_port = data->settings->fullcapture_port_range_start;
	uint16_t max_port = data->settings->fullcapture_port_range_end;

	if (max_port > 0 &&
		(in_port_range(sport, min_port, max_port) ||
		 in_port_range(dport, min_port, max_port))) {
		/*
		 * Before checking the well-known ports, see if the user has requested
		 * an increased snaplen for the port in question.
		 */
		return SNAPLEN_FULLCAPTURE_PORT;
	} else if (sport == PPM_PORT_MYSQL || dport == PPM_PORT_MYSQL) {
		if (lookahead_size >= 5) {
			if (get_buf(0) == 3 ||
			    get_buf(1) == 3 ||
			    get_buf(2) == 3 ||
			    get_buf(3) == 3 ||
			    get_buf(4) == 3) {
				return SNAPLEN_EXTENDED;
			} else if (get_buf(2) == 0 && get_buf(3) == 0) {
				return SNAPLEN_EXTENDED;
			}
		}
	} else if (sport == PPM_PORT_POSTGRES || dport == PPM_PORT_POSTGRES) {
		if (lookahead_size >= 2) {
			if ((get_buf(0) == 'Q' && get_buf(1) == 0) || /* SimpleQuery command */
			    (get_buf(0) == 'P' && get_buf(1) == 0) || /* Prepare statement command */
			    (get_buf(4) == 0 && get_buf(5) == 3 && get_buf(6) == 0) || /* startup command */
			    (get_buf(0) == 'E' && get_buf(1) == 0) /* error or execute command */
			) {
				return SNAPLEN_EXTENDED;
			}
		}
	} else if ((sport == PPM_PORT_MONGODB || dport == PPM_PORT_MONGODB) ||
			(lookahead_size >= 16 && (*(s32 *)&get_buf(12) == 1 || /* matches header */
						  *(s32 *)&get_buf(12) == 2001 ||
						  *(s32 *)&get_buf(12) == 2002 ||
						  *(s32 *)&get_buf(12) == 2003 ||
						  *(s32 *)&get_buf(12) == 2004 ||
						  *(s32 *)&get_buf(12) == 2005 ||
						  *(s32 *)&get_buf(12) == 2006 ||
						  *(s32 *)&get_buf(12) == 2007))) {
		return SNAPLEN_EXTENDED;
	} else if (dport == data->settings->statsd_port) {
		return SNAPLEN_EXTENDED;
	} else {
		if (lookahead_size >= 5) {
			u32 buf = *(u32 *)&get_buf(0);

#ifdef CONFIG_S390
			buf = __builtin_bswap32(buf);
#endif
			if (buf == BPF_HTTP_GET ||
			    buf == BPF_HTTP_POST ||
			    buf == BPF_HTTP_PUT ||
			    buf == BPF_HTTP_DELETE ||
			    buf == BPF_HTTP_TRACE ||
			    buf == BPF_HTTP_CONNECT ||
			    buf == BPF_HTTP_OPTIONS ||
			    (buf == BPF_HTTP_PREFIX && data->buf[(data->state->tail_ctx.curoff + 4) & SCRATCH_SIZE_HALF] == '/')) { // "HTTP/"
				return SNAPLEN_EXTENDED;
			}
		}
	}

	return res;
}

static __always_inline int unix_socket_path(char *dest, const char *user_ptr, size_t size) {
	int res = bpf_probe_read_kernel_str(dest,
				            size,
				            user_ptr);
	/*
  	 * Extract from: https://man7.org/linux/man-pages/man7/unix.7.html
	 * an abstract socket address is distinguished (from a
	 * pathname socket) by the fact that sun_path[0] is a null byte
	 * ('\0').  The socket's address in this namespace is given by
	 * the additional bytes in sun_path that are covered by the
	 * specified length of the address structure.
	 */
	if (res == 1) {
		dest[0] = '@';
		res = bpf_probe_read_kernel_str(dest + 1,
					        size - 1, // account for '@'
					        user_ptr + 1);
		res++; // account for '@'
	}
	return res;
}

static __always_inline u16 bpf_pack_addr(struct filler_data *data,
					 struct sockaddr *usrsockaddr,
					 int ulen)
{
	u32 ip;
	u16 port;
	sa_family_t family = usrsockaddr->sa_family;
	struct sockaddr_in *usrsockaddr_in;
	struct sockaddr_in6 *usrsockaddr_in6;
	struct sockaddr_un *usrsockaddr_un;
	u16 size;
	char *dest;
	int res;

	switch (family) {
	case AF_INET:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		ip = usrsockaddr_in->sin_addr.s_addr;
		port = ntohs(usrsockaddr_in->sin_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 4 + 2; /* family + ip + port */

		data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF] = socket_family_to_scap(family);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF], &ip, 4);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 5) & SCRATCH_SIZE_HALF], &port, 2);

		break;
	case AF_INET6:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

		/*
		 * Retrieve the src address
		 */
		port = ntohs(usrsockaddr_in6->sin6_port);

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 2; /* family + ip + port */

		data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF] = socket_family_to_scap(family);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF],
		       usrsockaddr_in6->sin6_addr.s6_addr, 16);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 17) & SCRATCH_SIZE_HALF], &port, 2);

		break;
	case AF_UNIX:
		/*
		 * Map the user-provided address to a sockaddr_in
		 */
		usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

		/*
		 * Put a 0 at the end of struct sockaddr_un because
		 * the user might not have considered it in the length
		 */
		if (ulen == sizeof(struct sockaddr_storage))
			((char *)usrsockaddr_un)[(ulen - 1) & SCRATCH_SIZE_MAX] = 0;
		else
			((char *)usrsockaddr_un)[ulen & SCRATCH_SIZE_MAX] = 0;

		/*
		 * Pack the data into the target buffer
		 */
		size = 1;

		data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF] = socket_family_to_scap(family);

		res = unix_socket_path(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF],
				       usrsockaddr_un->sun_path,
				       UNIX_PATH_MAX);

		size += res;

		break;
	default:
		size = 0;
		break;
	}

	return size;
}

static __always_inline long bpf_fd_to_socktuple(struct filler_data *data,
						int fd,
						struct sockaddr *usrsockaddr,
						int ulen,
						bool use_userdata,
						bool is_inbound,
						char *tmp_area)
{
	struct sockaddr_storage *sock_address;
	struct sockaddr_storage *peer_address;
	unsigned short family;
	struct socket *sock;
	struct sock *sk;
	long size = 0;
	struct in6_addr in6 = {0};

	sock = bpf_sockfd_lookup(data, fd);
	if (!sock)
		return 0;

	sock_address = (struct sockaddr_storage *)tmp_area;
	peer_address = (struct sockaddr_storage *)tmp_area + 1;

	if (!bpf_getsockname(sock, sock_address, 0))
		return 0;

	sk = _READ(sock->sk);
	if (!sk)
		return 0;

	family = _READ(sk->sk_family);

	switch (family) {
	case AF_INET:
	{
		u32 sip;
		u32 dip;
		u16 sport;
		u16 dport;

		if (!use_userdata) {
			if (bpf_getsockname(sock, peer_address, 1)) {
				if (is_inbound) {
					sip = ((struct sockaddr_in *)peer_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *)peer_address)->sin_port);
					dip = ((struct sockaddr_in *)sock_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *)sock_address)->sin_port);
				} else {
					sip = ((struct sockaddr_in *)sock_address)->sin_addr.s_addr;
					sport = ntohs(((struct sockaddr_in *)sock_address)->sin_port);
					dip = ((struct sockaddr_in *)peer_address)->sin_addr.s_addr;
					dport = ntohs(((struct sockaddr_in *)peer_address)->sin_port);
				}
			} else {
				sip = 0;
				sport = 0;
				dip = 0;
				dport = 0;
			}
		} else {
			struct sockaddr_in *usrsockaddr_in = (struct sockaddr_in *)usrsockaddr;

			if (is_inbound) {
				/* To take peer address info we try to use the kernel where possible.
				 * TCP allows us to obtain the right information, while the kernel doesn't fill
				 * `sk->__sk_common.skc_daddr` for UDP connection.
				 * Instead of having a custom logic for each protocol we try to read from
				 * kernel structs and if we don't find valid data we fallback to userspace
				 * structs.
				 */
				bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_dport);
				if(sport != 0)
				{
					/* We can read from the kernel */
					bpf_probe_read_kernel(&sip, sizeof(sip), &sk->__sk_common.skc_daddr);
					sport = ntohs(sport);
				}
				else
				{
					/* Fallback to userspace struct */
					sip = usrsockaddr_in->sin_addr.s_addr;
					sport = ntohs(usrsockaddr_in->sin_port);
				}
				dip = ((struct sockaddr_in *)sock_address)->sin_addr.s_addr;
				dport = ntohs(((struct sockaddr_in *)sock_address)->sin_port);
			} else {
				sip = ((struct sockaddr_in *)sock_address)->sin_addr.s_addr;
				sport = ntohs(((struct sockaddr_in *)sock_address)->sin_port);
				dip = usrsockaddr_in->sin_addr.s_addr;
				dport = ntohs(usrsockaddr_in->sin_port);
			}
		}

		size = 1 + 4 + 4 + 2 + 2;

		data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF] = socket_family_to_scap(family);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF], &sip, 4);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 5) & SCRATCH_SIZE_HALF], &sport, 2);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 7) & SCRATCH_SIZE_HALF], &dip, 4);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 11) & SCRATCH_SIZE_HALF], &dport, 2);

		break;
	}
	case AF_INET6:
	{
		u8 *sip6;
		u8 *dip6;
		u16 sport;
		u16 dport;

		if (!use_userdata) {
			if (bpf_getsockname(sock, peer_address, 1)) {
				if (is_inbound) {
					sip6 = ((struct sockaddr_in6 *)peer_address)->sin6_addr.s6_addr;
					sport = ntohs(((struct sockaddr_in6 *)peer_address)->sin6_port);
					dip6 = ((struct sockaddr_in6 *)sock_address)->sin6_addr.s6_addr;
					dport = ntohs(((struct sockaddr_in6 *)sock_address)->sin6_port);
				} else {
					sip6 = ((struct sockaddr_in6 *)sock_address)->sin6_addr.s6_addr;
					sport = ntohs(((struct sockaddr_in6 *)sock_address)->sin6_port);
					dip6 = ((struct sockaddr_in6 *)peer_address)->sin6_addr.s6_addr;
					dport = ntohs(((struct sockaddr_in6 *)peer_address)->sin6_port);
				}
			} else {
				memset(peer_address, 0, 16);
				sip6 = (u8 *)peer_address;
				dip6 = (u8 *)peer_address;
				sport = 0;
				dport = 0;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in6
			 */
			struct sockaddr_in6 *usrsockaddr_in6 = (struct sockaddr_in6 *)usrsockaddr;

			if (is_inbound) {
				bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_dport);
				if(sport != 0)
				{
					/* We can read from the kernel */
					bpf_probe_read_kernel(&in6, sizeof(in6), &sk->__sk_common.skc_v6_daddr);
					sip6 = in6.in6_u.u6_addr8;
					sport = ntohs(sport);
				}
				else
				{
					/* Fallback to userspace struct */
					sip6 = usrsockaddr_in6->sin6_addr.s6_addr;
					sport = ntohs(usrsockaddr_in6->sin6_port);
				}
				dip6 = ((struct sockaddr_in6 *)sock_address)->sin6_addr.s6_addr;
				dport = ntohs(((struct sockaddr_in6 *)sock_address)->sin6_port);
			} else {
				sip6 = ((struct sockaddr_in6 *)sock_address)->sin6_addr.s6_addr;
				sport = ntohs(((struct sockaddr_in6 *)sock_address)->sin6_port);
				dip6 = usrsockaddr_in6->sin6_addr.s6_addr;
				dport = ntohs(usrsockaddr_in6->sin6_port);
			}
		}

		/*
		 * Pack the tuple info in the temporary buffer
		 */
		size = 1 + 16 + 16 + 2 + 2; /* family + sip + dip + sport + dport */

		data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF] = socket_family_to_scap(family);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF], sip6, 16);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 17) & SCRATCH_SIZE_HALF], &sport, 2);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 19) & SCRATCH_SIZE_HALF], dip6, 16);
		memcpy(&data->buf[(data->state->tail_ctx.curoff + 35) & SCRATCH_SIZE_HALF], &dport, 2);

		break;
	}
	case AF_UNIX:
	{
		/*
		 * Retrieve the addresses
		 */
		struct unix_sock *us = (struct unix_sock *)sk;
		struct sock *speer = _READ(us->peer);
		char *us_name;

		data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF] = socket_family_to_scap(family);

		if (is_inbound) {
			memcpy(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF], &us, 8);
			memcpy(&data->buf[(data->state->tail_ctx.curoff + 1 + 8) & SCRATCH_SIZE_HALF], &speer, 8);
		} else {
			memcpy(&data->buf[(data->state->tail_ctx.curoff + 1) & SCRATCH_SIZE_HALF], &speer, 8);
			memcpy(&data->buf[(data->state->tail_ctx.curoff + 1 + 8) & SCRATCH_SIZE_HALF], &us, 8);
		}

		/*
		 * Pack the data into the target buffer
		 */
		size = 1 + 8 + 8;

		if (!use_userdata) {
			if (is_inbound) {
				us_name = ((struct sockaddr_un *)sock_address)->sun_path;
			} else {
				bpf_getsockname(sock, peer_address, 1);
				us_name = ((struct sockaddr_un *)peer_address)->sun_path;
			}
		} else {
			/*
			 * Map the user-provided address to a sockaddr_in
			 */
			struct sockaddr_un *usrsockaddr_un = (struct sockaddr_un *)usrsockaddr;

			/*
			 * Put a 0 at the end of struct sockaddr_un because
			 * the user might not have considered it in the length
			 */
			if (ulen == sizeof(struct sockaddr_storage))
				((char *)usrsockaddr_un)[(ulen - 1) & SCRATCH_SIZE_MAX] = 0;
			else
				((char *)usrsockaddr_un)[ulen & SCRATCH_SIZE_MAX] = 0;

			if (is_inbound)
				us_name = ((struct sockaddr_un *)sock_address)->sun_path;
			else
				us_name = usrsockaddr_un->sun_path;
		}

		int res = unix_socket_path(&data->buf[(data->state->tail_ctx.curoff + 1 + 8 + 8) & SCRATCH_SIZE_HALF],
					   us_name,
					   UNIX_PATH_MAX);

		size += res;

		break;
	}
	}

	return size;
}

static __always_inline int __bpf_read_val_into(struct filler_data *data,
					       unsigned long curoff_bounded,
					       unsigned long val,
					       volatile u16 read_size,
					       enum read_memory mem)
{
	int rc;
	int read_size_bound;

#ifdef BPF_FORBIDS_ZERO_ACCESS
	if (read_size == 0)
		return -1;

	read_size_bound = ((read_size - 1) & SCRATCH_SIZE_HALF) + 1;
#else
	read_size_bound = read_size & SCRATCH_SIZE_HALF;
#endif

	if (mem == KERNEL)
		rc = bpf_probe_read_kernel(&data->buf[curoff_bounded],
				read_size_bound,
				(void *)val);
	else
		rc = bpf_probe_read_user(&data->buf[curoff_bounded],
				read_size_bound,
				(void *)val);

	return rc;
}

static __always_inline int __bpf_val_to_ring(struct filler_data *data,
					     unsigned long val,
					     unsigned long val_len,
					     enum ppm_param_type type,
					     u8 dyn_idx,
					     bool enforce_snaplen,
					     enum read_memory mem)
{
	unsigned int len_dyn = 0;
	unsigned int len = 0;
	unsigned long curoff_bounded = 0;

	curoff_bounded = data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF;
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}

	if (dyn_idx != (u8)-1) {
		*((u8 *)&data->buf[curoff_bounded]) = dyn_idx;
		len_dyn = sizeof(u8);
		data->state->tail_ctx.curoff += len_dyn;
		data->state->tail_ctx.len += len_dyn;
	}

	curoff_bounded = data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF;
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}

	switch (type) {
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH: {
		if (!data->curarg_already_on_frame)
		{
			int res = -1;

			if (val)
				/* Return `res<0` only in case of error. */
				res = (mem == KERNEL) ? bpf_probe_read_kernel_str(&data->buf[curoff_bounded],
								PPM_MAX_ARG_SIZE,
								(const void *)val)
						      : bpf_probe_read_user_str(&data->buf[curoff_bounded],
								PPM_MAX_ARG_SIZE,
								(const void *)val);
			if(res >= 0)
			{
				len = res;
			}
			else
			{
				/* This should be already `0`, but just to be future-proof. */
				len = 0;
			}
		} 
		else
		{
			len = val_len;
		}
		break;
	}
	case PT_BYTEBUF: {
		if(data->curarg_already_on_frame || (val && val_len))
		{
			len = val_len;

			if(enforce_snaplen) 
			{
				u32 dpi_lookahead_size = DPI_LOOKAHEAD_SIZE;
				unsigned int sl;

				if(dpi_lookahead_size > len)
				{
					dpi_lookahead_size = len;
				}

				if(!data->curarg_already_on_frame) 
				{
					/* We need to read the first `dpi_lookahead_size` bytes. 
					 * If we are not able to read at least `dpi_lookahead_size` 
					 * we send an empty param `len=0`.
					 */
					volatile u16 read_size = dpi_lookahead_size;
					int rc = 0;

					rc = __bpf_read_val_into(data, curoff_bounded, val, read_size, mem);
					if (rc)
					{
						len=0;
						break;
					}
				}

				/* If `curarg` was already on frame, we are interested only in this computation,
				 * so we can understand how many bytes of the `curarg` we have to consider.
				 */
				sl = bpf_compute_snaplen(data, dpi_lookahead_size);
				if(len > sl)
				{
					len = sl;
				}
			}

			if (len > PPM_MAX_ARG_SIZE)
				len = PPM_MAX_ARG_SIZE;

			if(!data->curarg_already_on_frame)
			{
				volatile u16 read_size = len;
				int rc = 0;

				curoff_bounded = data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF;
				if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
				{
					return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
				}

				rc = __bpf_read_val_into(data, curoff_bounded, val, read_size, mem);
				if (rc)
				{
					len=0;
					break;
				}
			}
		} 
		else 
		{
			/* Handle NULL pointers */
			len = 0;
		}
		break;
	}
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
		if(data->curarg_already_on_frame)
		{
			len = val_len;
			break;
		}
		/* Cases in which we don't have the tuple and
		 * we want to send an empty param.
		 */
		else if(val==0)
		{
			len = 0;
			break;
		}
		bpf_printk("expected arg already on frame: evt_type %d, curarg %d, type %d\n",
				data->state->tail_ctx.evt_type,
				data->state->tail_ctx.curarg, type);
		return PPM_FAILURE_BUG;

	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
	case PT_UINT8:
	case PT_SIGTYPE:
		*((u8 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(u8);
		break;
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_UINT16:
	case PT_SYSCALLID:
		*((u16 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(u16);
		break;
	case PT_FLAGS32:
	case PT_MODE:
	case PT_UINT32:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
	case PT_ENUMFLAGS32:
		*((u32 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(u32);
		break;
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_UINT64:
		*((u64 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(u64);
		break;
	case PT_INT8:
		*((s8 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(s8);
		break;
	case PT_INT16:
		*((s16 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(s16);
		break;
	case PT_INT32:
		*((s32 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(s32);
		break;
	case PT_INT64:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		*((s64 *)&data->buf[curoff_bounded]) = val;
		len = sizeof(s64);
		break;
	default: {
		bpf_printk("unhandled type in bpf_val_to_ring: evt_type %d, curarg %d, type %d\n",
			   data->state->tail_ctx.evt_type,
			   data->state->tail_ctx.curarg, type);
		return PPM_FAILURE_BUG;
	}
	}
	if (len_dyn + len > PPM_MAX_ARG_SIZE)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}

	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len_dyn + len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	++data->state->tail_ctx.curarg;

	return PPM_SUCCESS;
}

static __always_inline int bpf_push_empty_param(struct filler_data *data)
{
	/* We push 0 in the length array */
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, 0);
	data->curarg_already_on_frame = false;

	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline enum read_memory param_type_to_mem(enum ppm_param_type type)
{
	/* __bpf_val_to_ring() uses bpf_probe_read_* functions for particular types
	 * only.  Instead of changing all places, let's keep it simple and try to
	 * spot the correct address space by type.
	 */

	switch (type)
	{
	case PT_CHARBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
	case PT_BYTEBUF:
		/* Those types typically read memory from user space pointers.
		 * If not, explicit use the respective helper with the _mem()
		 * suffix to specify the memory to read from.
		 *
		 * See also the usage below in the helpers.
		 */
		return USER;
	default:
		return KERNEL;
	}
}

static __always_inline int bpf_val_to_ring_mem(struct filler_data *data,
					       unsigned long val,
					       enum read_memory mem)
{
	const struct ppm_param_info *param_info;

	if (data->state->tail_ctx.curarg >= PPM_MAX_EVENT_PARAMS) {
		bpf_printk("invalid curarg: %d\n", data->state->tail_ctx.curarg);
		return PPM_FAILURE_BUG;
	}

	param_info = &data->evt->params[data->state->tail_ctx.curarg & (PPM_MAX_EVENT_PARAMS - 1)];

	return __bpf_val_to_ring(data, val, 0, param_info->type, -1, false, mem);
}

/// TODO: @Andreagit97 these functions should return void
static __always_inline int bpf_push_s64_to_ring(struct filler_data *data, s64 val)
{
	/// TODO: @Andreagit97 this could be removed in a second iteration.
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(s64);
	*((s64 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	/// TODO: @Andreagit97 this could be simplified
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_u64_to_ring(struct filler_data *data, u64 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(u64);
	*((u64 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_u32_to_ring(struct filler_data *data, u32 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(u32);
	*((u32 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_s32_to_ring(struct filler_data *data, s32 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(s32);
	*((s32 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_u16_to_ring(struct filler_data *data, u16 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(u16);
	*((u16 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_s16_to_ring(struct filler_data *data, s16 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(s16);
	*((s16 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_u8_to_ring(struct filler_data *data, u8 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(u8);
	*((u8 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_push_s8_to_ring(struct filler_data *data, s16 val)
{
	if (data->state->tail_ctx.curoff > SCRATCH_SIZE_HALF)
	{
		return PPM_FAILURE_FRAME_SCRATCH_MAP_FULL;
	}
	const unsigned int len = sizeof(s8);
	*((s8 *)&data->buf[data->state->tail_ctx.curoff & SCRATCH_SIZE_HALF]) = val;
	fixup_evt_arg_len(data->buf, data->state->tail_ctx.curarg, len);
	data->state->tail_ctx.curoff += len;
	data->state->tail_ctx.len += len;
	data->curarg_already_on_frame = false;
	/* We increment the current argument - to make verifier happy, properly check it */
	data->state->tail_ctx.curarg = SAFE_ARG_NUMBER(data->state->tail_ctx.curarg + 1);
	return PPM_SUCCESS;
}

static __always_inline int bpf_val_to_ring(struct filler_data *data,
					   unsigned long val)
{
	const struct ppm_param_info *param_info;

	/// TODO this is something we want to enforce at test time, not runtime
	if (data->state->tail_ctx.curarg >= PPM_MAX_EVENT_PARAMS) {
		bpf_printk("invalid curarg: %d\n", data->state->tail_ctx.curarg);
		return PPM_FAILURE_BUG;
	}

	param_info = &data->evt->params[data->state->tail_ctx.curarg & (PPM_MAX_EVENT_PARAMS - 1)];

	return __bpf_val_to_ring(data, val, 0, param_info->type, -1, false,
				 param_type_to_mem(param_info->type));
}

static __always_inline int bpf_val_to_ring_len(struct filler_data *data,
					       unsigned long val,
					       unsigned long val_len)
{
	const struct ppm_param_info *param_info;

	if (data->state->tail_ctx.curarg >= PPM_MAX_EVENT_PARAMS) {
		bpf_printk("invalid curarg: %d\n", data->state->tail_ctx.curarg);
		return PPM_FAILURE_BUG;
	}

	param_info = &data->evt->params[data->state->tail_ctx.curarg & (PPM_MAX_EVENT_PARAMS - 1)];

	return __bpf_val_to_ring(data, val, val_len, param_info->type, -1, false,
				 param_type_to_mem(param_info->type));
}

static __always_inline int bpf_val_to_ring_dyn(struct filler_data *data,
					       unsigned long val,
					       enum ppm_param_type type,
					       u8 dyn_idx)
{
	return __bpf_val_to_ring(data, val, 0, type, dyn_idx, false, param_type_to_mem(type));
}

static __always_inline int bpf_val_to_ring_type_mem(struct filler_data *data,
						unsigned long val,
						enum ppm_param_type type,
						enum read_memory mem)
{
	return __bpf_val_to_ring(data, val, 0, type, -1, false, mem);
}

static __always_inline int bpf_val_to_ring_type(struct filler_data *data,
						unsigned long val,
						enum ppm_param_type type)
{
	return __bpf_val_to_ring(data, val, 0, type, -1, false, param_type_to_mem(type));
}

static __always_inline bool bpf_in_ia32_syscall()
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 status = 0;

#ifdef CONFIG_X86_64

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 18)
	status = _READ(task->thread.status);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
	status = _READ(task->thread_info.status);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 2)
	status = _READ(task->thread.status);
#else
	status = _READ(task->thread_info.status);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 18) */

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/x86/include/asm/thread_info.h#L212
	 */
	return status & TS_COMPAT;

#elif defined(CONFIG_ARM64)

	/* See here for the definition:
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/arm64/include/asm/thread_info.h#L99
	 */
	status = _READ(task->thread_info.flags);
	return status & _TIF_32BIT;

#elif defined(CONFIG_S390)

	/* See here for the definition: 
	 * https://github.com/torvalds/linux/blob/69cb6c6556ad89620547318439d6be8bb1629a5a/arch/s390/include/asm/thread_info.h#L101
	 */
	status = _READ(task->thread_info.flags);
	return status & _TIF_31BIT;

#else

	/* Unknown architecture. */
	return false;

#endif /* CONFIG_X86_64 */
}

#endif
