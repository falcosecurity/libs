// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>

#include <libscap/scap.h>
#include <libscap/scap-int.h>
#include <libscap/linux/scap_linux_int.h>
#include <libscap/linux/scap_linux_platform.h>
#include <libscap/strl.h>
#include <libscap/strerror.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <libscap/uthash_ext.h>
#include <libscap/compat/misc.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <errno.h>
#include <netinet/tcp.h>
#if HAVE_SYS_MKDEV_H
#include <sys/mkdev.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h>
#endif
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
// #include <linux/sock_diag.h>
// #include <linux/unix_diag.h>
#include <libscap/linux/str_helpers.h>
#include <libscap/linux/read_helpers.h>

#define SOCKET_SCAN_BUFFER_SIZE 1024 * 1024

void scap_fd_free_ns_sockets_list(struct scap_ns_socket_list **sockets) {
	struct scap_ns_socket_list *fdi;
	struct scap_ns_socket_list *tfdi;

	if(*sockets) {
		HASH_ITER(hh, *sockets, fdi, tfdi) {
			HASH_DEL(*sockets, fdi);
			scap_fd_free_table(&fdi->sockets);
			free(fdi);
		}
		*sockets = NULL;
	}
}

int32_t scap_fd_handle_pipe(struct scap_proclist *proclist,
                            char *fname,
                            scap_threadinfo *tinfo,
                            scap_fdinfo *fdi,
                            char *error) {
	char link_name[SCAP_MAX_PATH_SIZE];
	ssize_t r;
	uint64_t ino;
	struct stat sb;

	r = readlink(fname, link_name, SCAP_MAX_PATH_SIZE - 1);
	if(r <= 0) {
		return scap_errprintf(error, errno, "Could not read link %s", fname);
	}
	link_name[r] = '\0';
	if(1 != sscanf(link_name, "pipe:[%" PRIi64 "]", &ino)) {
		// in this case we've got a named pipe
		// and we've got to call stat on the link name
		if(-1 == stat(link_name, &sb)) {
			return SCAP_SUCCESS;
		}
		ino = sb.st_ino;
	}
	strlcpy(fdi->info.fname, link_name, sizeof(fdi->info.fname));

	fdi->ino = ino;
	proclist->m_callbacks.m_proc_entry_cb(proclist->m_callbacks.m_callback_context,
	                                      error,
	                                      tinfo->tid,
	                                      tinfo,
	                                      fdi,
	                                      NULL);
	return SCAP_SUCCESS;
}

static inline uint32_t open_flags_to_scap(unsigned long flags) {
	uint32_t res = 0;

	switch(flags & (O_RDONLY | O_WRONLY | O_RDWR)) {
	case O_WRONLY:
		res |= PPM_O_WRONLY;
		break;
	case O_RDWR:
		res |= PPM_O_RDWR;
		break;
	default:
		res |= PPM_O_RDONLY;
		break;
	}

	if(flags & O_CREAT)
		res |= PPM_O_CREAT;

	if(flags & O_TMPFILE)
		res |= PPM_O_TMPFILE;

	if(flags & O_APPEND)
		res |= PPM_O_APPEND;

#ifdef O_DSYNC
	if(flags & O_DSYNC)
		res |= PPM_O_DSYNC;
#endif

	if(flags & O_EXCL)
		res |= PPM_O_EXCL;

	if(flags & O_NONBLOCK)
		res |= PPM_O_NONBLOCK;

	if(flags & O_SYNC)
		res |= PPM_O_SYNC;

	if(flags & O_TRUNC)
		res |= PPM_O_TRUNC;

#ifdef O_DIRECT
	if(flags & O_DIRECT)
		res |= PPM_O_DIRECT;
#endif

#ifdef O_DIRECTORY
	if(flags & O_DIRECTORY)
		res |= PPM_O_DIRECTORY;
#endif

#ifdef O_LARGEFILE
	if(flags & O_LARGEFILE)
		res |= PPM_O_LARGEFILE;
#endif

#ifdef O_CLOEXEC
	if(flags & O_CLOEXEC)
		res |= PPM_O_CLOEXEC;
#endif

	return res;
}

// Parse device major and minor from `buff`. `buff` must be a NUL-terminated string  in the form
// `<major>:<minor>`. Return true if both values are correctly read; false otherwise.
static bool parse_device_major_and_minor(char *buff, uint64_t *major, uint64_t *minor) {
	if(!str_scan_u64(&buff, 0, 10, major) || *buff != ':') {
		return false;
	}

	buff++;  // +1 for ':'
	return str_parse_u64(buff, 0, 10, minor);
}

static uint32_t scap_linux_get_device_by_mount_id_impl(struct scap_linux_platform *linux_platform,
                                                       unsigned long requested_mount_id,
                                                       const int fd) {
	char buff[4096];
	// `bytes_in_buff` accounts for the total amount of data currently present in `buff`.
	size_t bytes_in_buff = 0;
	while(1) {
		const ssize_t read_bytes = read(fd, buff + bytes_in_buff, sizeof(buff) - bytes_in_buff);
		if(read_bytes < 0) {
			if(errno == EINTR) {  // Re-attempt upon signal.
				continue;
			}
			return 0;
		}
		if(read_bytes == 0) {
			return 0;
		}
		bytes_in_buff += read_bytes;

		// Calculate the buffer valid data range, consisting of all read data up to the last '\n'
		// (i.e. excluding the trailing truncated new line, if present).
		// note: if we cannot find any '\n', we set `buff_valid_len` to 0 and see later if we can
		// recover a complete line with a shift logic and a subsequent read.
		// optimization: search for '\n' only in the new read data, because we are sure any old data
		// doesn't contain it.
		const char *const new_data_start = buff + bytes_in_buff - read_bytes;
		const char *const last_newline = memrchr(new_data_start, '\n', read_bytes);
		const size_t buff_valid_len = last_newline ? last_newline - buff + 1 : 0;

		const char *line_start = buff;
		const char *buff_valid_end = buff + buff_valid_len;
		// note: if `buff_valid_len` is 0, this loop doesn't run.
		while(line_start < buff_valid_end) {
			char *const line_end = memchr(line_start, '\n', buff_valid_end - line_start);
			if(!line_end) {
				// bug: if we enter the loop, the range [line_start, buff_valid_end] contains '\n',
				// so it's impossible to end up here.
				ASSERT(false);
				return 0;
			}

			// Replace '\n' with '\0' to make string-related API work.
			// note: the original '\n' is restored at the end of the iteration.
			*line_end = '\0';

			// Look for a line corresponding to the requested mount ID.
			char *scan_pos = (char *)line_start;
			uint64_t mount_id;
			if(!str_scan_u64(&scan_pos, 0, 10, &mount_id)) {
				// Malformed line.
				ASSERT(false);
				return 0;
			}

			if(mount_id != requested_mount_id) {
				*line_end = '\n';
				line_start = line_end + 1;
				continue;
			}

			// From now on, if an error occurs we must return, as there cannot be any further line
			// matching the same mount ID, as it is unique.

			// Skip the parent ID field.
			if(!mem_skip_fields(&scan_pos, line_end - scan_pos, 1)) {
				// Malformed line.
				ASSERT(false);
				return 0;
			}

			uint64_t major, minor;
			if(!parse_device_major_and_minor(scan_pos, &major, &minor)) {
				// Malformed line.
				ASSERT(false);
				return 0;
			}

			scap_mountinfo *mountinfo = malloc(sizeof(*mountinfo));
			if(mountinfo == NULL) {
				return 0;
			}

			const uint32_t dev = makedev(major, minor);
			mountinfo->mount_id = mount_id;
			mountinfo->dev = dev;
			int32_t uth_status = SCAP_SUCCESS;
			HASH_ADD_INT64(linux_platform->m_dev_list, mount_id, mountinfo);
			if(uth_status != SCAP_SUCCESS) {
				free(mountinfo);
			}
			return dev;
		}

		// Apply shifting logic to move the truncated trailing line (if any) at the beginning of the
		// buffer.
		// note: this remove from the buffer any processed data, that is data in the range
		// [buff, buff+buff_valid_len]).
		// note: the shift is not applied if we haven't processed any data in this iteration.
		const size_t buff_unprocessed_data_len = bytes_in_buff - buff_valid_len;
		if(buff_unprocessed_data_len > 0 && buff_valid_len > 0) {
			memmove(buff, buff + buff_valid_len, buff_unprocessed_data_len);
		}
		// Now the buffer contains only unprocessed data.
		bytes_in_buff = buff_unprocessed_data_len;
		if(bytes_in_buff == sizeof(buff)) {
			// It is almost impossible we filled the entire buffer with something not containing any
			// '\n' character. We don't have much to do here: just returning.
			ASSERT(false);
			return 0;
		}
	}

	// This is unreachable!
	ASSERT(false);
	return 0;
}

uint32_t scap_linux_get_device_by_mount_id(struct scap_platform *platform,
                                           const char *procdir,
                                           unsigned long requested_mount_id) {
	struct scap_linux_platform *linux_platform = (struct scap_linux_platform *)platform;

	scap_mountinfo *mountinfo;
	HASH_FIND_INT64(linux_platform->m_dev_list, &requested_mount_id, mountinfo);
	if(mountinfo != NULL) {
		return mountinfo->dev;
	}

	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%smountinfo", procdir);
	const int fd = open(fd_dir_name, O_RDONLY, 0);
	if(fd < 0) {
		return 0;
	}

	const uint32_t res =
	        scap_linux_get_device_by_mount_id_impl(linux_platform, requested_mount_id, fd);
	close(fd);
	return res;
}

void scap_fd_flags_file(scap_fdinfo *fdi, const char *procdir) {
	char filename[SCAP_MAX_PATH_SIZE];
	snprintf(filename, SCAP_MAX_PATH_SIZE, "%sfdinfo/%" PRId64, procdir, fdi->fd);
	const int fd = open(filename, O_RDONLY, 0);
	if(fd < 0) {
		return;
	}

	fdi->info.regularinfo.mount_id = 0;
	fdi->info.regularinfo.dev = 0;

	// note: `flags` and `mnt_id` rows appears early in the file (first few lines), so reading only
	// the first 512 bytes is sufficient to locate it reliably.
	char buffer[512];
	const ssize_t read_bytes = read_exact(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if(read_bytes <= 0) {
		return;
	}
	buffer[read_bytes] = '\0';

	const char *line_start = buffer;
	const char *const last_newline = memrchr(buffer, '\n', read_bytes);
	if(last_newline == NULL) {
		ASSERT(false);
		return;
	}

	const int VALUES_TO_ACQUIRE = 2;
	int acquired_values = 0;

	while(line_start < last_newline) {
		char *const line_end = memchr(line_start, '\n', last_newline - line_start + 1);
		if(!line_end) {
			// bug: if we enter the loop, the range [line_start, buff_valid_end] contains '\n', so
			// it's impossible to end up here.
			ASSERT(false);
			return;
		}

		const size_t line_len = line_end - line_start;

		// Replace '\n' with '\0' to make string-related API work.
		*line_end = '\0';
		switch(*line_start) {
		case 'f':
			if(MEMCMP_LITERAL(line_start, line_len, "flags:")) {
				uint64_t flags;
				if(str_parse_u64(line_start, sizeof("flags:") - 1, 8, &flags)) {
					fdi->info.regularinfo.open_flags = open_flags_to_scap(flags);
				} else {
					fdi->info.regularinfo.open_flags = PPM_O_NONE;
				}
				acquired_values++;
			}
			break;
		case 'm':
			if(MEMCMP_LITERAL(line_start, line_len, "mnt_id:")) {
				uint64_t mount_id;
				if(str_parse_u64(line_start, sizeof("mnt_id:") - 1, 10, &mount_id)) {
					fdi->info.regularinfo.mount_id = mount_id;
				}
				acquired_values++;
			}
			break;
		default:
			break;
		}

		if(acquired_values == VALUES_TO_ACQUIRE) {
			return;
		}

		line_start = line_end + 1;
	}
}

int32_t scap_fd_handle_regular_file(struct scap_proclist *proclist,
                                    char *fname,
                                    scap_threadinfo *tinfo,
                                    scap_fdinfo *fdi,
                                    const char *procdir,
                                    char *error) {
	char link_name[SCAP_MAX_PATH_SIZE];
	ssize_t r;

	r = readlink(fname, link_name, SCAP_MAX_PATH_SIZE - 1);
	if(r <= 0) {
		return SCAP_SUCCESS;
	}

	link_name[r] = '\0';

	if(SCAP_FD_UNSUPPORTED == fdi->type) {
		// try to classify by link name
		if(0 == strcmp(link_name, "anon_inode:[eventfd]")) {
			fdi->type = SCAP_FD_EVENT;
		} else if(0 == strcmp(link_name, "anon_inode:[signalfd]")) {
			fdi->type = SCAP_FD_SIGNALFD;
		} else if(0 == strcmp(link_name, "anon_inode:[eventpoll]")) {
			fdi->type = SCAP_FD_EVENTPOLL;
		} else if(0 == strcmp(link_name, "anon_inode:inotify")) {
			fdi->type = SCAP_FD_INOTIFY;
		} else if(0 == strcmp(link_name, "anon_inode:[timerfd]")) {
			fdi->type = SCAP_FD_TIMERFD;
		} else if(0 == strcmp(link_name, "anon_inode:[io_uring]")) {
			fdi->type = SCAP_FD_IOURING;
		} else if(0 == strcmp(link_name, "anon_inode:[userfaultfd]")) {
			fdi->type = SCAP_FD_USERFAULTFD;
		}
		// anon_inode:bpf-map
		// anon_inode:bpf_link
		// anon_inode:bpf-prog
		// anon_inode:bpf_iter
		else if(0 == strncmp(link_name, "anon_inode:[bpf", strlen("anon_inode:[bpf"))) {
			fdi->type = SCAP_FD_BPF;
		} else if(0 == strcmp(link_name, "anon_inode:[pidfd]")) {
			fdi->type = SCAP_FD_PIDFD;
		}

		if(SCAP_FD_UNSUPPORTED == fdi->type) {
			// still not able to classify
			// printf("unsupported %s -> %s\n",fname,link_name);
		}
		fdi->info.fname[0] = '\0';
	} else if(fdi->type == SCAP_FD_FILE_V2) {
		if(0 == strncmp(link_name, "/memfd:", strlen("/memfd:"))) {
			fdi->type = SCAP_FD_MEMFD;
			strlcpy(fdi->info.fname, link_name, sizeof(fdi->info.fname));
		} else {
			scap_fd_flags_file(fdi, procdir);
			strlcpy(fdi->info.regularinfo.fname, link_name, sizeof(fdi->info.regularinfo.fname));
		}
	} else {
		strlcpy(fdi->info.fname, link_name, sizeof(fdi->info.fname));
	}

	proclist->m_callbacks.m_proc_entry_cb(proclist->m_callbacks.m_callback_context,
	                                      error,
	                                      tinfo->tid,
	                                      tinfo,
	                                      fdi,
	                                      NULL);
	return SCAP_SUCCESS;
}

int32_t scap_fd_handle_socket(struct scap_proclist *proclist,
                              char *fname,
                              scap_threadinfo *tinfo,
                              scap_fdinfo *fdi,
                              char *procdir,
                              uint64_t net_ns,
                              struct scap_ns_socket_list **sockets_by_ns,
                              char *error) {
	char link_name[SCAP_MAX_PATH_SIZE];
	ssize_t r;
	scap_fdinfo *tfdi;
	uint64_t ino;
	struct scap_ns_socket_list *sockets = NULL;
	int32_t uth_status = SCAP_SUCCESS;

	if(*sockets_by_ns == (void *)-1) {
		return SCAP_SUCCESS;
	} else {
		HASH_FIND_INT64(*sockets_by_ns, &net_ns, sockets);
		if(sockets == NULL) {
			sockets = malloc(sizeof(struct scap_ns_socket_list));
			if(sockets == NULL) {
				return scap_errprintf(error, 0, "sockets allocation error");
			}
			sockets->net_ns = net_ns;
			sockets->sockets = NULL;
			char fd_error[SCAP_LASTERR_SIZE];

			HASH_ADD_INT64(*sockets_by_ns, net_ns, sockets);
			if(uth_status != SCAP_SUCCESS) {
				free(sockets);
				return scap_errprintf(error, 0, "socket list allocation error");
			}

			if(scap_fd_read_sockets(procdir, sockets, fd_error) == SCAP_FAILURE) {
				sockets->sockets = NULL;
				return scap_errprintf(error, 0, "Cannot read sockets (%s)", fd_error);
			}
		}
	}

	r = readlink(fname, link_name, SCAP_MAX_PATH_SIZE - 1);
	if(r <= 0) {
		return SCAP_SUCCESS;
	}

	link_name[r] = '\0';

	strlcpy(fdi->info.fname, link_name, sizeof(fdi->info.fname));

	// link name for sockets should be of the format socket:[ino]
	if(1 != sscanf(link_name, "socket:[%" PRIi64 "]", &ino)) {
		// it's a kind of socket, but we don't support it right now
		fdi->type = SCAP_FD_UNSUPPORTED;
		proclist->m_callbacks.m_proc_entry_cb(proclist->m_callbacks.m_callback_context,
		                                      error,
		                                      tinfo->tid,
		                                      tinfo,
		                                      fdi,
		                                      NULL);
		return SCAP_SUCCESS;
	}

	//
	// Lookup ino in the list of sockets
	//
	HASH_FIND_INT64(sockets->sockets, &ino, tfdi);
	if(tfdi != NULL) {
		memcpy(&(fdi->info), &(tfdi->info), sizeof(fdi->info));
		fdi->ino = ino;
		fdi->type = tfdi->type;
		proclist->m_callbacks.m_proc_entry_cb(proclist->m_callbacks.m_callback_context,
		                                      error,
		                                      tinfo->tid,
		                                      tinfo,
		                                      fdi,
		                                      NULL);
	}
	return SCAP_SUCCESS;
}

// Parse an IPv4 socket table address in the form <hex_ip>:<hex_port>, skipping any leading
// whitespace. Return a boolean indicating if the operation is successful. If the operation is
// successful, `ip_out` and `port_out` will contain the read data, and `*str` will point to the
// first character after the parsed content.
static bool scan_ipv4_socket_table_address(char **str, uint32_t *ip_out, uint16_t *port_out) {
	char *ptr = *str;

	uint32_t ip;
	if(!str_scan_u32(&ptr, 0, 16, &ip)) {
		return false;
	}

	// Skip ':'.
	if(*ptr != ':') {
		return false;
	}
	ptr++;

	uint16_t port;
	if(!str_scan_u16(&ptr, 0, 16, &port)) {
		return false;
	}

	*ip_out = ip;
	*port_out = port;
	*str = ptr;
	return true;
}

// Parse a single IPv4 socket table line and insert the obtained fdinfo into `sockets`. Return
// `SCAP_SUCCESS` if it can correctly parse the line or encounters a recoverable error (e.g.: the
// line could be simply skipped); return `SCAP_FAILURE` otherwise.
static int32_t parse_ipv4_socket_table_line(const char *const line_start,
                                            const char *const line_end,
                                            scap_fdinfo **sockets,
                                            const int l4proto,
                                            char *error) {
	// Skip the entire header and/or the `sl` field.
	char *scan_pos = memchr(line_start, ':', line_end - line_start);
	if(scan_pos == NULL) {
		return SCAP_SUCCESS;
	}

	scan_pos += 2;
	if(scan_pos + 80 >= line_end) {
		return SCAP_SUCCESS;
	}

	// Parse `local_address` and `remote_address` fields.
	uint32_t sip, dip;
	uint16_t sport, dport;
	if(!scan_ipv4_socket_table_address(&scan_pos, &sip, &sport) ||
	   !scan_ipv4_socket_table_address(&scan_pos, &dip, &dport)) {
		return SCAP_SUCCESS;
	}

	// Skip `st`, `tx_queue`, `tr`, `retrnsmt`, `uid` and `timeout` fields to parse `inode` field.
	if(!mem_skip_fields(&scan_pos, line_end - scan_pos, 6)) {
		return SCAP_SUCCESS;
	}

	// Parse `inode` field.
	uint64_t ino;
	if(!str_scan_u64(&scan_pos, 0, 10, &ino)) {
		return SCAP_SUCCESS;
	}

	// Allocate fdinfo and populate its fields.
	scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
	if(fdinfo == NULL) {
		return scap_errprintf(error,
		                      errno,
		                      "memory allocation error in parse_ipv4_socket_table_line()");
	}

	fdinfo->ino = ino;
	if(dip != 0) {
		fdinfo->type = SCAP_FD_IPV4_SOCK;
		fdinfo->info.ipv4info.sip = sip;
		fdinfo->info.ipv4info.dip = dip;
		fdinfo->info.ipv4info.sport = sport;
		fdinfo->info.ipv4info.dport = dport;
		fdinfo->info.ipv4info.l4proto = l4proto;
	} else {
		fdinfo->type = SCAP_FD_IPV4_SERVSOCK;
		fdinfo->info.ipv4serverinfo.ip = sip;
		fdinfo->info.ipv4serverinfo.port = sport;
		fdinfo->info.ipv4serverinfo.l4proto = l4proto;
	}

	// Add to the table.
	int32_t uth_status = SCAP_SUCCESS;
	HASH_ADD_INT64((*sockets), ino, fdinfo);
	if(uth_status != SCAP_SUCCESS) {
		free(fdinfo);
		return scap_errprintf(error, 0, "IPv4 socket allocation error");
	}
	return SCAP_SUCCESS;
}

// Convert a single hex char to 0-15. `c` must be a valid hex char (i.e.: '0'-'9','a'-'f','A'-'F').
static uint32_t hex_char_to_u32(const char c) {
	return (c & 0xF) + 9 * (c >> 6);
}

// Parse exactly 8 hex chars from `*str` and return the obtained 32 bits number. It moves `*str`
// forward of 8 chars.
static uint32_t scan_u32_hex_exact(char **str) {
	uint32_t val = 0;
	for(int i = 0; i < 8; i++) {
		val <<= 4;
		val |= hex_char_to_u32((*str)[i]);
	}
	*str += 8;
	return val;
}

// Parse an IPv6 socket table address in the form <hex_ip>:<hex_port>, skipping any leading
// whitespace. Return a boolean indicating if the operation is successful. If the operation is
// successful, `ip_out` and `port_out` will contain the read data, and `*str` will point to the
// first character after the parsed content.
static bool scan_ipv6_socket_table_address(char **str, uint32_t *ip_out, uint16_t *port_out) {
	char *ptr = *str;
	for(int i = 0; i < 4; i++) {
		*(ip_out + i) = scan_u32_hex_exact(&ptr);
	}

	// Skip ':'.
	if(*ptr != ':') {
		return false;
	}

	ptr++;

	if(!str_scan_u16(&ptr, 0, 16, port_out)) {
		return false;
	}

	*str = ptr;
	return true;
}

int32_t scap_fd_is_ipv6_server_socket(uint32_t ip6_addr[4]) {
	return 0 == ip6_addr[0] && 0 == ip6_addr[1] && 0 == ip6_addr[2] && 0 == ip6_addr[3];
}

// Parse a single IPv6 socket table line and insert the obtained fdinfo into `sockets`. Return
// `SCAP_SUCCESS` if it can correctly parse the line or encounters a recoverable error (e.g.: the
// line could be simply skipped); return `SCAP_FAILURE` otherwise.
static int32_t parse_ipv6_socket_table_line(const char *const line_start,
                                            const char *const line_end,
                                            scap_fdinfo **sockets,
                                            const int l4proto,
                                            char *error) {
	// Skip the entire header and/or the `sl` field.
	char *scan_pos = memchr(line_start, ':', line_end - line_start);
	if(scan_pos == NULL) {
		return SCAP_SUCCESS;
	}

	scan_pos += 2;
	if(scan_pos + 80 >= line_end) {
		return SCAP_SUCCESS;
	}

	// Parse `local_address` and `remote_address` fields.
	uint32_t sip[4], dip[4];
	uint16_t sport, dport;
	if(!scan_ipv6_socket_table_address(&scan_pos, sip, &sport) ||
	   !scan_ipv6_socket_table_address(&scan_pos, dip, &dport)) {
		return SCAP_SUCCESS;
	}

	// Skip `st`, `tx_queue`, `tr`, `retrnsmt`, `uid` and `timeout` fields to parse `inode` field.
	if(!mem_skip_fields(&scan_pos, line_end - scan_pos, 6)) {
		return SCAP_SUCCESS;
	}

	// Parse `inode` field.
	uint64_t ino;
	if(!str_scan_u64(&scan_pos, 0, 10, &ino)) {
		return SCAP_SUCCESS;
	}

	// Allocate fdinfo and populate its fields.
	scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
	if(fdinfo == NULL) {
		return scap_errprintf(error,
		                      errno,
		                      "memory allocation error in parse_ipv6_socket_table_line()");
	}

	fdinfo->ino = ino;
	if(!scap_fd_is_ipv6_server_socket(dip)) {
		fdinfo->type = SCAP_FD_IPV6_SOCK;
		memcpy(&fdinfo->info.ipv6info.sip, sip, sizeof(fdinfo->info.ipv6info.sip));
		memcpy(&fdinfo->info.ipv6info.dip, dip, sizeof(fdinfo->info.ipv6info.dip));
		fdinfo->info.ipv6info.sport = sport;
		fdinfo->info.ipv6info.dport = dport;
		fdinfo->info.ipv6info.l4proto = l4proto;
	} else {
		fdinfo->type = SCAP_FD_IPV6_SERVSOCK;
		memcpy(fdinfo->info.ipv6serverinfo.ip, sip, sizeof(fdinfo->info.ipv6serverinfo.ip));
		fdinfo->info.ipv6serverinfo.port = sport;
		fdinfo->info.ipv6serverinfo.l4proto = l4proto;
	}

	// Add to the table.
	int32_t uth_status = SCAP_SUCCESS;
	HASH_ADD_INT64((*sockets), ino, fdinfo);
	if(uth_status != SCAP_SUCCESS) {
		free(fdinfo);
		return scap_errprintf(error, 0, "IPv6 socket allocation error");
	}
	return SCAP_SUCCESS;
}

// Parse a single unix socket table line and insert the obtained fdinfo into `sockets`. Return
// `SCAP_SUCCESS` if it can correctly parse the line or encounters a recoverable error (e.g.: the
// line could be simply skipped); return `SCAP_FAILURE` otherwise.
static int32_t parse_unix_socket_table_line(const char *const line_start,
                                            const char *const line_end,
                                            scap_fdinfo **sockets,
                                            char *error) {
	// Parse `Num` field.
	// note: this will fail if this is the header line.
	char *scan_pos = (char *)line_start;
	uint64_t source;
	if(!str_scan_u64(&scan_pos, 0, 16, &source)) {
		return SCAP_SUCCESS;
	}

	// Skip ':'.
	if(*scan_pos != ':') {
		return SCAP_SUCCESS;
	}
	scan_pos++;

	// Skip `RefCount`, `Protocol`, `Flags`, `Type` and `St` fields to parse `Inode` field.
	if(!mem_skip_fields(&scan_pos, line_end - scan_pos, 5)) {
		return SCAP_SUCCESS;
	}

	// Parse `Inode` field.
	uint64_t ino;
	if(!str_scan_u64(&scan_pos, 0, 10, &ino)) {
		return SCAP_SUCCESS;
	}

	// Allocate fdinfo and populate its fields.
	scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
	if(fdinfo == NULL) {
		return scap_errprintf(error,
		                      errno,
		                      "memory allocation error in parse_unix_socket_table_line()");
	}

	fdinfo->type = SCAP_FD_UNIX_SOCK;
	fdinfo->info.unix_socket_info.source = source;
	fdinfo->info.unix_socket_info.destination = 0;
	fdinfo->ino = ino;

	// Parse `Path` field (if present).
	if(mem_skip_chars(&scan_pos, line_end - scan_pos, ' ')) {
		strlcpy(fdinfo->info.unix_socket_info.fname,
		        scan_pos,
		        sizeof(fdinfo->info.unix_socket_info.fname));
	} else {
		fdinfo->info.unix_socket_info.fname[0] = '\0';
	}

	// Add to the table.
	int32_t uth_status = SCAP_SUCCESS;
	HASH_ADD_INT64((*sockets), ino, fdinfo);
	if(uth_status != SCAP_SUCCESS) {
		free(fdinfo);
		return scap_errprintf(error, 0, "unix socket allocation error");
	}
	return SCAP_SUCCESS;
}

// Parse a single netlink socket table line and insert the obtained fdinfo into `sockets`. Return
// `SCAP_SUCCESS` if it can correctly parse the line or encounters a recoverable error (e.g.: the
// line could be simply skipped); return `SCAP_FAILURE` otherwise.
static int32_t parse_netlink_socket_table_line(const char *const line_start,
                                               const char *const line_end,
                                               scap_fdinfo **sockets,
                                               char *error) {
	// Skip the entire header (it begins with `sk`).
	if(*line_start == 's') {
		return SCAP_SUCCESS;
	}

	// Get the position of the first space after the `sk` field.
	char *scan_pos = memchr(line_start, ' ', line_end - line_start);
	if(scan_pos == NULL) {
		return SCAP_SUCCESS;
	}

	// Skip `Eth`, `Pid`, `Groups`, `Rmem`, `Wmem`, `Dump`, `Locks`, `Drops` to parse `Inode` field.
	if(!mem_skip_fields(&scan_pos, line_end - scan_pos, 8)) {
		return SCAP_SUCCESS;
	}

	// Parse `Inode` field.
	uint64_t ino;
	if(!str_scan_u64(&scan_pos, 0, 10, &ino)) {
		return SCAP_SUCCESS;
	}

	// Allocate fdinfo and populate its fields.
	// note(ekoops): not sure why, but the original caller called memset on the fdinfo, so I'm gonna
	// call `calloc()` instead of `malloc()` here.
	scap_fdinfo *fdinfo = calloc(1, sizeof(scap_fdinfo));
	if(fdinfo == NULL) {
		return scap_errprintf(error,
		                      errno,
		                      "memory allocation error in parse_netlink_socket_table_line()");
	}

	fdinfo->type = SCAP_FD_NETLINK;
	fdinfo->ino = ino;

	// Add to the table.
	int32_t uth_status = SCAP_SUCCESS;
	HASH_ADD_INT64((*sockets), ino, fdinfo);
	if(uth_status != SCAP_SUCCESS) {
		free(fdinfo);
		return scap_errprintf(error, 0, "netlink socket allocation error");
	}
	return SCAP_SUCCESS;
}

static int32_t parse_procfs_proc_pid_socket_table_file_impl(const int fd,
                                                            const char *const filename,
                                                            const int socket_domain,
                                                            scap_fdinfo **sockets,
                                                            const int l4proto,
                                                            char *const error) {
	// note: 32 kB is a good choice for the majority of the use cases. Each file line is
	// approximately 150 bytes. The following table estimate how many read() system call are issued
	// in the optimistic case (e.g.: no signals):
	// - 100 sockets -> ~15 kB -> 1 read()
	// - 1000 sockets -> ~150 kB -> ~5 read()
	// - 10000 sockets -> ~1.5 MB -> ~50 read()
	// Even in the worst scenario, the cost of issuing 50 system call should be overcome by the
	// cache-friendly accesses using the stack-allocated buffer.
	char buff[32 * 1024];
	// `bytes_in_buff` accounts for the total amount of data currently present in `buff`.
	size_t bytes_in_buff = 0;
	while(1) {
		const ssize_t read_bytes = read(fd, buff + bytes_in_buff, sizeof(buff) - bytes_in_buff);
		if(read_bytes < 0) {
			if(errno == EINTR) {  // Re-attempt upon signal.
				continue;
			}
			return scap_errprintf(error, errno, "can't read socket table file %s", filename);
		}
		if(read_bytes == 0) {
			return SCAP_SUCCESS;
		}
		bytes_in_buff += read_bytes;

		// Calculate the buffer valid data range, consisting of all read data up to the last '\n'
		// (i.e. excluding the trailing truncated new line, if present).
		// note: if we cannot find any '\n', we set `buff_valid_len` to 0 and see later if we can
		// recover a complete line with a shift logic and a subsequent read.
		// optimization: search for '\n' only in the new read data, because we are sure any old data
		// doesn't contain it.
		const char *const new_data_start = buff + bytes_in_buff - read_bytes;
		const char *const last_newline = memrchr(new_data_start, '\n', read_bytes);
		const size_t buff_valid_len = last_newline ? last_newline - buff + 1 : 0;

		const char *line_start = buff;
		const char *buff_valid_end = buff + buff_valid_len;
		// note: if `buff_valid_len` is 0, this loop doesn't run.
		while(line_start < buff_valid_end) {
			char *const line_end = memchr(line_start, '\n', buff_valid_end - line_start);
			if(!line_end) {
				// bug: if we enter the loop, the range [line_start, buff_valid_end] contains '\n',
				// so it's impossible to end up here.
				ASSERT(false);
				return scap_errprintf(error,
				                      0,
				                      "bug found while parsing socket table file %s: unexpected "
				                      "line with no newline",
				                      filename);
			}
			// Replace '\n' with '\0' to make string-related API work.
			// note: the original '\n' is restored at the end of the iteration.
			*line_end = '\0';

			int32_t res = SCAP_FAILURE;
			switch(socket_domain) {
			case AF_INET: {
				res = parse_ipv4_socket_table_line(line_start, line_end, sockets, l4proto, error);
				break;
			}
			case AF_INET6: {
				res = parse_ipv6_socket_table_line(line_start, line_end, sockets, l4proto, error);
				break;
			}
			case AF_UNIX: {
				res = parse_unix_socket_table_line(line_start, line_end, sockets, error);
				break;
			}
			case AF_NETLINK: {
				res = parse_netlink_socket_table_line(line_start, line_end, sockets, error);
				break;
			}
			default: {
				ASSERT(false);
				return scap_errprintf(
				        error,
				        0,
				        "bug found while parsing socket table file %s: unknown socket domain %d",
				        filename,
				        socket_domain);
			}
			}
			if(res != SCAP_SUCCESS) {
				return res;
			}

			*line_end = '\n';
			line_start = line_end + 1;
		}

		// Apply shifting logic to move the truncated trailing line (if any) at the beginning of the
		// buffer.
		// note: this remove from the buffer any processed data, that is data in the range
		// [buff, buff+buff_valid_len]).
		// note: the shift is not applied if we haven't processed any data in this iteration.
		const size_t buff_unprocessed_data_len = bytes_in_buff - buff_valid_len;
		if(buff_unprocessed_data_len > 0 && buff_valid_len > 0) {
			memmove(buff, buff + buff_valid_len, buff_unprocessed_data_len);
		}
		// Now the buffer contains only unprocessed data.
		bytes_in_buff = buff_unprocessed_data_len;
		if(bytes_in_buff == sizeof(buff)) {
			// It is almost impossible we filled the entire buffer with something not containing any
			// '\n' character. We don't have much to do here: just returning.
			ASSERT(false);
			return SCAP_SUCCESS;
		}
	}

	// This is unreachable!
	ASSERT(false);
	return scap_errprintf(error,
	                      0,
	                      "bug found while parsing socket table file %s: control should never "
	                      "reach any statement after the outer while loop in "
	                      "parse_procfs_proc_pid_socket_table_file_impl()!",
	                      filename);
}

static int32_t parse_procfs_proc_pid_socket_table_file(const char *filename,
                                                       const int socket_domain,
                                                       const int l4proto,
                                                       scap_fdinfo **sockets,
                                                       char *const error) {
	const int fd = open(filename, O_RDONLY, 0);
	if(fd == -1) {
		return scap_errprintf(error, errno, "can't open socket table file %s", filename);
	}

	const int32_t res = parse_procfs_proc_pid_socket_table_file_impl(fd,
	                                                                 filename,
	                                                                 socket_domain,
	                                                                 sockets,
	                                                                 l4proto,
	                                                                 error);
	close(fd);
	return res;
}

int32_t scap_fd_read_sockets_impl(char *procdir, struct scap_ns_socket_list *sockets, char *error) {
	char filename[SCAP_MAX_PATH_SIZE];
	char netroot[SCAP_MAX_PATH_SIZE];
	char err_buf[SCAP_LASTERR_SIZE];

	if(sockets->net_ns) {
		// Namespace support, look in /proc/PID/net/.
		snprintf(netroot, sizeof(netroot), "%snet/", procdir);
	} else {
		// No namespace support, look in the base /proc/net/.
		snprintf(netroot, sizeof(netroot), "%s/proc/net/", scap_get_host_root());
	}

	snprintf(filename, sizeof(filename), "%stcp", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_INET,
	                                           SCAP_L4_TCP,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read IPv4 TCP sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%sudp", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_INET,
	                                           SCAP_L4_UDP,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read IPv4 UDP sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%sraw", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_INET,
	                                           SCAP_L4_RAW,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read IPv4 raw sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%sunix", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_UNIX,
	                                           SCAP_L4_NA,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read unix sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%snetlink", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_NETLINK,
	                                           SCAP_L4_NA,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read netlink sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%stcp6", netroot);
	// We assume IPv6 isn't available if /proc/net/tcp6 is not available.
	if(access(filename, R_OK) != 0) {
		return SCAP_SUCCESS;
	}

	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_INET6,
	                                           SCAP_L4_TCP,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read IPv6 TCP sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%sudp6", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_INET6,
	                                           SCAP_L4_UDP,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read IPv6 UDP sockets: %s", err_buf);
	}

	snprintf(filename, sizeof(filename), "%sraw6", netroot);
	if(parse_procfs_proc_pid_socket_table_file(filename,
	                                           AF_INET6,
	                                           SCAP_L4_RAW,
	                                           &sockets->sockets,
	                                           err_buf) == SCAP_FAILURE) {
		return scap_errprintf(error, 0, "can't read IPv6 raw sockets: %s", err_buf);
	}

	return SCAP_SUCCESS;
}

int32_t scap_fd_read_sockets(char *procdir, struct scap_ns_socket_list *sockets, char *error) {
	const int32_t res = scap_fd_read_sockets_impl(procdir, sockets, error);
	if(res != SCAP_SUCCESS) {
		scap_fd_free_table(&sockets->sockets);
	}
	return res;
}

char *decode_st_mode(struct stat *sb) {
	switch(sb->st_mode & S_IFMT) {
	case S_IFBLK:
		return "block device";
		break;
	case S_IFCHR:
		return "character device";
		break;
	case S_IFDIR:
		return "directory";
		break;
	case S_IFIFO:
		return "FIFO/pipe";
		break;
	case S_IFLNK:
		return "symlink";
		break;
	case S_IFREG:
		return "regular file";
		break;
	case S_IFSOCK:
		return "socket";
		break;
	default:
		return "unknown?";
		break;
	}
}

static int32_t handle_file(struct scap_proclist *proclist,
                           char *f_name,
                           scap_threadinfo *tinfo,
                           scap_fdinfo *fdi,
                           char *procdir,
                           struct stat const *const sb,
                           uint64_t const net_ns,
                           struct scap_ns_socket_list **sockets_by_ns,
                           char *error) {
	switch(sb->st_mode & S_IFMT) {
	case S_IFIFO:
		fdi->type = SCAP_FD_FIFO;
		return scap_fd_handle_pipe(proclist, f_name, tinfo, fdi, error);
	case S_IFREG:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFLNK:
		fdi->type = SCAP_FD_FILE_V2;
		fdi->ino = sb->st_ino;
		return scap_fd_handle_regular_file(proclist, f_name, tinfo, fdi, procdir, error);
	case S_IFDIR:
		fdi->type = SCAP_FD_DIRECTORY;
		fdi->ino = sb->st_ino;
		return scap_fd_handle_regular_file(proclist, f_name, tinfo, fdi, procdir, error);
	case S_IFSOCK:
		fdi->type = SCAP_FD_UNKNOWN;
		return scap_fd_handle_socket(proclist,
		                             f_name,
		                             tinfo,
		                             fdi,
		                             procdir,
		                             net_ns,
		                             sockets_by_ns,
		                             error);
	default:
		fdi->type = SCAP_FD_UNSUPPORTED;
		fdi->ino = sb->st_ino;
		return scap_fd_handle_regular_file(proclist, f_name, tinfo, fdi, procdir, error);
	}
}

//
// Scan the directory containing the fd's of a proc /proc/x/fd
//
int32_t scap_fd_scan_fd_dir(struct scap_linux_platform *linux_platform,
                            struct scap_proclist *proclist,
                            char *procdir,
                            scap_threadinfo *tinfo,
                            struct scap_ns_socket_list **sockets_by_ns,
                            uint64_t *num_fds_ret,
                            char *error) {
	DIR *dir_p;
	struct dirent *dir_entry_p;
	int32_t res = SCAP_SUCCESS;
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char f_name[SCAP_MAX_PATH_SIZE];
	struct stat sb;
	uint64_t fd;
	scap_fdinfo fdi = {};
	uint64_t net_ns;
	uint32_t fd_added = 0;

	if(num_fds_ret != NULL) {
		*num_fds_ret = 0;
	}

	snprintf(fd_dir_name, sizeof(fd_dir_name), "%sfd", procdir);
	dir_p = opendir(fd_dir_name);
	if(dir_p == NULL) {
		scap_errprintf(error, 0, "error opening the directory %s", fd_dir_name);
		return SCAP_NOTFOUND;
	}

	// Get the network namespace of the process.
	snprintf(f_name, sizeof(f_name), "%sns/net", procdir);
	if(stat(f_name, &sb) == -1) {
		// Assume default network namespace.
		net_ns = 0;
	} else {
		net_ns = sb.st_ino;
	}

	while((dir_entry_p = readdir(dir_p)) != NULL &&
	      (linux_platform->m_fd_lookup_limit == 0 ||
	       fd_added < linux_platform->m_fd_lookup_limit)) {
		snprintf(f_name, sizeof(f_name), "%s/%s", fd_dir_name, dir_entry_p->d_name);

		if(-1 == stat(f_name, &sb) || 1 != sscanf(dir_entry_p->d_name, "%" PRIu64, &fd)) {
			continue;
		}
		fdi.fd = fd;

		// In no driver mode to limit cpu usage we just parse sockets
		// because we are interested only on them.
		if(linux_platform->m_minimal_scan && !S_ISSOCK(sb.st_mode)) {
			continue;
		}

		if(handle_file(proclist, f_name, tinfo, &fdi, procdir, &sb, net_ns, sockets_by_ns, error) !=
		   SCAP_SUCCESS) {
			break;
		}

		++fd_added;
	}
	closedir(dir_p);

	if(num_fds_ret != NULL) {
		*num_fds_ret = fd_added;
	}

	return res;
}

int32_t scap_fd_get_fdinfo(struct scap_linux_platform const *const linux_platform,
                           struct scap_proclist *proclist,
                           char *procdir,
                           scap_threadinfo *tinfo,
                           int const fd,
                           struct scap_ns_socket_list **sockets_by_ns,
                           char *error) {
	char f_name[SCAP_MAX_PATH_SIZE];
	struct stat sb;
	uint64_t net_ns;
	scap_fdinfo fdi = {};

	// Get the network namespace of the process.
	snprintf(f_name, sizeof(f_name), "%sns/net", procdir);
	if(stat(f_name, &sb) == -1) {
		// Assume default network namespace.
		net_ns = 0;
	} else {
		net_ns = sb.st_ino;
	}

	// Get file descriptor stat.
	snprintf(f_name, sizeof(f_name), "%sfd/%d", procdir, fd);
	if(stat(f_name, &sb) == -1) {
		scap_errprintf(error, 0, "error getting file status for %s", f_name);
		return SCAP_NOTFOUND;
	}
	fdi.fd = fd;

	// In no driver mode to limit cpu usage we just parse sockets
	// because we are interested only on them.
	if(linux_platform->m_minimal_scan && !S_ISSOCK(sb.st_mode)) {
		return SCAP_SUCCESS;
	}

	return handle_file(proclist, f_name, tinfo, &fdi, procdir, &sb, net_ns, sockets_by_ns, error);
}
