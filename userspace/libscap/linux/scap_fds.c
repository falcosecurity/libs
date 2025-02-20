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
	proclist->m_proc_callback(proclist->m_proc_callback_context,
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

uint32_t scap_linux_get_device_by_mount_id(struct scap_platform *platform,
                                           const char *procdir,
                                           unsigned long requested_mount_id) {
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_PATH_SIZE];
	FILE *finfo;
	scap_mountinfo *mountinfo;
	struct scap_linux_platform *linux_platform = (struct scap_linux_platform *)platform;

	HASH_FIND_INT64(linux_platform->m_dev_list, &requested_mount_id, mountinfo);
	if(mountinfo != NULL) {
		return mountinfo->dev;
	}

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%smountinfo", procdir);
	finfo = fopen(fd_dir_name, "r");
	if(finfo == NULL) {
		return 0;
	}

	while(fgets(line, sizeof(line), finfo) != NULL) {
		uint32_t mount_id, major, minor;
		if(sscanf(line, "%u %*u %u:%u", &mount_id, &major, &minor) != 3) {
			continue;
		}

		if(mount_id == requested_mount_id) {
			uint32_t dev = makedev(major, minor);
			mountinfo = malloc(sizeof(*mountinfo));
			if(mountinfo) {
				int32_t uth_status = SCAP_SUCCESS;
				mountinfo->mount_id = mount_id;
				mountinfo->dev = dev;
				HASH_ADD_INT64(linux_platform->m_dev_list, mount_id, mountinfo);
				if(uth_status != SCAP_SUCCESS) {
					free(mountinfo);
				}
			}
			fclose(finfo);
			return dev;
		}
	}
	fclose(finfo);
	return 0;
}

void scap_fd_flags_file(scap_fdinfo *fdi, const char *procdir) {
	char fd_dir_name[SCAP_MAX_PATH_SIZE];
	char line[SCAP_MAX_PATH_SIZE];
	FILE *finfo;

	snprintf(fd_dir_name, SCAP_MAX_PATH_SIZE, "%sfdinfo/%" PRId64, procdir, fdi->fd);
	finfo = fopen(fd_dir_name, "r");
	if(finfo == NULL) {
		return;
	}
	fdi->info.regularinfo.mount_id = 0;
	fdi->info.regularinfo.dev = 0;

	while(fgets(line, sizeof(line), finfo) != NULL) {
		// We are interested in the flags and the mnt_id.
		//
		// The format of the file is:
		// pos:    XXXX
		// flags:  YYYYYYYY
		// mnt_id: ZZZ

		if(!strncmp(line, "flags:\t", sizeof("flags:\t") - 1)) {
			uint32_t open_flags;
			errno = 0;
			unsigned long flags = strtoul(line + sizeof("flags:\t") - 1, NULL, 8);

			if(errno == ERANGE) {
				open_flags = PPM_O_NONE;
			} else {
				open_flags = open_flags_to_scap(flags);
			}

			fdi->info.regularinfo.open_flags = open_flags;
		} else if(!strncmp(line, "mnt_id:\t", sizeof("mnt_id:\t") - 1)) {
			errno = 0;
			unsigned long mount_id = strtoul(line + sizeof("mnt_id:\t") - 1, NULL, 10);

			if(errno != ERANGE) {
				fdi->info.regularinfo.mount_id = mount_id;
			}
		}
	}

	fclose(finfo);
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

	proclist->m_proc_callback(proclist->m_proc_callback_context,
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
				snprintf(error, SCAP_LASTERR_SIZE, "sockets allocation error");
				return SCAP_FAILURE;
			}
			sockets->net_ns = net_ns;
			sockets->sockets = NULL;
			char fd_error[SCAP_LASTERR_SIZE];

			HASH_ADD_INT64(*sockets_by_ns, net_ns, sockets);
			if(uth_status != SCAP_SUCCESS) {
				snprintf(error, SCAP_LASTERR_SIZE, "socket list allocation error");
				free(sockets);
				return SCAP_FAILURE;
			}

			if(scap_fd_read_sockets(procdir, sockets, fd_error) == SCAP_FAILURE) {
				snprintf(error, SCAP_LASTERR_SIZE, "Cannot read sockets (%s)", fd_error);
				sockets->sockets = NULL;
				return SCAP_FAILURE;
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
		proclist->m_proc_callback(proclist->m_proc_callback_context,
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
		proclist->m_proc_callback(proclist->m_proc_callback_context,
		                          error,
		                          tinfo->tid,
		                          tinfo,
		                          fdi,
		                          NULL);
	}
	return SCAP_SUCCESS;
}

int32_t scap_fd_read_unix_sockets_from_proc_fs(const char *filename,
                                               scap_fdinfo **sockets,
                                               char *error) {
	FILE *f;
	char line[SCAP_MAX_PATH_SIZE];
	int first_line = false;
	char *delimiters = " \t";
	char *token;
	int32_t uth_status = SCAP_SUCCESS;

	f = fopen(filename, "r");
	if(NULL == f) {
		ASSERT(false);
		return scap_errprintf(error, errno, "Could not open sockets file %s", filename);
	}
	while(NULL != fgets(line, sizeof(line), f)) {
		char *scratch;

		// skip the first line ... contains field names
		if(!first_line) {
			first_line = true;
			continue;
		}
		scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
		if(fdinfo == NULL) {
			snprintf(error, SCAP_LASTERR_SIZE, "fdinfo allocation error");
			fclose(f);
			return SCAP_FAILURE;
		}
		fdinfo->type = SCAP_FD_UNIX_SOCK;

		//
		// parse the fields
		//
		// 1. Num
		token = strtok_r(line, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		fdinfo->info.unix_socket_info.source = strtoul(token, NULL, 16);
		fdinfo->info.unix_socket_info.destination = 0;

		// 2. RefCount
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 3. Protocol
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 4. Flags
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 5. Type
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 6. St
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 7. Inode
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		sscanf(token, "%" PRIu64, &(fdinfo->ino));

		// 8. Path
		token = strtok_r(NULL, delimiters, &scratch);
		if(NULL != token) {
			strlcpy(fdinfo->info.unix_socket_info.fname,
			        token,
			        sizeof(fdinfo->info.unix_socket_info.fname));
		} else {
			fdinfo->info.unix_socket_info.fname[0] = '\0';
		}

		HASH_ADD_INT64((*sockets), ino, fdinfo);
		if(uth_status != SCAP_SUCCESS) {
			snprintf(error, SCAP_LASTERR_SIZE, "unix socket allocation error");
			fclose(f);
			free(fdinfo);
			return SCAP_FAILURE;
		}
	}
	fclose(f);
	return uth_status;
}

// sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
// ffff88011abfb000 0   0      00000000 0        0        0 2        0        13

int32_t scap_fd_read_netlink_sockets_from_proc_fs(const char *filename,
                                                  scap_fdinfo **sockets,
                                                  char *error) {
	FILE *f;
	char line[SCAP_MAX_PATH_SIZE];
	int first_line = false;
	char *delimiters = " \t";
	char *token;
	int32_t uth_status = SCAP_SUCCESS;

	f = fopen(filename, "r");
	if(NULL == f) {
		return scap_errprintf(error, errno, "Could not open netlink sockets file %s", filename);
	}
	while(NULL != fgets(line, sizeof(line), f)) {
		char *scratch;

		// skip the first line ... contains field names
		if(!first_line) {
			first_line = true;
			continue;
		}
		scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
		if(fdinfo == NULL) {
			snprintf(error, SCAP_LASTERR_SIZE, "fdinfo allocation error");
			fclose(f);
			return SCAP_FAILURE;
		}
		memset(fdinfo, 0, sizeof(scap_fdinfo));
		fdinfo->type = SCAP_FD_UNIX_SOCK;

		//
		// parse the fields
		//
		// 1. Num
		token = strtok_r(line, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 2. Eth
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 3. Pid
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 4. Groups
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 5. Rmem
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 6. Wmem
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 7. Dump
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 8. Locks
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 9. Drops
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		// 10. Inode
		token = strtok_r(NULL, delimiters, &scratch);
		if(token == NULL) {
			ASSERT(false);
			free(fdinfo);
			continue;
		}

		sscanf(token, "%" PRIu64, &(fdinfo->ino));

		HASH_ADD_INT64((*sockets), ino, fdinfo);
		if(uth_status != SCAP_SUCCESS) {
			snprintf(error, SCAP_LASTERR_SIZE, "netlink socket allocation error");
			fclose(f);
			free(fdinfo);
			return SCAP_FAILURE;
		}
	}
	fclose(f);
	return uth_status;
}

int32_t scap_fd_read_ipv4_sockets_from_proc_fs(const char *dir,
                                               int l4proto,
                                               scap_fdinfo **sockets,
                                               char *error) {
	FILE *f;
	int32_t uth_status = SCAP_SUCCESS;
	char *scan_buf;
	char *scan_pos;
	char *tmp_pos;
	uint32_t rsize;
	char *end;
	char tc;
	uint32_t j;

	scan_buf = (char *)malloc(SOCKET_SCAN_BUFFER_SIZE);
	if(scan_buf == NULL) {
		snprintf(error, SCAP_LASTERR_SIZE, "scan_buf allocation error");
		return SCAP_FAILURE;
	}

	f = fopen(dir, "r");
	if(NULL == f) {
		free(scan_buf);
		return scap_errprintf(error, errno, "Could not open ipv4 sockets dir %s", dir);
	}

	while((rsize = fread(scan_buf, 1, SOCKET_SCAN_BUFFER_SIZE, f)) != 0) {
		char *scan_end = scan_buf + rsize;
		scan_pos = scan_buf;

		while(scan_pos <= scan_end) {
			scan_pos = memchr(scan_pos, '\n', scan_end - scan_pos);

			if(scan_pos == NULL) {
				break;
			}

			scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
			if(fdinfo == NULL) {
				fclose(f);
				free(scan_buf);
				return scap_errprintf(
				        error,
				        errno,
				        "memory allocation error in scap_fd_read_ipv4_sockets_from_proc_fs");
			}

			//
			// Skip the sl field
			//
			scan_pos = memchr(scan_pos, ':', scan_end - scan_pos);
			if(scan_pos == NULL) {
				free(fdinfo);
				break;
			}

			scan_pos += 2;
			if(scan_pos + 80 >= scan_end) {
				free(fdinfo);
				break;
			}

			//
			// Scan the local address
			//
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv4info.sip = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv4info.sport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Scan the remote address
			//
			scan_pos += 5;

			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv4info.dip = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv4info.dport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Skip to parsing the inode
			//
			scan_pos += 4;

			for(j = 0; j < 6; j++) {
				scan_pos++;

				scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
				if(scan_pos == NULL) {
					break;
				}

				while(scan_pos < scan_end && *scan_pos == ' ') {
					scan_pos++;
				}

				if(scan_pos >= scan_end) {
					break;
				}
			}

			if(j < 6) {
				free(fdinfo);
				break;
			}

			tmp_pos = scan_pos;
			scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
			if(scan_pos == NULL || scan_pos >= scan_end) {
				free(fdinfo);
				break;
			}

			tc = *(scan_pos);

			fdinfo->ino = (uint64_t)strtoull(tmp_pos, &end, 10);

			*(scan_pos) = tc;

			//
			// Add to the table
			//
			if(fdinfo->info.ipv4info.dip == 0) {
				fdinfo->type = SCAP_FD_IPV4_SERVSOCK;
				fdinfo->info.ipv4serverinfo.l4proto = l4proto;
				fdinfo->info.ipv4serverinfo.port = fdinfo->info.ipv4info.sport;
				fdinfo->info.ipv4serverinfo.ip = fdinfo->info.ipv4info.sip;
			} else {
				fdinfo->type = SCAP_FD_IPV4_SOCK;
				fdinfo->info.ipv4info.l4proto = l4proto;
			}

			HASH_ADD_INT64((*sockets), ino, fdinfo);

			if(uth_status != SCAP_SUCCESS) {
				uth_status = SCAP_FAILURE;
				snprintf(error, SCAP_LASTERR_SIZE, "ipv4 socket allocation error");
				free(fdinfo);
				break;
			}

			scan_pos++;
		}
	}

	fclose(f);
	free(scan_buf);
	return uth_status;
}

int32_t scap_fd_is_ipv6_server_socket(uint32_t ip6_addr[4]) {
	return 0 == ip6_addr[0] && 0 == ip6_addr[1] && 0 == ip6_addr[2] && 0 == ip6_addr[3];
}

int32_t scap_fd_read_ipv6_sockets_from_proc_fs(char *dir,
                                               int l4proto,
                                               scap_fdinfo **sockets,
                                               char *error) {
	FILE *f;
	int32_t uth_status = SCAP_SUCCESS;
	char *scan_buf;
	char *scan_pos;
	char *tmp_pos;
	uint32_t rsize;
	char *end;
	char tc;
	uint32_t j;

	scan_buf = (char *)malloc(SOCKET_SCAN_BUFFER_SIZE);
	if(scan_buf == NULL) {
		snprintf(error, SCAP_LASTERR_SIZE, "scan_buf allocation error");
		return SCAP_FAILURE;
	}

	f = fopen(dir, "r");

	if(NULL == f) {
		free(scan_buf);
		return scap_errprintf(error, errno, "Could not open ipv6 sockets dir %s", dir);
	}

	while((rsize = fread(scan_buf, 1, SOCKET_SCAN_BUFFER_SIZE, f)) != 0) {
		char *scan_end = scan_buf + rsize;
		scan_pos = scan_buf;

		while(scan_pos <= scan_end) {
			scan_pos = memchr(scan_pos, '\n', scan_end - scan_pos);

			if(scan_pos == NULL) {
				break;
			}

			scap_fdinfo *fdinfo = malloc(sizeof(scap_fdinfo));
			if(fdinfo == NULL) {
				fclose(f);
				free(scan_buf);
				return scap_errprintf(
				        error,
				        errno,
				        "memory allocation error in scap_fd_read_ipv6_sockets_from_proc_fs");
			}

			//
			// Skip the sl field
			//
			scan_pos = memchr(scan_pos, ':', scan_end - scan_pos);
			if(scan_pos == NULL) {
				free(fdinfo);
				break;
			}

			scan_pos += 2;
			if(scan_pos + 80 >= scan_end) {
				free(fdinfo);
				break;
			}

			//
			// Scan the first address
			//
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[0] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[1] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[2] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			ASSERT(tc == ':');
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.sip[3] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv6info.sport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Scan the second address
			//
			scan_pos += 5;

			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[0] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[1] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[2] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 8;
			tc = *(scan_pos + 8);
			ASSERT(tc == ':');
			*(scan_pos + 8) = 0;
			fdinfo->info.ipv6info.dip[3] = strtoul(scan_pos, &end, 16);
			*(scan_pos + 8) = tc;

			scan_pos += 9;
			tc = *(scan_pos + 4);
			ASSERT(tc == ' ');
			*(scan_pos + 4) = 0;
			fdinfo->info.ipv6info.dport = (uint16_t)strtoul(scan_pos, &end, 16);
			*(scan_pos + 4) = tc;

			//
			// Skip to parsing the inode
			//
			scan_pos += 4;

			for(j = 0; j < 6; j++) {
				scan_pos++;

				scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
				if(scan_pos == NULL) {
					break;
				}

				while(scan_pos < scan_end && *scan_pos == ' ') {
					scan_pos++;
				}

				if(scan_pos >= scan_end) {
					break;
				}
			}

			if(j < 6) {
				free(fdinfo);
				break;
			}

			tmp_pos = scan_pos;
			scan_pos = memchr(scan_pos, ' ', scan_end - scan_pos);
			if(scan_pos == NULL || scan_pos >= scan_end) {
				free(fdinfo);
				break;
			}

			tc = *(scan_pos);

			fdinfo->ino = (uint64_t)strtoull(tmp_pos, &end, 10);

			*(scan_pos) = tc;

			//
			// Add to the table
			//
			if(scap_fd_is_ipv6_server_socket(fdinfo->info.ipv6info.dip)) {
				fdinfo->type = SCAP_FD_IPV6_SERVSOCK;
				fdinfo->info.ipv6serverinfo.l4proto = l4proto;
				fdinfo->info.ipv6serverinfo.port = fdinfo->info.ipv6info.sport;
				fdinfo->info.ipv6serverinfo.ip[0] = fdinfo->info.ipv6info.sip[0];
				fdinfo->info.ipv6serverinfo.ip[1] = fdinfo->info.ipv6info.sip[1];
				fdinfo->info.ipv6serverinfo.ip[2] = fdinfo->info.ipv6info.sip[2];
				fdinfo->info.ipv6serverinfo.ip[3] = fdinfo->info.ipv6info.sip[3];
			} else {
				fdinfo->type = SCAP_FD_IPV6_SOCK;
				fdinfo->info.ipv6info.l4proto = l4proto;
			}

			HASH_ADD_INT64((*sockets), ino, fdinfo);

			if(uth_status != SCAP_SUCCESS) {
				uth_status = SCAP_FAILURE;
				snprintf(error, SCAP_LASTERR_SIZE, "ipv6 socket allocation error");
				break;
			}

			scan_pos++;
		}
	}

	fclose(f);
	free(scan_buf);

	return uth_status;
}

int32_t scap_fd_read_sockets(char *procdir, struct scap_ns_socket_list *sockets, char *error) {
	char filename[SCAP_MAX_PATH_SIZE];
	char netroot[SCAP_MAX_PATH_SIZE];
	char err_buf[SCAP_LASTERR_SIZE];

	if(sockets->net_ns) {
		//
		// Namespace support, look in /proc/PID/net/
		//
		snprintf(netroot, sizeof(netroot), "%snet/", procdir);
	} else {
		//
		// No namespace support, look in the base /proc
		//
		snprintf(netroot, sizeof(netroot), "%s/proc/net/", scap_get_host_root());
	}

	snprintf(filename, sizeof(filename), "%stcp", netroot);
	if(scap_fd_read_ipv4_sockets_from_proc_fs(filename, SCAP_L4_TCP, &sockets->sockets, err_buf) ==
	   SCAP_FAILURE) {
		scap_fd_free_table(&sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv4 tcp sockets (%s)", err_buf);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%sudp", netroot);
	if(scap_fd_read_ipv4_sockets_from_proc_fs(filename, SCAP_L4_UDP, &sockets->sockets, err_buf) ==
	   SCAP_FAILURE) {
		scap_fd_free_table(&sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv4 udp sockets (%s)", err_buf);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%sraw", netroot);
	if(scap_fd_read_ipv4_sockets_from_proc_fs(filename, SCAP_L4_RAW, &sockets->sockets, err_buf) ==
	   SCAP_FAILURE) {
		scap_fd_free_table(&sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv4 raw sockets (%s)", err_buf);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%sunix", netroot);
	if(scap_fd_read_unix_sockets_from_proc_fs(filename, &sockets->sockets, err_buf) ==
	   SCAP_FAILURE) {
		scap_fd_free_table(&sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read unix sockets (%s)", err_buf);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%snetlink", netroot);
	if(scap_fd_read_netlink_sockets_from_proc_fs(filename, &sockets->sockets, err_buf) ==
	   SCAP_FAILURE) {
		scap_fd_free_table(&sockets->sockets);
		snprintf(error, SCAP_LASTERR_SIZE, "Could not read netlink sockets (%s)", err_buf);
		return SCAP_FAILURE;
	}

	snprintf(filename, sizeof(filename), "%stcp6", netroot);
	/* We assume if there is /proc/net/tcp6 that ipv6 is available */
	if(access(filename, R_OK) == 0) {
		if(scap_fd_read_ipv6_sockets_from_proc_fs(filename,
		                                          SCAP_L4_TCP,
		                                          &sockets->sockets,
		                                          err_buf) == SCAP_FAILURE) {
			scap_fd_free_table(&sockets->sockets);
			snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv6 tcp sockets (%s)", err_buf);
			return SCAP_FAILURE;
		}

		snprintf(filename, sizeof(filename), "%sudp6", netroot);
		if(scap_fd_read_ipv6_sockets_from_proc_fs(filename,
		                                          SCAP_L4_UDP,
		                                          &sockets->sockets,
		                                          err_buf) == SCAP_FAILURE) {
			scap_fd_free_table(&sockets->sockets);
			snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv6 udp sockets (%s)", err_buf);
			return SCAP_FAILURE;
		}

		snprintf(filename, sizeof(filename), "%sraw6", netroot);
		if(scap_fd_read_ipv6_sockets_from_proc_fs(filename,
		                                          SCAP_L4_RAW,
		                                          &sockets->sockets,
		                                          err_buf) == SCAP_FAILURE) {
			scap_fd_free_table(&sockets->sockets);
			snprintf(error, SCAP_LASTERR_SIZE, "Could not read ipv6 raw sockets (%s)", err_buf);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
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
		snprintf(error, SCAP_LASTERR_SIZE, "error opening the directory %s", fd_dir_name);
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
		return SCAP_NOTFOUND;
	}
	fdi.fd = fd;

	// In no driver mode to limit cpu usage we just parse sockets
	// because we are interested only on them.
	if(linux_platform->m_minimal_scan && !S_ISSOCK(sb.st_mode)) {
		return EXIT_SUCCESS;
	}

	return handle_file(proclist, f_name, tinfo, &fdi, procdir, &sb, net_ns, sockets_by_ns, error);
}
