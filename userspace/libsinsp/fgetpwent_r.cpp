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

//
// From-scratch implementations of fgetpwent_r() and fgetgrent_r() for
// platforms that lack them (e.g. musl).  These parse /etc/passwd and
// /etc/group line-by-line into caller-owned storage, with no global
// or thread-local state.
//
// This file is only compiled on non-glibc builds (see CMakeLists.txt).
//

#include <libsinsp/fgetpwent_r.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

// Find the next colon (or end-of-string) in s, return the length of the field.
static size_t field_len(const char *s) {
	const char *p = s;
	while(*p && *p != ':') {
		p++;
	}
	return static_cast<size_t>(p - s);
}

#ifdef HAVE_PWD_H
// Parse one line of /etc/passwd: name:passwd:uid:gid:gecos:dir:shell
int fgetpwent_r(FILE *f, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
	*result = nullptr;

	if(!fgets(buf, static_cast<int>(buflen), f)) {
		return errno ? errno : ENOENT;
	}

	// Strip trailing newline
	size_t line_len = strlen(buf);
	if(line_len > 0 && buf[line_len - 1] == '\n') {
		buf[--line_len] = '\0';
	}

	// Parse 7 colon-separated fields
	const char *fields[7];
	size_t lengths[7];
	const char *p = buf;
	for(int i = 0; i < 7; i++) {
		fields[i] = p;
		lengths[i] = field_len(p);
		p += lengths[i];
		if(*p == ':') {
			p++;
		} else if(i < 6) {
			return ENOENT;  // malformed line
		}
	}

	// Null-terminate each field in-place by overwriting ':' separators
	char *w = buf;
	for(int i = 0; i < 7; i++) {
		w += lengths[i];
		if(i < 6) {
			*w++ = '\0';
		}
	}

	pwd->pw_name = const_cast<char *>(fields[0]);
	pwd->pw_passwd = const_cast<char *>(fields[1]);
	pwd->pw_uid = static_cast<uid_t>(strtoul(fields[2], nullptr, 10));
	pwd->pw_gid = static_cast<gid_t>(strtoul(fields[3], nullptr, 10));
	pwd->pw_gecos = const_cast<char *>(fields[4]);
	pwd->pw_dir = const_cast<char *>(fields[5]);
	pwd->pw_shell = const_cast<char *>(fields[6]);

	*result = pwd;
	return 0;
}
#endif

#ifdef HAVE_GRP_H
// Parse one line of /etc/group: name:passwd:gid:member1,member2,...
int fgetgrent_r(FILE *f, struct group *grp, char *buf, size_t buflen, struct group **result) {
	*result = nullptr;

	if(!fgets(buf, static_cast<int>(buflen), f)) {
		return errno ? errno : ENOENT;
	}

	size_t line_len = strlen(buf);
	if(line_len > 0 && buf[line_len - 1] == '\n') {
		buf[--line_len] = '\0';
	}

	// Parse 4 colon-separated fields
	const char *fields[4];
	size_t lengths[4];
	const char *p = buf;
	for(int i = 0; i < 4; i++) {
		fields[i] = p;
		lengths[i] = field_len(p);
		p += lengths[i];
		if(*p == ':') {
			p++;
		} else if(i < 3) {
			return ENOENT;  // malformed line
		}
	}

	// Null-terminate each field in-place
	char *w = buf;
	for(int i = 0; i < 4; i++) {
		w += lengths[i];
		if(i < 3) {
			*w++ = '\0';
		}
	}

	grp->gr_name = const_cast<char *>(fields[0]);
	grp->gr_passwd = const_cast<char *>(fields[1]);
	grp->gr_gid = static_cast<gid_t>(strtoul(fields[2], nullptr, 10));

	// Parse comma-separated member list from fields[3].
	const char *members = fields[3];
	size_t members_len = lengths[3];

	// Count members
	size_t nmem = 0;
	if(members_len > 0) {
		nmem = 1;
		for(size_t i = 0; i < members_len; i++) {
			if(members[i] == ',') {
				nmem++;
			}
		}
	}

	// Place the char** pointer array after the parsed line data, aligned.
	char *after_line = const_cast<char *>(fields[3]) + members_len + 1;
	uintptr_t align_off = reinterpret_cast<uintptr_t>(after_line) % alignof(char *);
	if(align_off) {
		after_line += alignof(char *) - align_off;
	}
	char *end = buf + buflen;
	size_t ptrs_size = (nmem + 1) * sizeof(char *);
	if(after_line + ptrs_size > end) {
		return ERANGE;
	}

	grp->gr_mem = reinterpret_cast<char **>(after_line);

	// Split member list by replacing ',' with '\0'
	if(nmem > 0) {
		char *m = const_cast<char *>(fields[3]);
		size_t idx = 0;
		grp->gr_mem[idx++] = m;
		for(size_t i = 0; i < members_len; i++) {
			if(m[i] == ',') {
				m[i] = '\0';
				if(idx < nmem) {
					grp->gr_mem[idx++] = &m[i + 1];
				}
			}
		}
	}
	grp->gr_mem[nmem] = nullptr;

	*result = grp;
	return 0;
}
#endif
