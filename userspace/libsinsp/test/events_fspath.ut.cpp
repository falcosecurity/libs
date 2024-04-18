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

#include <fcntl.h>

#include <gtest/gtest.h>

#include "filter_compiler.h"
#include <sinsp_with_test_input.h>

class fspath : public sinsp_with_test_input
{
protected:

	const char *filename = "/tmp/random/dir.../..//../filename.txt";
	const char *resolved_filename = "/tmp/filename.txt";
	const char *rel_filename = "tmp/filename.txt";
	const char *resolved_rel_filename = "/root/tmp/filename.txt";

	const char *rel_filename_complex = "../\\.../../tmp/filename_complex";
	const char *resolved_rel_filename_complex = "/tmp/filename_complex";

	const char *rel_filename_nopath = "nopath";
	const char *resolved_rel_filename_nopath = "/root/nopath";

	const char *name = "/tmp/random/dir...///../../name/";
	const char *resolved_name = "/tmp/name";
	const char *rel_name = "tmp/random/dir...///../../name/";
	const char *resolved_rel_name = "/root/tmp/name";
	const char *path = "/tmp/path";
	const char *oldpath = "/tmp/oldpath";
	const char *newpath = "/tmp/newpath";
	const char *rel_oldpath = "tmp/oldpath";
	const char *rel_newpath = "tmp/newpath";
	const char *resolved_rel_oldpath = "/root/tmp/oldpath";
	const char *resolved_rel_newpath = "/root/tmp/newpath";
	const char *linkpath = "/tmp/linkpath";
	const char *targetpath = "/tmp/targetpath";
	const char *rel_linkpath = "tmp/linkpath";
	const char *rel_targetpath = "tmp/targetpath";
	const char *resolved_rel_linkpath = "/root/tmp/linkpath";
	const char *resolved_rel_targetpath = "/root/tmp/targetpath";
	const char *mountpath = "/mnt/cdrom";
	uint32_t mode = S_IFREG;
	int64_t res = 0;
	int64_t failed_res = -1;
	int64_t dirfd = 0;
	int64_t rel_dirfd = AT_FDCWD;
	int64_t olddirfd = -1;
	int64_t newdirfd = -1;
	int64_t linkdirfd = -1;
	int32_t flags = 0;
	int64_t fd = 3;
	int32_t open_flags = PPM_O_RDWR;
	uint32_t dev = 0;
	uint64_t ino = 0;
	uint32_t resolve = 0;
	uint32_t uid = 0;
	uint32_t gid = 0;

	const char *fs_path_name = "fs.path.name";
	const char *fs_path_nameraw = "fs.path.nameraw";
	const char *fs_path_source = "fs.path.source";
	const char *fs_path_sourceraw = "fs.path.sourceraw";
	const char *fs_path_target = "fs.path.target";
	const char *fs_path_targetraw = "fs.path.targetraw";

	void SetUp()
	{
		sinsp_with_test_input::SetUp();
		add_default_init_thread();
		open_inspector();
	}

	void inject_open_event()
	{
		sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 0);
		evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, path, open_flags, mode, dev, ino);
		ASSERT_STREQ(get_field_as_string(evt, "fd.name").c_str(), path);
	}

	void verify_no_fields(sinsp_evt *evt)

	{
		ASSERT_FALSE(field_has_value(evt, fs_path_name));
		ASSERT_FALSE(field_has_value(evt, fs_path_nameraw));
		ASSERT_FALSE(field_has_value(evt, fs_path_source));
		ASSERT_FALSE(field_has_value(evt, fs_path_sourceraw));
		ASSERT_FALSE(field_has_value(evt, fs_path_target));
		ASSERT_FALSE(field_has_value(evt, fs_path_targetraw));
	}

	void verify_value_using_filters(sinsp_evt *evt,
					const char *field,
					const char *expected)
	{
		std::string fieldstr = field;

		std::string eq_filter_str = fieldstr + " = " + expected;
		filter_run(evt, true, eq_filter_str);

		std::string in_filter_str = fieldstr + " in (" + expected + ")";
		filter_run(evt, true, in_filter_str);

		std::string pmatch_filter_str = fieldstr + " pmatch (" + expected + ")";
		filter_run(evt, true, pmatch_filter_str);
	}

	void verify_fields(sinsp_evt *evt,
			   const char *expected_name,
			   const char *expected_nameraw,
			   const char *expected_source,
			   const char *expected_sourceraw,
			   const char *expected_target,
			   const char *expected_targetraw)
	{
		if(expected_name)
		{
			ASSERT_STREQ(get_field_as_string(evt, fs_path_name).c_str(), expected_name);
			verify_value_using_filters(evt, fs_path_name, expected_name);
		}

		if(expected_nameraw)
		{
			ASSERT_STREQ(get_field_as_string(evt, fs_path_nameraw).c_str(), expected_nameraw);
			verify_value_using_filters(evt, fs_path_nameraw, expected_nameraw);
		}

		if(expected_source)
		{
			ASSERT_STREQ(get_field_as_string(evt, fs_path_source).c_str(), expected_source);
			verify_value_using_filters(evt, fs_path_source, expected_source);
		}

		if(expected_sourceraw)
		{
			ASSERT_STREQ(get_field_as_string(evt, fs_path_sourceraw).c_str(), expected_sourceraw);
			verify_value_using_filters(evt, fs_path_sourceraw, expected_sourceraw);
		}

		if(expected_target)
		{
			ASSERT_STREQ(get_field_as_string(evt, fs_path_target).c_str(), expected_target);
			verify_value_using_filters(evt, fs_path_target, expected_target);
		}

		if(expected_targetraw)
		{
			ASSERT_STREQ(get_field_as_string(evt, fs_path_targetraw).c_str(), expected_targetraw);
			verify_value_using_filters(evt, fs_path_targetraw, expected_targetraw);
		}
	}

	void test_enter(ppm_event_code event_type, uint32_t n, ...)
	{
		va_list args;
		va_start(args, n);
		sinsp_evt* evt = add_event_advance_ts_v(increasing_ts(), 1, event_type, n, args);
		va_end(args);

		verify_no_fields(evt);
	}

	void test_exit_path(const char *expected_name, const char *expected_name_raw,
			    ppm_event_code event_type, uint32_t n, ...)
	{

		va_list args;
		va_start(args, n);
		sinsp_evt* evt = add_event_advance_ts_v(increasing_ts(), 1, event_type, n, args);
		va_end(args);

		verify_fields(evt, expected_name, expected_name_raw, NULL, NULL, NULL, NULL);
	}

	void test_exit_source_target(const char *expected_source,
					 const char *expected_sourceraw,
					 const char *expected_target,
					 const char *expected_targetraw,
					 ppm_event_code event_type, uint32_t n, ...)
	{

		va_list args;
		va_start(args, n);
		sinsp_evt* evt = add_event_advance_ts_v(increasing_ts(), 1, event_type, n, args);
		va_end(args);

		verify_fields(evt,
			      NULL, NULL,
			      expected_source, expected_sourceraw,
			      expected_target, expected_targetraw);
	}

	void test_failed_exit(ppm_event_code event_type, uint32_t n, ...)
	{
		va_list args;
		va_start(args, n);
		sinsp_evt* evt = add_event_advance_ts_v(increasing_ts(), 1, event_type, n, args);
		va_end(args);

		verify_no_fields(evt);
	}
};

TEST_F(fspath, mkdir)
{
	test_enter(PPME_SYSCALL_MKDIR_E, 2, path, mode);
	test_exit_path(path, path, PPME_SYSCALL_MKDIR_X, 1, res);
	test_failed_exit(PPME_SYSCALL_MKDIR_X, 1, failed_res);
}

TEST_F(fspath, mkdir_2)
{
	test_enter(PPME_SYSCALL_MKDIR_2_E, 1, mode);
	test_exit_path(path, path, PPME_SYSCALL_MKDIR_2_X, 2, res, path);
	test_failed_exit(PPME_SYSCALL_MKDIR_2_X, 2, failed_res, path);
}

TEST_F(fspath, mkdirat)
{
	test_enter(PPME_SYSCALL_MKDIRAT_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_MKDIRAT_X, 4, res, dirfd, path, mode);
	test_failed_exit(PPME_SYSCALL_MKDIRAT_X, 4, failed_res, dirfd, path, mode);
}

TEST_F(fspath, rmdir)
{
	test_enter(PPME_SYSCALL_RMDIR_E, 1, path);
	test_exit_path(path, path, PPME_SYSCALL_RMDIR_X, 1, res);
	test_failed_exit(PPME_SYSCALL_RMDIR_X, 1, failed_res);
}

TEST_F(fspath, rmdir_2)
{
	test_enter(PPME_SYSCALL_RMDIR_2_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_RMDIR_2_X, 2, res, path);
	test_failed_exit(PPME_SYSCALL_RMDIR_2_X, 2, failed_res, path);
}

TEST_F(fspath, unlink)
{
	test_enter(PPME_SYSCALL_UNLINK_E, 1, path);
	test_exit_path(path, path, PPME_SYSCALL_UNLINK_X, 1, res);
	test_failed_exit(PPME_SYSCALL_UNLINK_X, 1, failed_res);
}

TEST_F(fspath, unlinkat)
{
	test_enter(PPME_SYSCALL_UNLINKAT_E, 2, dirfd, name);
	test_exit_path(resolved_name, name, PPME_SYSCALL_UNLINKAT_X, 1, res);
	test_failed_exit(PPME_SYSCALL_UNLINKAT_X, 1, failed_res);
}

TEST_F(fspath, unlink_2)
{
	test_enter(PPME_SYSCALL_UNLINK_2_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_UNLINK_2_X, 2, res, path);
	test_failed_exit(PPME_SYSCALL_UNLINK_2_X, 2, failed_res, path);
}

TEST_F(fspath, unlinkat_2)
{
	test_enter(PPME_SYSCALL_UNLINKAT_2_E, 0);
	test_exit_path(resolved_rel_name, rel_name, PPME_SYSCALL_UNLINKAT_2_X, 4, res, rel_dirfd, rel_name, flags);
	test_failed_exit(PPME_SYSCALL_UNLINKAT_2_X, 4, failed_res, dirfd, name, flags);
}

TEST_F(fspath, open)
{
	test_enter(PPME_SYSCALL_OPEN_E, 3, name, open_flags, mode);
	test_exit_path(resolved_name, name, PPME_SYSCALL_OPEN_X, 6, fd, name, open_flags, mode, dev, ino);
	test_failed_exit(PPME_SYSCALL_OPEN_X, 6, failed_res, "<NA>", open_flags, mode, dev, ino);
}

TEST_F(fspath, openat)
{
	test_enter(PPME_SYSCALL_OPENAT_E, 4, dirfd, name, open_flags, mode);
	test_exit_path(resolved_name, name, PPME_SYSCALL_OPENAT_X, 1, fd);
	test_failed_exit(PPME_SYSCALL_OPENAT_X, 6, failed_res);
}

TEST_F(fspath, openat_2)
{
	test_enter(PPME_SYSCALL_OPENAT_2_E, 4, dirfd, name, open_flags, mode);
	test_exit_path(resolved_name, name, PPME_SYSCALL_OPENAT_2_X, 7, fd, dirfd, name, open_flags, mode, dev, ino);
	test_failed_exit(PPME_SYSCALL_OPENAT_2_X, 7, failed_res, dirfd, name, open_flags, mode, dev, ino);
}

TEST_F(fspath, openat2)
{
	test_enter(PPME_SYSCALL_OPENAT2_E, 5, dirfd, name, open_flags, mode, resolve);
	test_exit_path(resolved_rel_name, rel_name, PPME_SYSCALL_OPENAT2_X, 6, fd, rel_dirfd, rel_name, open_flags, mode, resolve);
	test_failed_exit(PPME_SYSCALL_OPENAT2_X, 6, failed_res, dirfd, name, open_flags, mode, resolve);
}

TEST_F(fspath, fchmodat)
{
	test_enter(PPME_SYSCALL_FCHMODAT_E, 0);
	test_exit_path(resolved_filename, filename, PPME_SYSCALL_FCHMODAT_X, 4, res, dirfd, filename, mode);
	test_failed_exit(PPME_SYSCALL_FCHMODAT_X, 4, failed_res, dirfd, filename, mode);
}

TEST_F(fspath, fchmodat_relative)
{
	test_enter(PPME_SYSCALL_FCHMODAT_E, 0);
	test_exit_path(resolved_rel_filename, rel_filename, PPME_SYSCALL_FCHMODAT_X, 4, res, rel_dirfd, rel_filename, mode);
}

TEST_F(fspath, fchmodat_relative_complex)
{
	test_enter(PPME_SYSCALL_FCHMODAT_E, 0);
	test_exit_path(resolved_rel_filename_complex, rel_filename_complex, PPME_SYSCALL_FCHMODAT_X, 4, res, rel_dirfd, rel_filename_complex, mode);
}

TEST_F(fspath, fchmodat_relative_nopath)
{
	test_enter(PPME_SYSCALL_FCHMODAT_E, 0);
	test_exit_path(resolved_rel_filename_nopath, rel_filename_nopath, PPME_SYSCALL_FCHMODAT_X, 4, res, rel_dirfd, rel_filename_nopath, mode);
}

TEST_F(fspath, chmod)
{
	test_enter(PPME_SYSCALL_CHMOD_E, 0);
	test_exit_path(resolved_filename, filename, PPME_SYSCALL_CHMOD_X, 3, res, filename, mode);
	test_failed_exit(PPME_SYSCALL_CHMOD_X, 3, failed_res, filename, mode);
}

TEST_F(fspath, chmod_relative)
{
	test_enter(PPME_SYSCALL_CHMOD_E, 0);
	test_exit_path(resolved_rel_filename, rel_filename, PPME_SYSCALL_CHMOD_X, 3, res, rel_filename, mode);
}

TEST_F(fspath, fchmod)
{
	// We need to open a fd first so fchmod can act on it
	inject_open_event();

	test_enter(PPME_SYSCALL_FCHMOD_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_FCHMOD_X, 3, res, fd, mode);
	test_failed_exit(PPME_SYSCALL_FCHMOD_X, 3, failed_res, fd, mode);
}

TEST_F(fspath, chown)
{
	test_enter(PPME_SYSCALL_CHOWN_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_CHOWN_X, 4, res, path, uid, gid);
	test_failed_exit(PPME_SYSCALL_CHOWN_X, 4, failed_res, path, uid, gid);
}

TEST_F(fspath, lchown)
{
	test_enter(PPME_SYSCALL_LCHOWN_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_LCHOWN_X, 4, res, path, uid, gid);
	test_failed_exit(PPME_SYSCALL_LCHOWN_X, 4, failed_res, path, uid, gid);
}

TEST_F(fspath, fchown)
{
	// We need to open a fd first so fchown can act on it
	inject_open_event();

	test_enter(PPME_SYSCALL_FCHOWN_E, 0);
	test_exit_path(path, path, PPME_SYSCALL_FCHOWN_X, 4, res, fd, uid, gid);
	test_failed_exit(PPME_SYSCALL_FCHOWN_X, 4, failed_res, fd, uid, gid);
}

TEST_F(fspath, fchownat)
{
	// the term "pathname" is only used for this syscall, so not putting at class level
	const char *pathname = "/tmp/pathname";

	test_enter(PPME_SYSCALL_FCHOWNAT_E, 0);
	test_exit_path(pathname, pathname, PPME_SYSCALL_FCHOWNAT_X, 6, res, dirfd, pathname, uid, gid, flags);
	test_failed_exit(PPME_SYSCALL_FCHOWNAT_X, 6, failed_res, dirfd, pathname, uid, gid, flags);
}

TEST_F(fspath, fchownat_relative)
{
	// the term "pathname" is only used for this syscall, so not putting at class level
	const char *rel_pathname = "tmp/pathname";
	const char *resolved_rel_pathname = "/root/tmp/pathname";

	test_enter(PPME_SYSCALL_FCHOWNAT_E, 0);
	test_exit_path(resolved_rel_pathname, rel_pathname, PPME_SYSCALL_FCHOWNAT_X, 6, res, rel_dirfd, rel_pathname, uid, gid, flags);
}

TEST_F(fspath, quotactl)
{
	// All of these are only used here so not putting in class
	uint16_t cmd = 0;
	uint8_t type = 0;
	uint32_t id = 0;
	uint8_t quota_fmt = 0;
	const char *quotafilepath = "";
	uint64_t dqb_bhardlimit = 0;
	uint64_t dqb_bsoftlimit = 0;
	uint64_t dqb_curspace = 0;
	uint64_t dqb_ihardlimit = 0;
	uint64_t dqb_isoftlimit = 0;
	uint64_t dqb_btime = 0;
	uint64_t dqb_itime = 0;
	uint64_t dqi_bgrace = 0;
	uint64_t dqi_igrace = 0;
	uint8_t dqi_flags = 0;
	uint8_t quota_fmt_out = 0;

	test_enter(PPME_SYSCALL_QUOTACTL_E, 4, cmd, type, id, quota_fmt);
	test_exit_path(path, path, PPME_SYSCALL_QUOTACTL_X, 14, res, path, quotafilepath,
		       dqb_bhardlimit, dqb_bsoftlimit, dqb_curspace, dqb_ihardlimit,
		       dqb_isoftlimit, dqb_btime, dqb_itime, dqi_bgrace,
		       dqi_igrace, dqi_flags, quota_fmt_out);
	test_failed_exit(PPME_SYSCALL_QUOTACTL_X, 14, failed_res, path, quotafilepath,
			 dqb_bhardlimit, dqb_bsoftlimit, dqb_curspace, dqb_ihardlimit,
			 dqb_isoftlimit, dqb_btime, dqb_itime, dqi_bgrace, dqi_igrace,
			 dqi_flags, quota_fmt_out);
}

TEST_F(fspath, rename)
{
	test_enter(PPME_SYSCALL_RENAME_E, 0);
	test_exit_source_target(oldpath, oldpath, newpath, newpath, PPME_SYSCALL_RENAME_X, 3, res, oldpath, newpath);
	test_failed_exit(PPME_SYSCALL_RENAME_X, 3, failed_res, oldpath, newpath);
}

TEST_F(fspath, renameat)
{
	test_enter(PPME_SYSCALL_RENAMEAT_E, 0);
	test_exit_source_target(oldpath, oldpath, newpath, newpath, PPME_SYSCALL_RENAMEAT_X, 5, res, olddirfd, oldpath, newdirfd, newpath);
	test_failed_exit(PPME_SYSCALL_RENAMEAT_X, 5, failed_res, olddirfd, oldpath, newdirfd, newpath);
}

TEST_F(fspath, renameat2)
{
	test_enter(PPME_SYSCALL_RENAMEAT2_E, 0);
	test_exit_source_target(oldpath, oldpath, newpath, newpath, PPME_SYSCALL_RENAMEAT2_X, 5, res, olddirfd, oldpath, newdirfd, newpath, flags);
	test_failed_exit(PPME_SYSCALL_RENAMEAT2_X, 5, failed_res, olddirfd, oldpath, newdirfd, newpath, flags);
}

TEST_F(fspath, link)
{
	test_enter(PPME_SYSCALL_LINK_E, 2, oldpath, newpath);
	test_exit_source_target(newpath, newpath, oldpath, oldpath, PPME_SYSCALL_LINK_X, 1, res);
	test_failed_exit(PPME_SYSCALL_LINK_X, 1, failed_res);
}

TEST_F(fspath, link_relative)
{
	test_enter(PPME_SYSCALL_LINK_E, 2, rel_oldpath, rel_newpath);
	test_exit_source_target(resolved_rel_newpath, rel_newpath,
				    resolved_rel_oldpath, rel_oldpath,
				    PPME_SYSCALL_LINK_X, 1, res);
}

TEST_F(fspath, linkat)
{
	test_enter(PPME_SYSCALL_LINKAT_E, 4, olddirfd, oldpath, newdirfd, newpath);
	test_exit_source_target(newpath, newpath, oldpath, oldpath, PPME_SYSCALL_LINKAT_X, 1, res);
	test_failed_exit(PPME_SYSCALL_LINKAT_X, 1, failed_res);
}

TEST_F(fspath, linkat_relative)
{
	test_enter(PPME_SYSCALL_LINKAT_E, 4, olddirfd, rel_oldpath, newdirfd, rel_newpath);
	test_exit_source_target(resolved_rel_newpath, rel_newpath,
				    resolved_rel_oldpath, rel_oldpath,
				    PPME_SYSCALL_LINKAT_X, 1, res);
}

TEST_F(fspath, link_2)
{
	test_enter(PPME_SYSCALL_LINK_2_E, 0);
	test_exit_source_target(newpath, newpath, oldpath, oldpath, PPME_SYSCALL_LINK_2_X, 3, res, oldpath, newpath);
	test_failed_exit(PPME_SYSCALL_LINK_2_X, 3, failed_res, oldpath, newpath);
}

TEST_F(fspath, link_2_relative)
{
	test_enter(PPME_SYSCALL_LINK_2_E, 0);
	test_exit_source_target(resolved_rel_newpath, rel_newpath,
				    resolved_rel_oldpath, rel_oldpath,
				    PPME_SYSCALL_LINK_2_X, 3, res, rel_oldpath, rel_newpath);
}

TEST_F(fspath, linkat_2)
{
	test_enter(PPME_SYSCALL_LINKAT_2_E, 0);
	test_exit_source_target(newpath, newpath, oldpath, oldpath, PPME_SYSCALL_LINKAT_2_X, 6, res, olddirfd, oldpath, newdirfd, newpath, flags);
	test_failed_exit(PPME_SYSCALL_LINKAT_2_X, 6, failed_res, olddirfd, oldpath, newdirfd, newpath, flags);
}

TEST_F(fspath, linkat_2_relative)
{
	test_enter(PPME_SYSCALL_LINKAT_2_E, 0);
	test_exit_source_target(resolved_rel_newpath, rel_newpath,
				    resolved_rel_oldpath, rel_oldpath,
				    PPME_SYSCALL_LINKAT_2_X, 6, res, olddirfd, rel_oldpath, newdirfd, rel_newpath, flags);
}

TEST_F(fspath, symlink)
{
	test_enter(PPME_SYSCALL_SYMLINK_E, 0);
	test_exit_source_target(linkpath, linkpath, targetpath, targetpath, PPME_SYSCALL_SYMLINK_X, 3, res, targetpath, linkpath);
	test_failed_exit(PPME_SYSCALL_SYMLINK_X, 3, failed_res, targetpath, linkpath);
}

TEST_F(fspath, symlink_relative)
{
	test_enter(PPME_SYSCALL_SYMLINK_E, 0);
	test_exit_source_target(resolved_rel_linkpath, rel_linkpath,
				    resolved_rel_targetpath, rel_targetpath,
				    PPME_SYSCALL_SYMLINK_X, 3, res, rel_targetpath, rel_linkpath);
}

TEST_F(fspath, symlinkat)
{
	test_enter(PPME_SYSCALL_SYMLINKAT_E, 0);
	test_exit_source_target(linkpath, linkpath, targetpath, targetpath, PPME_SYSCALL_SYMLINKAT_X, 4, res, targetpath, linkdirfd, linkpath);
	test_failed_exit(PPME_SYSCALL_SYMLINKAT_X, 4, failed_res, targetpath, linkdirfd, linkpath);
}

TEST_F(fspath, symlinkat_relative)
{
	test_enter(PPME_SYSCALL_SYMLINKAT_E, 0);
	test_exit_source_target(resolved_rel_linkpath, rel_linkpath,
				    resolved_rel_targetpath, rel_targetpath,
				    PPME_SYSCALL_SYMLINKAT_X, 4, res, rel_targetpath, linkdirfd, rel_linkpath);
}

TEST_F(fspath, mount)
{
	const char *devpath = "/dev/cdrom0";
	const char *mounttype = "iso9660";

	test_enter(PPME_SYSCALL_MOUNT_E, 1, flags);
	test_exit_source_target(devpath, devpath, mountpath, mountpath, PPME_SYSCALL_MOUNT_X, 4, res, devpath, mountpath, mounttype);
	test_failed_exit(PPME_SYSCALL_MOUNT_X, 4, failed_res, devpath, mountpath, mounttype);
}

TEST_F(fspath, umount)
{
	test_enter(PPME_SYSCALL_UMOUNT_E, 1, flags);
	test_exit_path(mountpath, mountpath, PPME_SYSCALL_UMOUNT_X, 2, res, mountpath);
	test_failed_exit(PPME_SYSCALL_UMOUNT_X, 2, failed_res, mountpath);
}

TEST_F(fspath, umount_1)
{
	test_enter(PPME_SYSCALL_UMOUNT_1_E, 0);
	test_exit_path(mountpath, mountpath, PPME_SYSCALL_UMOUNT_1_X, 2, res, mountpath);
	test_failed_exit(PPME_SYSCALL_UMOUNT_1_X, 2, failed_res, mountpath);
}

TEST_F(fspath, umount2)
{
	test_enter(PPME_SYSCALL_UMOUNT2_E, 1, flags);
	test_exit_path(mountpath, mountpath, PPME_SYSCALL_UMOUNT2_X, 2, res, mountpath);
	test_failed_exit(PPME_SYSCALL_UMOUNT2_X, 2, failed_res, mountpath);
}
