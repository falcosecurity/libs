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

#include <gtest/gtest.h>
#include <libsinsp/sinsp.h>
#include <libsinsp/logger.h>
#include <sys/stat.h>
#include <fcntl.h>

static void log_callback_fn(std::string&& str, const sinsp_logger::severity sev)
{
	return;
}

TEST(sinsp_logger, constructor)
{
	ASSERT_FALSE(libsinsp_logger()->has_output());
	ASSERT_EQ(libsinsp_logger()->get_severity(), sinsp_logger::SEV_INFO);
	ASSERT_EQ(libsinsp_logger()->get_log_output_type(), sinsp_logger::OT_NONE);
}

TEST(sinsp_logger, output_type)
{
	ASSERT_FALSE(libsinsp_logger()->has_output());
	libsinsp_logger()->add_stdout_log();
	libsinsp_logger()->add_stderr_log();
	libsinsp_logger()->disable_timestamps();
	libsinsp_logger()->add_encoded_severity();
	libsinsp_logger()->add_callback_log(log_callback_fn);

	// int fd = open(".", O_WRONLY | O_TMPFILE, 0);

	int fd = open("./xyazd", O_RDWR | O_CREAT, S_IWUSR);
	libsinsp_logger()->add_file_log("./xyazd");
	close(fd);

	ASSERT_EQ(libsinsp_logger()->get_log_output_type(), (sinsp_logger::OT_STDOUT | sinsp_logger::OT_STDERR | sinsp_logger::OT_FILE | sinsp_logger::OT_CALLBACK | sinsp_logger::OT_NOTS | sinsp_logger::OT_ENCODE_SEV));

	libsinsp_logger()->remove_callback_log();
	ASSERT_EQ(libsinsp_logger()->get_log_output_type(), (sinsp_logger::OT_STDOUT | sinsp_logger::OT_STDERR | sinsp_logger::OT_FILE | sinsp_logger::OT_NOTS | sinsp_logger::OT_ENCODE_SEV));
	ASSERT_TRUE(libsinsp_logger()->has_output());
}

TEST(sinsp_logger, get_set_severity)
{
	libsinsp_logger()->set_severity(sinsp_logger::SEV_FATAL);
	ASSERT_EQ(libsinsp_logger()->get_severity(), sinsp_logger::SEV_FATAL);
	ASSERT_TRUE(libsinsp_logger()->is_enabled(sinsp_logger::SEV_FATAL));
	ASSERT_FALSE(libsinsp_logger()->is_enabled(sinsp_logger::SEV_TRACE));
	ASSERT_FALSE(libsinsp_logger()->is_enabled(sinsp_logger::SEV_CRITICAL));
	libsinsp_logger()->set_severity(sinsp_logger::SEV_NOTICE);
	ASSERT_FALSE(libsinsp_logger()->is_enabled(sinsp_logger::SEV_INFO));
	ASSERT_TRUE(libsinsp_logger()->is_enabled(sinsp_logger::SEV_ERROR));
}
