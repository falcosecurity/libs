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
#include <sinsp.h>
#include <logger.h>
#include <sys/stat.h>
#include <fcntl.h>

static void log_callback_fn(std::string&& str, const sinsp_logger::severity sev)
{
	return;
}

TEST(sinsp_logger, constructor)
{
	auto logger = sinsp_logger();
	ASSERT_FALSE(logger.has_output());
	ASSERT_EQ(logger.get_severity(), sinsp_logger::SEV_INFO);
	ASSERT_EQ(logger.get_log_output_type(), sinsp_logger::OT_NONE);
}

TEST(sinsp_logger, output_type)
{
	auto logger = sinsp_logger();
	ASSERT_FALSE(logger.has_output());
	logger.add_stdout_log();
	logger.add_stderr_log();
	logger.disable_timestamps();
	logger.add_encoded_severity();
	logger.add_callback_log(log_callback_fn);

	// int fd = open(".", O_WRONLY | O_TMPFILE, 0);

	int fd = open("./xyazd", O_RDWR | O_CREAT, S_IWUSR);
	logger.add_file_log("./xyazd");
	close(fd);

	ASSERT_EQ(logger.get_log_output_type(), (sinsp_logger::OT_STDOUT | sinsp_logger::OT_STDERR | sinsp_logger::OT_FILE | sinsp_logger::OT_CALLBACK | sinsp_logger::OT_NOTS | sinsp_logger::OT_ENCODE_SEV));

	logger.remove_callback_log();
	ASSERT_EQ(logger.get_log_output_type(), (sinsp_logger::OT_STDOUT | sinsp_logger::OT_STDERR | sinsp_logger::OT_FILE | sinsp_logger::OT_NOTS | sinsp_logger::OT_ENCODE_SEV));
	ASSERT_TRUE(logger.has_output());
}

TEST(sinsp_logger, get_set_severity)
{
	auto logger = sinsp_logger();
	logger.set_severity(sinsp_logger::SEV_FATAL);
	ASSERT_EQ(logger.get_severity(), sinsp_logger::SEV_FATAL);
	ASSERT_TRUE(logger.is_enabled(sinsp_logger::SEV_FATAL));
	ASSERT_FALSE(logger.is_enabled(sinsp_logger::SEV_TRACE));
	ASSERT_FALSE(logger.is_enabled(sinsp_logger::SEV_CRITICAL));
	logger.set_severity(sinsp_logger::SEV_NOTICE);
	ASSERT_FALSE(logger.is_enabled(sinsp_logger::SEV_INFO));
	ASSERT_TRUE(logger.is_enabled(sinsp_logger::SEV_ERROR));
}
