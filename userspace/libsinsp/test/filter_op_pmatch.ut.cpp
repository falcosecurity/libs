/*
Copyright (C) 2022 The Falco Authors.

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

#include <random>
#include <sstream>
#include <filesystem>

#include <sinsp.h>
#include <gtest/gtest.h>

#include "sinsp_with_test_input.h"
#include "filter_compiler.h"

// A wrapper around a temporary path that deletes it on exit
class temp_dir
{
public:
	temp_dir()
	{
		std::random_device dev;
		std::mt19937 prng(dev());
		std::uniform_int_distribution<uint64_t> rand(0);
		for(uint64_t i = 0; i < 100; i++)
		{
			std::stringstream ss;
			ss << std::hex << rand(prng);
			m_path = std::filesystem::temp_directory_path() / ss.str();
			if (std::filesystem::create_directory(m_path))
			{
				return;
			}
		}

		m_path = std::filesystem::path();
	};

	virtual ~temp_dir()
	{
		if(!m_path.empty())
		{
			std::filesystem::remove_all(m_path);
		}
	};

	std::filesystem::path& path()
	{
		return m_path;
	};

private:
	std::filesystem::path m_path;
};

TEST_F(sinsp_with_test_input, pmatch)
{
	add_default_init_thread();

	open_inspector();

	temp_dir root;
	ASSERT_FALSE(root.path().empty());

	std::filesystem::path dir = root.path() / "dir";
	std::filesystem::path subdir = root.path() / "dir" / "subdir";
	std::filesystem::path dir2 = root.path() / "dir2";
	std::filesystem::path dir3 = root.path() / "dir3";
	std::filesystem::path topglob = root.path() / "*";
	std::filesystem::path subdirglob = root.path() / "*" / "subdir";
	std::filesystem::path subdir2glob = root.path() / "*" / "subdir2";
	std::filesystem::path subglob = root.path() / "*" / "*";
	std::filesystem::path subsubglob = root.path() / "*" / "*" / "subsubdir";

	// The file in the event is /TMPDIR/dir/subdir/file.txt. In
	// order for the glob()s to work we need to create subdir but
	// not the file itself.
	ASSERT_TRUE(std::filesystem::create_directories(subdir));
	std::filesystem::path file = subdir / "file.txt";

	int64_t fd = 1;
	sinsp_evt * evt = add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, fd, file.string().c_str(), 0, 0, 0, (uint64_t) 0);

	filter_run(evt, true, "fd.name pmatch (" + dir.string() + ")");
	filter_run(evt, true, "fd.name pmatch (" + subdir.string() + ")");
	filter_run(evt, false, "fd.name pmatch (" + dir2.string() + ")");
	filter_run(evt, true, "fd.name pmatch (" + dir.string() + "," + dir2.string() + ")");
	filter_run(evt, false, "fd.name pmatch (" + dir3.string() + "," + dir2.string() + ")");
	filter_run(evt, true, "fd.name pmatch (" + topglob.string() + ")");
	filter_run(evt, true, "fd.name pmatch (" + subdirglob.string() + ")");
	filter_run(evt, false, "fd.name pmatch (" + subdir2glob.string() + ")");
	filter_run(evt, true, "fd.name pmatch (" + subglob.string() + ")");
	filter_run(evt, false, "fd.name pmatch (" + subsubglob.string() + ")");
}
