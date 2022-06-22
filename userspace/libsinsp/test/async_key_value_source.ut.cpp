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

#include <async/async_key_value_source.h>
#include <gtest/gtest.h>
#include <cstdlib>
#include <memory>

class test_key_value_source : public libsinsp::async_key_value_source<std::string, uint64_t> {
public:
	test_key_value_source(uint64_t delay_sec, uint64_t wait_response_ms) :
		async_key_value_source<std::string, uint64_t>(wait_response_ms, UINT64_MAX),
		m_delay_sec(delay_sec)
	{}

	virtual ~test_key_value_source()
	{
		stop();
	}

	void run_impl()
	{
		std::string key;

		while(dequeue_next_key(key))
		{
			if(m_delay_sec > 0)
			{
				sleep(m_delay_sec);
			}
			store_value(key, (uint64_t) atoi(key.c_str()));
		}
	}

protected:
	uint64_t m_delay_sec;
};

TEST(async_key_value_source_test, no_lookup)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(0, UINT64_MAX));
}

TEST(async_key_value_source_test, basic)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(0, UINT64_MAX));
	uint64_t value;

	while(!t->lookup("1", value))
	{
		sleep(1);
	}
	ASSERT_EQ(1, value);
}

TEST(async_key_value_source_test, long_delay_lookups)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(5, UINT64_MAX));
	uint64_t value;

	while(!t->lookup("1", value))
	{
		sleep(1);
	}
	ASSERT_EQ(1, value);
}

TEST(async_key_value_source_test, basic_nowait)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(0, 0));
	uint64_t value;

	while(!t->lookup("1", value))
	{
		sleep(1);
	}
	ASSERT_EQ(1, value);
}

TEST(async_key_value_source_test, long_delay_lookups_nowait)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(5, 0));
	uint64_t value;

	while(!t->lookup("1", value))
	{
		sleep(1);
	}
	ASSERT_EQ(1, value);
}
