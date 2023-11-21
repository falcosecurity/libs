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

#include <libsinsp/async/async_key_value_source.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cassert>
#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <thread>
namespace
{

struct result
{
	uint64_t val = 0;
	int retries = 0;
};

class test_key_value_source : public libsinsp::async_key_value_source<std::string, result>
{
public:
	test_key_value_source(uint64_t delay_ms, uint64_t wait_response_ms, uint64_t ttl_ms = std::numeric_limits<uint64_t>::max(), short num_failures = 0, short backoff_ms = 10):
		async_key_value_source<std::string, result>(wait_response_ms, ttl_ms),
		m_delay_ms(delay_ms),
		m_num_failures(num_failures),
		m_backoff_ms(backoff_ms)
	{
		assert(m_num_failures >= 0);
		assert(backoff_ms >= 0);
	}

	virtual ~test_key_value_source()
	{
		stop();
	}

	bool next_key(std::string& key)
	{
		return dequeue_next_key(key);
	}

	void run_impl()
	{
		std::string key;
		result res;

		while(dequeue_next_key(key, &res))
		{
			if(m_delay_ms > 0)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(m_delay_ms));
			}
			if(res.retries < m_num_failures)
			{
				res.retries++;
				// Simulate failures, re-enqueue the key after m_backoff_ms milliseconds
				defer_lookup(key,
					     &res,
					     std::chrono::milliseconds(m_backoff_ms));
			}
			else
			{
				res.val = (uint64_t)atoi(key.c_str());
				store_value(key, res);
			}
		}
	}

protected:
	uint64_t m_delay_ms;
	short m_num_failures;
	short m_backoff_ms;
};

TEST(async_key_value_source_test, no_lookup)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(0, UINT64_MAX));
}

TEST(async_key_value_source_test, basic)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(0, UINT64_MAX));
	result res;

	while(!t->lookup("1", res))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	ASSERT_EQ(1, res.val);
}

TEST(async_key_value_source_test, long_delay_lookups)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(500, UINT64_MAX));
	result res;

	while(!t->lookup("1", res))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	ASSERT_EQ(1, res.val);
}

TEST(async_key_value_source_test, basic_nowait)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(0, 0));
	result res;

	while(!t->lookup("1", res))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	ASSERT_EQ(1, res.val);
}

TEST(async_key_value_source_test, long_delay_lookups_nowait)
{
	std::unique_ptr<test_key_value_source> t(new test_key_value_source(500, 0));
	result res;

	while(!t->lookup("1", res))
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	ASSERT_EQ(1, res.val);
}

TEST(async_key_value_source_test, async)
{
	uint64_t ttl_ms = std::numeric_limits<uint64_t>::max();
	short num_failures = 3;
	test_key_value_source t(0, 0, ttl_ms, num_failures);
	result res;
	std::condition_variable cv;
	std::mutex cv_m;

	bool done = false;
	t.lookup("1", res, [&cv, &done](const std::string& key, const result& res)
		 {
	            ASSERT_EQ(1, res.val);
	            ASSERT_EQ(3, res.retries);
                done = true;
                cv.notify_all(); });
	std::unique_lock<std::mutex> lk(cv_m);
	if(!cv.wait_for(lk, std::chrono::milliseconds(100), [&done]()
			{ return done; }))
		FAIL() << "Timeout expired while waiting for result";
}

TEST(async_key_value_source_test, async_ttl_expired)
{
	uint64_t ttl_ms = 10;
	short num_failures = 3;
	short backoff_ms = 6;
	test_key_value_source t(0, 0, ttl_ms, num_failures, backoff_ms);
	result res;
	std::condition_variable cv;
	std::mutex cv_m;

	bool done = false;
	t.lookup(
		"1", res,
		[&cv, &done](const std::string& key, const result& res)
		{
			FAIL() << "unexpected callback for key: " << key;
			done = true;
			cv.notify_all();
		},
		[&cv, &done](const std::string& key)
		{
			ASSERT_EQ("1", key);
			done = true;
			cv.notify_all();
		});
	std::unique_lock<std::mutex> lk(cv_m);
	if(!cv.wait_for(lk, std::chrono::milliseconds(100), [&done]()
			{ return done; }))
		FAIL() << "Timeout expired while waiting for result";
	// Verify that no keys are left in the queue.
	std::string key;
	ASSERT_FALSE(t.next_key(key));
}

} // namespace
