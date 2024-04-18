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

using namespace libsinsp;

namespace
{

/**
 * Intermediate realization of async_key_value_source that can return pre-canned
 * results.
 */
class precanned_metadata_source : public async_key_value_source<std::string, std::string>
{
public:
	const static uint64_t FOREVER_MS;

	precanned_metadata_source(const uint64_t max_wait_ms, const uint64_t ttl_ms = FOREVER_MS)
	    : async_key_value_source(max_wait_ms, ttl_ms),
	      m_responses()
	{
	}

	void set_response(const std::string& key, const std::string& response)
	{
		m_responses[key] = response;
	}

	std::string get_response(const std::string& key) { return m_responses[key]; }

private:
	std::map<std::string, std::string> m_responses;
};
const uint64_t precanned_metadata_source::FOREVER_MS = static_cast<uint64_t>(~0L);

/**
 * Realization of async_key_value_source that returns results without delay.
 */
class immediate_metadata_source : public precanned_metadata_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	immediate_metadata_source(const uint64_t max_wait_ms = MAX_WAIT_TIME_MS)
	    : precanned_metadata_source(max_wait_ms)
	{
	}

protected:
	virtual void run_impl() override
	{
		std::string key;

		while (dequeue_next_key(key))
		{
			store_value(key, get_response(key));
		}
	}
};
const uint64_t immediate_metadata_source::MAX_WAIT_TIME_MS = 5000;

/**
 * Realization of async_key_value_source that returns results with some
 * specified delay.
 */
class delayed_metadata_source : public precanned_metadata_source
{
public:
	const static uint64_t MAX_WAIT_TIME_MS;

	delayed_metadata_source(const uint64_t delay_ms, const uint64_t ttl_ms = FOREVER_MS)
	    : precanned_metadata_source(MAX_WAIT_TIME_MS, ttl_ms),
	      m_delay_ms(delay_ms),
	      m_response_available(false)
	{
	}

	bool is_response_available() const { return m_response_available; }

protected:
	virtual void run_impl() override
	{
		std::string key;

		m_response_available = false;

		while (dequeue_next_key(key))
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(m_delay_ms));
			store_value(key, get_response(key));
			m_response_available = true;
		}
	}

private:
	uint64_t m_delay_ms;
	bool m_response_available;
};
const uint64_t delayed_metadata_source::MAX_WAIT_TIME_MS = 0;

/**
 * Ensure that a concrete async_key_value_source is in the expected initial
 * state after construction.
 */
TEST(async_key_value_source_test, construction)
{
	immediate_metadata_source source;

	ASSERT_EQ(immediate_metadata_source::MAX_WAIT_TIME_MS, source.get_max_wait());
	ASSERT_EQ(precanned_metadata_source::FOREVER_MS, source.get_ttl());
	ASSERT_FALSE(source.is_running());
}

/**
 * Ensure that if a concrete async_key_value_source returns the metadata before
 * the timeout, that the lookup() method returns true, and that it returns
 * the metadata in the output parameter.
 */
TEST(async_key_value_source_test, lookup_key_immediate_return)
{
	const std::string key = "foo";
	const std::string metadata = "bar";
	std::string response = "response-not-set";

	immediate_metadata_source source;

	// Seed the precanned response
	source.set_response(key, metadata);

	ASSERT_TRUE(source.lookup(key, response));
	ASSERT_EQ(metadata, response);
	ASSERT_TRUE(source.is_running());
}

/**
 * Ensure that get_complete_results returns all complete results
 */
TEST(async_key_value_source_test, get_complete_results)
{
	const std::string key1 = "foo1";
	const std::string key2 = "foo2";
	const std::string metadata = "bar";
	std::string response1 = "response1-not-set";
	std::string response2 = "response2-not-set";

	delayed_metadata_source source(500);

	// Seed the precanned response
	source.set_response(key1, metadata);
	source.set_response(key2, metadata);

	EXPECT_FALSE(source.lookup(key1, response1));
	EXPECT_FALSE(source.lookup(key2, response2));
	EXPECT_EQ("response1-not-set", response1);
	EXPECT_EQ("response2-not-set", response2);

	usleep(1100000);
	EXPECT_TRUE(source.is_running());
	auto completed = source.get_complete_results();

	EXPECT_EQ(2, completed.size());
	EXPECT_EQ(metadata, completed[key1]);
	EXPECT_EQ(metadata, completed[key2]);
}

/**
 * Ensure that get_complete_results returns all complete results
 * but does *not* return results that have not yet been computed
 */
TEST(async_key_value_source_test, get_complete_results_incomplete)
{
	const std::string key1 = "foo1";
	const std::string key2 = "foo2";
	const std::string metadata = "bar";
	std::string response1 = "response1-not-set";
	std::string response2 = "response2-not-set";

	delayed_metadata_source source(500);

	// Seed the precanned response
	source.set_response(key1, metadata);
	source.set_response(key2, metadata);

	EXPECT_FALSE(source.lookup(key1, response1));
	EXPECT_FALSE(source.lookup(key2, response2));
	EXPECT_EQ("response1-not-set", response1);
	EXPECT_EQ("response2-not-set", response2);

	usleep(600000);
	EXPECT_TRUE(source.is_running());
	auto completed = source.get_complete_results();

	EXPECT_EQ(1, completed.size());
	EXPECT_EQ(metadata, completed[key1]);

	source.stop();
}

/**
 * Ensure that lookup_delayed() does not return the value immediately
 * but only after the specified time
 */
TEST(async_key_value_source_test, lookup_delayed)
{
	const std::string key = "foo_delayed";
	const std::string metadata = "bar";
	std::string response = "response-not-set";

	immediate_metadata_source source(0);

	// Seed the precanned response
	source.set_response(key, metadata);

	// the delayed lookup cannot return a value right away
	EXPECT_FALSE(source.lookup_delayed(key, response, std::chrono::milliseconds(500)));
	EXPECT_EQ("response-not-set", response);

	// after 300 ms, the response should not yet be ready
	usleep(300000);
	EXPECT_TRUE(source.is_running());
	EXPECT_EQ("response-not-set", response);

	// add 100 ms just in case -- after 600 ms we should have the response
	usleep(300000);
	EXPECT_TRUE(source.is_running());
	EXPECT_TRUE(source.lookup(key, response));
	EXPECT_EQ(metadata, response);
}

/**
 * Ensure that if a concrete async_key_value_source cannot return the result
 * before the timeout, and if the client did not provide a callback, that
 * calling lookup() after the result it available returns the value.
 */
TEST(async_key_value_source_test, lookup_key_delayed_return_second_call)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metadata = "myvalue";

	delayed_metadata_source source(DELAY_MS);

	std::string response = "response-not-set";
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metadata);

	response_found = source.lookup(key, response);

	ASSERT_FALSE(response_found);

	// Since we didn't supply a callback, a subsequent call to lookup
	// after the metadata collection is complete will return the previously
	// collected metadata.  We know it should delay DELAY_MS, so wait that
	// long, but expect some scheduling overhead.  If we have to wait more
	// than 5 seconds, something went wrong.
	std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_MS));
	const int FIVE_SECS_IN_MS = 5 * 1000;
	for (int i = 0; !source.is_response_available() && i < FIVE_SECS_IN_MS; ++i)
	{
		// Avoid tight busy loop
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	// Response should now be available
	response_found = source.lookup(key, response);

	ASSERT_TRUE(response_found);
	ASSERT_EQ(metadata, response);
}

/**
 * Ensure that if a concrete async_key_value_source cannot return the result
 * before the timeout, and if the client did provide a callback, that the
 * callback is invoked with the metadata once they're avaialble.
 */
TEST(async_key_value_source_test, look_key_delayed_async_callback)
{
	const uint64_t DELAY_MS = 50;
	const std::string key = "mykey";
	const std::string metadata = "myvalue";

	delayed_metadata_source source(DELAY_MS);

	std::string sync_response = "sync-response-not-set";
	std::string async_response = "async-response-not-set";
	bool async_response_received = false;
	bool response_found;

	// Seed the precanned response
	source.set_response(key, metadata);

	response_found =
	    source.lookup(key,
	                  sync_response,
	                  [&async_response, &async_response_received](const std::string& key,
	                                                              const std::string& value)
	                  {
		                  async_response = value;
		                  async_response_received = true;
	                  });

	ASSERT_FALSE(response_found);

	// Since we didn't supply a callback, a subsequent call to lookup
	// after the metadata collection is complete will return the previously
	// collected metadata.  We know it should delay DELAY_MS, so wait that
	// long, but expect some scheduling overhead.  If we have to wait more
	// than 5 seconds, something went wrong.
	std::this_thread::sleep_for(std::chrono::milliseconds(DELAY_MS));
	const int FIVE_SECS_IN_MS = 5 * 1000;
	for (int i = 0; !async_response_received && i < FIVE_SECS_IN_MS; ++i)
	{
		// Avoid tight busy loop
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	ASSERT_EQ(metadata, async_response);
}

/**
 * Ensure that "old" results are pruned
 */
TEST(async_key_value_source_test, prune_old_metadata)
{
	const uint64_t DELAY_MS = 0;
	const uint64_t TTL_MS = 20;

	const std::string key1 = "mykey1";
	const std::string metadata1 = "myvalue1";

	const std::string key2 = "mykey2";
	const std::string metadata2 = "myvalue2";

	delayed_metadata_source source(DELAY_MS, TTL_MS);
	std::string response = "response-not-set";

	// Seed the precanned response
	source.set_response(key1, metadata1);
	source.set_response(key2, metadata2);

	// Since DELAY_MS is 0, then lookup should return false immediately,
	// and should almost immediately add the result to the cache
	ASSERT_FALSE(source.lookup(key1, response));

	// Wait long enough for the old entry to require pruning
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * TTL_MS));

	// Request the other key.  This should wake up the thread and actually
	// preform the pruning.
	ASSERT_FALSE(source.lookup(key2, response));

	// Wait long enough for the async thread to get woken up and to
	// prune the old entry
	std::this_thread::sleep_for(std::chrono::milliseconds(TTL_MS));

	// Since the first key should have been pruned, a second call to
	// fetch the first key should also return false.
	ASSERT_FALSE(source.lookup(key1, response));
}

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
