/*
Copyright (C) 2021 The Falco Authors.

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

#include <sys/types.h>
#if defined(_WIN64) || defined(WIN64) || defined(_WIN32) || defined(WIN32)
#include <WinSock2.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <string>
#include <thread>
#include <chrono>
#include <future>
#include <mutex>
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
#include "tbb/concurrent_unordered_map.h"
#endif
#include "sinsp.h"



class sinsp_dns_manager
{
public:

	bool match(const char *name, int af, void *addr, uint64_t ts);
	string name_of(int af, void *addr, uint64_t ts);

	void cleanup();

        static sinsp_dns_manager& get()
        {
            static sinsp_dns_manager instance;
            return instance;
        };

	void set_erase_timeout(uint64_t ns)
	{
		m_erase_timeout = ns;
	};
	void set_base_refresh_timeout(uint64_t ns)
	{
		m_base_refresh_timeout = ns;
	};
	void set_max_refresh_timeout(uint64_t ns)
	{
		m_max_refresh_timeout = ns;
	};
	void clear_cache()
	{
		std::lock_guard<std::mutex> lk(m_erase_mutex);
		m_cache.clear();
	}

	size_t size()
	{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
		return m_cache.size();
#else
		return 0;
#endif
	};

private:

	static void refresh(std::future<void> f_exit);

	sinsp_dns_manager() :
		m_erase_timeout(3600 * ONE_SECOND_IN_NS),
		m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
		m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
	{};
        sinsp_dns_manager(sinsp_dns_manager const&) = delete;
        void operator=(sinsp_dns_manager const&) = delete;

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
	class dns_info
	{
	public:
		uint64_t m_timeout;
		uint64_t m_last_resolve_ts =0;
		uint64_t m_last_used_ts = 0;
		bool refresh (const std::string &name);

		bool contains(const ipv6addr& v6)
		{
			std::lock_guard<std::mutex> lk(m_mtx);
			return m_v6_addrs.find(v6) != m_v6_addrs.end();
		}

		bool contains(const uint32_t & v4)
		{
			std::lock_guard<std::mutex> lk(m_mtx);
			return m_v4_addrs.find(v4) != m_v4_addrs.end();
		}
	private:
		std::mutex m_mtx;
		std::set<uint32_t> m_v4_addrs;
		std::set<ipv6addr> m_v6_addrs;
	};

	typedef tbb::concurrent_unordered_map<std::string, std::shared_ptr<dns_info>> c_dns_table;
	c_dns_table m_cache;
#endif

	// tbb concurrent unordered map is not thread-safe for deletions,
	// so we still need a mutex, but the chances of waiting are really
	// low, since we will almost never do an erase.
	std::mutex m_erase_mutex;

	// used to let m_resolver know when to terminate
	std::promise<void> m_exit_signal;

	std::thread *m_resolver;

	uint64_t m_erase_timeout;
	uint64_t m_base_refresh_timeout;
	uint64_t m_max_refresh_timeout;
};
