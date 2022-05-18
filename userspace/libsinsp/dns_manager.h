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
#ifdef _WIN32
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
#include <utility>
#include "sinsp.h"

class sinsp_dns_manager
{
public:
	bool match(const char *name, int af, void *addr, uint64_t ts);
	std::string name_of(int af, void *addr, uint64_t ts);

	void cleanup();

	static sinsp_dns_manager &get();

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

	void clear_cache();
	size_t size();

	sinsp_dns_manager(sinsp_dns_manager const &) = delete;
	void operator=(sinsp_dns_manager const &) = delete;

private:
	sinsp_dns_manager();

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
	class dns_cache;
	std::unique_ptr<dns_cache> m_dns_cache;
	static void refresh(std::future<void> f_exit);
	std::promise<void> m_exit_signal;
	std::atomic<bool> m_resolver_flag;
	std::thread *m_resolver = nullptr;
#endif

	uint64_t m_erase_timeout;
	uint64_t m_base_refresh_timeout;
	uint64_t m_max_refresh_timeout;
};
