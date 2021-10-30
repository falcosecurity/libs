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

#include "dns_manager.h"

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
#include <tbb/concurrent_unordered_map.h>
#include <tbb/queuing_rw_mutex.h>

// template helpers to convert AF INET/INET6 into map keys
template <int> class af_converter{};

// ipv4
template <> class af_converter<AF_INET>
{
public:
	typedef int32_t type;
	static type value(void *addr){ return *(uint32_t *)addr; }
};

// ipv6
template <> class af_converter<AF_INET6>
{
public:
	typedef std::string type; // convert to string to use default hash
	static type value(void *addr)
	{
		char str[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, addr, str, INET6_ADDRSTRLEN) == nullptr)
		{
			SINSP_ERROR("error converting INET6 = %p", addr);
		}
		return str;
	}
};

// dns info to hold timestamps amd resolution results.
// results are intermediate to be inserted into map containers
class dns_info
{
private:
	template <typename T>
	using set_t = std::set<T>;

	template <typename T>
	using set_ptr_t=std::shared_ptr<set_t<T>>;

	set_ptr_t<uint32_t> m_v4_addrs = std::make_shared<set_t<uint32_t>>();
	set_ptr_t<ipv6addr> m_v6_addrs = std::make_shared<set_t<ipv6addr>>();

	uint64_t m_max_refresh_timeout;

	uint64_t m_refresh_timeout = 0;
	uint64_t m_last_resolve_ts = 0;

public:
	volatile mutable uint64_t m_last_used_ts = 0;

	dns_info(const std::string &name, uint64_t base_timeout, uint64_t max_timeout, uint64_t ts):
		m_max_refresh_timeout(max_timeout),
		m_refresh_timeout(base_timeout),
		m_last_resolve_ts(ts),
		m_last_used_ts(ts)
	{
		refresh(name);
	}

	dns_info(const std::string &name, const dns_info &other, uint64_t max_timeout, uint64_t ts)
	{
		m_max_refresh_timeout = max_timeout;

		m_last_used_ts    = other.m_last_used_ts;
		m_last_resolve_ts = other.m_last_resolve_ts;
		m_refresh_timeout = other.m_refresh_timeout;

		if (ts > m_last_resolve_ts + m_refresh_timeout)
		{
			m_last_resolve_ts = ts;
			refresh(name);
		}
		else
		{
			*m_v4_addrs = *other.m_v4_addrs;
			*m_v6_addrs = *other.m_v6_addrs;

			if(m_refresh_timeout < m_max_refresh_timeout)
			{
				m_refresh_timeout <<= 1;
			}
		}
	}

	dns_info(dns_info&& rh) = delete;
	dns_info(const dns_info& rh) = delete;
	dns_info &operator=(dns_info&&) = delete;
	dns_info &operator=(dns_info) = delete;

	bool is_expired(uint64_t erase_timeout, uint64_t ts) const
	{
		return (ts > m_last_used_ts) &&
		       (ts - m_last_used_ts) > erase_timeout;
	}

	const set_t<uint32_t>& getv4_addrs () const
	{
		return *m_v4_addrs;
	}

	const set_t<ipv6addr>& getv6_addrs () const
	{
		return *m_v6_addrs;
	}

private:
	void refresh(const string &name)
	{
		addrinfo hints{}, *result, *rp;
		memset(&hints, 0, sizeof(struct addrinfo));

		// Allow IPv4 or IPv6, all socket types, all protocols
		hints.ai_family = AF_UNSPEC;

		int s = getaddrinfo(name.c_str(), nullptr, &hints, &result);
		if (!s && result)
		{
			for (rp = result; rp != nullptr; rp = rp->ai_next)
			{
				if(rp->ai_family == AF_INET)
				{
					m_v4_addrs->insert(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
				}
				else // AF_INET6
				{
					ipv6addr v6;
					memcpy(v6.m_b, ((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr, sizeof(ipv6addr));
					m_v6_addrs->insert(v6);
				}
			}
			freeaddrinfo(result);
		}
	}
};

using dns_info_table_t = tbb::concurrent_unordered_map<std::string, std::shared_ptr<dns_info>>;

// Generic name <-> address
template<typename First, typename Second>
class dns_map
{
private:
	template<typename T, typename U>
	using match_map_t = std::map<std::pair<T, U>,  dns_info *>; //tbb::concurrent_unordered_map<std::pair<T, U>,  dns_info *>;
	match_map_t<First, Second> m_match_map;
public:

	bool match(First fidx, Second sidx, uint64_t ts)
	{
		auto it = m_match_map.find( std::make_pair(fidx, sidx)) ;
		if (it == m_match_map.end()){
			return false;
		}
		it-> second->m_last_used_ts = ts;
		return true;
	}

	Second name_of(First fidx, uint64_t ts)
	{
		auto it = m_match_map.lower_bound( std::make_pair(fidx, Second())) ;
		if (it == m_match_map.end() || it->first.first != fidx){
			return {};
		}
		it-> second->m_last_used_ts = ts;
		return it->first.second;
	}

	void insert (First fidx, Second sidx, dns_info * info)
	{
		// lookup is blocked during insertion
		m_match_map[std::make_pair(fidx, sidx)] = info;
	}
};

// Generic AF address converter -> name map
template <int AF>
class dns_addr_map
{
private:
	typedef af_converter<AF> af_converter_t;
	typedef typename af_converter_t::type addr_t;
	dns_map<addr_t, std::string> m_addr_to_name_map;
public:
	void insert (std::string name, addr_t addr, dns_info * info)
	{
		m_addr_to_name_map.insert(addr, name, info);
	}
	std::string name_of(void *addr, uint64_t ts)
	{
		return m_addr_to_name_map.name_of(af_converter_t::value(addr), ts);
	}
	bool match(std::string name, void* addr, uint64_t ts)
	{
		return m_addr_to_name_map.match(af_converter_t::value(addr), name, ts);
	}
};

// combined v4, v6 maps
class dns_af_cache
{
private:
	dns_addr_map<AF_INET>  m_v4_cache;
	dns_addr_map<AF_INET6> m_v6_cache;
public:
	dns_info_table_t m_info_table;

	std::string name_of(int af, void *addr, uint64_t ts)
	{
		if (af == AF_INET)
		{
			return m_v4_cache.name_of(addr, ts);
		}
		else if (af == AF_INET6)
		{
			return m_v6_cache.name_of(addr, ts);
		}
		return {};
	}

	bool match(int af, std::string name, void* addr, uint64_t ts)
	{
		if (af == AF_INET)
		{
			return m_v4_cache.match(name, addr, ts);
		}
		else if (af == AF_INET6)
		{
			return m_v6_cache.match(name, addr, ts);
		}
		return false;
	}

	bool has_name(std::string name) const
	{
		return m_info_table.count(name) > 0;
	}

	void insert(std::string name, std::shared_ptr<dns_info> info)
	{
		for (auto& addr : info->getv4_addrs())
		{
			m_v4_cache.insert(name, addr, info.get());
		}

		for (auto addr : info->getv6_addrs())
		{
			m_v6_cache.insert(name, af_converter<AF_INET6>::value(&addr.m_b[0]), info.get());
		}
		m_info_table[name] = info;
	}
};

// cache class to provide work/shadow caches for fast switching
class sinsp_dns_manager::dns_cache
{
private:
	std::vector<std::shared_ptr<dns_af_cache>> m_cashes;
	std::mutex m_cache_swap_mtx;
	using scoped_lock = typename  std::lock_guard<std::mutex>;
public:
	dns_cache()
	{
		m_cashes.emplace_back(new dns_af_cache()); // work
		m_cashes.emplace_back(new dns_af_cache()); // shadow
	}

	std::shared_ptr<dns_af_cache> get_work()
	{
		scoped_lock lk(m_cache_swap_mtx); // can use reader lock when available
		return m_cashes[0];
	}

	std::shared_ptr<dns_af_cache> get_shadow()
	{
		scoped_lock lk(m_cache_swap_mtx); // can use reader lock when available
		m_cashes[1] = std::make_shared<dns_af_cache>();
		return m_cashes[1];
	}

	// swap work <- shadow <- new
	void swap()
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_cashes[0] = m_cashes[1];
		m_cashes[1] = std::make_shared<dns_af_cache>();
	}

	// insert dns record
	void insert(std::string name, std::shared_ptr<dns_info> info)
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_cashes[0]->insert(name, info);
		m_cashes[1]->insert(name, info);
	}

	// clear caches
	void clear()
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_cashes[0] = std::make_shared<dns_af_cache>();
		m_cashes[1] = std::make_shared<dns_af_cache>();
	}
};

// threaded refresh method that populates shadow copy and "atomically" swaps it with work one
void sinsp_dns_manager::refresh(std::future<void> f_exit)
{
	sinsp_dns_manager &manager = sinsp_dns_manager::get();
	while(true)
	{
		uint64_t base_refresh_timeout = manager.m_base_refresh_timeout;
		uint64_t max_refresh_timeout = manager.m_max_refresh_timeout;
		uint64_t erase_timeout = manager.m_erase_timeout;

		auto shadow_cache = manager.m_dns_cache->get_shadow();
		auto work_cache = manager.m_dns_cache->get_work();

		if(!work_cache->m_info_table.empty())
		{
			uint64_t ts = sinsp_utils::get_current_time_ns();

			for(auto &it: work_cache->m_info_table)
			{
				const std::string &name = it.first;
				auto info = it.second;

				if(!info->is_expired(erase_timeout, ts))
				{
					shadow_cache->insert(name,
							     std::make_shared<dns_info>(name, *info, max_refresh_timeout, ts));
				}
			}
			manager.m_dns_cache->swap();
		}

		if(f_exit.wait_for(std::chrono::nanoseconds(base_refresh_timeout)) == std::future_status::ready)
		{
			break;
		}
	}
}

// match name with address
bool sinsp_dns_manager::match(const char *name, int af, void *addr, uint64_t ts)
{
	bool expect = false;
	if (m_resolver_flag.compare_exchange_strong(expect, true))
	{
		m_resolver = new thread(sinsp_dns_manager::refresh, m_exit_signal.get_future());
	}

	if(m_dns_cache->get_work()->match(af, name, addr, ts))
	{
		return true;
	}

	if (m_dns_cache->get_work()->has_name(name))
	{
		return false;
	}

	string sname = string(name);
	const auto& m = sinsp_dns_manager::get();
	m_dns_cache->insert(sname, make_shared<dns_info>(name, m.m_base_refresh_timeout, m.m_max_refresh_timeout, ts));
	return m_dns_cache->get_work()->match(af, name, addr, ts);
}

// resolve name by address
string sinsp_dns_manager::name_of(int af, void *addr, uint64_t ts)
{
	bool expect = false;
	if (m_resolver_flag.compare_exchange_strong(expect, true))
	{
		m_resolver = new thread(sinsp_dns_manager::refresh, m_exit_signal.get_future());
	}

	return m_dns_cache->get_work()->name_of(af, addr, ts);
}

// cleanup on terminate
void sinsp_dns_manager::cleanup()
{
	bool expect = true;
	if (m_resolver_flag.compare_exchange_strong(expect, false))
	{
		// this is not thread safe.
		// problem with this singleton implementation
		// not introducing a mutex for the performance's sake
		m_exit_signal.set_value();
		m_resolver->join();
		m_resolver = nullptr;
		m_dns_cache.reset(new sinsp_dns_manager::dns_cache());
		m_exit_signal = std::promise<void>();
	}
}

// get cache names size
size_t sinsp_dns_manager::size()
{
	return m_dns_cache->get_work()-> m_info_table.size();
}

// client call to clear cache
void sinsp_dns_manager::clear_cache()
{
	m_dns_cache->clear();
}

// ctor
sinsp_dns_manager::sinsp_dns_manager():
	m_dns_cache(new sinsp_dns_manager::dns_cache()),
	m_resolver(nullptr),
	m_erase_timeout(3600 * ONE_SECOND_IN_NS),
	m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
	m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
{
	m_resolver_flag.store(false);
}

#else

void sinsp_dns_manager::refresh(std::future<void> f_exit)
{
}

void sinsp_dns_manager::clear_cache()
{
}

size_t sinsp_dns_manager::size()
{
	return 0;
}

sinsp_dns_manager::sinsp_dns_manager():
	m_resolver(nullptr),
	m_erase_timeout(3600 * ONE_SECOND_IN_NS),
	m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
	m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
{
}

bool sinsp_dns_manager::match(const char *name, int af, void *addr, uint64_t ts)
{
	return false;
}

string sinsp_dns_manager::name_of(int af, void *addr, uint64_t ts)
{
	return {};
}

void sinsp_dns_manager::cleanup()
{
}

#endif

sinsp_dns_manager &sinsp_dns_manager::get()
{
	static sinsp_dns_manager instance;
	return instance;
}
