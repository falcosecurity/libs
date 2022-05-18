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

// template helpers to convert AF INET/INET6 into map keys
template <int> class af_converter{};

// ipv4
template <> class af_converter<AF_INET>
{
public:
	typedef uint32_t type;
	static type value(void *addr){ return *(uint32_t *)addr; }
};

// ipv6
template <> class af_converter<AF_INET6>
{
public:
	typedef std::pair<uint64_t, uint64_t> type;
	static type value(void *addr)
	{
		auto * a = (uint64_t*)(addr);
		return {a[0], a[1]};
	}

	typedef typename tbb::tbb_hash_compare<ipv6addr> hash_t;
};

// dns info to hold timestamps and resolution results.
// results are intermediate to be inserted into map containers
class dns_info
{
private:

	uint64_t m_max_refresh_timeout = 0;
	uint64_t m_refresh_timeout = 0;
	uint64_t m_last_resolve_ts = 0;

	template <int AF>
	class container
	{
	private:
		std::set<typename af_converter<AF>::type> m_addrs;
	public:
		bool has_address(void* addr) const
		{
			return m_addrs.find(af_converter<AF>::value(addr)) != m_addrs.end();
		}

		void insert (void* addr)
		{
			m_addrs.insert(af_converter<AF>::value(addr));
		}

		template <template <typename T> class I>
		void copy (I<typename af_converter<AF>::type>& inserter) const
		{
			if (!m_addrs.empty())
			{
				inserter.insert(m_addrs.begin(), m_addrs.end());
			}
		}

		bool operator !=(const container& other)
		{
			return m_addrs != other.m_addrs;
		}

		container& operator =(const container &other)
		{
			m_addrs = other.m_addrs;
			return *this;
		}

		container& operator =(const container &&other) = delete;
	};

	std::shared_ptr<container<AF_INET>>  m_v4_addrs = std::make_shared<container<AF_INET>>();
	std::shared_ptr<container<AF_INET6>> m_v6_addrs = std::make_shared<container<AF_INET6>>();

public:
	volatile mutable uint64_t m_last_used_ts = 0;

	dns_info(dns_info&& rh) = delete;
	dns_info(const dns_info& rh) = delete;

	dns_info &operator=(dns_info&&) = delete;
	dns_info &operator=(dns_info) = delete;

	dns_info(const std::string &name, uint64_t base_timeout, uint64_t max_timeout, uint64_t ts):
		m_max_refresh_timeout(max_timeout),
		m_refresh_timeout(base_timeout),
		m_last_resolve_ts(ts),
		m_last_used_ts(ts)
	{
		g_logger.format(sinsp_logger::SEV_DEBUG, "dns_info create new %s", name.c_str());
		resolve(name);
	}

	dns_info(const std::string &name, const dns_info &other, uint64_t max_timeout, uint64_t ts)
	{
		m_max_refresh_timeout = max_timeout;

		m_last_used_ts    = other.m_last_used_ts;
		m_last_resolve_ts = other.m_last_resolve_ts;
		m_refresh_timeout = other.m_refresh_timeout;

		*m_v4_addrs = *other.m_v4_addrs;
		*m_v6_addrs = *other.m_v6_addrs;

		if (ts > m_last_resolve_ts + m_refresh_timeout)
		{
			m_last_resolve_ts = ts;
			if (!resolve(name) && m_refresh_timeout < m_max_refresh_timeout)
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "dns_info refresh skipped  %s", name.c_str());
				m_refresh_timeout <<= 1; // double the timeout until 320 secs
			}
			else
			{
				g_logger.format(sinsp_logger::SEV_DEBUG, "dns_info refreshed %s", name.c_str());
			}
		}

	}

	bool is_expired(uint64_t erase_timeout, uint64_t ts) const
	{
		return (ts > m_last_used_ts) &&
		       (ts - m_last_used_ts) > erase_timeout;
	}

	bool has_address(int af, void* addr, uint64_t ts) const
	{
		auto ret = (af == AF_INET) ? m_v4_addrs->has_address(addr) : m_v6_addrs->has_address(addr);
		if (ret)
		{
			m_last_used_ts = ts;
		}
		return ret;
	}

	template <template<class T> class I>
	void copy_addrs(I<typename af_converter<AF_INET>::type> inserter) const
	{
		m_v4_addrs->copy(inserter);
	}

	template <template<class T> class I>
	void copy_addrs(I<typename af_converter<AF_INET6>::type> inserter) const
	{
		m_v6_addrs->copy(inserter);
	}

private:
	bool resolve(const string &name)
	{
		addrinfo hints{}, *result, *rp;
		memset(&hints, 0, sizeof(struct addrinfo));

		// Allow IPv4 or IPv6, all socket types, all protocols
		hints.ai_family = AF_UNSPEC;
		int s = getaddrinfo(name.c_str(), nullptr, &hints, &result);
		if (!s && result)
		{
			auto v4_addrs = std::make_shared<container<AF_INET>>();
			auto v6_addrs = std::make_shared<container<AF_INET6>>();

			for (rp = result; rp != nullptr; rp = rp->ai_next)
			{
				if(rp->ai_family == AF_INET)
				{
					v4_addrs->insert(&((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
				}
				else // AF_INET6
				{
					v6_addrs->insert(((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr) ;
				}
			}
			freeaddrinfo(result);
			bool update = false;
			if (*v4_addrs != *m_v4_addrs)
			{
				m_v4_addrs = v4_addrs;
				update = true;
			}
			if (*v6_addrs != *m_v6_addrs)
			{
				m_v6_addrs = v6_addrs;
				update = true;
			}
			return update;
		}
		g_logger.format(sinsp_logger::SEV_INFO, "dns_info: unable to resolve name='%s'", name.c_str());
		return false;
	}
};

// Generic AF address converter -> name map
template <int AF>
class dns_addr_map
{
private:
	typedef af_converter<AF> af_converter_t;
	typedef typename af_converter_t::type addr_t;
	tbb::concurrent_unordered_map<addr_t, std::pair<std::string, const dns_info *> > m_map;
public:
	template<class T>
	class inserter
	{
	private:
		dns_addr_map &m_parent;
		const std::string &m_name;
		const dns_info *m_info;
	public:
		static const int af_type = AF;
		inserter(dns_addr_map &parent, const string &name, const dns_info *info):
			m_parent(parent), m_name(name), m_info(info) {}

		template<template <class U> class II >
		void insert(II<T> first, II<T> last)
		{
			while (first != last)
			{
				m_parent.insert(m_name, *first, m_info);
				++first;
			}
		}
	};

	inserter<addr_t> get_inserter(const string &name, const dns_info *info)
	{
		return {*this, name, info};
	}

	void insert (const std::string& name, addr_t addr, const dns_info * info)
	{
		m_map[addr] = std::make_pair(name, info);
	}

	std::string name_of(void *addr, uint64_t ts) const
	{
		const auto it = m_map.find(af_converter_t::value(addr));
		if (it == m_map.end())
		{
			return {};
		}
		it->second.second->m_last_used_ts = ts;
		return it->second.first;
	}
};

// combined v4, v6 maps
class dns_af_cache
{
private:
	dns_addr_map<AF_INET>  m_v4_cache;
	dns_addr_map<AF_INET6> m_v6_cache;
public:
	tbb::concurrent_unordered_map<std::string, std::shared_ptr<const dns_info>> m_info_table;

	enum match_result
	{
		MATCH_OK,
		MATCH_NO_ADDRESS,
		MATCH_NO_NAME
	};

	match_result match_by_name(int af, const std::string& name, void* addr, uint64_t ts)
	{
		auto it = m_info_table.find(name);
		if (it == m_info_table.end())
		{
			return MATCH_NO_NAME;
		}
		return it->second->has_address(af, addr, ts) ? MATCH_OK : MATCH_NO_ADDRESS;
	}

	std::string name_of(int af, void *addr, uint64_t ts) const
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

	void insert(const std::string& name, std::shared_ptr<const dns_info> info)
	{
		info->copy_addrs( m_v4_cache.get_inserter(name, info.get()));
		info->copy_addrs( m_v6_cache.get_inserter(name, info.get()));
		m_info_table[name] = info;
	}
};

// cache class to provide work/shadow caches for fast switching
class sinsp_dns_manager::dns_cache
{
private:
	std::vector<std::shared_ptr<dns_af_cache>> m_caches;
	std::mutex m_cache_swap_mtx;
	using scoped_lock = typename  std::lock_guard<std::mutex>;
public:
	dns_cache()
	{
		m_caches.emplace_back(new dns_af_cache()); // work
		m_caches.emplace_back(new dns_af_cache()); // shadow
	}

	std::shared_ptr<dns_af_cache> get_work()
	{
		scoped_lock lk(m_cache_swap_mtx);
		return m_caches[0];
	}

	// create and get
	// new shadow is requested only once in the refresher thread.
	// we create new to discard entries possibly duplicated by the insert
	std::shared_ptr<dns_af_cache> create_shadow()
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_caches[1] = std::make_shared<dns_af_cache>();
		return m_caches[1];
	}

	// swap work <- shadow <- new
	void swap()
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_caches[0] = m_caches[1];
		m_caches[1] = std::make_shared<dns_af_cache>();
	}

	// inserting synchronized into two caches to keep in sync with the refresher thread
	// if it's currently running, otherwise the shadow entries will be discarded
	// on create_shadow request - a small overhead we pay for not locking individual entries
	void insert(const std::string& name, std::shared_ptr<const dns_info> info)
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_caches[0]->insert(name, info);
		m_caches[1]->insert(name, info);
	}

	// clear caches
	void clear()
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_caches[0] = std::make_shared<dns_af_cache>();
		m_caches[1] = std::make_shared<dns_af_cache>();
	}
};

// threaded refresh method that populates shadow copy and "atomically" swaps it with the work one
void sinsp_dns_manager::refresh(std::future<void> f_exit)
{
	sinsp_dns_manager &manager = sinsp_dns_manager::get();
	while(true)
	{
		uint64_t base_refresh_timeout = manager.m_base_refresh_timeout;
		uint64_t max_refresh_timeout = manager.m_max_refresh_timeout;
		uint64_t erase_timeout = manager.m_erase_timeout;

		// create and fill shadow cache in the background
		auto shadow_cache = manager.m_dns_cache->create_shadow();
		auto work_cache = manager.m_dns_cache->get_work();

		auto n_names = work_cache->m_info_table.size();
		if(!work_cache->m_info_table.empty())
		{
			uint64_t ts = sinsp_utils::get_current_time_ns();

			for(auto &it: work_cache->m_info_table)
			{
				const std::string &name = it.first;
				auto info = it.second;

				if(!info->is_expired(erase_timeout, ts))
				{
					// add shadow entries
					shadow_cache->insert(name,
							     std::make_shared<dns_info>(name, *info, max_refresh_timeout, ts));
				}
			}
			// set shadow as work cache
			// work is auto deleted by shared_ptr
			manager.m_dns_cache->swap();
		}
		auto new_size = shadow_cache->m_info_table.size();

		g_logger.format(sinsp_logger::SEV_DEBUG, "sinsp_dns_manager::refresh: names=%lu, retired=%lu", new_size, n_names - new_size);

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

	auto result = m_dns_cache->get_work()->match_by_name(af, name, addr, ts);
	if(result == dns_af_cache::MATCH_OK)
	{
		return true;
	}

	if (result == dns_af_cache::MATCH_NO_ADDRESS)
	{
		return false;
	}

	// MATCH_NO_NAME
	const auto& m = sinsp_dns_manager::get();
	m_dns_cache->insert(name, make_shared<dns_info>(name, m.m_base_refresh_timeout, m.m_max_refresh_timeout, ts));
	return m_dns_cache->get_work()->match_by_name(af, name, addr, ts) == dns_af_cache::MATCH_OK;
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
		// this is not thread safe against quick restart
		// not introducing a mutex for the performance's sake
		m_dns_cache->clear();
		m_exit_signal.set_value();
		m_resolver->join();
		m_resolver = nullptr;
		m_exit_signal = std::promise<void>();

		g_logger.format(sinsp_logger::SEV_DEBUG, "sinsp_dns_manager::cleanup");
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
	g_logger.format(sinsp_logger::SEV_DEBUG, "sinsp_dns_manager::clear_cache");
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
