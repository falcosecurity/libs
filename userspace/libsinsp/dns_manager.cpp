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

#define G_LOG_FORMAT(s, fmt, ...)                                       \
	do                                                                  \
	{                                                                   \
		if (s >= g_logger.get_severity())                               \
		{                                                               \
			g_logger.format(sinsp_logger::SEV_DEBUG, fmt, __VA_ARGS__); \
		}                                                               \
	} while (0)


static std::string ip2str(int af, const void* addr)
{
	char buff[64];
	return inet_ntop(af, addr, buff, sizeof(buff));
}

// template type converters AF INET/INET6
template<int AF>
struct af_type_traits;

// ipv4
template<>
struct af_type_traits<AF_INET>
{
	typedef uint32_t type;
};

// ipv6
template<>
struct af_type_traits<AF_INET6>
{
	typedef std::pair<uint64_t, uint64_t> type;
};

// hash function
template <int AF>
struct af_hash_func;

template <>
struct af_hash_func<AF_INET>
{
	using type = typename af_type_traits<AF_INET>::type;
	std::size_t operator ()(const type& v) const
	{
		return std::hash<type>{}(v);
	}
};

template <>
struct af_hash_func<AF_INET6>
{
	using type = typename af_type_traits<AF_INET6>::type;
	std::size_t operator ()(const type& v) const
	{
		return tbb::tbb_hash<type>{}(v);
	}
};


/* *
 * to address functions
 */
template<int AF>
struct void_ptr_to_address;

template<>
struct void_ptr_to_address<AF_INET>
{
	af_type_traits<AF_INET>::type operator()(const void* addr) const
	{
		return *(uint32_t*)addr;
	}
};

template<>
struct void_ptr_to_address<AF_INET6>
{
	af_type_traits<AF_INET6>::type operator()(const void* addr) const
	{
		return {((const uint64_t*)addr)[0], ((const uint64_t*)addr)[1]};
	}
};

template <int AF>
typename af_type_traits<AF>::type to_address(const void* v)
{
	return void_ptr_to_address<AF>{}(v);
}

/*
 *
 */
template<int AF>
struct addrinfo_to_address;

template<>
struct addrinfo_to_address<AF_INET>
{
	af_type_traits<AF_INET>::type operator()(const addrinfo* info) const
	{
		return to_address<AF_INET>(&((sockaddr_in*)info->ai_addr)->sin_addr.s_addr);
	}
};

template<>
struct addrinfo_to_address<AF_INET6>
{
	af_type_traits<AF_INET6>::type operator()(const addrinfo* info) const
	{
		return to_address<AF_INET6>(((sockaddr_in6*)info->ai_addr)->sin6_addr.s6_addr);
	}
};

template <int AF>
typename af_type_traits<AF>::type to_address(const addrinfo* info)
{
	return addrinfo_to_address<AF>{}(info);
}

/* *
 *  to string functions
 */
template<int AF>
struct address_to_string;

template<>
struct address_to_string<AF_INET>
{
	std::string operator()(const af_type_traits<AF_INET>::type& v) const
	{
		return ip2str(AF_INET, &v);
	}
};

template<>
struct address_to_string<AF_INET6>
{
	std::string operator()(const af_type_traits<AF_INET6>::type& v) const
	{
		uint64_t v_addr[]{v.first, v.second};
		return ip2str(AF_INET6, v_addr) ;
	}
};

template<int AF>
std::string to_string(const typename af_type_traits<AF>::type& v)
{
	return address_to_string<AF>{}(v);
}

template<int AF>
using addr_consumer_t = std::function<void(const typename af_type_traits<AF>::type&)>;

template<int AF>
class container
{
	using addr_t = typename af_type_traits<AF>::type;

public:
	bool has_address(void* addr, uint64_t ts)
	{
		const auto it = m_addrs.find(to_address<AF>(addr));
		const auto ret = it != m_addrs.end();

		if (ret)
		{
			it->second = ts;
		}

		G_LOG_FORMAT(sinsp_logger::SEV_DEBUG,
		             "dns_info: lookup address: %s in: [%s]; found=%s",
		             ip2str(AF, addr).c_str(),
		             to_string().c_str(),
		             ret ? "true" : "false");
		return ret;
	}

	// insert copy
	bool insert(const addr_t& addr, uint64_t ts)
	{
		const auto it = m_addrs.find(addr);
		if (it == m_addrs.end())
		{
			// new address
			m_addrs.template emplace(addr, ts);
			return true;
		}

		// already resolved
		it->second = ts;
		return false;
	}

	// insert from resolve
	bool insert(addrinfo* addr, uint64_t ts)
	{
		return insert(to_address<AF>(addr), ts);
	}

	// garbage collector
	void gc(uint64_t erase_timeout, uint64_t ts)
	{
		auto n_erased = 0;
		for (auto it = m_addrs.begin(); it != m_addrs.end();)
		{
			if (it->second + erase_timeout < ts)
			{
				++n_erased;
				it = m_addrs.erase(it);
			}
			else
			{
				++it;
			}
		}

		if (n_erased > 0)
		{
			G_LOG_FORMAT(sinsp_logger::SEV_DEBUG,
			             "dns_info gc: removed: %d remaining: %d",
			             n_erased,
			             (int32_t)m_addrs.size());
		}
	}

	void copy(const addr_consumer_t<AF>& consumer) const
	{
		for (const auto& iter : m_addrs)
		{
			consumer(iter.first);
		}
	}

	void clear() { m_addrs.clear(); }

	bool empty() { return m_addrs.empty(); }

	size_t size() { return m_addrs.size(); }

	std::string to_string()
	{
		std::string out;
		for (auto e : m_addrs)
		{
			if (!out.empty())
			{
				out += ", ";
			}
			out += ::to_string<AF>(e.first);
		}
		return out;
	}

private:
	std::unordered_map<addr_t, uint64_t, af_hash_func<AF>> m_addrs;
};

// dns info to hold timestamps and resolution results.
// results are intermediate to be inserted into map containers
class dns_info
{
public:
	volatile mutable uint64_t m_last_used_ts = 0;

	dns_info(dns_info&& rh) = delete;
	dns_info(const dns_info& rh) = delete;

	dns_info& operator=(dns_info&&) = delete;
	dns_info& operator=(dns_info) = delete;

	// first lookup ctor
	dns_info(const std::string& name, uint64_t base_timeout, uint64_t max_timeout, uint64_t ts)
	    : m_last_used_ts(ts),
	      m_max_refresh_timeout(max_timeout),
	      m_refresh_timeout(base_timeout),
	      m_last_resolve_ts(ts)
	{
		resolve(name, ts, 1);
		G_LOG_FORMAT(sinsp_logger::SEV_DEBUG,
		             "dns_info: create new %s, ipv4: [%s], ipv6: [%s]",
		             name.c_str(),
		             m_v4_addrs->to_string().c_str(),
		             m_v6_addrs->to_string().c_str());
	}

	// refresh copy ctor
	dns_info(const std::string& name,
	         const dns_info& other,
	         uint64_t max_timeout,
	         uint64_t erase_timeout,
	         uint64_t ts)
	{
		m_max_refresh_timeout = max_timeout;

		m_last_used_ts = other.m_last_used_ts;
		m_last_resolve_ts = other.m_last_resolve_ts;
		m_refresh_timeout = other.m_refresh_timeout;

		*m_v4_addrs = *other.m_v4_addrs;
		*m_v6_addrs = *other.m_v6_addrs;

		m_v4_addrs->gc(erase_timeout, ts);
		m_v6_addrs->gc(erase_timeout, ts);

		auto refresh_timeout =
		    m_refresh_timeout / (m_v4_addrs->size() + m_v6_addrs->size() > 1 ? 10 : 1);
		if (ts > m_last_resolve_ts + refresh_timeout)
		{
			m_last_resolve_ts = ts;
			auto updated = resolve(name, ts, 3);

			if (!updated && m_refresh_timeout < m_max_refresh_timeout)
			{
				m_refresh_timeout <<= 1;  // double the timeout until 320 secs
			}

			G_LOG_FORMAT(
			    sinsp_logger::SEV_DEBUG,
			    "dns_info resolve: name: %s, updated: %s, next refresh in: %llu sec, ipv4: [%s], "
			    "ipv6: [%s]",
			    name.c_str(),
			    updated ? "true" : "false",
			    (m_refresh_timeout / (m_v4_addrs->size() + m_v6_addrs->size() > 1 ? 10 : 1)) /
			        ONE_SECOND_IN_NS,
			    m_v4_addrs->to_string().c_str(),
			    m_v6_addrs->to_string().c_str());
		}
	}

	bool is_expired(uint64_t erase_timeout, uint64_t ts) const
	{
		return (ts > m_last_used_ts) && (ts - m_last_used_ts) > erase_timeout;
	}

	bool has_address(int af, void* addr, uint64_t ts) const
	{
		auto ret =
		    (af == AF_INET) ? m_v4_addrs->has_address(addr, ts) : m_v6_addrs->has_address(addr, ts);

		if (ret)
		{
			m_last_used_ts = ts;
		}
		return ret;
	}

	void copy_addrs( const addr_consumer_t<AF_INET>& consumer ) const
	{
		m_v4_addrs->copy(consumer);
	}

	void copy_addrs( const addr_consumer_t<AF_INET6>& consumer ) const
	{
		m_v6_addrs->copy(consumer);
	}

private:
	bool resolve(const string& name, uint64_t ts, int n_iter)
	{
		addrinfo hints{}, *result, *rp;
		memset(&hints, 0, sizeof(struct addrinfo));

		// Allow IPv4 or IPv6, all socket types, all protocols
		hints.ai_family = AF_UNSPEC;
		int s = getaddrinfo(name.c_str(), nullptr, &hints, &result);

		if (s)
		{
			G_LOG_FORMAT(sinsp_logger::SEV_WARNING,
			             "dns_info: unable to resolve name='%s', error=%d",
			             name.c_str(),
			             s);
			return false;
		}

		if (result == nullptr)
		{
			G_LOG_FORMAT(sinsp_logger::SEV_DEBUG,
			             "dns_info: empty resolve result for name='%s'",
			             name.c_str());
			m_v4_addrs->clear();
			m_v6_addrs->clear();
			return false;
		}

		bool updated = false;
		int n_recs = 0;

		for (rp = result; rp != nullptr; rp = rp->ai_next)
		{
			n_recs++;
			updated |= (rp->ai_family == AF_INET) ? m_v4_addrs->insert(rp, ts)
			                                      : m_v6_addrs->insert(rp, ts);
		}

		freeaddrinfo(result);
		// recurse for n_iter
		if (n_recs > 1 && --n_iter > 0)
		{
			updated |= resolve(name, ts, n_iter);
		}
		return updated;
	}

	uint64_t m_max_refresh_timeout = 0;
	uint64_t m_refresh_timeout = 0;
	uint64_t m_last_resolve_ts = 0;

	std::shared_ptr<container<AF_INET>> m_v4_addrs = std::make_shared<container<AF_INET>>();
	std::shared_ptr<container<AF_INET6>> m_v6_addrs = std::make_shared<container<AF_INET6>>();
};

// Generic AF address converter -> name map
template<int AF>
class dns_addr_map
{
public:
	using addr_t = typename af_type_traits<AF>::type;

	void insert(const std::string& name, const dns_info* info)
	{
		info->copy_addrs([&](const addr_t& addr)
				 { m_map[addr] = std::make_pair(name, info); });
	}

	std::string name_of(void* addr, uint64_t ts) const
	{
		const auto it = m_map.find(to_address<AF>(addr));
		if (it == m_map.end())
		{
			return {};
		}
		it->second.second->m_last_used_ts = ts;
		return it->second.first;
	}

private:
	tbb::concurrent_unordered_map<addr_t, std::pair<std::string, const dns_info*>> m_map;
};

// combined v4, v6 maps
class dns_af_cache
{
public:

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

	std::string name_of(int af, void* addr, uint64_t ts) const
	{
		return (af == AF_INET) ? m_v4_cache.name_of(addr, ts) : m_v6_cache.name_of(addr, ts);
	}

	void insert(const std::string& name, std::shared_ptr<const dns_info> info)
	{
		m_v4_cache.insert(name, info.get());
		m_v6_cache.insert(name, info.get());
		m_info_table[name] = info;
	}

	std::size_t size() const
	{
		return m_info_table.size();
	}

	// async
	bool refresh(std::shared_ptr<dns_af_cache> shadow_cache, uint64_t erase_timeout, uint64_t max_refresh_timeout)
	{
		if (m_info_table.empty())
		{
			return false;
		}

		uint64_t ts = sinsp_utils::get_current_time_ns();

		for (auto& it : m_info_table)
		{
			const std::string& name = it.first;
			auto info = it.second;

			if (!info->is_expired(erase_timeout, ts))
			{
				// add shadow entries
				shadow_cache->insert(name,
				                     std::make_shared<dns_info>(name,
				                                                *info,
				                                                max_refresh_timeout,
				                                                erase_timeout,
				                                                ts));
			}
		}
		return true;
	}

private:
	tbb::concurrent_unordered_map<std::string, std::shared_ptr<const dns_info>> m_info_table;
	dns_addr_map<AF_INET> m_v4_cache;
	dns_addr_map<AF_INET6> m_v6_cache;
};

// cache class to provide work/shadow caches for fast switching
class sinsp_dns_manager::dns_cache
{
private:
	std::vector<std::shared_ptr<dns_af_cache>> m_caches;
	std::mutex m_cache_swap_mtx;
	using scoped_lock = typename std::lock_guard<std::mutex>;

public:
	dns_cache()
	{
		m_caches.emplace_back(new dns_af_cache());  // work
		m_caches.emplace_back(new dns_af_cache());  // shadow
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
	sinsp_dns_manager& manager = sinsp_dns_manager::get();
	while(true)
	{
		uint64_t base_refresh_timeout = manager.m_base_refresh_timeout;
		uint64_t max_refresh_timeout = manager.m_max_refresh_timeout;
		uint64_t erase_timeout = manager.m_erase_timeout;

		// create and fill shadow cache in the background
		auto shadow_cache = manager.m_dns_cache->create_shadow();
		auto work_cache = manager.m_dns_cache->get_work();

		if (manager.m_dns_cache->get_work()->refresh(manager.m_dns_cache->create_shadow(),
		                                             erase_timeout,
		                                             max_refresh_timeout))
		{
			manager.m_dns_cache->swap();
		}

		G_LOG_FORMAT(sinsp_logger::SEV_DEBUG, "%s", "sinsp_dns_manager: refreshed");

		if (f_exit.wait_for(std::chrono::nanoseconds(base_refresh_timeout / 10)) ==
		    std::future_status::ready)
		{
			break;
		}
	}
}

// match name with address
bool sinsp_dns_manager::match(const char* name, int af, void* addr, uint64_t ts)
{
	bool expect = false;
	if (m_resolver_flag.compare_exchange_strong(expect, true))
	{
		m_resolver = new thread(sinsp_dns_manager::refresh, m_exit_signal.get_future());
	}

	auto result = m_dns_cache->get_work()->match_by_name(af, name, addr, ts);
	if (result == dns_af_cache::MATCH_OK)
	{
		return true;
	}

	if (result == dns_af_cache::MATCH_NO_ADDRESS)
	{
		return false;
	}

	// MATCH_NO_NAME
	const auto& m = sinsp_dns_manager::get();
	m_dns_cache->insert(
	    name,
	    make_shared<dns_info>(name, m.m_base_refresh_timeout, m.m_max_refresh_timeout, ts));

	return m_dns_cache->get_work()->match_by_name(af, name, addr, ts) == dns_af_cache::MATCH_OK;
}

// resolve name by address
std::string sinsp_dns_manager::name_of(int af, void* addr, uint64_t ts)
{
	bool expect = false;
	if (m_resolver_flag.compare_exchange_strong(expect, true))
	{
		m_resolver = new thread(sinsp_dns_manager::refresh, m_exit_signal.get_future());
	}

	auto ret = m_dns_cache->get_work()->name_of(af, addr, ts);

	G_LOG_FORMAT(sinsp_logger::SEV_DEBUG,
	             "dns_info name_of %s:'%s'",
	             ip2str(af, addr).c_str(),
	             ret.c_str());

	return ret;
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

		G_LOG_FORMAT(sinsp_logger::SEV_DEBUG, "%s", "sinsp_dns_manager::cleanup");
	}
}

// get cache names size
size_t sinsp_dns_manager::size()
{
	return m_dns_cache->get_work()->size();
}

// client call to clear cache
void sinsp_dns_manager::clear_cache()
{
	G_LOG_FORMAT(sinsp_logger::SEV_DEBUG, "%s", "sinsp_dns_manager::clear_cache");
	m_dns_cache->clear();
}

// ctor
sinsp_dns_manager::sinsp_dns_manager()
    : m_dns_cache(new sinsp_dns_manager::dns_cache()),
      m_resolver(nullptr),
      m_erase_timeout(3600 * ONE_SECOND_IN_NS),
      m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
      m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
{
	m_resolver_flag.store(false);
}

#else

void sinsp_dns_manager::refresh(std::future<void> f_exit) {}

void sinsp_dns_manager::clear_cache() {}

size_t sinsp_dns_manager::size()
{
	return 0;
}

sinsp_dns_manager::sinsp_dns_manager()
    : m_resolver(nullptr),
      m_erase_timeout(3600 * ONE_SECOND_IN_NS),
      m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
      m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
{
}

bool sinsp_dns_manager::match(const char* name, int af, void* addr, uint64_t ts)
{
	return false;
}

string sinsp_dns_manager::name_of(int af, void* addr, uint64_t ts)
{
	return {};
}

void sinsp_dns_manager::cleanup() {}

#endif

sinsp_dns_manager& sinsp_dns_manager::get()
{
	static sinsp_dns_manager instance;
	return instance;
}
