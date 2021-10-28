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

#include <iostream>
#include "dns_manager.h"

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)

template <int> class af_converter{};

template <> class af_converter<AF_INET>
{
public:
	typedef int32_t type;

	static type value(void *addr){ return *(uint32_t *)addr; }
};

template <> class af_converter<AF_INET6>
{
public:
	typedef std::string type;
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

struct dns_info
{
public:
	uint64_t m_timeout=0;
	uint64_t m_last_resolve_ts =0;
	uint64_t m_last_used_ts = 0;

	std::set<uint32_t> m_v4_addrs;
	std::set<ipv6addr> m_v6_addrs;

	bool operator==(const dns_info &other) const
	{
		return m_v4_addrs == other.m_v4_addrs && m_v6_addrs == other.m_v6_addrs;
	};
	bool operator!=(const dns_info &other) const
	{
		return !operator==(other);
	};

	void refresh(const string &name)
	{
		addrinfo hints{}, *result, *rp;
		memset(&hints, 0, sizeof(struct addrinfo));

		// Allow IPv4 or IPv6, all socket types, all protocols
		hints.ai_family = AF_UNSPEC;

		m_v4_addrs.clear();
		m_v6_addrs.clear();

		int s = getaddrinfo(name.c_str(), nullptr, &hints, &result);
		if (!s && result)
		{
			for (rp = result; rp != nullptr; rp = rp->ai_next)
			{
				if(rp->ai_family == AF_INET)
				{
					m_v4_addrs.insert(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
				}
				else // AF_INET6
				{
					ipv6addr v6;
					memcpy(v6.m_b, ((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr, sizeof(ipv6addr));
					m_v6_addrs.insert(v6);
				}
			}
			freeaddrinfo(result);
		}
	}
};

using dns_info_table_t = tbb::concurrent_unordered_map<std::string, std::shared_ptr<dns_info>>;

template<typename First, typename Second>
class dns_map
{
private:
	typedef tbb::concurrent_unordered_map<Second, dns_info *> inner_map_t;
	typedef tbb::concurrent_unordered_map<First, inner_map_t> outer_map_t;
	outer_map_t m_map;
public:
	Second get_sindex(First fidx, uint64_t ts)
	{
		const auto fit = m_map.find(fidx);
		if(fit == m_map.end() || fit->second.empty())
		{
			return {};
		}

		auto sit = fit->second.begin();
		sit->second->m_last_used_ts = ts;
		return sit->first;
	}

	bool has_value(First fidx, Second sidx, uint64_t ts)
	{
		const auto fit = m_map.find(fidx);
		if(fit == m_map.end() || fit->second.empty())
		{
			return false;
		}

		auto sit = fit->second.find(sidx);
		if(sit == fit->second.end())
		{
			return false;
		}

		sit->second->m_last_used_ts = ts;
		return true;
	}

	void insert (First fidx, Second sidx, dns_info * info, uint64_t ts)
	{
		//info->m_last_used_ts = ts;
		m_map[fidx][sidx] = info;
	}
};

template <int AF> class dns_addr_map
{
private:
	typedef af_converter<AF> af_converter_t;
	typedef typename af_converter_t::type addr_t;
	dns_map<addr_t, std::string> m_addr_to_name_map;
public:
	void insert (std::string name, addr_t addr, dns_info * info, uint64_t ts)
	{
		m_addr_to_name_map.insert(addr, name, info, ts);
	}
	std::string name_of(void *addr, uint64_t ts)
	{
		return m_addr_to_name_map.get_sindex(af_converter_t::value(addr), ts);
	}
	bool match(std::string name, void* addr, uint64_t ts)
	{
		return m_addr_to_name_map.has_value(af_converter_t::value(addr), name, ts);
	}
};

class dns_af_cache
{
private:
	dns_addr_map<AF_INET>  m_v4_cache;
	dns_addr_map<AF_INET6> m_v6_cache;
public:
	dns_info_table_t m_info_table;

	void print_stats()
	{
		//SINSP_DEBUG("v4_size=%lu, v6_size=%lu", m_v4_cache.size(), m_v6_cache.size() );
	}

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

	void insert(std::string name, std::shared_ptr<dns_info> info, uint64_t ts)
	{
		for (auto addr : info->m_v4_addrs)
		{
			m_v4_cache.insert(name, addr, info.get(), ts);
		}

		for (auto addr : info->m_v6_addrs)
		{
			m_v6_cache.insert(name, af_converter<AF_INET6>::value(&addr.m_b[0]), info.get(), ts);
		}
		m_info_table[name] = info;
	}
};

class sinsp_dns_manager::dns_cache
{
private:
	tbb::concurrent_vector<std::shared_ptr<dns_af_cache>> m_cashes;
	tbb::queuing_rw_mutex m_cache_swap_mtx;
	using scoped_lock = typename tbb::queuing_rw_mutex::scoped_lock;
public:
	dns_cache()
	{
		m_cashes.emplace_back(new dns_af_cache());
		m_cashes.emplace_back(new dns_af_cache());
	}

	std::shared_ptr<dns_af_cache> get_work()
	{
		scoped_lock lk(m_cache_swap_mtx, false);
		return m_cashes[0];
	}

	std::shared_ptr<dns_af_cache> get_shadow()
	{
		scoped_lock lk(m_cache_swap_mtx, false);
		m_cashes[1] = std::make_shared<dns_af_cache>();
		return m_cashes[1];
	}

	void swap()
	{
		//std::cout << "swap\n";

		scoped_lock lk(m_cache_swap_mtx);
		m_cashes[0] = m_cashes[1];
		m_cashes[1] = std::make_shared<dns_af_cache>();
	}

	void insert(std::string name, std::shared_ptr<dns_info> info, uint64_t ts)
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_cashes[0]->insert(name, info, ts);
		m_cashes[1]->insert(name, info, ts);
	}

	void clear()
	{
		scoped_lock lk(m_cache_swap_mtx);
		m_cashes[0] = std::make_shared<dns_af_cache>();
		m_cashes[1] = std::make_shared<dns_af_cache>();
	}
};

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
//				auto prt= [&](const std::string& act, dns_info *i) {
//					std::cout << "\nacction: " << act << " info{ name:" << name
//						  << " last_used:" << i->m_last_used_ts/ONE_SECOND_IN_NS
//						  << " last_resolved:" << i->m_last_resolve_ts/ONE_SECOND_IN_NS
//						  << " timeout:" << i->m_timeout/ONE_SECOND_IN_NS
//						  << "\n";
//				};

				if((ts > info->m_last_used_ts) &&
				   (ts - info->m_last_used_ts) > erase_timeout)
				{
					//prt("erase", info.get());
					// remove the entry if it's hasn't been used for a whole hour
				}
				else
				{
					auto n_info = new dns_info();
					n_info->m_last_used_ts = info->m_last_used_ts;
					n_info->m_last_resolve_ts = info->m_last_resolve_ts;
					n_info->m_timeout = info->m_timeout;

					if(ts > n_info->m_last_resolve_ts + n_info->m_timeout && *n_info != *info)
					{
						n_info->refresh(name);
						n_info->m_timeout = base_refresh_timeout;
						n_info->m_last_resolve_ts  = ts;
						//prt("refresh", n_info);
					}
					else if(n_info->m_timeout < max_refresh_timeout)
					{
						// double the timeout until 320 secs
						n_info->m_timeout <<= 1;
						//prt("copy timeout", n_info);
					}
					else
					{
						//prt("copy", n_info);
					}
					shadow_cache->insert(name, std::shared_ptr<dns_info>(n_info), ts);
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

bool sinsp_dns_manager::match(const char *name, int af, void *addr, uint64_t ts)
{
	if(!m_resolver)
	{
		m_resolver = new thread(sinsp_dns_manager::refresh, m_exit_signal.get_future());
	}

	if( m_dns_cache->get_work()->match(af, name, addr, ts))
	{
		return true;
	}

	string sname = string(name);
	auto dinfo = make_shared<dns_info>();
	dinfo->refresh(sname);
	dinfo->m_last_used_ts = ts;
	dinfo->m_timeout = sinsp_dns_manager::get().m_base_refresh_timeout;
	dinfo->m_last_resolve_ts = ts;
	m_dns_cache->insert(sname, dinfo, ts);
	return m_dns_cache->get_work()->match(af, name, addr, ts);
}

string sinsp_dns_manager::name_of(int af, void *addr, uint64_t ts)
{
	return m_dns_cache->get_work()->name_of(af, addr, ts);
}

void sinsp_dns_manager::cleanup()
{
	if(m_resolver)
	{
		m_exit_signal.set_value();
		m_resolver->join();
		m_resolver = nullptr;
		m_exit_signal = std::promise<void>();
	}
}


size_t sinsp_dns_manager::size()
{
	return m_dns_cache->get_work()-> m_info_table.size();
}

void sinsp_dns_manager::clear_cache()
{
	m_dns_cache->clear();
}

sinsp_dns_manager::sinsp_dns_manager():
	m_dns_cache(new sinsp_dns_manager::dns_cache()),
	m_resolver(nullptr),
	m_erase_timeout(3600 * ONE_SECOND_IN_NS),
	m_base_refresh_timeout(10 * ONE_SECOND_IN_NS),
	m_max_refresh_timeout(320 * ONE_SECOND_IN_NS)
{
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

