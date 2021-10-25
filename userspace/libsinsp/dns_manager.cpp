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

void sinsp_dns_manager::refresh(std::future<void> f_exit)
{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
	sinsp_dns_manager &manager = sinsp_dns_manager::get();

	while(true)
	{
		uint64_t base_refresh_timeout = manager.m_base_refresh_timeout;
		uint64_t max_refresh_timeout = manager.m_max_refresh_timeout;
		uint64_t erase_timeout = manager.m_erase_timeout;

		if(!manager.m_cache.empty())
		{
			std::list<std::string> to_delete;

			uint64_t ts = sinsp_utils::get_current_time_ns();

			for(auto &it: manager.m_cache)
			{
				const std::string &name = it.first;
				auto info = it.second;

				if((ts > info->m_last_used_ts) &&
				   (ts - info->m_last_used_ts) > erase_timeout)
				{
					// remove the entry if it's hasn't been used for a whole hour
					to_delete.push_back(name);
				}
				else if(ts > (info->m_last_resolve_ts + info->m_timeout))
				{
					// dns_info::operator!= will check if some
					// v4 or v6 addresses are changed from the
					// last resolution
					if(info->refresh(name))
					{
						info->m_timeout = base_refresh_timeout;
						info->m_last_resolve_ts = info->m_last_resolve_ts = ts;
					}
					else if(info->m_timeout < max_refresh_timeout)
					{
						// double the timeout until 320 secs
						info->m_timeout <<= 1;
					}
				}
			}
			if(!to_delete.empty())
			{
				manager.m_erase_mutex.lock();
				for(const auto &name : to_delete)
				{
					manager.m_cache.unsafe_erase(name);
				}
				manager.m_erase_mutex.unlock();
			}
		}

		if(f_exit.wait_for(std::chrono::nanoseconds(base_refresh_timeout)) == std::future_status::ready)
		{
			break;
		}
	}
#endif
}

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
bool sinsp_dns_manager::dns_info::refresh(const string &name)
{
	std::set<uint32_t> v4_addrs;
	std::set<ipv6addr> v6_addrs;

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
				v4_addrs.insert(((struct sockaddr_in*)rp->ai_addr)->sin_addr.s_addr);
			}
			else // AF_INET6
			{
				ipv6addr v6;
				memcpy(v6.m_b, ((struct sockaddr_in6*)rp->ai_addr)->sin6_addr.s6_addr, sizeof(ipv6addr));
				v6_addrs.insert(v6);
			}
		}
		freeaddrinfo(result);
	}

	std::lock_guard<std::mutex> lk(m_mtx);
	if (m_v4_addrs == v4_addrs && m_v6_addrs == m_v6_addrs)
	{
		return false;
	}
	m_v4_addrs = std::move(v4_addrs);
	m_v6_addrs = std::move(v6_addrs);
	return true;
}
#endif

bool sinsp_dns_manager::match(const char *name, int af, void *addr, uint64_t ts)
{
#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
	if(!m_resolver)
	{
		m_resolver = new thread(sinsp_dns_manager::refresh, m_exit_signal.get_future());
	}

	std::shared_ptr<dns_info> dinfo;
	string sname = string(name);

	{
		std::lock_guard<std::mutex> lk(m_erase_mutex);

		const auto &it = m_cache.find(sname);
		if(it == m_cache.end())
		{
			dinfo = std::make_shared<dns_info>();
			dinfo->refresh(name);
			dinfo->m_timeout = m_base_refresh_timeout;
			dinfo->m_last_resolve_ts = ts;
			m_cache.emplace(name, dinfo);
		}
		else
		{
			dinfo = it->second;
			dinfo->m_last_used_ts = ts;
		}
	}

	if(af == AF_INET6)
	{
		ipv6addr v6;
		memcpy(v6.m_b, addr, sizeof(ipv6addr));
		return dinfo->contains(v6);
	}
	else if(af == AF_INET)
	{
		return dinfo->contains(*(uint32_t *)addr);
	}
#endif
	return false;
}

string sinsp_dns_manager::name_of(int af, void *addr, uint64_t ts)
{
	string ret;

#if defined(HAS_CAPTURE) && !defined(CYGWING_AGENT) && !defined(_WIN32)
	std::lock_guard<std::mutex> lk (m_erase_mutex);
	if(!m_cache.empty())
	{
		if(af == AF_INET6)
		{
			ipv6addr v6;
			memcpy(v6.m_b, addr, sizeof(ipv6addr));
			for(auto &it: m_cache)
			{
				if (it.second->contains(v6))
				{
					it.second->m_last_used_ts = ts;
					return it.first;
				}
			}
		}
		else if(af == AF_INET)
		{
			for(auto &it: m_cache)
			{
				if(it.second->contains(*(uint32_t *)addr))
				{
					it.second->m_last_used_ts = ts;
					return it.first;
				}
			}
		}
	}
#endif
	return ret;
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
