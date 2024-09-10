// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <thread_pool_bs.h>

#include <BS_thread_pool.hpp>

void thread_pool_bs::default_bs_tp_deleter::operator()(BS::thread_pool* __ptr) const {
	std::default_delete<BS::thread_pool>{}(__ptr);
}

thread_pool_bs::thread_pool_bs(size_t num_workers): m_pool(nullptr), m_routines() {
	if(num_workers == 0) {
		m_pool = std::unique_ptr<BS::thread_pool, default_bs_tp_deleter>(new BS::thread_pool());
	} else {
		m_pool = std::unique_ptr<BS::thread_pool, default_bs_tp_deleter>(
		        new BS::thread_pool(num_workers));
	}
}

thread_pool_bs::routine_id_t thread_pool_bs::subscribe(const std::function<bool()>& func) {
	m_routines.push_back(std::make_shared<std::function<bool()>>(func));
	auto& new_routine = m_routines.back();
	run_routine(new_routine);

	return reinterpret_cast<thread_pool_bs::routine_id_t>(new_routine.get());
}

bool thread_pool_bs::unsubscribe(thread_pool_bs::routine_id_t id) {
	bool removed = false;
	m_routines.remove_if([id, &removed](const std::shared_ptr<std::function<bool()>>& v) {
		if(v.get() == reinterpret_cast<std::function<bool()>*>(id)) {
			removed = true;
			return true;
		}

		return false;
	});

	return removed;
}

void thread_pool_bs::purge() {
	m_routines.clear();

	m_pool->purge();
	m_pool->wait();
}

size_t thread_pool_bs::routines_num() {
	return m_routines.size();
}

void thread_pool_bs::run_routine(std::shared_ptr<std::function<bool()>> routine) {
	m_pool->detach_task([this, routine] {
		if(routine.use_count() <= 1) {
			return;
		}

		if(!((*routine) && (*routine)())) {
			m_routines.remove(routine);
			return;
		}

		run_routine(routine);
	});
}
