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

#include <list>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>

class thread_pool
{
public:
	using routine_id_t = std::function<bool()>*;

	thread_pool() = default;

	virtual ~thread_pool() = default;

	/*!
  	* \brief Subscribes a routine to the thread pool.
	*
	* \param func The routine to be subscribed, represented by a function returning a bool value.
	* Returning false causes the routine to be unsubscribed from the thread pool.
	*
	* \return An handle representing a specific routine.
	* This can later be used to unsubscribe the routine.
	*/
	virtual routine_id_t subscribe(const std::function<bool()>& func) = 0;

	/*!
  	* \brief Unsubscribes a routine from the thread pool.
	*
	* \param id A routine handle.
	*/
	virtual void unsubscribe(routine_id_t id) = 0;

	/*!
  	* \brief Unsubscribes all the subscribed routines and waits for the running ones to finish.
	*/
	virtual void purge() = 0;

	/*!
	* \return The count of currently subscribed routines.
	*/
	virtual size_t routines_num() = 0;
};

namespace BS {
	class thread_pool;
};

class bs_thread_pool : public thread_pool
{
public:
	bs_thread_pool(size_t num_workers = 0);

	virtual ~bs_thread_pool()
	{
		purge();
	}

	thread_pool::routine_id_t subscribe(const std::function<bool()>& func);

	void unsubscribe(thread_pool::routine_id_t id);

    void purge();

	size_t routines_num();

private:
	struct default_bs_tp_deleter { void operator()(BS::thread_pool* __ptr) const; };

	void run_routine(std::shared_ptr<std::function<bool()>> id);

	std::unique_ptr<BS::thread_pool, default_bs_tp_deleter> m_pool;
	std::list<std::shared_ptr<std::function<bool()>>> m_routines;
};