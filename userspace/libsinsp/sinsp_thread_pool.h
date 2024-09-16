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
#pragma once

#include <list>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>

class sinsp_thread_pool {
public:
	using routine_id_t = uintptr_t;

	sinsp_thread_pool() = default;

	virtual ~sinsp_thread_pool() = default;

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
	virtual bool unsubscribe(routine_id_t id) = 0;

	/*!
	 * \brief Unsubscribes all the subscribed routines and waits for the running ones to finish.
	 */
	virtual void purge() = 0;

	/*!
	 * \return The count of currently subscribed routines.
	 */
	virtual size_t routines_num() = 0;
};
