// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

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
#include <queue>
#include <vector>
#include <functional>
#include <libsinsp/event.h>

class sinsp_observer;

/*!
  \brief Data structure holding parser processing verdict.
  `sinsp_parser` populates an instance of this structure in order to provide information regarding
  actions that must be taken as a result of observing some particular kind of events. The user must
  call the `must_*` methods to verify that data for a particular kind of action are registered
  before calling the corresponding `get_*` method to get the data.
*/
class sinsp_parser_verdict {
	/*!
	  \brief The action to be taken by the verdict enforcer.
	*/
	enum action {
		NONE = 0,
		TID_REMOVAL = 1 << 0,
		FDS_REMOVAL = 1 << 1,
		OBSERVER_POST_PROCESS = 1 << 2,
	};

	int actions;
	int64_t m_tid_to_remove;
	int64_t m_tid_of_fd_to_remove;
	std::vector<int64_t> m_fds_to_remove;
	typedef std::function<void(sinsp_observer* observer, sinsp_evt* evt)> post_process_cb;
	std::queue<post_process_cb> m_post_process_cbs;

	void default_tid_to_remove() { m_tid_to_remove = -1; }

	void default_fds_to_remove() {
		m_tid_to_remove = -1;
		m_fds_to_remove.clear();
	}

	void default_post_process_cbs() {
		// Clear the queue by swapping it with an empty instance.
		std::queue<post_process_cb>().swap(m_post_process_cbs);
	}

public:
	sinsp_parser_verdict() { clear(); }

	/*!
	  \brief Register a thread removal.
	  \param tid The id of the thread that is mandated to be removed.
	  \note Calling this overwrite any previously registered thread removal.
	*/
	void set_tid_to_remove(const int64_t tid) {
		actions |= TID_REMOVAL;
		m_tid_to_remove = tid;
	}

	/*!
	  \brief Return true if a thread removal was registered.
	 */
	bool must_remove_tid() const { return (actions & TID_REMOVAL) != 0; }

	/*!
	  \brief Return the registered thread id to be removed.
	  \note This must be called only after `must_remove_tid()` returns `true`.
	 */
	int64_t get_tid_to_remove() const { return m_tid_to_remove; }

	/*!
	  \brief Unregister the registered thread removal.
	*/
	void clear_tid_to_remove() {
		actions &= ~TID_REMOVAL;
		default_tid_to_remove();
	}

	/*!
	  \brief Register the removal of a file descriptor for a particular thread.
	  \param tid The id of the thread owning the file descriptor to be removed.
	  \param fd The fd to be removed.
	  \note The current implementation supports the removal of multiple file descriptors for a
	  single thread but not the removal of file descriptors associated with multiple threads. Each
	  time this API is called, the registered thread id is overwritten: this means that, if the user
	  wants to register the removal of multiple file descriptors for a single thread, it must call
	  this API multiple times, by providing the same thread id and a different file descriptor each
	  time.
	*/
	void add_fd_to_remove(const int64_t tid, const int64_t fd) {
		actions |= FDS_REMOVAL;
		m_tid_of_fd_to_remove = tid;
		m_fds_to_remove.push_back(fd);
	}

	/*!
	  \brief Return true if a file descriptors removal was registered.
	 */
	bool must_remove_fds() const { return (actions & FDS_REMOVAL) != 0; }

	/*!
	  \brief Return the registered thread id of the file descriptors scheduled to be removed.
	  \note This must be called only after `must_remove_fds()` returns `true`.
	 */
	int64_t get_tid_of_fds_to_remove() const { return m_tid_of_fd_to_remove; }

	/*!
	  \brief Return the file descriptors to be removed.
	  \note This must be called only after `must_remove_fds()` returns `true`.
	 */
	const std::vector<int64_t>& get_fds_to_remove() const { return m_fds_to_remove; }

	/*!
	  \brief Unregister every registered file descriptor removal.
	*/
	void clear_fds_to_remove() {
		actions &= ~FDS_REMOVAL;
		default_fds_to_remove();
	}

	/*!
	  \brief Register the execution of a post-process observer callback.
	  \param pcb The post-process observer callback to be executed.
	*/
	void add_post_process_cbs(const post_process_cb& pcb) {
		actions |= OBSERVER_POST_PROCESS;
		m_post_process_cbs.emplace(pcb);
	}

	/*!
	  \brief Return true if the execution of post-process observer callbacks was registered.
	 */
	bool must_run_post_process_cbs() const { return (actions & OBSERVER_POST_PROCESS) != 0; }

	/*!
	  \brief Return the registered post-process observer callbacks
	  \note This must be called only after `must_run_post_process_cbs()` returns `true`.
	 */
	std::queue<post_process_cb> get_post_process_cbs() { return m_post_process_cbs; }

	/*!
	  \brief Unregister every registered post-process observer callback.
	*/
	void clear_post_process_cbs() {
		actions &= ~OBSERVER_POST_PROCESS;
		default_post_process_cbs();
	}

	/*!
	  \brief Reset the verdict to the default configuration.
	*/
	void clear() {
		actions = NONE;
		default_tid_to_remove();
		default_fds_to_remove();
		default_post_process_cbs();
	}
};
