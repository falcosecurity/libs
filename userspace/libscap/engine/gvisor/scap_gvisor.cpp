/*
Copyright (C) 2022 The Falco Authors.

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


#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include <vector>

#include "gvisor.h"

#include "../../../common/strlcpy.h"

namespace scap_gvisor {

engine::engine(char *lasterr)
{
    m_lasterr = lasterr;
}

engine::~engine()
{

}

int32_t engine::init(std::string socket_path)
{
	// Initialize the listen fd
	int sock, ret;
	struct sockaddr_un address;
	unsigned long old_umask;
	m_socket_path = socket_path;
	if (m_socket_path.empty())
	{
		strlcpy(m_lasterr, "Empty gVisor socket path", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	unlink(m_socket_path.c_str());

	sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(sock == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot create unix socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strlcpy(address.sun_path, m_socket_path.c_str(), sizeof(address.sun_path));

	old_umask = umask(0);
	ret = bind(sock, (struct sockaddr *)&address, sizeof(address));
	if(ret == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot bind unix socket: %s", strerror(errno));
		umask(old_umask);
		return SCAP_FAILURE;
	}

	ret = listen(sock, 128);
	if(ret == -1)
	{
		umask(old_umask);
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot listen on gvisor unix socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}

	umask(old_umask);
	m_listenfd = sock;

	// Initialize the epoll fd
	m_epollfd = epoll_create(1);
	if(m_epollfd == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot create epollfd socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}

    return SCAP_SUCCESS;
}

int32_t engine::close()
{
	free_sandbox_buffers();
	unlink(m_socket_path.c_str());
    return SCAP_SUCCESS;
}

void engine::free_sandbox_buffers()
{
	for (const auto& kv : m_sandbox_buffers) {
		free(kv.second.buf);
	}
	m_sandbox_buffers.clear();
}

static void accept_thread(int listenfd, int epollfd)
{
	while(true)
	{
		int client = accept(listenfd, NULL, NULL);
		if (client < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return;
		}

		struct epoll_event evt;
		evt.data.fd = client;
		evt.events = EPOLLIN;
		if(epoll_ctl(epollfd, EPOLL_CTL_ADD, client, &evt) < 0)
		{
			return;
		}
	}
}

int32_t engine::start_capture()
{
	m_accept_thread = std::thread(accept_thread, m_listenfd, m_epollfd);
	m_accept_thread.detach();

    return SCAP_SUCCESS;
}

int32_t engine::stop_capture()
{
	free_sandbox_buffers();
    return SCAP_SUCCESS;
}

// Reads one gvisor message from the specified fd, stores the resulting events overwriting m_buffers and adds pointers to m_event_queue.
// Returns:
// * SCAP_SUCCESS in case of success
// * SCAP_FAILURE in case of a fatal error while reading from the fd or allocating memory (m_lasterr is filled)
// * SCAP_ILLEGAL_INPUT in case of parsing errors
// * SCAP_EOF if there is no more data to process from this fd
int32_t engine::process_message_from_fd(int fd)
{
	char message[GVISOR_MAX_MESSAGE_SIZE];

	ssize_t nbytes = read(fd, message, GVISOR_MAX_MESSAGE_SIZE);
	if(nbytes == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Error reading from gvisor client: %s", strerror(errno));
		return SCAP_FAILURE;
	}
	else if(nbytes == 0)
	{
		::close(fd);
		if (m_sandbox_buffers.count(fd) == 1)
		{
			free(m_sandbox_buffers[fd].buf);
			m_sandbox_buffers.erase(fd);
		}

		return SCAP_EOF;
	}

	// check if we need to allocate a new buffer for this sandbox
	if(m_sandbox_buffers.count(fd) != 1)
	{
		scap_sized_buffer new_buf;
		new_buf.buf = malloc(GVISOR_INITIAL_EVENT_BUFFER_SIZE);
		new_buf.size = GVISOR_INITIAL_EVENT_BUFFER_SIZE;
		if (new_buf.buf == nullptr)
		{
			snprintf(m_lasterr, SCAP_LASTERR_SIZE, "could not initialize %zu bytes for gvisor sandbox on fd %d", new_buf.size, fd);
			return SCAP_FAILURE;
		}
		m_sandbox_buffers[fd] = new_buf;
	}

	scap_sized_buffer &sandbox_buf = m_sandbox_buffers[fd];
	scap_const_sized_buffer gvisor_msg = {.buf = static_cast<void*>(message), .size = static_cast<size_t>(nbytes)};

	struct parsers::parse_result parse_result = parsers::parse_gvisor_proto(gvisor_msg, sandbox_buf);
	if(parse_result.status == SCAP_INPUT_TOO_SMALL)
	{
		sandbox_buf.buf = realloc(sandbox_buf.buf, parse_result.size);
		if(!sandbox_buf.buf)
		{
			strlcpy(m_lasterr, "Cannot realloc gvisor buffer", SCAP_LASTERR_SIZE);
			return SCAP_FAILURE;
		}
		sandbox_buf.size = parse_result.size;
		parse_result = parsers::parse_gvisor_proto(gvisor_msg, sandbox_buf);
	} 

	if(parse_result.status != SCAP_SUCCESS)
	{
		strlcpy(m_lasterr, parse_result.error.c_str(), SCAP_LASTERR_SIZE);
		return parse_result.status;
	}

	for(scap_evt *evt : parse_result.scap_events)
	{
		m_event_queue.push_back(evt);
	}
}

int32_t engine::next(scap_evt **pevent, uint16_t *pcpuid)
{
	struct epoll_event evts[GVISOR_MAX_READY_SANDBOXES];

	// if there are still events to process do it before getting more
	if(!m_event_queue.empty())
	{
		*pevent = m_event_queue.front();
		m_event_queue.pop_front();
		return SCAP_SUCCESS;
	}

	int nfds = epoll_wait(m_epollfd, evts, GVISOR_MAX_READY_SANDBOXES, -1);
	if (nfds < 0)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "epoll_wait error: %s", strerror(errno));
		return SCAP_TIMEOUT;
	}

	for (int i = 0; i < nfds; ++i) {
		if (evts[i].events & EPOLLIN) {
			uint32_t status = process_message_from_fd(evts[i].data.fd);
			if (status == SCAP_FAILURE) {
				return SCAP_FAILURE;
			}

			// useful for debugging but we might want to do better
			if (status == SCAP_ILLEGAL_INPUT) {
				return SCAP_FAILURE;
			}
		}

		if ((evts[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0)
		{
			return SCAP_EOF;
		}

		if (evts[i].events & EPOLLERR)
		{
			int socket_error = 0;
			socklen_t len = sizeof(socket_error);
			if(getsockopt(evts[i].data.fd, SOL_SOCKET, SO_ERROR, &socket_error, &len))
			{
				snprintf(m_lasterr, SCAP_LASTERR_SIZE, "epoll error: %s", strerror(socket_error));
				return SCAP_FAILURE;
			}
		}
	}

	// check if any message has been processed and return the first
	if(!m_event_queue.empty())
	{
		*pevent = m_event_queue.front();
		m_event_queue.pop_front();
		return SCAP_SUCCESS;
	}

	// nothing to do
    return SCAP_TIMEOUT;
}

} // namespace scap_gvisor
