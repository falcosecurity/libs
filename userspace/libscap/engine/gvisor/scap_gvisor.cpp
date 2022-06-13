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
#include <sys/wait.h>

#include <vector>

#include <json/json.h>

#include "gvisor.h"
#include "pkg/sentry/seccheck/points/common.pb.h"

#include "../../../common/strlcpy.h"

namespace scap_gvisor {

constexpr uint32_t min_supported_version = 1;
constexpr uint32_t current_version = 1;
constexpr uint32_t max_ready_sandboxes = 32;
constexpr size_t max_message_size = 300 * 1024;
constexpr size_t initial_event_buffer_size = 32;
constexpr int listen_backlog_size = 128;
constexpr size_t max_line_size = 2048;
// todo(loresuso): change default to k8s path
const std::string default_runsc_root_path = "/var/run/docker/runtime-runc/moby";

sandbox_entry::sandbox_entry()
{
	m_buf.buf = nullptr;
	m_buf.size = 0;
}

sandbox_entry::~sandbox_entry()
{
	if (m_buf.buf != nullptr)
	{
		free(m_buf.buf);
	}
}

int32_t sandbox_entry::expand_buffer(size_t size)
{
	void* new_buf;

	if (m_buf.buf == nullptr) {
		new_buf = malloc(size);
	} else
	{
		new_buf = realloc(m_buf.buf, size);
	}

	if (new_buf == nullptr)
	{
		return SCAP_FAILURE;
	}

	m_buf.buf = new_buf;
	m_buf.size = size;

	return SCAP_SUCCESS;
}

engine::engine(char *lasterr)
{
    m_lasterr = lasterr;
}

engine::~engine()
{

}

int32_t engine::init(std::string socket_path, std::string root_path, std::string trace_session_path)
{
	m_root_path = root_path;
	m_trace_session_path = trace_session_path;
	
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

	ret = listen(sock, listen_backlog_size);
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
	stop_capture();
	unlink(m_socket_path.c_str());
    return SCAP_SUCCESS;
}

void engine::free_sandbox_buffers()
{
	m_sandbox_data.clear();
}

static bool handshake(int client)
{
	std::vector<char> buf(max_message_size);
	ssize_t bytes = read(client, buf.data(), buf.size());
	if(bytes < 0)
	{
		return false;
	}
	else if(static_cast<size_t>(bytes) == buf.size())
	{
		return false;
	}

	gvisor::common::Handshake in = {};
	if(!in.ParseFromArray(buf.data(), bytes))
	{
		return false;
	}

	if(in.version() < min_supported_version)
	{
		return false;
	}

	gvisor::common::Handshake out;
	out.set_version(current_version);
	if(!out.SerializeToFileDescriptor(client))
	{
		return false;
	}
	
	return true;
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
			// connection shutdown
			return;
		}

		if(!handshake(client))
		{
			close(client);
			continue;
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
	//
	// Retrieve all running sandboxes
	// We will need to recreate a session for each of them
	//
	std::vector<std::string> existing_sandboxes = runsc_list();

	// Start accepting connections
	m_accept_thread = std::thread(accept_thread, m_listenfd, m_epollfd);
	m_accept_thread.detach();

	m_capture_started = true;
	
	for(const auto& sandbox : existing_sandboxes)
	{
		// Since they were already running, we need to force the creation
		runsc_trace_create(sandbox, true);
	}


	// Catch all sandboxes that might have been created in the meantime
	std::vector<std::string> new_sandboxes = runsc_list();

	// Remove the existing sandboxes (erase-remove idiom)
	new_sandboxes.erase(
		remove_if(
			new_sandboxes.begin(),
			new_sandboxes.end(),
			[&existing_sandboxes](const std::string &s) -> bool
			{
				auto res = find(existing_sandboxes.begin(), existing_sandboxes.end(), s);
				return res != existing_sandboxes.end();
			}),
		new_sandboxes.end());

	// Create new session for remaining sandboxes
	for(const auto& sandbox : new_sandboxes)
	{
		runsc_trace_create(sandbox, false);
	}

    return SCAP_SUCCESS;
}

int32_t engine::stop_capture()
{
	if (!m_capture_started)
	{
		return SCAP_SUCCESS;
	}

	shutdown(m_listenfd, 2);
	::close(m_epollfd);
	free_sandbox_buffers();
	m_capture_started = false;
    return SCAP_SUCCESS;
}

uint32_t engine::get_threadinfos(uint64_t *n, const scap_threadinfo **tinfos)
{
	// Add logic to parse process and file list from runsc here

	*tinfos = m_threadinfos_threads.data();
	*n = m_threadinfos_threads.size();

	return SCAP_SUCCESS;
}

uint32_t engine::get_fdinfos(const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos)
{
	*n = m_threadinfos_fds[tinfo->tid].size();
	if (*n != 0) {
		*fdinfos = m_threadinfos_fds[tinfo->tid].data();
	}

	return SCAP_SUCCESS;
}

uint32_t engine::get_vxid(uint64_t xid)
{
	return parsers::get_vxid(xid);
}

// Reads one gvisor message from the specified fd, stores the resulting events overwriting m_buffers and adds pointers to m_event_queue.
// Returns:
// * SCAP_SUCCESS in case of success
// * SCAP_FAILURE in case of a fatal error while reading from the fd or allocating memory (m_lasterr is filled)
// * SCAP_ILLEGAL_INPUT in case of parsing errors
// * SCAP_EOF if there is no more data to process from this fd
int32_t engine::process_message_from_fd(int fd)
{
	char message[max_message_size];

	ssize_t nbytes = read(fd, message, max_message_size);
	if(nbytes == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Error reading from gvisor client: %s", strerror(errno));
		return SCAP_FAILURE;
	}
	else if(nbytes == 0)
	{
		::close(fd);
		m_sandbox_data.erase(fd);

		return SCAP_EOF;
	}

	// check if we need to allocate a new buffer for this sandbox
	if(m_sandbox_data.count(fd) != 1)
	{
		m_sandbox_data.emplace(fd, sandbox_entry{});
		if (m_sandbox_data[fd].expand_buffer(initial_event_buffer_size) == SCAP_FAILURE) {
			snprintf(m_lasterr, SCAP_LASTERR_SIZE, "could not initialize %zu bytes for gvisor sandbox on fd %d", initial_event_buffer_size, fd);
			return SCAP_FAILURE;
		}
	}

	scap_const_sized_buffer gvisor_msg = {.buf = static_cast<void*>(message), .size = static_cast<size_t>(nbytes)};

	struct parsers::parse_result parse_result = parsers::parse_gvisor_proto(gvisor_msg, m_sandbox_data[fd].m_buf);
	if(parse_result.status == SCAP_INPUT_TOO_SMALL)
	{
		if (m_sandbox_data[fd].expand_buffer(parse_result.size) == SCAP_FAILURE)
		{
			snprintf(m_lasterr, SCAP_LASTERR_SIZE,"Cannot realloc gvisor buffer to %zu", parse_result.size);
			return SCAP_FAILURE;
		};
		parse_result = parsers::parse_gvisor_proto(gvisor_msg, m_sandbox_data[fd].m_buf);
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

	return parse_result.status;
}

int32_t engine::next(scap_evt **pevent, uint16_t *pcpuid)
{
	struct epoll_event evts[max_ready_sandboxes];

	// if there are still events to process do it before getting more
	if(!m_event_queue.empty())
	{
		*pevent = m_event_queue.front();
		m_event_queue.pop_front();
		return SCAP_SUCCESS;
	}

	int nfds = epoll_wait(m_epollfd, evts, max_ready_sandboxes, -1);
	if (nfds < 0)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "epoll_wait error: %s", strerror(errno));
		if (errno == EINTR) {
			// Syscall interrupted. Nothing else to read.
			return SCAP_EOF;
		}
		// unhandled error
		return SCAP_FAILURE;
	}

	for (int i = 0; i < nfds; ++i) {
		int fd = evts[i].data.fd;
		if (evts[i].events & EPOLLIN) {
			uint32_t status = process_message_from_fd(fd);
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
			::close(fd);
			m_sandbox_data.erase(fd);
		}

		if (evts[i].events & EPOLLERR)
		{
			int socket_error = 0;
			socklen_t len = sizeof(socket_error);
			if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len))
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

std::vector<std::string> engine::runsc(char *argv[])
{
	std::vector<std::string> res;
	int pipefds[2];

	int ret = pipe(pipefds);
	if(ret)
	{
		return res;
	}

	int pid = fork();
	if(pid > 0)
	{
		char line[max_line_size];
		int status;
		
		::close(pipefds[1]);
		wait(&status);
		if(status)
		{
			return res;
		}

		FILE *f = fdopen(pipefds[0], "r");
		if(!f)
		{
			return res;
		}

		while(fgets(line, max_line_size, f))
		{
			res.emplace_back(std::string(line));
		}

		fclose(f);
	}
	else
	{
		::close(pipefds[0]);
		dup2(pipefds[1], STDOUT_FILENO);
		execvp("runsc", argv);
		exit(1);
	}

	return res;
}

std::vector<std::string> engine::runsc_list()
{
	std::vector<std::string> sandboxes;

	const char *argv[] = {
		"runsc", 
		"--root",
		m_root_path.c_str(),
		"list",
		NULL
	};

	std::vector<std::string> output = runsc((char **)argv);

	for(auto &line : output)
	{
		if(line.find("running") != std::string::npos)
		{
			std::string sandbox = line.substr(0, line.find_first_of(" ", 0));
			sandboxes.emplace_back(sandbox);
		}
	}

	return sandboxes;
}

void engine::runsc_trace_create(const std::string &sandbox_id, bool force)
{
	const char *argv[] = {
		"runsc", 
		"--root",
		m_root_path.c_str(),
		"trace",
		"create",
		force ? "--force" : "",
		"--config", 
		m_trace_session_path.c_str(),
		sandbox_id.c_str(),
		NULL
	};

	runsc((char **)argv);
}

} // namespace scap_gvisor
