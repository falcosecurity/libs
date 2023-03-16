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
#include <fstream>
#include <sstream>

#include "gvisor.h"
#include "pkg/sentry/seccheck/points/common.pb.h"

#include "strlcpy.h"

namespace scap_gvisor {

constexpr uint32_t min_supported_version = 1;
constexpr uint32_t current_version = 1;
constexpr uint32_t max_ready_sandboxes = 32;
constexpr size_t max_message_size = 300 * 1024;
constexpr size_t initial_event_buffer_size = 32;
constexpr int listen_backlog_size = 128;
const std::string default_root_path = "/var/run/docker/runtime-runc/moby";

sandbox_entry::sandbox_entry()
{
	m_buf.buf = nullptr;
	m_buf.size = 0;
	m_last_dropped_count = 0;
	m_closing = false;
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

	if (m_buf.buf == nullptr)
	{
		new_buf = malloc(size);
		if (new_buf == nullptr)
		{
			return SCAP_FAILURE;
		}
	} else
	{
		new_buf = realloc(m_buf.buf, size);
		if (new_buf == nullptr)
		{
			return SCAP_FAILURE;
		}
	}

	m_buf.buf = new_buf;
	m_buf.size = size;

	return SCAP_SUCCESS;
}

engine::engine(char *lasterr)
{
    m_lasterr = lasterr;
	m_gvisor_stats.n_evts = 0;
	m_gvisor_stats.n_drops_parsing = 0;
	m_gvisor_stats.n_drops_gvisor = 0;
}

engine::~engine()
{

}

int32_t engine::init(std::string config_path, std::string root_path)
{
	if(root_path.empty())
	{
		m_root_path = default_root_path;
	}
	else
	{
		m_root_path = root_path;
	}

	m_trace_session_path = config_path;
	
	std::ifstream config_file(config_path);
	if (config_file.fail())
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Could not open gVisor configuration file %s", config_path.c_str());
		return SCAP_FAILURE;
	}
	std::stringstream config_buf;
	config_buf << config_file.rdbuf();

	parsers::config_result config_result = parsers::parse_config(config_buf.str());
	if(config_result.status != SCAP_SUCCESS)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Could not parse gVisor configuration file %s : %s",
			config_path.c_str(), config_result.error.c_str());
		return config_result.status;
	}

	// Initialize the listen fd
	m_socket_path = config_result.socket_path;
	if (m_socket_path.empty())
	{
		strlcpy(m_lasterr, "Empty gVisor socket path", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	unlink(m_socket_path.c_str());
	
	// Check if runsc is installed in the system
	runsc::result version = runsc::version();
	if(version.error)
	{
		strlcpy(m_lasterr, "Cannot find runsc binary", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}

	int sock = socket(PF_UNIX, SOCK_SEQPACKET, 0);
	if(sock == -1)
	{
		snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot create unix socket: %s", strerror(errno));
		return SCAP_FAILURE;
	}
	sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strlcpy(address.sun_path, m_socket_path.c_str(), sizeof(address.sun_path));

	unsigned long old_umask = umask(0);
	int ret = bind(sock, (sockaddr *)&address, sizeof(address));
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

		epoll_event evt;
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
	runsc::result exisiting_sandboxes_res = runsc::list(m_root_path);
	if(exisiting_sandboxes_res.error)
	{
		strlcpy(m_lasterr, "Error listing running sandboxes", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}
	std::vector<std::string> &existing_sandboxes = exisiting_sandboxes_res.output;

	// Start accepting connections
	m_accept_thread = std::thread(accept_thread, m_listenfd, m_epollfd);
	m_accept_thread.detach();

	m_capture_started = true;
	
	for(const auto& sandbox : existing_sandboxes)
	{
		// Since they were already running, we need to force the creation
		runsc::result trace_create_res = runsc::trace_create(m_root_path, m_trace_session_path, sandbox, true);
		if(trace_create_res.error)
		{
			// some sandboxes may not be traced, we can skip them safely
			continue;
		}
	}

	// Catch all sandboxes that might have been created in the meantime
	runsc::result new_sandboxes_res = runsc::list(m_root_path);
	if(new_sandboxes_res.error)
	{
		strlcpy(m_lasterr, "Error listing running sandboxes", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}
	std::vector<std::string> &new_sandboxes = new_sandboxes_res.output;

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
		runsc::result trace_create_res = runsc::trace_create(m_root_path, m_trace_session_path, sandbox, false);
		if(trace_create_res.error)
		{
			// some sandboxes may not be traced, we can skip them safely
			continue;
		}
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

	runsc::result sandboxes_res = runsc::list(m_root_path);
	if(sandboxes_res.error)
	{
		strlcpy(m_lasterr, "Error listing running sandboxes", SCAP_LASTERR_SIZE);
		return SCAP_FAILURE;
	}
	std::vector<std::string> &sandboxes = sandboxes_res.output;
	for(const auto &sandbox : sandboxes)
	{
		// todo(loresuso): change session name when gVisor will support it
		runsc::result trace_delete_res = runsc::trace_delete(m_root_path, "Default", sandbox);
		if(trace_delete_res.error)
		{
			snprintf(m_lasterr, SCAP_LASTERR_SIZE, "Cannot delete session for sandbox %s", sandbox.c_str());
			return SCAP_FAILURE;
		}
	}	

	m_capture_started = false;
    return SCAP_SUCCESS;
}

uint32_t engine::get_threadinfos(uint64_t *n, const scap_threadinfo **tinfos)
{
	runsc::result sandboxes_res = runsc::list(m_root_path);
	std::vector<std::string> &sandboxes = sandboxes_res.output;

	m_threadinfos_threads.clear();
	m_threadinfos_fds.clear();

	for(const auto &sandbox : sandboxes)
	{
		runsc::result procfs_res = runsc::trace_procfs(m_root_path, sandbox);

		// We may be unable to read procfs for several reasons, e.g. the pause container on k8s or a sandbox that was
		// being removed
		if (procfs_res.error != 0)
		{
			continue;
		}

		for(const auto &line : procfs_res.output)
		{
			// skip first line of the output and empty lines
			if(line.find("PROCFS DUMP") != std::string::npos || std::all_of(line.begin(), line.end(), isspace))
			{
				continue;
			}

			parsers::procfs_result res = parsers::parse_procfs_json(line, sandbox);
			if(res.status != SCAP_SUCCESS)
			{
				*tinfos = NULL;
				*n = 0;
				snprintf(m_lasterr, SCAP_LASTERR_SIZE, "%s", res.error.c_str());
				return res.status;
			}
			
			m_threadinfos_threads.emplace_back(res.tinfo);
			m_threadinfos_fds[res.tinfo.tid] = res.fdinfos;
		}
	}

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

int32_t engine::get_stats(scap_stats *stats)
{
	stats->n_drops = m_gvisor_stats.n_drops_parsing + m_gvisor_stats.n_drops_gvisor;
	stats->n_drops_bug = m_gvisor_stats.n_drops_parsing;
	stats->n_drops_buffer = m_gvisor_stats.n_drops_gvisor;
	stats->n_evts = m_gvisor_stats.n_evts;
	return SCAP_SUCCESS;
}

// Reads one gvisor message from the specified fd, stores the resulting events overwriting m_buffers and adds pointers to m_event_queue.
// Returns:
// * SCAP_SUCCESS in case of success
// * SCAP_FAILURE in case of a fatal error while reading from the fd or allocating memory (m_lasterr is filled)
// * SCAP_NOT_SUPPORTED if the message type is not currently supported
// * SCAP_ILLEGAL_INPUT in case of parsing errors (invalid message or parsing issue)
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

	parsers::parse_result parse_result = parsers::parse_gvisor_proto(gvisor_msg, m_sandbox_data[fd].m_buf);
	if(parse_result.status == SCAP_INPUT_TOO_SMALL)
	{
		if (m_sandbox_data[fd].expand_buffer(parse_result.size) == SCAP_FAILURE)
		{
			snprintf(m_lasterr, SCAP_LASTERR_SIZE,"Cannot realloc gvisor buffer to %zu", parse_result.size);
			return SCAP_FAILURE;
		};
		parse_result = parsers::parse_gvisor_proto(gvisor_msg, m_sandbox_data[fd].m_buf);
	} 

	if(parse_result.status == SCAP_NOT_SUPPORTED)
	{
		strlcpy(m_lasterr, parse_result.error.c_str(), SCAP_LASTERR_SIZE);
		return SCAP_NOT_SUPPORTED;
	}

	if(parse_result.status == SCAP_FAILURE)
	{
		strlcpy(m_lasterr, parse_result.error.c_str(), SCAP_LASTERR_SIZE);
		return SCAP_ILLEGAL_INPUT;
	}

	uint64_t delta = parse_result.dropped_count - m_sandbox_data[fd].m_last_dropped_count;
	m_sandbox_data[fd].m_last_dropped_count = parse_result.dropped_count;
	m_gvisor_stats.n_drops_gvisor += delta;

	for(scap_evt *evt : parse_result.scap_events)
	{
		m_event_queue.push_back(evt);
	}

	return parse_result.status;
}

int32_t engine::next(scap_evt **pevent, uint16_t *pcpuid)
{
	epoll_event evts[max_ready_sandboxes];
	*pcpuid = 0;

	// if there are still events to process do it before getting more
	if(!m_event_queue.empty())
	{
		*pevent = m_event_queue.front();
		m_event_queue.pop_front();
		m_gvisor_stats.n_evts++;
		return SCAP_SUCCESS;
	}

	// at this moment, there are no events in any of the buffers we allocated
	// for each sandbox: this is the right place to close fds and deallocate
	// buffers safely for all the sandboxes that are no longer connected. 

	for(auto it = m_sandbox_data.begin(); it != m_sandbox_data.end(); )
	{
		sandbox_entry &sandbox = it->second;
		if(sandbox.m_closing)
		{
			::close(it->first);
			it = m_sandbox_data.erase(it);
		}
		else
		{
			it++;
		}
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
			else if (status == SCAP_EOF)
			{
				m_sandbox_data[fd].m_closing = true;
			}

			// ignore unsupported messages, we will simply discard them
			if (status == SCAP_NOT_SUPPORTED) {
				continue;
			}

			// ignore parsing errors, we will simply discard the message
			if (status == SCAP_ILLEGAL_INPUT) {
				m_gvisor_stats.n_drops_parsing++;
				continue;
			}
		}

		if ((evts[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0)
		{
			m_sandbox_data[fd].m_closing = true;
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
		m_gvisor_stats.n_evts++;
		return SCAP_SUCCESS;
	}

	// nothing to do
    return SCAP_TIMEOUT;
}

} // namespace scap_gvisor
