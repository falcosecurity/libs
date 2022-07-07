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

#pragma once

#include <stdint.h>
#include <string>
#include <thread> 
#include <atomic>
#include <deque>
#include <vector>
#include <unordered_map>

#include "scap.h"

namespace scap_gvisor {

#pragma pack(push, 1)
struct header
{
	uint16_t header_size;
	uint16_t message_type;
	uint32_t dropped_count;
};
#pragma pack(pop)

namespace parsers {

struct parse_result {
    // the scap status of the operation
	uint32_t status;
    // description of the error in case of failure
	std::string error;
    // the total encoded event(s) size
	size_t size;
    // pointers to each encoded event within the supplied output buffer
	std::vector<scap_evt*> scap_events;
    // number of events dropped by gVisor
    uint32_t dropped_count;
};

struct procfs_result {
    // the scap status of the operation
    uint32_t status;
    // description of the error in case of failure
    std::string error;
    // the resulting thread information
    scap_threadinfo tinfo;
    // the fdinfos associated with this thread
    std::vector<scap_fdinfo> fdinfos;
};

struct config_result {
    // the scap status of the operation
    uint32_t status;
    // description of the error in case of failure
    std::string error;
    // the socket path
    std::string socket_path;
};

/*!
    \brief Translate a gVisor seccheck protobuf into one, or more, scap events
    \param gvisor_buf the source buffer that contains the raw event coming from gVisor
    \param scap_buf the buffer that will be used to store the encoded scap events
    \return a parse_result struct. 
        If the encoding is successful:
            - the status field will be set as SCAP_SUCCESS
            - the scap_events vector will contain pointers to each encoded event, all located within scap_buf's memory
            - the size field will indicate the total used size in scap_buf.
        If the buffer is too small to contain all encoded events:
            - the status field will be set as SCAP_INPUT_TOO_SMALL
            - the size field will be set to the total required size to fully translate the supplied gVisor event
        In case of any error:
            - the status field will be set to SCAP_FAILURE for parsing erros, SCAP_NOT_SUPPORTED for unsupported events
            - the error field will contain a string representation of the error
*/
parse_result parse_gvisor_proto(scap_const_sized_buffer gvisor_buf, scap_sized_buffer scap_buf);

procfs_result parse_procfs_json(const std::string &input, const std::string &sandbox);

uint64_t get_vxid(uint64_t vxid);

config_result parse_config(std::string config);

} // namespace parsers

namespace runsc
{

    struct result {
        int error;
        std::vector<std::string> output;
    };

    result version();
    result list(const std::string &root_path);
    result trace_create(const std::string &root_path, const std::string &trace_session_path, const std::string &sandbox_id, bool force);
    result trace_delete(const std::string &root_path, const std::string &session_name, const std::string &sandbox_id);
    result trace_procfs(const std::string &root_path, const std::string &sandbox_id);

} // namespace runsc

// contains entries to store per-sandbox data and buffers to use to write events in
class sandbox_entry {
public:
	sandbox_entry();
    ~sandbox_entry();

    int32_t expand_buffer(size_t size);

    scap_sized_buffer m_buf;
    uint64_t m_last_dropped_count;
	bool m_closing;
};

class engine {
public:
    engine(char *lasterr);
    ~engine();
    int32_t init(std::string config_path, std::string root_path);
    int32_t close();

    int32_t start_capture();
    int32_t stop_capture();

    int32_t next(scap_evt **pevent, uint16_t *pcpuid);

    uint32_t get_threadinfos(uint64_t *n, const scap_threadinfo **tinfos);
    uint32_t get_fdinfos(const scap_threadinfo *tinfo, uint64_t *n, const scap_fdinfo **fdinfos);
    uint32_t get_vxid(uint64_t pid);
    int32_t get_stats(scap_stats  *stats);
private:
    int32_t process_message_from_fd(int fd);
    void free_sandbox_buffers();

    char *m_lasterr;
    int m_listenfd = 0;
    int m_epollfd = 0;
    bool m_capture_started = false;

    std::string m_socket_path;
    std::thread m_accept_thread;

    // contains pointers to parsed events to process
    std::deque<scap_evt *> m_event_queue{};

    // stores per-sandbox data. All buffers used to contain parsed event data are owned by this map
    std::unordered_map<int, sandbox_entry> m_sandbox_data;

    // the following two maps store and manage memory for thread information requested
    // when get_threadinfos() is called. They are only updated upon get_threadinfos()
    std::vector<scap_threadinfo> m_threadinfos_threads;
    std::unordered_map<uint64_t, std::vector<scap_fdinfo>> m_threadinfos_fds;

    // the following two strings contains the path of the root dir used by the runsc command
    // and the path the trace session configuration file used to set up traces, respectively
    std::string m_root_path;
    std::string m_trace_session_path;

    struct gvisor_stats
    {
        // total number of events received from gVisor
        uint64_t n_evts;
        // total number of drops due to parsig errors
        uint64_t n_drops_parsing;
        // total number of drops on gVisor side
        uint64_t n_drops_gvisor;
    } m_gvisor_stats;

};

} // namespace scap_gvisor
