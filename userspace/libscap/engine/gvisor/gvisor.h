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
#include <map>

#include "scap.h"

#define GVISOR_MAX_READY_SANDBOXES 32

#define GVISOR_MAX_MESSAGE_SIZE 300 * 1024
#define GVISOR_INITIAL_EVENT_BUFFER_SIZE 32

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
};
typedef struct parse_result parse_result;

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
            - the status field will be set to the relevant SCAP_* value
            - the error field will contain a string representation of the error
*/
parse_result parse_gvisor_proto(scap_const_sized_buffer gvisor_buf, scap_sized_buffer scap_buf);

} // namespace parsers


class engine {
public:
    engine(char *lasterr);
    ~engine();
    int32_t init(std::string socket_path);
    int32_t close();

    int32_t start_capture();
    int32_t stop_capture();

    int32_t next(scap_evt **pevent, uint16_t *pcpuid);
    
private:
    int32_t process_message_from_fd(int fd);
    void free_sandbox_buffers();

    char *m_lasterr;
    int m_listenfd;
    int m_epollfd;
    std::string m_socket_path;
    std::thread m_accept_thread;
    std::deque<scap_evt *> m_event_queue{};

    // buffers in which to store events, one per each active sandbox, indexed by fd
    std::map<int, scap_sized_buffer> m_sandbox_buffers;
};

} // namespace scap_gvisor
