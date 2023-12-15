// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

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

#include <libscap/scap.h>
#include <gtest/gtest.h>
#include <google/protobuf/any.pb.h>

#include <pkg/sentry/seccheck/points/syscall.pb.h>
#include <pkg/sentry/seccheck/points/sentry.pb.h>
#include <pkg/sentry/seccheck/points/container.pb.h>
#include <libscap/engine/gvisor/gvisor.h>

#ifdef __x86_64__
#include "../../driver/syscall_compat_x86_64.h"
#elif __aarch64__
#include "../../driver/syscall_compat_aarch64.h"
#elif __s390x__
#include "../../driver/syscall_compat_s390x.h"
#endif /* __x86_64__ */

template<class T>
uint32_t prepare_message(char *message, uint32_t message_size, uint16_t message_type, T &gvisor_evt)
{
    uint32_t proto_size = static_cast<uint32_t>(gvisor_evt.ByteSizeLong());
    uint16_t header_size = sizeof(scap_gvisor::header);
    uint32_t total_size = header_size + proto_size;
    uint32_t dropped_count = 0;

    // Fill the message header
    memcpy(message, &header_size, sizeof(uint16_t));
    memcpy(&message[sizeof(uint16_t)], &message_type, sizeof(uint16_t));
    memcpy(&message[sizeof(uint16_t) + sizeof(uint16_t)], &dropped_count, sizeof(uint32_t));

    // Serialize proto
    gvisor_evt.SerializeToArray(&message[header_size], message_size - header_size);

    return total_size;
}

TEST(gvisor_parsers, parse_execve_e)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_EXECVE;
    gvisor_evt.set_sysno(__NR_execve);
    gvisor_evt.set_pathname("/usr/bin/ls");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 1);
    EXPECT_STREQ(static_cast<const char*>(decoded_params[0].buf), "/usr/bin/ls");
}

TEST(gvisor_parsers, parse_container_id)
{
    char message[1024];

    std::string container_id = "1234";
    std::string parsed_container_id;
    gvisor::syscall::Execve execve_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_EXECVE;
    execve_evt.set_sysno(__NR_execve);
    execve_evt.set_pathname("/usr/bin/ls");
    auto *context_data = execve_evt.mutable_context_data();
    context_data->set_container_id(container_id);

    uint32_t total_size = prepare_message(message, 1024, message_type, execve_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};

    parsed_container_id = scap_gvisor::parsers::parse_container_id(gvisor_msg);
    EXPECT_EQ(container_id, parsed_container_id);

    gvisor::syscall::Fork fork_evt;
    message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_FORK;
    fork_evt.set_sysno(__NR_fork);
    context_data = fork_evt.mutable_context_data();
    container_id = "my_container_id";
    context_data->set_container_id(container_id);

    total_size = prepare_message(message, 1024, message_type, fork_evt);

    gvisor_msg = {.buf = message, .size = total_size};
    parsed_container_id = scap_gvisor::parsers::parse_container_id(gvisor_msg);
    EXPECT_EQ(container_id, parsed_container_id);

    gvisor::container::Start start_evt;
    message_type = gvisor::common::MessageType::MESSAGE_CONTAINER_START;
    container_id = "deadbeef";
    start_evt.set_id(container_id);
    start_evt.mutable_args()->Add("ls");
    context_data = start_evt.mutable_context_data();
    context_data->set_cwd("/root");

    total_size = prepare_message(message, 1024, message_type, start_evt);

    gvisor_msg = {.buf = message, .size = total_size};
    parsed_container_id = scap_gvisor::parsers::parse_container_id(gvisor_msg);
    EXPECT_EQ(container_id, parsed_container_id);
}


TEST(gvisor_parsers, parse_execve_x)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_EXECVE;
    gvisor_evt.set_sysno(__NR_execve);
    gvisor_evt.set_pathname("/usr/bin/ls");
    gvisor_evt.mutable_argv()->Add("ls");
    gvisor_evt.mutable_argv()->Add("a");
    gvisor_evt.mutable_argv()->Add("b");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");
    context_data->set_cwd("/root");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 27);
    EXPECT_STREQ(static_cast<const char*>(decoded_params[1].buf), "/usr/bin/ls"); // exe
    EXPECT_STREQ(static_cast<const char*>(decoded_params[6].buf), "/root"); // cwd
    EXPECT_STREQ(static_cast<const char*>(decoded_params[13].buf), "ls"); // comm
}

TEST(gvisor_parsers, parse_fork_e)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Fork gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_FORK;
    gvisor_evt.set_sysno(__NR_fork);
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    EXPECT_EQ(res.scap_events[0]->type, PPME_SYSCALL_FORK_20_E);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 0);
}

TEST(gvisor_parsers, parse_fork_x)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Fork gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_FORK;
    gvisor_evt.set_sysno(__NR_fork);
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");
    context_data->set_process_name("ls");
    context_data->set_cwd("/root");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 21);
    EXPECT_STREQ(static_cast<const char*>(decoded_params[1].buf), "ls"); // exe
    EXPECT_STREQ(static_cast<const char*>(decoded_params[6].buf), "/root"); // cwd
    EXPECT_STREQ(static_cast<const char*>(decoded_params[13].buf), "ls"); // comm
}

TEST(gvisor_parsers, parse_clone_e)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Clone gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_CLONE;
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    EXPECT_EQ(res.scap_events[0]->type, PPME_SYSCALL_CLONE_20_E);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 0);
}

TEST(gvisor_parsers, parse_clone_x)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Clone gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_CLONE;
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");
    context_data->set_process_name("ls");
    context_data->set_cwd("/root");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 21);
    EXPECT_STREQ(static_cast<const char*>(decoded_params[1].buf), "ls"); // exe
    EXPECT_STREQ(static_cast<const char*>(decoded_params[6].buf), "/root"); // cwd
    EXPECT_STREQ(static_cast<const char*>(decoded_params[13].buf), "ls"); // comm
}

TEST(gvisor_parsers, parse_socketpair_e)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::SocketPair gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_SOCKETPAIR;
    gvisor_evt.set_domain(995);
    gvisor_evt.set_type(996);
    gvisor_evt.set_protocol(997);
    gvisor_evt.set_socket1(998);
    gvisor_evt.set_socket2(999);

    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    EXPECT_EQ(res.scap_events[0]->type, PPME_SOCKET_SOCKETPAIR_E);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 3);

    EXPECT_EQ(decoded_params[0].size, 4);
    EXPECT_EQ(*(static_cast<int32_t*>(decoded_params[0].buf)), 995);  // domain

    EXPECT_EQ(decoded_params[1].size, 4);
    EXPECT_EQ(*(static_cast<int32_t*>(decoded_params[1].buf)), 996);  // type

    EXPECT_EQ(decoded_params[2].size, 4);
    EXPECT_EQ(*(static_cast<int32_t*>(decoded_params[2].buf)), 997);  // protocol
}

TEST(gvisor_parsers, parse_socketpair_x)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::SocketPair gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_SOCKETPAIR;
    gvisor_evt.set_domain(995);
    gvisor_evt.set_type(996);
    gvisor_evt.set_protocol(997);
    gvisor_evt.set_socket1(998);
    gvisor_evt.set_socket2(999);

    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    EXPECT_EQ(res.scap_events[0]->type, PPME_SOCKET_SOCKETPAIR_X);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 5);

    EXPECT_EQ(decoded_params[1].size, 8);
    EXPECT_EQ(*(static_cast<int64_t*>(decoded_params[1].buf)), 998);  // fd1

    EXPECT_EQ(decoded_params[2].size, 8);
    EXPECT_EQ(*(static_cast<int64_t*>(decoded_params[2].buf)), 999);  // fd2
}

TEST(gvisor_parsers, parse_container_start)
{
    char message[1024];
    char buffer[1024];

    gvisor::container::Start gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_CONTAINER_START;
    gvisor_evt.set_id("deadbeef");
    gvisor_evt.mutable_args()->Add("ls");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_cwd("/root");

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);

    EXPECT_EQ(res.scap_events.size(), 4);
    EXPECT_EQ(res.scap_events[0]->type, PPME_SYSCALL_CLONE_20_E);
    EXPECT_EQ(res.scap_events[1]->type, PPME_SYSCALL_CLONE_20_X);
    EXPECT_EQ(res.scap_events[2]->type, PPME_SYSCALL_EXECVE_19_E);
    EXPECT_EQ(res.scap_events[3]->type, PPME_SYSCALL_EXECVE_19_X);
}

TEST(gvisor_parsers, unhandled_syscall)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Syscall gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_RAW;
    gvisor_evt.set_sysno(999);
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_NE(res.error.find("Unhandled syscall"), std::string::npos);
    EXPECT_EQ(res.status, SCAP_NOT_SUPPORTED);
}

TEST(gvisor_parsers, small_buffer)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    uint16_t message_type = gvisor::common::MessageType::MESSAGE_SYSCALL_EXECVE;
    gvisor_evt.set_sysno(__NR_execve);
    gvisor_evt.set_pathname("/usr/bin/ls");
    gvisor_evt.mutable_argv()->Add("ls");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");
    context_data->set_cwd("/root");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    uint32_t total_size = prepare_message(message, 1024, message_type, gvisor_evt);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1};

    scap_gvisor::parsers::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ(res.status, SCAP_INPUT_TOO_SMALL);
    scap_buf.size = res.size;
    res = scap_gvisor::parsers::parse_gvisor_proto(10, gvisor_msg, scap_buf);
    EXPECT_EQ(res.status, SCAP_SUCCESS);
}

TEST(gvisor_parsers, procfs_entry)
{
    std::string not_json = "not a json string";
    uint32_t sandbox_id = 0xdeadbeef;

    scap_gvisor::parsers::procfs_result res = scap_gvisor::parsers::parse_procfs_json(not_json, sandbox_id);
    EXPECT_EQ(res.status, SCAP_FAILURE);

    std::string json = R"(
{
  "args": [ "bash" ],
  "clone_ts": 1655473752715788585,
  "cwd": "/",
  "env": [
    "HOSTNAME=91e91fdd849d",
    "TERM=xterm",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root"
  ],
  "exe": "/usr/bin/bash",
  "fdlist": [
    {
      "number": 0,
      "mode": 0,
      "path": "host:[1]"
    },
    {
      "number": 1,
      "mode": 0,
      "path": "host:[1]"
    },
    {
      "number": 2,
      "mode": 0,
      "path": "host:[1]"
    },
    {
      "number": 255,
      "mode": 0,
      "path": "host:[1]"
    }
  ],
  "limits": {
    "RLIMIT_NOFILE": {
      "cur": 1048576,
      "max": 1048576
    }
  },
  "root": "/",
  "stat": {
    "pgid": 1,
    "sid": 1
  },
  "status": {
    "comm": "bash",
    "gid": {"effective": 0, "real": 0, "saved": 0},
    "pid": 1,
    "uid": {"effective": 0, "real": 0, "saved": 0},
    "vm_rss": 4664,
    "vm_size": 12164
  }
}
    )";

    res = scap_gvisor::parsers::parse_procfs_json(json, sandbox_id);
    EXPECT_EQ(res.status, SCAP_SUCCESS);
    EXPECT_EQ(res.tinfo.vtid, 1);
    EXPECT_STREQ(res.tinfo.comm, "bash");
    EXPECT_STREQ(res.tinfo.exepath, "/usr/bin/bash");
    std::string args = std::string(res.tinfo.args, res.tinfo.args_len);
    EXPECT_TRUE(args.find("bash") != std::string::npos);
    std::string env = std::string(res.tinfo.env, res.tinfo.env_len);
    EXPECT_TRUE(env.find("HOSTNAME=91e91fdd849d") != std::string::npos);
    EXPECT_TRUE(env.find("TERM=xterm") != std::string::npos);
    EXPECT_TRUE(env.find("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin") != std::string::npos);
    EXPECT_TRUE(env.find("HOME=/root") != std::string::npos);

    std::string json_missing_fields = "{\"exe\":\"/usr/bin/bash\"}\n";
    res = scap_gvisor::parsers::parse_procfs_json(json_missing_fields, sandbox_id);
    EXPECT_EQ(res.status, SCAP_FAILURE);
    EXPECT_STREQ(res.error.c_str(), "Missing json field or wrong type: cannot parse procfs entry");

    std::string args_arr = "[ \"bash\" ]";
    std::string args_no_arr = "\"bash\"";
    auto pos = json.find(args_arr);
    json.replace(pos, args_arr.size(), args_no_arr);
    res = scap_gvisor::parsers::parse_procfs_json(json, sandbox_id);
    EXPECT_EQ(res.status, SCAP_FAILURE);
    EXPECT_STREQ(res.error.c_str(), "Missing json field or wrong type: cannot parse procfs entry");

}

TEST(gvisor_parsers, config_socket)
{
    std::string config = R"(
{
    "trace_session": {
        "name": "Default",
        "points": [
        {
            "name": "container/start",
            "context_fields": [
                "cwd",
                "time"
            ]
        },
        {
            "name": "syscall/openat/enter",
            "context_fields": [
                "credentials",
                "container_id",
                "thread_id",
                "task_start_time",
                "time"
            ]
        },
        {
            "name": "syscall/openat/exit",
            "context_fields": [
                "credentials",
                "container_id",
                "thread_id",
                "task_start_time",
                "time"
            ]
        },
        {
            "name": "sentry/task_exit",
            "context_fields": [
                "credentials",
                "container_id",
                "thread_id",
                "task_start_time",
                "time"
            ]
        }
        ],
        "sinks": [
        {
            "name": "remote",
            "config": {
                "endpoint": "/tmp/gvisor.sock"
            }
        }
        ]
    }
}
    )";

    scap_gvisor::parsers::config_result res;

    res = scap_gvisor::parsers::parse_config(config);
    EXPECT_EQ(res.status, SCAP_SUCCESS);
    EXPECT_STREQ(res.socket_path.c_str(), "/tmp/gvisor.sock");
}
