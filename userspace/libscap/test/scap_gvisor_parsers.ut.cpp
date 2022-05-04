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

#include "scap.h"
#include <gtest/gtest.h>
#include "../../common/strlcpy.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"
#include "engine/gvisor/gvisor.h"

uint32_t prepare_message(char *message, uint32_t message_size, google::protobuf::Any &any)
{
    uint32_t proto_size = static_cast<uint32_t>(any.ByteSizeLong()); 
    uint16_t header_size = sizeof(scap_gvisor::header);
    uint32_t total_size = header_size + proto_size;
    uint32_t dropped_count = 0;
    memcpy(message, &header_size, sizeof(uint16_t));
    memcpy(&message[sizeof(uint32_t)], &dropped_count, sizeof(uint32_t));
    any.SerializeToArray(&message[header_size], message_size - header_size);
    return total_size;
}

TEST(gvisor_parsers, parse_execve_e)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    gvisor_evt.set_pathname("/usr/bin/ls");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    struct scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 1);
    EXPECT_STREQ(static_cast<const char*>(decoded_params[0].buf), "/usr/bin/ls");
}

TEST(gvisor_parsers, parse_execve_x)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    gvisor_evt.set_pathname("/usr/bin/ls");
    gvisor_evt.mutable_argv()->Add("ls");
    gvisor_evt.mutable_argv()->Add("a");
    gvisor_evt.mutable_argv()->Add("b");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");
    context_data->set_cwd("/root");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_EQ("", res.error);
    EXPECT_EQ(res.status, SCAP_SUCCESS);

    EXPECT_EQ(res.scap_events.size(), 1);

    struct scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(res.scap_events[0], decoded_params);
    EXPECT_EQ(n, 20);
    EXPECT_STREQ(static_cast<const char*>(decoded_params[1].buf), "/usr/bin/ls"); // exe
    EXPECT_STREQ(static_cast<const char*>(decoded_params[6].buf), "/root"); // cwd
    EXPECT_STREQ(static_cast<const char*>(decoded_params[13].buf), "ls"); // comm
}

TEST(gvisor_parsers, parse_container_start)
{
    char message[1024];
    char buffer[1024];

    gvisor::container::Start gvisor_evt;
    gvisor_evt.set_id("deadbeef");
    gvisor_evt.mutable_args()->Add("ls");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_cwd("/root");

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(gvisor_msg, scap_buf);

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
    gvisor_evt.set_sysno(999);
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1024};

    scap_gvisor::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_NE(res.error.find("Unhandled syscall"), std::string::npos);
    EXPECT_EQ(res.status, SCAP_TIMEOUT);
}

TEST(gvisor_parsers, small_buffer)
{
    char message[1024];
    char buffer[1024];

    gvisor::syscall::Execve gvisor_evt;
    gvisor_evt.set_pathname("/usr/bin/ls");
    gvisor_evt.mutable_argv()->Add("ls");
    auto *context_data = gvisor_evt.mutable_context_data();
    context_data->set_container_id("1234");
    context_data->set_cwd("/root");
    gvisor::syscall::Exit *exit = gvisor_evt.mutable_exit();
    exit->set_result(0);

    google::protobuf::Any any;
    any.PackFrom(gvisor_evt);

    uint32_t total_size = prepare_message(message, 1024, any);

    scap_const_sized_buffer gvisor_msg = {.buf = message, .size = total_size};
    scap_sized_buffer scap_buf = {.buf = buffer, .size = 1};

    scap_gvisor::parse_result res = scap_gvisor::parsers::parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_EQ(res.status, SCAP_INPUT_TOO_SMALL);
    scap_buf.size = res.size;
    res = scap_gvisor::parsers::parse_gvisor_proto(gvisor_msg, scap_buf);
    EXPECT_EQ(res.status, SCAP_SUCCESS);
}
