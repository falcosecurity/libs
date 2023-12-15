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

// fills the buffer with ASCII data to catch bugs
static void fill_buffer(scap_sized_buffer buf)
{
    char *cbuf = static_cast<char*>(buf.buf);
    size_t i = 0;
    for (char upper = 'A'; upper < 'Z'; upper++) {
        for (char lower = 'a'; lower < 'z'; lower++) {
            for (char digit = '0'; digit < '9'; digit++) {
                if (i == buf.size) return;
                cbuf[i] = upper;
                i++;
                if (i == buf.size) return;
                cbuf[i] = lower;
                i++;
                if (i == buf.size) return;
                cbuf[i] = digit;
                i++;
            }
        }
    }
}

// This function behaves exactly like scap_event_encode_params but it will allocate the event and return it by setting the event pointer.
static int32_t scap_event_generate(scap_evt **event, char *error, ppm_event_code event_type, uint32_t n, ...)
{
    scap_sized_buffer event_buf = {NULL, 0};
    size_t event_size;
    va_list args;
    va_start(args, n);
    int32_t ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);
    va_end(args);

    if(ret != SCAP_INPUT_TOO_SMALL) {
        if (ret == SCAP_SUCCESS) {
            snprintf(error, SCAP_LASTERR_SIZE, "Could not generate event. Expected SCAP_INPUT_TOO_SMALL, got SCAP_SUCCESS for event type %d with %d args", event_type, n);
        }
        return SCAP_FAILURE;
    }

    event_buf.buf = malloc(event_size);
    event_buf.size = event_size;

    fill_buffer(event_buf);

    if(event_buf.buf == NULL) {
        snprintf(error, SCAP_LASTERR_SIZE, "Could not generate event. Allocation failed for %zu bytes", event_size);
        return SCAP_FAILURE;
    }

    va_start(args, n);
    ret = scap_event_encode_params_v(event_buf, &event_size, error, event_type, n, args);
    va_end(args);

    if(ret != SCAP_SUCCESS) {
        free(event_buf.buf);
        event_buf.size = 0;
    }

    *event = (scap_evt*)event_buf.buf;

    return ret;
}

TEST(scap_event, empty_clone)
{
    char scap_error[SCAP_LASTERR_SIZE];
    scap_evt *maybe_evt;
    uint32_t status = scap_event_generate(&maybe_evt, scap_error, PPME_SYSCALL_CLONE_20_E, 0);
    ASSERT_EQ(status, SCAP_SUCCESS) << "scap_event_generate failed with error " << scap_error;
    ASSERT_NE(maybe_evt, nullptr);
    std::unique_ptr<scap_evt, decltype(free)*> evt {maybe_evt, free};

    EXPECT_EQ(evt->nparams, 0);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(evt.get(), decoded_params);
    EXPECT_EQ(n, 0);
}

TEST(scap_event, int_args)
{
    char scap_error[SCAP_LASTERR_SIZE];
    scap_evt *maybe_evt;
    uint32_t status = scap_event_generate(&maybe_evt, scap_error, PPME_SYSCALL_KILL_E, 2, 1234, 9);
    ASSERT_EQ(status, SCAP_SUCCESS) << "scap_event_generate failed with error " << scap_error;
    ASSERT_NE(maybe_evt, nullptr);
    std::unique_ptr<scap_evt, decltype(free)*> evt {maybe_evt, free};

    EXPECT_EQ(evt->nparams, 2);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(evt.get(), decoded_params);
    EXPECT_EQ(n, 2);
    EXPECT_EQ(decoded_params[0].size, sizeof(uint64_t));
    uint64_t val64;
    memcpy(&val64, decoded_params[0].buf, sizeof(uint64_t));
    EXPECT_EQ(val64, 1234);

    uint8_t val8;
    memcpy(&val8, decoded_params[1].buf, sizeof(uint8_t));
    EXPECT_EQ(val8, 9);
}

TEST(scap_event, empty_buffers)
{
    char scap_error[SCAP_LASTERR_SIZE];

    // empty string should be of size 1
    scap_evt *maybe_evt;
    uint32_t status = scap_event_generate(&maybe_evt, scap_error, PPME_SYSCALL_GETCWD_X, 2, 0, "");
    ASSERT_EQ(status, SCAP_SUCCESS) << "scap_event_generate failed with error " << scap_error;
    ASSERT_NE(maybe_evt, nullptr);
    std::unique_ptr<scap_evt, decltype(free)*> evt {maybe_evt, free};

    EXPECT_EQ(evt->nparams, 2);

    scap_sized_buffer decoded_params[PPM_MAX_EVENT_PARAMS];
    uint32_t n = scap_event_decode_params(evt.get(), decoded_params);
    EXPECT_EQ(n, 2);
    EXPECT_EQ(decoded_params[0].size, sizeof(uint64_t));
    EXPECT_EQ(decoded_params[1].size, 1);

    status = scap_event_generate(&maybe_evt, scap_error, PPME_SYSCALL_READ_X, 2, 0, scap_const_sized_buffer{nullptr, 0});
    ASSERT_EQ(status, SCAP_SUCCESS) << "scap_event_generate failed with error " << scap_error;
    ASSERT_NE(maybe_evt, nullptr);
    evt.reset(maybe_evt);

    n = scap_event_decode_params(evt.get(), decoded_params);
    EXPECT_EQ(n, 2);
    EXPECT_EQ(decoded_params[0].size, sizeof(uint64_t));
    EXPECT_EQ(decoded_params[1].size, 0);
}
