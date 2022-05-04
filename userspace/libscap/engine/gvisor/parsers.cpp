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
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/un.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <functional>
#include <unordered_map>
#include <sstream>
#include <string>

#include "gvisor.h"
#include "../../driver/ppm_events_public.h"

#include "userspace_flag_helpers.h"

#include "google/protobuf/any.pb.h"
#include "pkg/sentry/seccheck/points/syscall.pb.h"
#include "pkg/sentry/seccheck/points/sentry.pb.h"
#include "pkg/sentry/seccheck/points/container.pb.h"

namespace scap_gvisor {
namespace parsers {

constexpr size_t prefix_len = sizeof("type.googleapis.com/") - 1;
constexpr size_t max_event_size = 300 * 1024;

typedef std::function<parse_result(const google::protobuf::Any &any, scap_sized_buffer scap_buf)> Callback;

std::map<std::string, Callback> dispatchers = {
};

struct parse_result parse_gvisor_proto(struct scap_const_sized_buffer gvisor_buf, struct scap_sized_buffer scap_buf)
{
	struct parse_result ret = {0};
	const char *buf = static_cast<const char*>(gvisor_buf.buf);

	// XXX this may change with a wire protocol update
	const header *hdr = reinterpret_cast<const header *>(buf);
	if(hdr->header_size > gvisor_buf.size)
	{
		ret.error = std::string("Header size (") + std::to_string(hdr->header_size) + ") is larger than message " + std::to_string(gvisor_buf.size);
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	const char *proto = &buf[hdr->header_size];
	ssize_t proto_size = gvisor_buf.size - hdr->header_size;

	google::protobuf::Any any;
	if(!any.ParseFromArray(proto, proto_size))
	{
		ret.error = std::string("Invalid protobuf message");
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	auto url = any.type_url();
	if(url.size() <= prefix_len)
	{
		ret.error = std::string("Invalid URL ") + url;
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	const std::string name = url.substr(prefix_len);

	Callback cb = dispatchers[name];
	if(cb == nullptr)
	{
		ret.error = std::string("No callback registered for ") + name;
		ret.status = SCAP_TIMEOUT;
		return ret;
	}

	return cb(any, scap_buf);
}

} // namespace parsers
} // namespace scap_gvisor