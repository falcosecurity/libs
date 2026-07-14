// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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

#include <gtest/gtest.h>

#include <libsinsp/fdinfo.h>

// content_equals() is the predicate that decides whether two entries from
// different processes may become one shared entry, so a field it forgets to
// compare does not fail loudly: it merges two distinct fds and lets one process
// observe the other's state. These tests pin every field down by changing it
// one at a time and demanding that the answer flips.
namespace {

// An entry with every field content_equals() looks at set to something
// distinctive, so that zeroing or overwriting any one of them is a change.
sinsp_fdinfo make_fdinfo(const scap_fd_type type) {
	sinsp_fdinfo fdinfo;

	fdinfo.m_type = type;
	fdinfo.m_openflags = PPM_O_RDWR;
	fdinfo.m_flags = sinsp_fdinfo::FLAGS_FROM_PROC | sinsp_fdinfo::FLAGS_ROLE_CLIENT;
	fdinfo.m_dev = 0x0801;
	fdinfo.m_mount_id = 25;
	fdinfo.m_ino = 4711;
	fdinfo.m_pid = 1234;
	fdinfo.m_fd = 3;
	fdinfo.m_name = "the-name";
	fdinfo.m_name_raw = "the-raw-name";

	switch(type) {
	case SCAP_FD_IPV4_SOCK:
		fdinfo.m_sockinfo.m_ipv4info.m_fields = {0x0a000001, 0x0a000002, 4242, 80, 6};
		break;
	case SCAP_FD_IPV6_SOCK:
		fdinfo.m_sockinfo.m_ipv6info.m_fields = {ipv6addr("2001:db8::1"),
		                                         ipv6addr("2001:db8::2"),
		                                         4242,
		                                         80,
		                                         6};
		break;
	case SCAP_FD_UNIX_SOCK:
		fdinfo.m_sockinfo.m_unixinfo.m_fields = {0xdeadbeefUL, 0xcafebabeUL};
		break;
	case SCAP_FD_IPV4_SERVSOCK:
		fdinfo.m_sockinfo.m_ipv4serverinfo = {0x0a000001, 80, 6};
		break;
	case SCAP_FD_IPV6_SERVSOCK:
		fdinfo.m_sockinfo.m_ipv6serverinfo = {ipv6addr("2001:db8::1"), 80, 6};
		break;
	default:
		break;
	}

	return fdinfo;
}

// Expects that applying `mutate` to a copy of `base` makes the two differ, in
// both directions (the predicate is used symmetrically by the dedup pass).
template<typename Mutation>
void expect_differs(const sinsp_fdinfo& base, const char* what, Mutation mutate) {
	SCOPED_TRACE(what);

	sinsp_fdinfo other = base;
	ASSERT_TRUE(base.content_equals(other));

	mutate(other);
	EXPECT_FALSE(base.content_equals(other));
	EXPECT_FALSE(other.content_equals(base));
}

// An entry type carrying state of its own, like the ones event processors build
// through libsinsp::event_processor::build_fdinfo().
class extended_fdinfo : public sinsp_fdinfo {
public:
	std::unique_ptr<sinsp_fdinfo> clone() const override {
		auto ret = std::make_unique<extended_fdinfo>();
		ret->sinsp_fdinfo::operator=(*this);
		ret->m_extra = m_extra;
		return ret;
	}

	bool content_equals(const sinsp_fdinfo& other) const override {
		if(!sinsp_fdinfo::content_equals(other)) {
			return false;
		}
		const auto* typed = dynamic_cast<const extended_fdinfo*>(&other);
		return typed != nullptr && m_extra == typed->m_extra;
	}

	uint64_t m_extra = 0;
};

}  // namespace

TEST(fdinfo_content_equals, identical_entries_are_equal) {
	for(const auto type : {SCAP_FD_FILE_V2,
	                       SCAP_FD_DIRECTORY,
	                       SCAP_FD_IPV4_SOCK,
	                       SCAP_FD_IPV6_SOCK,
	                       SCAP_FD_UNIX_SOCK,
	                       SCAP_FD_IPV4_SERVSOCK,
	                       SCAP_FD_IPV6_SERVSOCK}) {
		SCOPED_TRACE(static_cast<int>(type));

		const auto a = make_fdinfo(type);
		const auto b = make_fdinfo(type);
		EXPECT_TRUE(a.content_equals(b));
		EXPECT_TRUE(b.content_equals(a));
	}
}

TEST(fdinfo_content_equals, every_common_field_counts) {
	const auto base = make_fdinfo(SCAP_FD_FILE_V2);

	expect_differs(base, "type", [](sinsp_fdinfo& f) { f.m_type = SCAP_FD_FIFO; });
	expect_differs(base, "openflags", [](sinsp_fdinfo& f) { f.m_openflags = PPM_O_RDONLY; });
	expect_differs(base, "flags", [](sinsp_fdinfo& f) { f.set_overlay_upper(); });
	expect_differs(base, "dev", [](sinsp_fdinfo& f) { f.m_dev = 0x0802; });
	expect_differs(base, "mount_id", [](sinsp_fdinfo& f) { f.m_mount_id = 26; });
	expect_differs(base, "ino", [](sinsp_fdinfo& f) { f.m_ino = 4712; });
	expect_differs(base, "pid", [](sinsp_fdinfo& f) { f.m_pid = 1235; });
	expect_differs(base, "fd", [](sinsp_fdinfo& f) { f.m_fd = 4; });
	expect_differs(base, "name", [](sinsp_fdinfo& f) { f.m_name = "another-name"; });
	expect_differs(base, "name_raw", [](sinsp_fdinfo& f) { f.m_name_raw = "another-raw-name"; });
}

TEST(fdinfo_content_equals, ipv4_tuple_counts) {
	const auto base = make_fdinfo(SCAP_FD_IPV4_SOCK);

	expect_differs(base, "sip", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4info.m_fields.m_sip = 0x0a000003;
	});
	expect_differs(base, "dip", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4info.m_fields.m_dip = 0x0a000004;
	});
	expect_differs(base, "sport", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4info.m_fields.m_sport = 4243;
	});
	expect_differs(base, "dport", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4info.m_fields.m_dport = 443;
	});
	expect_differs(base, "l4proto", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4info.m_fields.m_l4proto = 17;
	});
}

TEST(fdinfo_content_equals, ipv6_tuple_counts) {
	const auto base = make_fdinfo(SCAP_FD_IPV6_SOCK);

	expect_differs(base, "sip", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6info.m_fields.m_sip = ipv6addr("2001:db8::3");
	});
	expect_differs(base, "dip", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6info.m_fields.m_dip = ipv6addr("2001:db8::4");
	});
	expect_differs(base, "sport", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6info.m_fields.m_sport = 4243;
	});
	expect_differs(base, "dport", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6info.m_fields.m_dport = 443;
	});
	expect_differs(base, "l4proto", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6info.m_fields.m_l4proto = 17;
	});
}

TEST(fdinfo_content_equals, unix_tuple_counts) {
	const auto base = make_fdinfo(SCAP_FD_UNIX_SOCK);

	expect_differs(base, "source", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_unixinfo.m_fields.m_source = 0x1234;
	});
	expect_differs(base, "dest", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_unixinfo.m_fields.m_dest = 0x5678;
	});
}

TEST(fdinfo_content_equals, ipv4_server_info_counts) {
	const auto base = make_fdinfo(SCAP_FD_IPV4_SERVSOCK);

	expect_differs(base, "ip", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4serverinfo.m_ip = 0x0a000005;
	});
	expect_differs(base, "port", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4serverinfo.m_port = 443;
	});
	expect_differs(base, "l4proto", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv4serverinfo.m_l4proto = 17;
	});
}

TEST(fdinfo_content_equals, ipv6_server_info_counts) {
	const auto base = make_fdinfo(SCAP_FD_IPV6_SERVSOCK);

	expect_differs(base, "ip", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6serverinfo.m_ip = ipv6addr("2001:db8::5");
	});
	expect_differs(base, "port", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6serverinfo.m_port = 443;
	});
	expect_differs(base, "l4proto", [](sinsp_fdinfo& f) {
		f.m_sockinfo.m_ipv6serverinfo.m_l4proto = 17;
	});
}

// The socket state lives in a union, so only the member the type selects may be
// compared: an IPv4 socket must not be told apart by bytes belonging to the
// IPv6 tuple it does not have.
TEST(fdinfo_content_equals, only_the_selected_union_member_counts) {
	const auto base = make_fdinfo(SCAP_FD_IPV4_SOCK);

	sinsp_fdinfo other = base;
	other.m_sockinfo.m_ipv6info.m_fields.m_l4proto = 17;  // past the IPv4 tuple
	EXPECT_TRUE(base.content_equals(other));

	// ... and a non-socket entry ignores the union altogether.
	const auto file = make_fdinfo(SCAP_FD_FILE_V2);
	sinsp_fdinfo other_file = file;
	other_file.m_sockinfo.m_ipv4info.m_fields.m_sip = 0x0a000009;
	EXPECT_TRUE(file.content_equals(other_file));
}

// Two entries of a subclass that differ only in the subclass's own state are
// not interchangeable, which is why the predicate is virtual: a non-virtual one
// would compare the base fields, answer true, and let them be merged.
TEST(fdinfo_content_equals, subclass_state_counts) {
	extended_fdinfo a;
	a.sinsp_fdinfo::operator=(make_fdinfo(SCAP_FD_FILE_V2));
	extended_fdinfo b;
	b.sinsp_fdinfo::operator=(make_fdinfo(SCAP_FD_FILE_V2));

	const sinsp_fdinfo& base_a = a;
	const sinsp_fdinfo& base_b = b;
	EXPECT_TRUE(base_a.content_equals(base_b));

	b.m_extra = 1;
	EXPECT_FALSE(base_a.content_equals(base_b));
	EXPECT_FALSE(base_b.content_equals(base_a));

	// A base entry and a subclass entry are never the same thing either.
	const auto plain = make_fdinfo(SCAP_FD_FILE_V2);
	EXPECT_FALSE(base_b.content_equals(plain));
}
