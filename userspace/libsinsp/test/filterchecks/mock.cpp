// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <sinsp_with_test_input.h>
#include <gtest/gtest.h>
#include <test_utils.h>

#define RETURN_EXTRACT_VAR(x)                                                                                          \
	do                                                                                                             \
	{                                                                                                              \
		*len = sizeof((x));                                                                                    \
		return (uint8_t*)&(x);                                                                                 \
	} while(0)

#define RETURN_EXTRACT_STRING(x)                                                                                       \
	do                                                                                                             \
	{                                                                                                              \
		*len = (x).size();                                                                                     \
		return (uint8_t*)(x).c_str();                                                                          \
	} while(0)

static const filtercheck_field_info sinsp_filter_check_mock_fields[] = {
	{PT_INT64, EPF_NONE, PF_ID, "test.int64", "", ""},
	{PT_CHARBUF, EPF_NONE, PF_NA, "test.charbuf", "", ""},
	{PT_BYTEBUF, EPF_NONE, PF_NA, "test.bytebuf", "", ""},
	{PT_CHARBUF, EPF_IS_LIST | EPF_NO_TRANSFORMER, PF_NA, "test.list", "", ""},
	{PT_CHARBUF, EPF_IS_LIST, PF_NA, "test.another_list", "", ""},
	{PT_CHARBUF, EPF_NONE, PF_NA, "test.more_than_256", "", ""},
	{PT_CHARBUF, EPF_NONE, PF_NA, "test.base64", "", ""},
};

class sinsp_filter_check_mock : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_INT64 = 0,
		TYPE_CHARBUF,
		TYPE_BYTEBUF,
		TYPE_LIST,
		TYPE_ANOTHER_LIST,
		TYPE_MORE_THAN_256,
		TYPE_BASE64,
	};

	sinsp_filter_check_mock()
	{
		m_info.m_name = "test";
		m_info.m_desc = "";
		m_info.m_fields = sinsp_filter_check_mock_fields;
		m_info.m_nfields = sizeof(sinsp_filter_check_mock_fields) / sizeof(sinsp_filter_check_mock_fields[0]);
	}
	virtual ~sinsp_filter_check_mock() = default;

	std::unique_ptr<sinsp_filter_check> allocate_new() override
	{
		return std::make_unique<sinsp_filter_check_mock>();
	}

protected:
	bool extract(sinsp_evt* evt, OUT std::vector<extract_value_t>& values, bool sanitize_strings) override
	{
		static const char* list_value_1 = "value1";
		static const char* list_value_2 = "charbuf";

		values.clear();
		if(m_field_id == TYPE_LIST || m_field_id == TYPE_ANOTHER_LIST)
		{
			extract_value_t val1;
			val1.ptr = (uint8_t*)list_value_1;
			val1.len = strlen(list_value_1);

			extract_value_t val2;
			val2.ptr = (uint8_t*)list_value_2;
			val2.len = strlen(list_value_2);

			values.push_back(val1);
			values.push_back(val2);
			return true;
		}
		return sinsp_filter_check::extract(evt, values, sanitize_strings);
	}

	uint8_t* extract_single(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override
	{
		*len = 0;
		switch(m_field_id)
		{
		case TYPE_INT64:
			m_u64_val = 1;
			RETURN_EXTRACT_VAR(m_u64_val);
		case TYPE_CHARBUF:
			m_str_val = "charbuf";
			RETURN_EXTRACT_STRING(m_str_val);
		case TYPE_BYTEBUF:
			m_str_val = "bytebuf";
			RETURN_EXTRACT_STRING(m_str_val);
		case TYPE_MORE_THAN_256:
			m_str_val = std::string(257, 'a');
			RETURN_EXTRACT_STRING(m_str_val);
		case TYPE_BASE64:
			m_str_val = "Y2hhcmJ1Zg=="; // base64("charbuf")
			RETURN_EXTRACT_STRING(m_str_val);
		default:
			throw std::runtime_error("unknown field id: " + std::to_string(m_field_id));
			break;
		}
		return NULL;
	}

private:
	std::string m_str_val;
	uint64_t m_u64_val;
};

// Note the we create a filter check without values on purpose.
static std::unique_ptr<sinsp_filter_check> create_filtercheck_from_field(sinsp* inspector, std::string_view field,
									 enum cmpop op = CO_EQ)
{
	sinsp_filter_check_list filter_list;
	filter_list.add_filter_check(std::make_unique<sinsp_filter_check_mock>());
	sinsp_filter_factory factory(inspector, filter_list);
	auto check = factory.new_filtercheck(field);
	check->m_cmpop = op;
	check->m_boolop = BO_NONE;
	check->parse_field_name(field, true, true);
	return check;
}

static void add_filtercheck_value_vec(sinsp_filter_check* chk, const std::vector<std::string>& vec)
{
	for(size_t i = 0; i < vec.size(); i++)
	{
		chk->add_filter_value(vec[i].c_str(), vec[i].size(), i);
	}
}

TEST(mock_filtercheck_creation, simple_const_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.int64");
	add_filtercheck_value_vec(chk.get(), {"64"});
	ASSERT_EQ(chk->get_filter_values().size(), 1);
	ASSERT_FALSE(chk->has_filtercheck_value());
	ASSERT_FALSE(chk->get_filter_values().empty());
}

TEST(mock_filtercheck_creation, simple_const_list)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list");
	add_filtercheck_value_vec(chk.get(), {"2", "3"});
	ASSERT_EQ(chk->get_filter_values().size(), 2);
	ASSERT_FALSE(chk->has_filtercheck_value());
}

TEST(mock_filtercheck_creation, value_list_with_eq_operator)
{
	// note(jasondellaluce): we are adding more than one value on a field that doesn't
	// support it due to the `EQ` operator, as we don't allow a syntax like
	// `test.charbuf = (charbuf, not-charbuf)`. However, we should be protected
	// as:
	// - the filter parser does not allow a syntax like this to be accepted
	// - the filter comparisons should ignore any non-first value for operators like `=`
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	add_filtercheck_value_vec(chk.get(), {"charbuf", "not-charbuf"});
	ASSERT_EQ(chk->get_filter_values().size(), 2);
	ASSERT_FALSE(chk->has_filtercheck_value());
}

TEST(mock_filtercheck_creation, bytebuf_value_too_long)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.bytebuf");
	// For BYTEBUF values there is a limit on the len. (at max 256 chars)
	std::string long_string(257, 'a');
	ASSERT_THROW(add_filtercheck_value_vec(chk.get(), {long_string}), sinsp_exception);
}

TEST(mock_filtercheck_creation, charbuf_value_too_long)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	// For CHARBUF values (and others) there is a limit on the len. (at max 256 chars)
	std::string long_string(257, 'a');
	ASSERT_THROW(add_filtercheck_value_vec(chk.get(), {long_string}), sinsp_exception);
}

TEST(mock_filtercheck_creation, rhs_filter_with_same_type)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	auto rhs_chk = create_filtercheck_from_field(&insp, "test.more_than_256");
	ASSERT_NO_THROW(chk->add_filter_value(std::move(rhs_chk)));
	ASSERT_TRUE(chk->has_filtercheck_value());
}

TEST(mock_filtercheck_creation, rhs_filter_after_const_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	add_filtercheck_value_vec(chk.get(), {"test"});
	auto rhs_chk = create_filtercheck_from_field(&insp, "test.more_than_256");
	// we already have a const value associated with the filter check
	ASSERT_THROW(chk->add_filter_value(std::move(rhs_chk)), sinsp_exception);
}

TEST(mock_filtercheck_creation, const_value_after_rhs_filter)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	auto rhs_chk = create_filtercheck_from_field(&insp, "test.more_than_256");
	ASSERT_NO_THROW(chk->add_filter_value(std::move(rhs_chk)));
	ASSERT_THROW(add_filtercheck_value_vec(chk.get(), {"test"}), sinsp_exception);
}

TEST(mock_filtercheck_creation, more_than_one_rhs_filter)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	auto rhs_chk = create_filtercheck_from_field(&insp, "test.more_than_256");
	auto rhs_chk2 = create_filtercheck_from_field(&insp, "test.more_than_256");
	ASSERT_NO_THROW(chk->add_filter_value(std::move(rhs_chk)));
	ASSERT_THROW(chk->add_filter_value(std::move(rhs_chk2)), sinsp_exception);
}

TEST(mock_filtercheck_compare, single_value_CO_EQ_list)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf", CO_EQ);
	add_filtercheck_value_vec(chk.get(), {"charbuf", "not-charbuf"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, single_value_CO_EQ_rhs_filter_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf", CO_EQ);
	chk->add_filter_value(create_filtercheck_from_field(&insp, "test.base64"));
	ASSERT_FALSE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, single_value_CO_EQ_rhs_filter_list)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf", CO_EQ);
	ASSERT_THROW(chk->add_filter_value(create_filtercheck_from_field(&insp, "test.list")), sinsp_exception);
}

TEST(mock_filtercheck_compare, single_value_CO_IN_list)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf", CO_IN);
	add_filtercheck_value_vec(chk.get(), {"charbuf", "not-charbuf"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, single_value_CO_IN_rhs_filter_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf", CO_IN);
	chk->add_filter_value(create_filtercheck_from_field(&insp, "test.base64"));
	ASSERT_FALSE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, list_CO_EQ_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list", CO_EQ);
	add_filtercheck_value_vec(chk.get(), {"charbuf"});
	// CO_EQ should not be supported for lists
	ASSERT_THROW(chk->compare(nullptr), sinsp_exception);
}

TEST(mock_filtercheck_compare, list_CO_EQ_rhs_filter_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list", CO_EQ);
	ASSERT_THROW(chk->add_filter_value(create_filtercheck_from_field(&insp, "test.charbuf")), sinsp_exception);
}

TEST(mock_filtercheck_compare, list_CO_IN_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list", CO_IN);
	add_filtercheck_value_vec(chk.get(), {"value1"});
	ASSERT_FALSE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, list_CO_IN_rhs_filter_list)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list", CO_IN);
	chk->add_filter_value(create_filtercheck_from_field(&insp, "test.another_list"));
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, list_CO_INTERSECTS_value)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list", CO_INTERSECTS);
	add_filtercheck_value_vec(chk.get(), {"value1"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, list_CO_INTERSECTS_rhs_filter_list)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list", CO_INTERSECTS);
	chk->add_filter_value(create_filtercheck_from_field(&insp, "test.another_list"));
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_compare, rhs_filter_CO_PMATCH_not_supported)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf", CO_PMATCH);
	ASSERT_THROW(chk->add_filter_value(create_filtercheck_from_field(&insp, "test.charbuf")), sinsp_exception);
}

TEST(mock_filtercheck_compare, rhs_filter_EPF_NO_RHS_flag)
{
	sinsp insp;

	{
		// This case should be ok, no exceptions
		auto chk = create_filtercheck_from_field(&insp, "fd.cip");
		chk->add_filter_value(create_filtercheck_from_field(&insp, "fd.sip"));
	}

	{
		// "fd.ip" is not allowed to be used on the left since it has the `EPF_NO_RHS` flag.
		auto chk = create_filtercheck_from_field(&insp, "fd.ip");
		ASSERT_THROW(chk->add_filter_value(create_filtercheck_from_field(&insp, "fd.sip")), sinsp_exception);
	}

	{
		// "fd.ip" is not allowed to be used on the right since it has the `EPF_NO_RHS` flag.
		auto chk = create_filtercheck_from_field(&insp, "fd.sip");
		ASSERT_THROW(chk->add_filter_value(create_filtercheck_from_field(&insp, "fd.ip")), sinsp_exception);
	}
}

#if !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)
TEST_F(sinsp_with_test_input, check_some_fd_fields)
{
	add_default_init_thread();
	open_inspector();

	// Prepare the setup to extract something from the filter checks `fd.cip`.
	int64_t client_fd = 9;
	int64_t return_value = 0;

	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t)PPM_AF_INET6, (uint32_t)SOCK_DGRAM,
			     (uint32_t)0);
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

	sockaddr_in6 client = test_utils::fill_sockaddr_in6(DEFAULT_CLIENT_PORT, DEFAULT_IPV6_CLIENT_STRING);
	sockaddr_in6 server = test_utils::fill_sockaddr_in6(DEFAULT_SERVER_PORT, DEFAULT_IPV6_SERVER_STRING);
	std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));

	/* The connect enter event populates the destination ip and the destination port thanks to the `server_sockaddr`
	 */
	add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd,
			     scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});
	std::vector<uint8_t> socktuple =
		test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
	auto evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value,
					scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

	{
		// fd.cip will extract an ipv6 we cannot compare it with an ipv4, so we expect false
		auto chk = create_filtercheck_from_field(&m_inspector, "fd.cip");
		add_filtercheck_value_vec(chk.get(), {DEFAULT_IPV4_CLIENT_STRING});
		ASSERT_FALSE(chk->compare(evt));
	}

	{
		// this should match
		auto chk = create_filtercheck_from_field(&m_inspector, "fd.cip");
		add_filtercheck_value_vec(chk.get(), {DEFAULT_IPV6_CLIENT_STRING});
		ASSERT_TRUE(chk->compare(evt));
	}

	{
		// Server and client ip should be different
		auto chk = create_filtercheck_from_field(&m_inspector, "fd.cip");
		chk->add_filter_value(create_filtercheck_from_field(&m_inspector, "fd.sip"));
		ASSERT_FALSE(chk->compare(evt));
	}

	{
		// fd.types with const values
		ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(ipv6,file)");
		auto chk = create_filtercheck_from_field(&m_inspector, "fd.types", CO_IN);
		add_filtercheck_value_vec(chk.get(), {"file", "ipv6"});
		ASSERT_TRUE(chk->compare(evt));
	}

	{
		// fd.types with rhs filter check
		ASSERT_EQ(get_field_as_string(evt, "fd.types"), "(ipv6,file)");
		auto chk = create_filtercheck_from_field(&m_inspector, "fd.types", CO_IN);
		ASSERT_ANY_THROW(chk->add_filter_value(create_filtercheck_from_field(&m_inspector, "fd.types")));
	}
}
#endif // !defined(_WIN32) && !defined(__EMSCRIPTEN__) && !defined(__APPLE__)

/////////////////////
// TRANSFORMERS
/////////////////////

TEST(mock_filtercheck_transformers, to_string_method_with_transformers)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	ASSERT_TRUE(chk->has_transformers());
	ASSERT_EQ(std::string(chk->tostring(nullptr)), "CHARBUF");
}

TEST(mock_filtercheck_transformers, simple_compare_with_transformers)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	add_filtercheck_value_vec(chk.get(), {"CHARBUF"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_transformers, same_transformer_multiple_times)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	add_filtercheck_value_vec(chk.get(), {"CHARBUF"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_transformers, filter_with_not_supported_transformer)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.list");
	ASSERT_THROW(chk->add_transformer(filter_transformer_type::FTR_TOUPPER), sinsp_exception);
}

TEST(mock_filtercheck_transformers, specular_expression)
{
	sinsp insp;
	// we want to check this filter `toupper(test.charbuf) = toupper(test.charbuf)` returns `true`.
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);

	auto rhs_chk = create_filtercheck_from_field(&insp, "test.charbuf");
	rhs_chk->add_transformer(filter_transformer_type::FTR_TOUPPER);

	chk->add_filter_value(std::move(rhs_chk));
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_transformers, toupper_plus_tolower)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.charbuf");
	chk->add_transformer(filter_transformer_type::FTR_TOUPPER);
	chk->add_transformer(filter_transformer_type::FTR_TOLOWER);
	add_filtercheck_value_vec(chk.get(), {"charbuf"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_transformers, base64)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.base64");
	chk->add_transformer(filter_transformer_type::FTR_BASE64);
	ASSERT_EQ(std::string(chk->tostring(nullptr)), "charbuf");
	add_filtercheck_value_vec(chk.get(), {"charbuf"});
	ASSERT_TRUE(chk->compare(nullptr));
}

TEST(mock_filtercheck_transformers, reflect_base64)
{
	sinsp insp;
	auto chk = create_filtercheck_from_field(&insp, "test.base64");
	chk->add_transformer(filter_transformer_type::FTR_BASE64);

	auto rhs_chk = create_filtercheck_from_field(&insp, "test.base64");
	rhs_chk->add_transformer(filter_transformer_type::FTR_BASE64);

	chk->add_filter_value(std::move(rhs_chk));
	ASSERT_TRUE(chk->compare(nullptr));
}
