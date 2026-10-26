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
#include <json/json.h>

#include <libsinsp/sinsp.h>
#include <libsinsp/filter.h>
#include <libsinsp/filter_check_list.h>

#include <cstdio>
#include <map>

#include <sinsp_with_test_input.h>

using namespace std;

// Valid argument types for filter fields
static const set<string> VALID_ARGUMENT_TYPES = {"INDEX", "KEY"};

// Helper function to create comma-separated string from valid argument types
static string get_valid_argument_types_str() {
	string result;
	for(const auto& type : VALID_ARGUMENT_TYPES) {
		if(!result.empty()) {
			result += ", ";
		}
		result += type;
	}
	return result;
}

// Helper function to create synthetic field class for testing
static sinsp_filter_factory::filter_fieldclass_info create_test_field_class(
        const string& name,
        const string& desc = "Test field class for unit testing",
        const string& shortdesc = "Test fields") {
	sinsp_filter_factory::filter_fieldclass_info fc;
	fc.name = name;
	fc.desc = desc;
	fc.shortdesc = shortdesc;
	return fc;
}

// Helper function to add a field with comprehensive attribute control
static void add_test_field(sinsp_filter_factory::filter_fieldclass_info& fc,
                           const string& name,
                           const string& desc,
                           const string& data_type = "string",
                           bool is_list = false,
                           bool is_deprecated = false,
                           bool arg_index = false,
                           bool arg_key = false,
                           bool arg_required = false,
                           bool arg_allowed = false) {
	sinsp_filter_factory::filter_field_info field;
	field.name = name;
	field.desc = desc;
	field.data_type = data_type;

	// Add tags based on properties
	if(is_list) {
		field.tags.insert("EPF_IS_LIST");
	}
	if(is_deprecated) {
		field.tags.insert("DEPRECATED");
	}
	if(arg_required) {
		field.tags.insert("ARG_REQUIRED");
	}
	if(arg_allowed) {
		field.tags.insert("ARG_ALLOWED");
	}
	if(arg_index) {
		field.tags.insert("ARG_INDEX");
	}
	if(arg_key) {
		field.tags.insert("ARG_KEY");
	}

	fc.fields.push_back(field);
}

// Helper function to create a comprehensive test field class with all attribute types
// This is reusable across as_json, as_markdown, and as_string tests
static sinsp_filter_factory::filter_fieldclass_info create_comprehensive_test_fields(
        const string& class_name = "test") {
	auto fc = create_test_field_class(class_name,
	                                  "Comprehensive test field class",
	                                  "Test all attributes");

	// Basic fields with different data types
	add_test_field(fc, class_name + ".string_field", "String field", "string");
	add_test_field(fc, class_name + ".int_field", "Integer field", "int64");
	add_test_field(fc, class_name + ".bool_field", "Boolean field", "bool");

	// List field
	add_test_field(fc, class_name + ".list_field", "List field", "string", true);

	// Deprecated field
	add_test_field(fc, class_name + ".deprecated_field", "Deprecated field", "string", false, true);

	// Fields with different argument configurations
	add_test_field(fc, class_name + ".no_arg", "Field with no arguments", "string");

	add_test_field(fc,
	               class_name + ".index_required",
	               "Field with required INDEX argument",
	               "string",
	               false,
	               false,
	               true,
	               false,
	               true,
	               false);

	add_test_field(fc,
	               class_name + ".key_allowed",
	               "Field with optional KEY argument",
	               "string",
	               false,
	               false,
	               false,
	               true,
	               false,
	               true);

	add_test_field(fc,
	               class_name + ".both_args",
	               "Field with INDEX and KEY arguments",
	               "string",
	               false,
	               false,
	               true,
	               true,
	               true,
	               false);

	// Complex field with multiple attributes
	add_test_field(fc,
	               class_name + ".complex",
	               "Complex field with multiple attributes",
	               "string",
	               true,
	               false,
	               true,
	               true,
	               false,
	               true);

	return fc;
}

// Test get_argument_type() method
TEST(filter_fields_info, get_argument_type) {
	// Create synthetic field class with various argument types
	auto field_class = create_test_field_class("test");

	// Add field with no argument support
	add_test_field(field_class, "test.no_arg", "Field with no arguments", "string");

	// Add field with required INDEX argument
	add_test_field(field_class,
	               "test.index_arg",
	               "Field with INDEX argument",
	               "string",
	               false,
	               false,
	               true,
	               false,
	               true,
	               false);

	// Add field with optional KEY argument
	add_test_field(field_class,
	               "test.key_arg",
	               "Field with KEY argument",
	               "string",
	               false,
	               false,
	               false,
	               true,
	               false,
	               true);

	// Add field with both INDEX and KEY arguments (required)
	add_test_field(field_class,
	               "test.both_args",
	               "Field with INDEX and KEY arguments",
	               "string",
	               false,
	               false,
	               true,
	               true,
	               true,
	               false);

	// Find specific fields to test
	bool found_no_arg_field = false;
	bool found_index_arg_field = false;
	bool found_key_arg_field = false;
	bool found_both_args_field = false;

	for(const auto& field : field_class.fields) {
		auto arg_type = field.get_argument_type();

		// Test field with no argument support
		if(field.name == "test.no_arg") {
			EXPECT_EQ(arg_type, sinsp_filter_factory::ARG_TYPE_NONE);
			found_no_arg_field = true;
		}

		// Test field with INDEX argument
		if(field.name == "test.index_arg") {
			EXPECT_TRUE(arg_type & sinsp_filter_factory::ARG_TYPE_INDEX);
			found_index_arg_field = true;
		}

		// Test field with KEY argument
		if(field.name == "test.key_arg") {
			EXPECT_TRUE(arg_type & sinsp_filter_factory::ARG_TYPE_KEY);
			found_key_arg_field = true;
		}

		// Test field with both arguments
		if(field.name == "test.both_args") {
			EXPECT_TRUE(arg_type & sinsp_filter_factory::ARG_TYPE_INDEX);
			EXPECT_TRUE(arg_type & sinsp_filter_factory::ARG_TYPE_KEY);
			found_both_args_field = true;
		}

		// Verify the return value is one of the valid enum values
		EXPECT_TRUE(arg_type == sinsp_filter_factory::ARG_TYPE_NONE ||
		            (arg_type & sinsp_filter_factory::ARG_TYPE_INDEX) ||
		            (arg_type & sinsp_filter_factory::ARG_TYPE_KEY))
		        << "Field " << field.name << " returned invalid argument type: " << (int)arg_type;

		// Verify consistency: if a field doesn't expect args, type should be NONE
		if(field.is_expecting_arg() == sinsp_filter_factory::ARG_REQ_NONE) {
			EXPECT_EQ(arg_type, sinsp_filter_factory::ARG_TYPE_NONE)
			        << "Field " << field.name << " doesn't expect args but has non-NONE type";
		}
	}

	EXPECT_TRUE(found_no_arg_field) << "Should find field with no argument support";
	EXPECT_TRUE(found_index_arg_field) << "Should find field with INDEX argument";
	EXPECT_TRUE(found_key_arg_field) << "Should find field with KEY argument";
	EXPECT_TRUE(found_both_args_field) << "Should find field with both arguments";
}

// Test is_expecting_arg() method with synthetic fields
TEST(filter_fields_info, is_expecting_arg) {
	// Create synthetic field class with various argument configurations
	auto field_class = create_test_field_class("test");

	// Add field with required argument
	add_test_field(field_class,
	               "test.required",
	               "Field with required argument",
	               "string",
	               false,
	               false,
	               false,
	               false,
	               true,
	               false);

	// Add field with allowed (optional) argument
	add_test_field(field_class,
	               "test.allowed",
	               "Field with allowed argument",
	               "string",
	               false,
	               false,
	               false,
	               false,
	               false,
	               true);

	// Add field with no argument
	add_test_field(field_class,
	               "test.none",
	               "Field with no argument",
	               "string",
	               false,
	               false,
	               false,
	               false,
	               false,
	               false);

	// Verify each field reports correct argument requirement
	bool found_arg_required = false;
	bool found_arg_allowed = false;
	bool found_arg_none = false;

	for(const auto& field : field_class.fields) {
		auto arg_req = field.is_expecting_arg();

		if(field.name == "test.required") {
			EXPECT_EQ(arg_req, sinsp_filter_factory::ARG_REQ_REQUIRED);
			found_arg_required = true;
		} else if(field.name == "test.allowed") {
			EXPECT_EQ(arg_req, sinsp_filter_factory::ARG_REQ_ALLOWED);
			found_arg_allowed = true;
		} else if(field.name == "test.none") {
			EXPECT_EQ(arg_req, sinsp_filter_factory::ARG_REQ_NONE);
			found_arg_none = true;
		}
	}

	EXPECT_TRUE(found_arg_required) << "Should have tested field with required argument";
	EXPECT_TRUE(found_arg_allowed) << "Should have tested field with allowed argument";
	EXPECT_TRUE(found_arg_none) << "Should have tested field with no argument";
}

// Test as_json() method basic functionality
TEST(filter_fields_info, as_json_basic) {
	// Create a simple test field class
	auto field_class = create_test_field_class("test", "Simple test field class", "Basic test");

	// Add a few basic fields
	add_test_field(field_class, "test.field1", "First test field", "string");
	add_test_field(field_class, "test.field2", "Second test field", "int64");
	add_test_field(field_class, "test.field3", "Third test field", "bool");

	// Generate JSON
	string json_str = field_class.as_json();
	EXPECT_FALSE(json_str.empty());

	// Parse JSON
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	bool parse_success =
	        reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors);

	ASSERT_TRUE(parse_success) << "JSON parsing failed: " << errors;

	// Verify basic structure
	EXPECT_TRUE(root.isMember("name"));
	EXPECT_EQ(root["name"].asString(), "test");

	EXPECT_TRUE(root.isMember("fields"));
	EXPECT_TRUE(root["fields"].isArray());
	EXPECT_GT(root["fields"].size(), 0);

	// Verify field structure
	for(const auto& field : root["fields"]) {
		EXPECT_TRUE(field.isMember("name"));
		EXPECT_TRUE(field.isMember("type"));
		EXPECT_TRUE(field.isMember("desc"));
		EXPECT_TRUE(field.isMember("is_list"));
		EXPECT_TRUE(field.isMember("argument"));
	}
}

// Test as_json() with fields that have arguments - using synthetic fields
TEST(filter_fields_info, as_json_with_arguments) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	// Generate JSON
	string json_str = field_class.as_json();
	EXPECT_FALSE(json_str.empty());

	// Parse JSON
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	bool parse_success =
	        reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors);

	ASSERT_TRUE(parse_success) << "JSON parsing failed: " << errors;

	// Verify we find fields with arguments and typed arguments
	bool found_field_with_args = false;
	bool found_field_with_typed_args = false;

	for(const auto& field : root["fields"]) {
		if(!field["argument"].isNull()) {
			found_field_with_args = true;

			// Field should have an argument field with proper structure
			EXPECT_TRUE(field.isMember("argument"));

			// Check argument structure
			auto& argument = field["argument"];
			EXPECT_TRUE(argument.isMember("required"));
			EXPECT_TRUE(argument["required"].isBool());
			EXPECT_TRUE(argument.isMember("type"));
			EXPECT_TRUE(argument["type"].isArray());

			// Verify typed arguments (INDEX/KEY)
			if(argument["type"].size() > 0) {
				found_field_with_typed_args = true;

				// Verify type array contains only valid values
				for(const auto& type : argument["type"]) {
					EXPECT_TRUE(type.isString());
					string type_str = type.asString();
					EXPECT_TRUE(VALID_ARGUMENT_TYPES.count(type_str) > 0)
					        << "Field " << field["name"].asString()
					        << " has invalid argument type: " << type_str
					        << " (expected one of: " << get_valid_argument_types_str() << ")";
				}
			}
		}
	}

	EXPECT_TRUE(found_field_with_args)
	        << "Should find at least one field with arguments in JSON output";
	EXPECT_TRUE(found_field_with_typed_args)
	        << "Should find at least one field with typed arguments in JSON output";
}

// Test as_json() with comprehensive field attributes - using synthetic fields
TEST(filter_fields_info, as_json_comprehensive_attributes) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	// Generate JSON with deprecated fields included
	string json_str = field_class.as_json({}, true);
	EXPECT_FALSE(json_str.empty());

	// Parse JSON
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	bool parse_success =
	        reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors);

	ASSERT_TRUE(parse_success) << "JSON parsing failed: " << errors;

	// Verify comprehensive structure
	EXPECT_TRUE(root.isMember("name"));
	EXPECT_EQ(root["name"].asString(), "test");
	EXPECT_TRUE(root.isMember("fields"));
	EXPECT_TRUE(root["fields"].isArray());

	// Track what we've validated
	bool found_list_field = false;
	bool found_deprecated_field = false;
	set<string> data_types_seen;

	for(const auto& field : root["fields"]) {
		// All fields should have basic structure
		EXPECT_TRUE(field.isMember("name"));
		EXPECT_TRUE(field["name"].isString());
		EXPECT_TRUE(field.isMember("type"));
		EXPECT_TRUE(field["type"].isString());
		EXPECT_TRUE(field.isMember("desc"));
		EXPECT_TRUE(field["desc"].isString());
		EXPECT_TRUE(field.isMember("is_list"));
		EXPECT_TRUE(field["is_list"].isBool());
		EXPECT_TRUE(field.isMember("argument"));

		// Track data types
		data_types_seen.insert(field["type"].asString());

		// Check for list field
		if(field["name"].asString() == "test.list_field") {
			EXPECT_TRUE(field["is_list"].asBool());
			found_list_field = true;
		}

		// Check for deprecated field
		if(field["name"].asString() == "test.deprecated_field") {
			EXPECT_TRUE(field.isMember("is_deprecated"));
			EXPECT_TRUE(field["is_deprecated"].isBool());
			found_deprecated_field = true;
		}
	}

	EXPECT_TRUE(found_list_field) << "Should have found list field in JSON";
	EXPECT_TRUE(found_deprecated_field) << "Should have found deprecated field in JSON";
	EXPECT_GE(data_types_seen.size(), 2) << "Should have multiple data types";
}

// Test as_json() with fields that don't have arguments
TEST(filter_fields_info, as_json_without_arguments) {
	// Create test field class with fields that have no arguments
	auto field_class = create_test_field_class("test");

	// Add field with no arguments
	add_test_field(field_class, "test.no_arg", "Field without arguments", "string");
	add_test_field(field_class, "test.another_no_arg", "Another field without arguments", "int64");

	// Add field with arguments for comparison
	add_test_field(field_class,
	               "test.with_arg",
	               "Field with arguments",
	               "string",
	               false,
	               false,
	               true,
	               false,
	               false,
	               true);

	string json_str = field_class.as_json();

	// Parse JSON
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	bool parse_success =
	        reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors);

	ASSERT_TRUE(parse_success) << "JSON parsing failed: " << errors;

	// Verify all fields have valid structure and values
	for(const auto& field : root["fields"]) {
		EXPECT_TRUE(field.isMember("name"));
		EXPECT_TRUE(field["name"].isString());

		EXPECT_TRUE(field.isMember("type"));
		EXPECT_TRUE(field["type"].isString());

		EXPECT_TRUE(field.isMember("is_list"));
		EXPECT_TRUE(field["is_list"].isBool());

		EXPECT_TRUE(field.isMember("desc"));
		EXPECT_TRUE(field["desc"].isString());

		EXPECT_TRUE(field.isMember("argument"));

		// If argument is not null, verify its structure and valid values
		if(!field["argument"].isNull()) {
			EXPECT_TRUE(field["argument"].isObject())
			        << "Field " << field["name"].asString()
			        << " has non-null argument that is not an object";

			auto& arg = field["argument"];
			EXPECT_TRUE(arg.isMember("required"));
			EXPECT_TRUE(arg["required"].isBool()) << "Field " << field["name"].asString()
			                                      << " has argument.required that is not a boolean";

			EXPECT_TRUE(arg.isMember("type"));
			EXPECT_TRUE(arg["type"].isArray()) << "Field " << field["name"].asString()
			                                   << " has argument.type that is not an array";

			// Verify type array contains only valid values
			for(const auto& type : arg["type"]) {
				EXPECT_TRUE(type.isString()) << "Field " << field["name"].asString()
				                             << " has non-string value in argument.type array";

				string type_str = type.asString();
				EXPECT_TRUE(VALID_ARGUMENT_TYPES.count(type_str) > 0)
				        << "Field " << field["name"].asString()
				        << " has invalid argument type: " << type_str
				        << " (expected one of: " << get_valid_argument_types_str() << ")";
			}
		}
	}

	// Find field without arguments
	bool found_no_arg = false;
	for(const auto& field : root["fields"]) {
		if(field["name"].asString() == "test.no_arg") {
			found_no_arg = true;

			// Should have argument field set to null
			EXPECT_TRUE(field.isMember("argument"));
			EXPECT_TRUE(field["argument"].isNull());

			break;
		}
	}

	EXPECT_TRUE(found_no_arg) << "Should find field without arguments in JSON output";
}

// Test as_json() with event sources - using synthetic fields
TEST(filter_fields_info, as_json_with_event_sources) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	std::set<std::string> sources = {"syscall", "plugin"};
	string json_str = field_class.as_json(sources);

	// Parse JSON
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	bool parse_success =
	        reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors);

	ASSERT_TRUE(parse_success) << "JSON parsing failed: " << errors;

	// Verify event sources are included
	EXPECT_TRUE(root.isMember("event_sources"));
	EXPECT_TRUE(root["event_sources"].isArray());
	EXPECT_EQ(root["event_sources"].size(), 2);
}

// Test as_json() with deprecated fields
TEST(filter_fields_info, as_json_with_deprecated) {
	// Create test field class with deprecated and non-deprecated fields
	auto field_class = create_test_field_class("test");

	// Add non-deprecated field
	add_test_field(field_class, "test.active", "Active field", "string");

	// Add deprecated field
	add_test_field(field_class, "test.old", "Deprecated field", "string", false, true);

	// Generate JSON with deprecated indicator included
	string json_with_deprecated = field_class.as_json({}, true);

	// Generate JSON without deprecated indicator
	string json_without_deprecated = field_class.as_json({}, false);

	// Both should be valid
	EXPECT_FALSE(json_with_deprecated.empty());
	EXPECT_FALSE(json_without_deprecated.empty());

	// Parse JSON with deprecated indicator
	{
		Json::Value root;
		Json::CharReaderBuilder builder;
		std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
		std::string errors;
		bool parse_success =
		        reader->parse(json_with_deprecated.c_str(),
		                      json_with_deprecated.c_str() + json_with_deprecated.size(),
		                      &root,
		                      &errors);

		ASSERT_TRUE(parse_success) << "JSON parsing failed";

		// When including deprecated indicator, fields should have is_deprecated member
		for(const auto& field : root["fields"]) {
			EXPECT_TRUE(field.isMember("is_deprecated"));
		}

		// Should have both fields
		EXPECT_EQ(root["fields"].size(), 2);
	}

	// Parse JSON without deprecated indicator
	{
		Json::Value root;
		Json::CharReaderBuilder builder;
		std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
		std::string errors;
		bool parse_success =
		        reader->parse(json_without_deprecated.c_str(),
		                      json_without_deprecated.c_str() + json_without_deprecated.size(),
		                      &root,
		                      &errors);

		ASSERT_TRUE(parse_success) << "JSON parsing failed";

		// When not including deprecated indicator, fields should NOT have is_deprecated member
		for(const auto& field : root["fields"]) {
			EXPECT_FALSE(field.isMember("is_deprecated"));
		}

		// Should still have both fields (deprecated flag controls member presence, not filtering)
		EXPECT_EQ(root["fields"].size(), 2);
	}
}

// Test as_json() for various field types to ensure no crashes
TEST(filter_fields_info, as_json_all_fields) {
	// Create multiple test field classes with different configurations
	std::vector<sinsp_filter_factory::filter_fieldclass_info> field_classes;

	// Basic field class
	auto fc1 = create_test_field_class("basic");
	add_test_field(fc1, "basic.field1", "Basic field", "string");
	field_classes.push_back(fc1);

	// Field class with lists
	auto fc2 = create_test_field_class("lists");
	add_test_field(fc2, "lists.field1", "List field", "string", true);
	field_classes.push_back(fc2);

	// Field class with arguments
	auto fc3 = create_test_field_class("args");
	add_test_field(fc3,
	               "args.field1",
	               "Field with args",
	               "string",
	               false,
	               false,
	               true,
	               true,
	               false,
	               true);
	field_classes.push_back(fc3);

	// Field class with deprecated fields
	auto fc4 = create_test_field_class("deprecated");
	add_test_field(fc4, "deprecated.field1", "Deprecated field", "string", false, true);
	field_classes.push_back(fc4);

	// Test that all field classes can be serialized without crashing
	for(const auto& field_class : field_classes) {
		// Should not crash
		string json_str = field_class.as_json();

		// If not empty, should be valid JSON
		if(!json_str.empty()) {
			Json::Value root;
			Json::CharReaderBuilder builder;
			std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
			std::string errors;
			bool parse_success = reader->parse(json_str.c_str(),
			                                   json_str.c_str() + json_str.size(),
			                                   &root,
			                                   &errors);

			EXPECT_TRUE(parse_success)
			        << "JSON parsing failed for field class: " << field_class.name
			        << "\nErrors: " << errors;
		}
	}
}

// Test that fields correctly report is_list property
TEST(filter_fields_info, is_list_in_json) {
	// Create test field class with list and non-list fields
	auto field_class = create_test_field_class("test");

	// Add non-list field
	add_test_field(field_class, "test.single", "Single value field", "string");

	// Add list field
	add_test_field(field_class, "test.multiple", "Multiple value field", "string", true);

	string json_str = field_class.as_json();

	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	bool parse_success =
	        reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors);

	ASSERT_TRUE(parse_success);

	// Verify is_list is correctly reported
	bool found_list_field = false;
	bool found_non_list_field = false;

	for(const auto& field : root["fields"]) {
		if(field["name"].asString() == "test.multiple") {
			found_list_field = true;
			EXPECT_TRUE(field["is_list"].asBool());
		}
		if(field["name"].asString() == "test.single") {
			found_non_list_field = true;
			EXPECT_FALSE(field["is_list"].asBool());
		}
	}

	EXPECT_TRUE(found_list_field) << "Should find list field";
	EXPECT_TRUE(found_non_list_field) << "Should find non-list field";
}

// Helper to add a field with an explicit raw type and operator allowlist
static void add_typed_test_field(sinsp_filter_factory::filter_fieldclass_info& fc,
                                 const string& name,
                                 ppm_param_type type,
                                 bool is_list = false,
                                 uint32_t allowed_ops = 0,
                                 bool arg_index = false) {
	add_test_field(fc, name, name, param_type_to_string(type), is_list, false, arg_index);
	fc.fields.back().type = type;
	fc.fields.back().allowed_ops = allowed_ops;
}

static Json::Value parse_json(const string& json_str) {
	Json::Value root;
	Json::CharReaderBuilder builder;
	std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
	std::string errors;
	EXPECT_TRUE(reader->parse(json_str.c_str(), json_str.c_str() + json_str.size(), &root, &errors))
	        << errors;
	return root;
}

static set<string> json_strings(const Json::Value& arr) {
	set<string> res;
	for(const auto& v : arr) {
		res.insert(v.asString());
	}
	return res;
}

static Json::Value find_json_field(const Json::Value& root, const string& name) {
	for(const auto& field : root["fields"]) {
		if(field["name"].asString() == name) {
			return field;
		}
	}
	ADD_FAILURE() << "field not found: " << name;
	return Json::Value();
}

TEST(filter_fields_info, as_json_operators_omitted_by_default) {
	auto fc = create_test_field_class("test");
	add_typed_test_field(fc, "test.str", PT_CHARBUF);

	auto root = parse_json(fc.as_json());
	auto field = find_json_field(root, "test.str");
	EXPECT_FALSE(field.isMember("operators"));
	EXPECT_FALSE(field.isMember("modifier_operators"));
	EXPECT_FALSE(field.isMember("suppressed_operators"));
	EXPECT_FALSE(field.isMember("suppressed_modifier_operators"));
}

TEST(filter_fields_info, as_json_operators_by_type) {
	auto fc = create_test_field_class("test");
	add_typed_test_field(fc, "test.str", PT_CHARBUF);
	add_typed_test_field(fc, "test.num", PT_INT64);
	add_typed_test_field(fc, "test.bool", PT_BOOL);
	add_typed_test_field(fc, "test.ip", PT_IPV4ADDR);
	add_typed_test_field(fc, "test.buf", PT_BYTEBUF);
	add_typed_test_field(fc, "test.list", PT_CHARBUF, true);
	// an index argument does not change the operators of a list field
	add_typed_test_field(fc, "test.list_idx", PT_CHARBUF, true, 0, true);

	auto root = parse_json(fc.as_json({}, false, true));

	auto str = find_json_field(root, "test.str");
	auto str_ops = json_strings(str["operators"]);
	EXPECT_TRUE(str_ops.count("contains"));
	EXPECT_TRUE(str_ops.count("regex"));
	EXPECT_TRUE(str_ops.count("exists"));
	EXPECT_TRUE(json_strings(str["modifier_operators"]).count("contains"));
	EXPECT_FALSE(json_strings(str["modifier_operators"]).count("in"));
	EXPECT_FALSE(json_strings(str["modifier_operators"]).count("exists"));

	auto num_ops = json_strings(find_json_field(root, "test.num")["operators"]);
	EXPECT_TRUE(num_ops.count("<"));
	EXPECT_TRUE(num_ops.count("intersects"));
	EXPECT_FALSE(num_ops.count("contains"));
	EXPECT_TRUE(json_strings(find_json_field(root, "test.num")["modifier_operators"]).count("="));
	EXPECT_FALSE(json_strings(find_json_field(root, "test.num")["modifier_operators"])
	                     .count("contains"));

	auto bool_ops = json_strings(find_json_field(root, "test.bool")["operators"]);
	EXPECT_TRUE(bool_ops.count("="));
	EXPECT_FALSE(bool_ops.count("<"));

	auto ip = find_json_field(root, "test.ip");
	EXPECT_EQ(json_strings(ip["operators"]),
	          (set<string>{"=", "!=", "in", "exists", "intersects"}));
	EXPECT_EQ(json_strings(ip["modifier_operators"]), (set<string>{"=", "!="}));

	auto buf_ops = json_strings(find_json_field(root, "test.buf")["operators"]);
	EXPECT_TRUE(buf_ops.count("bcontains"));
	EXPECT_FALSE(buf_ops.count("regex"));

	for(const auto* name : {"test.list", "test.list_idx"}) {
		auto list = find_json_field(root, name);
		EXPECT_EQ(json_strings(list["operators"]), (set<string>{"in", "exists", "intersects"}))
		        << name;
		EXPECT_TRUE(list["modifier_operators"].empty()) << name;
	}
}

TEST(filter_fields_info, as_json_suppressed_operators) {
	auto fc = create_test_field_class("test");
	add_typed_test_field(fc,
	                     "test.restricted",
	                     PT_CHARBUF,
	                     false,
	                     cmpop_mask({CO_EQ, CO_NE, CO_IN, CO_EXISTS}));
	add_typed_test_field(fc, "test.free", PT_CHARBUF);

	auto root = parse_json(fc.as_json({}, false, true));

	auto restricted = find_json_field(root, "test.restricted");
	auto suppressed = json_strings(restricted["suppressed_operators"]);
	EXPECT_TRUE(suppressed.count("contains"));
	EXPECT_TRUE(suppressed.count("<"));
	EXPECT_FALSE(suppressed.count("="));
	EXPECT_FALSE(suppressed.count("in"));
	EXPECT_FALSE(suppressed.count("exists"));
	// suppressed operators are a subset of the supported ones
	auto ops = json_strings(restricted["operators"]);
	for(const auto& op : suppressed) {
		EXPECT_TRUE(ops.count(op)) << op;
	}
	// modifiers are never evaluated on restricted fields
	EXPECT_EQ(json_strings(restricted["suppressed_modifier_operators"]),
	          json_strings(restricted["modifier_operators"]));

	auto free_field = find_json_field(root, "test.free");
	EXPECT_FALSE(free_field.isMember("suppressed_operators"));
	EXPECT_FALSE(free_field.isMember("suppressed_modifier_operators"));
}

TEST(filter_fields_info, as_json_enforced_operators) {
	auto fc = create_test_field_class("test");
	add_typed_test_field(fc, "test.enforced", PT_UINT64);
	fc.fields.back().enforced_ops = cmpop_mask({CO_EQ});
	add_typed_test_field(fc, "test.free", PT_UINT64);

	auto root = parse_json(fc.as_json({}, false, true));

	// the field supports exactly the enforced operators: nothing is reported as suppressed
	auto enforced = find_json_field(root, "test.enforced");
	EXPECT_EQ(json_strings(enforced["operators"]), (set<string>{"="}));
	EXPECT_TRUE(enforced["modifier_operators"].empty());
	EXPECT_FALSE(enforced.isMember("suppressed_operators"));
	EXPECT_FALSE(enforced.isMember("suppressed_modifier_operators"));

	auto free_field = find_json_field(root, "test.free");
	EXPECT_TRUE(json_strings(free_field["operators"]).count("<"));
	EXPECT_FALSE(free_field["modifier_operators"].empty());
}

TEST(filter_fields_info, as_json_transformer_operators) {
	auto fc = create_test_field_class("test");
	add_typed_test_field(fc, "test.str", PT_CHARBUF);
	add_typed_test_field(fc, "test.num", PT_INT64);
	add_typed_test_field(fc, "test.list", PT_CHARBUF, true);
	add_typed_test_field(fc, "test.no_tr", PT_CHARBUF);
	fc.fields.back().tags.insert("EPF_NO_TRANSFORMER");

	auto root = parse_json(fc.as_json({}, false, true));

	// len() turns strings into numbers, string transformers keep the type
	auto str = find_json_field(root, "test.str");
	ASSERT_TRUE(str.isMember("transformers"));
	const auto& trs = str["transformers"];
	EXPECT_EQ(trs["len"]["type"].asString(), "UINT64");
	EXPECT_FALSE(trs["len"]["is_list"].asBool());
	EXPECT_TRUE(json_strings(trs["len"]["operators"]).count("<"));
	EXPECT_FALSE(json_strings(trs["len"]["operators"]).count("contains"));
	EXPECT_EQ(trs["tolower"]["type"].asString(), "CHARBUF");
	EXPECT_TRUE(json_strings(trs["tolower"]["operators"]).count("contains"));
	EXPECT_TRUE(json_strings(trs["tolower"]["modifier_operators"]).count("contains"));
	EXPECT_TRUE(trs.isMember("toupper"));
	EXPECT_TRUE(trs.isMember("basename"));
	EXPECT_TRUE(trs.isMember("b64"));
	// the internal storage transformer is never exposed
	EXPECT_FALSE(trs.isMember("storage"));

	// transformers that don't apply to the type are left out
	EXPECT_FALSE(find_json_field(root, "test.num").isMember("transformers"));

	// len() of a list is a number
	auto list = find_json_field(root, "test.list");
	EXPECT_EQ(list["transformers"]["len"]["type"].asString(), "UINT64");
	EXPECT_FALSE(list["transformers"]["len"]["is_list"].asBool());
	EXPECT_TRUE(json_strings(list["transformers"]["len"]["operators"]).count("<"));

	EXPECT_FALSE(find_json_field(root, "test.no_tr").isMember("transformers"));

	// omitted by default
	root = parse_json(fc.as_json());
	EXPECT_FALSE(find_json_field(root, "test.str").isMember("transformers"));
}

TEST(filter_fields_info, as_json_dynamic_type_operators) {
	auto fc = create_test_field_class("test");
	add_typed_test_field(fc, "test.dyn", PT_DYN);

	auto root = parse_json(fc.as_json({}, false, true));
	auto field = find_json_field(root, "test.dyn");
	EXPECT_TRUE(field["operators"].isNull());
	EXPECT_TRUE(field["modifier_operators"].isNull());
}

// How the real compiler treats restricted operators: rejected for evt.around (enforced), accepted
// but not evaluated for the fd fields with an advisory mask.
TEST(filter_fields_info, suppressed_operators_compiler_behavior) {
	sinsp inspector;
	sinsp_filter_check_list checks;
	auto factory = std::make_shared<sinsp_filter_factory>(&inspector, checks);
	auto compiles = [&](const string& filter) {
		try {
			sinsp_filter_compiler(factory, filter).compile();
			return true;
		} catch(const std::exception&) {
			return false;
		}
	};

	EXPECT_TRUE(compiles("evt.around[1000] = 1000"));
	EXPECT_FALSE(compiles("evt.around[1000] > 1000"));
	EXPECT_FALSE(compiles("evt.around[1000] in (1000, 2000)"));
	EXPECT_FALSE(compiles("evt.around[1000] exists"));
	EXPECT_FALSE(compiles("evt.around[1000] = anyof (1000, 2000)"));

	EXPECT_TRUE(compiles("fd.port intersects (80, 443)"));
	EXPECT_TRUE(compiles("fd.ip intersects (10.0.0.1)"));
}

// Appends an IPv4 address (network order) and a port (host order), as scap packs them
static void append_ipv4_endpoint(std::vector<uint8_t>& buf, const char* ip, uint16_t port) {
	unsigned int b[4] = {};
	ASSERT_EQ(sscanf(ip, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]), 4) << ip;
	for(const auto byte : b) {
		buf.push_back(static_cast<uint8_t>(byte));
	}
	const auto* port_bytes = reinterpret_cast<const uint8_t*>(&port);
	buf.insert(buf.end(), port_bytes, port_bytes + sizeof(port));
}

// An operator expression for a field, with the result it must have when the operator (or
// modifier) is really evaluated. When it is reported as suppressed, the expression must instead
// not match or fail (operators), or evaluate only the first value (modifiers).
struct op_case {
	std::string op;
	std::string filter;
	bool result_if_supported;
	bool result_if_ignored;  // only for modifiers
};

// Evaluates the filters of the fields with an advisory operator mask against a real event, so
// that the suppressed operators reported in the JSON can't drift from the compare functions.
TEST_F(sinsp_with_test_input, as_json_suppressed_operators_match_evaluation) {
	add_default_init_thread();
	open_inspector();
	auto* evt = generate_socket_exit_event();
	int64_t return_value = 0;

	// the connect tuple is built by hand since the test_utils socket helpers are not available
	// on every platform: scap family, then the address and port of the client and of the server
	std::vector<uint8_t> socktuple = {PPM_AF_INET};
	append_ipv4_endpoint(socktuple, "172.40.111.222", 54321);
	append_ipv4_endpoint(socktuple, "142.251.111.147", 443);
	std::vector<uint8_t> server_sockaddr = {PPM_AF_INET};
	append_ipv4_endpoint(server_sockaddr, "142.251.111.147", 443);
	evt = add_event_advance_ts(
	        increasing_ts(),
	        1,
	        PPME_SOCKET_CONNECT_X,
	        4,
	        return_value,
	        scap_const_sized_buffer{socktuple.data(), socktuple.size()},
	        sinsp_test_input::socket_params::default_fd,
	        scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});

	// Every case matches the event when the operator is evaluated (the port is 443, the server
	// address 142.251.111.147). Modifier cases are written so that evaluating only the first value
	// gives the opposite result.
	const std::vector<op_case> port_ops = {
	        {"=", "fd.%s = 443", true, false},
	        {"!=", "fd.%s != 80", true, false},
	        {"<", "fd.%s < 500", true, false},
	        {"<=", "fd.%s <= 443", true, false},
	        {">", "fd.%s > 100", true, false},
	        {">=", "fd.%s >= 443", true, false},
	        {"in", "fd.%s in (443)", true, false},
	        {"intersects", "fd.%s intersects (443)", true, false},
	        {"exists", "fd.%s exists", true, false},
	};
	const std::vector<op_case> port_mods = {
	        {"=", "fd.%s = anyof (80, 443)", true, false},
	        {"=", "fd.%s = oneof (80, 443)", true, false},
	        {"!=", "fd.%s != allof (80, 443)", false, true},
	};
	const std::vector<op_case> ip_ops = {
	        {"=", "fd.%s = 142.251.111.147", true, false},
	        {"!=", "fd.%s != 10.0.0.1", true, false},
	        {"in", "fd.%s in (142.251.111.147)", true, false},
	        {"intersects", "fd.%s intersects (142.251.111.147)", true, false},
	        {"exists", "fd.%s exists", true, false},
	};
	const std::vector<op_case> ip_mods = {
	        {"=", "fd.%s = anyof (10.0.0.1, 142.251.111.147)", true, false},
	        {"=", "fd.%s = oneof (10.0.0.1, 142.251.111.147)", true, false},
	        {"!=", "fd.%s != allof (10.0.0.1, 142.251.111.147)", false, true},
	};
	const std::vector<op_case> net_ops = {
	        {"=", "fd.%s = 142.0.0.0/4", true, false},
	        {"!=", "fd.%s != 10.0.0.0/8", true, false},
	        {"in", "fd.%s in (142.0.0.0/4)", true, false},
	        {"intersects", "fd.%s intersects (142.0.0.0/4)", true, false},
	        {"exists", "fd.%s exists", true, false},
	};
	const std::vector<op_case> net_mods = {
	        {"=", "fd.%s = anyof (10.0.0.0/8, 142.0.0.0/4)", true, false},
	        {"=", "fd.%s = oneof (10.0.0.0/8, 142.0.0.0/4)", true, false},
	        {"!=", "fd.%s != allof (10.0.0.0/8, 142.0.0.0/4)", false, true},
	};
	struct field_cases {
		std::string name;
		const std::vector<op_case>* ops;
		const std::vector<op_case>* mods;
	};
	const std::vector<field_cases> fields = {
	        {"fd.port", &port_ops, &port_mods},
	        {"fd.proto", &port_ops, &port_mods},
	        {"fd.ip", &ip_ops, &ip_mods},
	        {"fd.net", &net_ops, &net_mods},
	};

	sinsp_filter_factory factory(&m_inspector, m_default_filterlist);
	std::map<std::string, Json::Value> json_fields;
	for(const auto& fc : factory.get_fields()) {
		const auto json_str = fc.as_json({}, false, true);
		if(json_str.empty()) {
			continue;
		}
		const auto root = parse_json(json_str);
		for(const auto& f : root["fields"]) {
			json_fields[f["name"].asString()] = f;
		}
	}

	auto expr = [](std::string filter, const std::string& field) {
		return filter.replace(filter.find("%s"), 2, field.substr(3));
	};

	for(const auto& fcase : fields) {
		SCOPED_TRACE(fcase.name);
		ASSERT_TRUE(json_fields.count(fcase.name));
		const auto& field = json_fields[fcase.name];
		const auto suppressed = json_strings(field["suppressed_operators"]);
		const auto suppressed_mods = json_strings(field["suppressed_modifier_operators"]);
		const auto operators = json_strings(field["operators"]);
		// the cases must cover every operator of the field, so that a new one is noticed
		std::set<std::string> covered;
		for(const auto& c : *fcase.ops) {
			covered.insert(c.op);
			ASSERT_TRUE(operators.count(c.op)) << c.op;
			const auto filter = expr(c.filter, fcase.name);
			if(suppressed.count(c.op)) {
				// the field either never matches or fails when evaluating the operator
				bool matched = false;
				try {
					matched = eval_filter(evt, filter);
				} catch(const sinsp_exception&) {
				}
				EXPECT_FALSE(matched) << filter;
			} else {
				EXPECT_EQ(eval_filter(evt, filter), c.result_if_supported) << filter;
			}
		}
		EXPECT_EQ(covered, operators);

		// modifiers are never evaluated by fields with a mask: only the first value is compared
		ASSERT_FALSE(suppressed_mods.empty());
		for(const auto& c : *fcase.mods) {
			ASSERT_TRUE(suppressed_mods.count(c.op)) << c.op;
			EXPECT_EQ(eval_filter(evt, expr(c.filter, fcase.name)), c.result_if_ignored)
			        << expr(c.filter, fcase.name);
		}
	}
}

// Guards against the allowlists drifting from the type-based rules
TEST(filter_fields_info, as_json_operators_real_fields) {
	sinsp inspector;
	sinsp_filter_check_list checks;
	sinsp_filter_factory factory(&inspector, checks);

	bool found_domain_field = false;
	bool found_around = false;
	bool found_rawarg = false;
	bool found_proc_name = false;
	for(const auto& fc : factory.get_fields()) {
		for(const auto& fld : fc.fields) {
			if(fld.allowed_ops == 0) {
				continue;
			}
			for(uint8_t op = CO_EQ; op <= CO_REGEX; op++) {
				if(!cmpop_in_mask(fld.allowed_ops, static_cast<cmpop>(op))) {
					continue;
				}
				bool supported = false;
				for(const auto& cmp : flt_supported_cmpops(fld.type, fld.is_list())) {
					supported |= cmp.op == op;
				}
				EXPECT_TRUE(supported) << fld.name << " allows op " << std::to_string(op);
			}
		}

		// classes without any visible field serialize to an empty string
		const auto json_str = fc.as_json({}, false, true);
		if(json_str.empty()) {
			continue;
		}
		auto root = parse_json(json_str);
		if(root.isMember("fields")) {
			for(const auto& field : root["fields"]) {
				const auto name = field["name"].asString();
				if(name == "evt.around") {
					found_around = true;
					// enforced by the compiler, so it redefines the operators
					EXPECT_EQ(json_strings(field["operators"]), (set<string>{"="}));
					EXPECT_TRUE(field["modifier_operators"].empty());
					EXPECT_FALSE(field.isMember("suppressed_operators"));
				} else if(name == "evt.rawarg") {
					found_rawarg = true;
					EXPECT_TRUE(field["operators"].isNull());
				} else if(name == "proc.name") {
					found_proc_name = true;
					EXPECT_TRUE(field["transformers"].isMember("len"));
					EXPECT_FALSE(field.isMember("suppressed_operators"));
				} else if(name == "fd.cip.name" || name == "fd.sip.name" || name == "fd.lip.name" ||
				          name == "fd.rip.name") {
					EXPECT_FALSE(field.isMember("transformers")) << name;
				}
			}
			// string operators work on fd.*ip.name whenever a name is resolved, so nothing is
			// suppressed
			for(const auto* name : {"fd.cip.name", "fd.sip.name", "fd.lip.name", "fd.rip.name"}) {
				for(const auto& field : root["fields"]) {
					if(field["name"].asString() != name) {
						continue;
					}
					found_domain_field = true;
					EXPECT_FALSE(field.isMember("suppressed_operators")) << name;
					EXPECT_FALSE(field.isMember("suppressed_modifier_operators")) << name;
					EXPECT_TRUE(json_strings(field["operators"]).count("contains")) << name;
				}
			}
		}
	}
	EXPECT_TRUE(found_domain_field);
	EXPECT_TRUE(found_around);
	EXPECT_TRUE(found_rawarg);
	EXPECT_TRUE(found_proc_name);
}

// Test as_markdown() basic functionality - using synthetic fields
TEST(filter_fields_info, as_markdown_basic) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	// Generate markdown
	string markdown_str = field_class.as_markdown();
	EXPECT_FALSE(markdown_str.empty());

	// Verify basic markdown structure
	EXPECT_TRUE(markdown_str.find("## Field Class:") != string::npos)
	        << "Markdown should contain field class header";
	EXPECT_TRUE(markdown_str.find("test") != string::npos) << "Markdown should contain class name";
	EXPECT_TRUE(markdown_str.find("Name | Type | Description") != string::npos)
	        << "Markdown should contain table header";
	EXPECT_TRUE(markdown_str.find(":----|:-----|:-----------") != string::npos)
	        << "Markdown should contain table separator";

	// Should contain at least one field
	EXPECT_TRUE(markdown_str.find("`test.") != string::npos)
	        << "Markdown should contain at least one field with backticks";
}

// Test as_markdown() with event sources - using synthetic fields
TEST(filter_fields_info, as_markdown_with_event_sources) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	std::set<std::string> sources = {"syscall", "plugin"};
	string markdown_str = field_class.as_markdown(sources);

	// Verify event sources are included
	EXPECT_TRUE(markdown_str.find("Event Sources:") != string::npos);
	EXPECT_TRUE(markdown_str.find("syscall") != string::npos);
	EXPECT_TRUE(markdown_str.find("plugin") != string::npos);
}

// Test as_markdown() with deprecated fields
TEST(filter_fields_info, as_markdown_with_deprecated) {
	// Create test field class with deprecated and non-deprecated fields
	auto field_class = create_test_field_class("test");

	// Add non-deprecated field
	add_test_field(field_class, "test.active", "Active field", "string");

	// Add deprecated field
	add_test_field(field_class, "test.old", "Deprecated field", "string", false, true);

	// Generate markdown with deprecated indicator included
	string markdown_with_deprecated = field_class.as_markdown({}, true);

	// Generate markdown without deprecated indicator
	string markdown_without_deprecated = field_class.as_markdown({}, false);

	// Both should be valid
	EXPECT_FALSE(markdown_with_deprecated.empty());
	EXPECT_FALSE(markdown_without_deprecated.empty());

	// Both versions should contain all fields (deprecated flag controls indicator, not filtering)
	EXPECT_TRUE(markdown_with_deprecated.find("test.old") != string::npos)
	        << "Markdown with deprecated indicator should contain deprecated field";
	EXPECT_TRUE(markdown_without_deprecated.find("test.old") != string::npos)
	        << "Markdown without deprecated indicator should still contain deprecated field";

	// Both should contain the active field
	EXPECT_TRUE(markdown_with_deprecated.find("test.active") != string::npos);
	EXPECT_TRUE(markdown_without_deprecated.find("test.active") != string::npos);
}

// Test as_markdown() for various field types to ensure no crashes
TEST(filter_fields_info, as_markdown_all_fields) {
	// Create multiple test field classes with different configurations
	std::vector<sinsp_filter_factory::filter_fieldclass_info> field_classes;

	// Basic field class
	auto fc1 = create_test_field_class("basic");
	add_test_field(fc1, "basic.field1", "Basic field", "string");
	field_classes.push_back(fc1);

	// Field class with lists
	auto fc2 = create_test_field_class("lists");
	add_test_field(fc2, "lists.field1", "List field", "string", true);
	field_classes.push_back(fc2);

	// Field class with arguments
	auto fc3 = create_test_field_class("args");
	add_test_field(fc3,
	               "args.field1",
	               "Field with args",
	               "string",
	               false,
	               false,
	               true,
	               true,
	               false,
	               true);
	field_classes.push_back(fc3);

	// Field class with deprecated fields
	auto fc4 = create_test_field_class("deprecated");
	add_test_field(fc4, "deprecated.field1", "Deprecated field", "string", false, true);
	field_classes.push_back(fc4);

	// Test that all field classes can generate markdown without crashing
	for(const auto& field_class : field_classes) {
		// Should not crash
		string markdown_str = field_class.as_markdown();

		// If not empty, should contain basic markdown structure
		if(!markdown_str.empty()) {
			EXPECT_TRUE(markdown_str.find("## Field Class:") != string::npos ||
			            markdown_str.find("Field Class:") != string::npos)
			        << "Markdown should have a field class header for: " << field_class.name;
		}
	}
}

// Test as_string() basic functionality - using synthetic fields
TEST(filter_fields_info, as_string_basic) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	// Generate string representation (non-verbose)
	string str_output = field_class.as_string(false);
	EXPECT_FALSE(str_output.empty());

	// Verify basic string structure
	EXPECT_TRUE(str_output.find("Field Class:") != string::npos)
	        << "String output should contain 'Field Class:' label";
	EXPECT_TRUE(str_output.find("test") != string::npos)
	        << "String output should contain class name";
	EXPECT_TRUE(str_output.find("------") != string::npos)
	        << "String output should contain separator line";
}

// Test as_string() verbose vs non-verbose - using synthetic fields
TEST(filter_fields_info, as_string_verbose) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	// Generate both verbose and non-verbose
	string str_verbose = field_class.as_string(true);
	string str_non_verbose = field_class.as_string(false);

	EXPECT_FALSE(str_verbose.empty());
	EXPECT_FALSE(str_non_verbose.empty());

	// Both should contain the class name
	EXPECT_TRUE(str_verbose.find("test") != string::npos);
	EXPECT_TRUE(str_non_verbose.find("test") != string::npos);
}

// Test as_string() with event sources - using synthetic fields
TEST(filter_fields_info, as_string_with_event_sources) {
	// Use comprehensive test fields
	auto field_class = create_comprehensive_test_fields("test");

	std::set<std::string> sources = {"syscall", "plugin"};
	string str_output = field_class.as_string(false, sources);

	// Verify event sources are included
	EXPECT_TRUE(str_output.find("Event Sources:") != string::npos);
	EXPECT_TRUE(str_output.find("syscall") != string::npos);
	EXPECT_TRUE(str_output.find("plugin") != string::npos);
}

// Test as_string() with deprecated fields
TEST(filter_fields_info, as_string_with_deprecated) {
	// Create test field class with deprecated and non-deprecated fields
	auto field_class = create_test_field_class("test");

	// Add non-deprecated field
	add_test_field(field_class, "test.active", "Active field", "string");

	// Add deprecated field
	add_test_field(field_class, "test.old", "Deprecated field", "string", false, true);

	// Generate string with deprecated indicator included
	string str_with_deprecated = field_class.as_string(false, {}, true);

	// Generate string without deprecated indicator
	string str_without_deprecated = field_class.as_string(false, {}, false);

	// Both should be valid
	EXPECT_FALSE(str_with_deprecated.empty());
	EXPECT_FALSE(str_without_deprecated.empty());

	// Both versions should contain all fields (deprecated flag controls indicator, not filtering)
	EXPECT_TRUE(str_with_deprecated.find("test.old") != string::npos)
	        << "String with deprecated indicator should contain deprecated field";
	EXPECT_TRUE(str_without_deprecated.find("test.old") != string::npos)
	        << "String without deprecated indicator should still contain deprecated field";

	// Both should contain the active field
	EXPECT_TRUE(str_with_deprecated.find("test.active") != string::npos);
	EXPECT_TRUE(str_without_deprecated.find("test.active") != string::npos);
}

// Test as_string() for various field types to ensure no crashes
TEST(filter_fields_info, as_string_all_fields) {
	// Create multiple test field classes with different configurations
	std::vector<sinsp_filter_factory::filter_fieldclass_info> field_classes;

	// Basic field class
	auto fc1 = create_test_field_class("basic");
	add_test_field(fc1, "basic.field1", "Basic field", "string");
	field_classes.push_back(fc1);

	// Field class with lists
	auto fc2 = create_test_field_class("lists");
	add_test_field(fc2, "lists.field1", "List field", "string", true);
	field_classes.push_back(fc2);

	// Field class with arguments
	auto fc3 = create_test_field_class("args");
	add_test_field(fc3,
	               "args.field1",
	               "Field with args",
	               "string",
	               false,
	               false,
	               true,
	               true,
	               false,
	               true);
	field_classes.push_back(fc3);

	// Field class with deprecated fields
	auto fc4 = create_test_field_class("deprecated");
	add_test_field(fc4, "deprecated.field1", "Deprecated field", "string", false, true);
	field_classes.push_back(fc4);

	// Test that all field classes can generate string output without crashing
	for(const auto& field_class : field_classes) {
		// Should not crash
		string str_output = field_class.as_string(false);

		// If not empty, should contain basic structure
		if(!str_output.empty()) {
			EXPECT_TRUE(str_output.find("Field Class:") != string::npos)
			        << "String output should have a field class label for: " << field_class.name;
		}
	}
}
