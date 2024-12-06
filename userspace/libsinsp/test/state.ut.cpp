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

#include <gtest/gtest.h>
#include <libsinsp/state/static_struct.h>
#include <libsinsp/state/dynamic_struct.h>
#include <libsinsp/state/table_registry.h>
#include <libsinsp/sinsp.h>

TEST(typeinfo, basic_tests) {
	struct some_unknown_type {};
	ASSERT_ANY_THROW(libsinsp::state::typeinfo::of<some_unknown_type>());
	ASSERT_EQ(libsinsp::state::typeinfo::of<std::string>().size(), sizeof(std::string));
	ASSERT_EQ(libsinsp::state::typeinfo::of<std::string>(),
	          libsinsp::state::typeinfo::of<std::string>());
}

TEST(static_struct, defs_and_access) {
	struct err_multidef_struct : public libsinsp::state::static_struct {
		libsinsp::state::static_struct::field_infos static_fields() const override {
			libsinsp::state::static_struct::field_infos ret;
			define_static_field(ret, this, m_num, "num");
			define_static_field(ret, this, m_num, "num");
			return ret;
		}

		uint32_t m_num{0};
	};

	class sample_struct : public libsinsp::state::static_struct {
	public:
		libsinsp::state::static_struct::field_infos static_fields() const override {
			libsinsp::state::static_struct::field_infos ret;
			define_static_field(ret, this, m_num, "num");
			define_static_field(ret, this, m_str, "str", true);
			return ret;
		}

		uint32_t get_num() const { return m_num; }
		void set_num(uint32_t v) { m_num = v; }
		const std::string& get_str() const { return m_str; }
		void set_str(const std::string& v) { m_str = v; }

	private:
		uint32_t m_num{0};
		std::string m_str;
	};

	struct sample_struct2 : public libsinsp::state::static_struct {
	public:
		libsinsp::state::static_struct::field_infos static_fields() const override {
			libsinsp::state::static_struct::field_infos ret;
			define_static_field(ret, this, m_num, "num");
			return ret;
		}

		uint32_t m_num{0};
	};

	// test errors
	ASSERT_ANY_THROW(err_multidef_struct().static_fields());

	sample_struct s;
	const auto& fields = s.static_fields();

	// check field definitions
	auto field_num = fields.find("num");
	auto field_str = fields.find("str");
	ASSERT_EQ(fields.size(), 2);
	ASSERT_EQ(fields, sample_struct().static_fields());

	ASSERT_NE(field_num, fields.end());
	ASSERT_EQ(field_num->second.name(), "num");
	ASSERT_EQ(field_num->second.readonly(), false);
	ASSERT_EQ(field_num->second.info(), libsinsp::state::typeinfo::of<uint32_t>());

	ASSERT_NE(field_str, fields.end());
	ASSERT_EQ(field_str->second.name(), "str");
	ASSERT_EQ(field_str->second.readonly(), true);
	ASSERT_EQ(field_str->second.info(), libsinsp::state::typeinfo::of<std::string>());

	// check field access
	auto acc_num = field_num->second.new_accessor<uint32_t>();
	auto acc_str = field_str->second.new_accessor<std::string>();
	ASSERT_ANY_THROW(field_num->second.new_accessor<uint64_t>());
	ASSERT_ANY_THROW(field_str->second.new_accessor<uint64_t>());

	ASSERT_EQ(s.get_num(), 0);
	ASSERT_EQ(s.get_static_field(acc_num), 0);
	s.set_num(5);
	ASSERT_EQ(s.get_num(), 5);
	uint32_t u32tmp = 0;
	s.get_static_field(acc_num, u32tmp);
	ASSERT_EQ(u32tmp, 5);
	s.set_static_field(acc_num, (uint32_t)6);
	ASSERT_EQ(s.get_num(), 6);
	ASSERT_EQ(s.get_static_field(acc_num), 6);

	std::string str = "";
	ASSERT_EQ(s.get_str(), str);
	ASSERT_EQ(s.get_static_field(acc_str), str);
	str = "hello";
	s.set_str("hello");
	ASSERT_EQ(s.get_str(), str);
	s.get_static_field(acc_str, str);
	ASSERT_EQ(str, "hello");
	ASSERT_ANY_THROW(s.set_static_field(acc_str, "hello"));  // readonly

	const char* cstr = "sample";
	s.set_str("");
	s.get_static_field(acc_str, cstr);
	ASSERT_EQ(strcmp(cstr, ""), 0);
	s.set_str("hello");
	s.get_static_field(acc_str, cstr);
	ASSERT_EQ(strcmp(cstr, "hello"), 0);
	ASSERT_EQ(cstr, s.get_str().c_str());
	ASSERT_ANY_THROW(s.set_static_field(acc_str, cstr));  // readonly

	// illegal access from an accessor created from different definition list
	// note: this should supposedly be checked for and throw an exception,
	// but for now we have no elegant way to do it efficiently.
	// todo(jasondellaluce): find a good way to check for this
	sample_struct2 s2;
	auto acc_num2 = s2.static_fields().find("num")->second.new_accessor<uint32_t>();
	ASSERT_NO_THROW(s.get_static_field(acc_num2));
}

TEST(dynamic_struct, defs_and_access) {
	auto fields = std::make_shared<libsinsp::state::dynamic_struct::field_infos>();

	struct sample_struct : public libsinsp::state::dynamic_struct {
	public:
		sample_struct(const std::shared_ptr<field_infos>& i): dynamic_struct(i) {}
	};

	// struct construction and setting fields definition
	sample_struct s(fields);
	ASSERT_ANY_THROW(s.set_dynamic_fields(nullptr));
	ASSERT_ANY_THROW(
	        s.set_dynamic_fields(std::make_shared<libsinsp::state::dynamic_struct::field_infos>()));
	// The double paranthesis fixes
	// Error C2063 'std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>' : not a function
	// C on the Windows compiler. This should be quirk of the Windows compiler.
	ASSERT_NO_THROW(
	        (sample_struct(std::shared_ptr<libsinsp::state::dynamic_struct::field_infos>())));
	ASSERT_NO_THROW(sample_struct(nullptr));
	auto s2 = sample_struct(nullptr);
	s2.set_dynamic_fields(fields);
	ASSERT_NO_THROW(s2.set_dynamic_fields(fields));

	// check field definitions
	ASSERT_EQ(fields->fields().size(), 0);
	ASSERT_EQ(fields, s.dynamic_fields());

	// adding new fields
	auto field_num = fields->add_field<uint64_t>("num");
	ASSERT_EQ(fields->fields().size(), 1);
	ASSERT_EQ(field_num, fields->fields().find("num")->second);
	ASSERT_EQ(field_num.name(), "num");
	ASSERT_EQ(field_num.info(), libsinsp::state::typeinfo::of<uint64_t>());
	ASSERT_EQ(field_num, fields->add_field<uint64_t>("num"));
	ASSERT_ANY_THROW(fields->add_field<uint32_t>("num"));

	auto field_str = fields->add_field<std::string>("str");
	ASSERT_EQ(fields->fields().size(), 2);
	ASSERT_EQ(field_str, fields->fields().find("str")->second);
	ASSERT_EQ(field_str.name(), "str");
	ASSERT_EQ(field_str.info(), libsinsp::state::typeinfo::of<std::string>());
	ASSERT_EQ(field_str, fields->add_field<std::string>("str"));
	ASSERT_ANY_THROW(fields->add_field<uint32_t>("str"));

	// check field access
	auto acc_num = field_num.new_accessor<uint64_t>();
	auto acc_str = field_str.new_accessor<std::string>();
	ASSERT_ANY_THROW(field_num.new_accessor<uint32_t>());
	ASSERT_ANY_THROW(field_str.new_accessor<uint32_t>());

	uint64_t tmp;
	s.get_dynamic_field(acc_num, tmp);
	ASSERT_EQ(tmp, 0);
	s.set_dynamic_field(acc_num, (uint64_t)6);
	s.get_dynamic_field(acc_num, tmp);
	ASSERT_EQ(tmp, 6);

	std::string tmpstr;
	s.get_dynamic_field(acc_str, tmpstr);
	ASSERT_EQ(tmpstr, std::string(""));
	s.set_dynamic_field(acc_str, std::string("hello"));
	s.get_dynamic_field(acc_str, tmpstr);
	ASSERT_EQ(tmpstr, std::string("hello"));

	s.set_dynamic_field(acc_str, std::string(""));
	const char* ctmpstr = "sample";
	s.get_dynamic_field(acc_str, ctmpstr);
	ASSERT_EQ(strcmp(ctmpstr, ""), 0);
	ctmpstr = "hello";
	s.set_dynamic_field(acc_str, ctmpstr);
	ctmpstr = "";
	s.get_dynamic_field(acc_str, ctmpstr);
	ASSERT_EQ(strcmp(ctmpstr, "hello"), 0);

	// illegal access from an accessor created from different definition list
	auto fields2 = std::make_shared<libsinsp::state::dynamic_struct::field_infos>();
	auto field_num2 = fields2->add_field<uint64_t>("num");
	auto acc_num2 = field_num2.new_accessor<uint64_t>();
	ASSERT_ANY_THROW(s.get_dynamic_field(acc_num2, tmp));
}

TEST(dynamic_struct, mem_ownership) {
	struct sample_struct : public libsinsp::state::dynamic_struct {
		sample_struct(const std::shared_ptr<field_infos>& i): dynamic_struct(i) {}
	};

	std::string tmpstr1, tmpstr2;
	auto defs1 = std::make_shared<libsinsp::state::dynamic_struct::field_infos>();

	// construct two entries, test safety checks
	sample_struct s1(nullptr);
	ASSERT_NO_THROW(s1.set_dynamic_fields(nullptr));
	ASSERT_NO_THROW(s1.set_dynamic_fields(defs1));
	sample_struct s2(defs1);
	ASSERT_ANY_THROW(s1.set_dynamic_fields(nullptr));
	ASSERT_NO_THROW(s1.set_dynamic_fields(defs1));
	ASSERT_ANY_THROW(s1.set_dynamic_fields(
	        std::make_shared<libsinsp::state::dynamic_struct::field_infos>()));

	// define a string dynamic field
	auto field_str = defs1->add_field<std::string>("str");
	auto field_str_acc = field_str.new_accessor<std::string>();

	// write same value in both structs, ensure they have two distinct copies
	s1.set_dynamic_field(field_str_acc, std::string("hello"));
	s1.get_dynamic_field(field_str_acc, tmpstr1);
	ASSERT_EQ(tmpstr1, std::string("hello"));
	s2.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_EQ(tmpstr2, std::string(""));  // s2 should not be influenced
	s2.set_dynamic_field(field_str_acc, std::string("hello2"));
	s2.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_EQ(tmpstr2, tmpstr1 + "2");
	s1.get_dynamic_field(field_str_acc, tmpstr1);  // s1 should not be influenced
	ASSERT_EQ(tmpstr2, tmpstr1 + "2");

	// deep copy and memory ownership (constructor)
	sample_struct s3(s1);
	ASSERT_EQ(s1.dynamic_fields().get(), s3.dynamic_fields().get());
	s1.get_dynamic_field(field_str_acc, tmpstr1);
	s3.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_EQ(tmpstr1, tmpstr2);
	s3.set_dynamic_field(field_str_acc, std::string("hello3"));
	s1.get_dynamic_field(field_str_acc, tmpstr1);  // should still be "hello" as before
	s3.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_NE(tmpstr1, tmpstr2);

	// deep copy and memory ownership (assignment)
	sample_struct s4(std::make_shared<libsinsp::state::dynamic_struct::field_infos>());
	s4 = s1;
	ASSERT_EQ(s1.dynamic_fields().get(), s4.dynamic_fields().get());
	s1.get_dynamic_field(field_str_acc, tmpstr1);
	s4.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_EQ(tmpstr1, tmpstr2);
	s4.set_dynamic_field(field_str_acc, std::string("hello4"));
	s1.get_dynamic_field(field_str_acc, tmpstr1);  // should still be "hello" as before
	s4.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_NE(tmpstr1, tmpstr2);

	// deep copy and memory ownership (assignment, null initial definitions)
	sample_struct s5(nullptr);
	s5 = s1;
	ASSERT_EQ(s1.dynamic_fields().get(), s5.dynamic_fields().get());
	s1.get_dynamic_field(field_str_acc, tmpstr1);
	s5.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_EQ(tmpstr1, tmpstr2);
	s5.set_dynamic_field(field_str_acc, std::string("hello4"));
	s1.get_dynamic_field(field_str_acc, tmpstr1);  // should still be "hello" as before
	s5.get_dynamic_field(field_str_acc, tmpstr2);
	ASSERT_NE(tmpstr1, tmpstr2);
}

TEST(table_registry, defs_and_access) {
	class sample_table : public libsinsp::state::table<uint64_t> {
	public:
		sample_table(): table("sample") {}

		size_t entries_count() const override { return m_entries.size(); }

		void clear_entries() override { m_entries.clear(); }

		std::unique_ptr<libsinsp::state::table_entry> new_entry() const override {
			return std::unique_ptr<libsinsp::state::table_entry>(
			        new libsinsp::state::table_entry(dynamic_fields()));
		}

		bool foreach_entry(std::function<bool(libsinsp::state::table_entry& e)> pred) override {
			for(const auto& e : m_entries) {
				if(!pred(*e.second)) {
					return false;
				}
			}
			return true;
		}

		std::shared_ptr<libsinsp::state::table_entry> get_entry(const uint64_t& key) override {
			const auto& it = m_entries.find(key);
			if(it == m_entries.end()) {
				return nullptr;
			}
			return it->second;
		}

		std::shared_ptr<libsinsp::state::table_entry> add_entry(
		        const uint64_t& key,
		        std::unique_ptr<libsinsp::state::table_entry> entry) override {
			m_entries[key] = std::move(entry);
			return m_entries[key];
		}

		bool erase_entry(const uint64_t& key) override { return m_entries.erase(key) != 0; }

	private:
		std::unordered_map<uint64_t, std::shared_ptr<libsinsp::state::table_entry>> m_entries;
	};

	libsinsp::state::table_registry r;
	ASSERT_EQ(r.tables().size(), 0);
	ASSERT_EQ(r.get_table<uint64_t>("sample"), nullptr);
	ASSERT_ANY_THROW(r.add_table<uint64_t>(nullptr));

	sample_table t;
	r.add_table(&t);
	ASSERT_EQ(r.tables().size(), 1);
	ASSERT_EQ(r.tables().find("sample")->second, &t);
	ASSERT_EQ(r.get_table<uint64_t>("sample"), &t);
	ASSERT_ANY_THROW(r.add_table(&t));             // double registration
	ASSERT_ANY_THROW(r.get_table<int>("sample"));  // bad key type
}

TEST(thread_manager, table_access) {
	// note: used for regression checks, keep this updated as we make
	// new fields available
	static const int s_threadinfo_static_fields_count = 32;

	sinsp inspector;
	auto table = static_cast<libsinsp::state::table<int64_t>*>(inspector.m_thread_manager.get());

	// empty table state and info
	ASSERT_EQ(table->name(), "threads");
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	ASSERT_EQ(*table->static_fields(), sinsp_threadinfo().static_fields());
	ASSERT_NE(table->dynamic_fields(), nullptr);
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 0);
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->get_entry(999), nullptr);
	ASSERT_EQ(table->erase_entry(999), false);

	// create and add a thread
	auto newt = table->new_entry();
	auto newtinfo = dynamic_cast<sinsp_threadinfo*>(newt.get());
	auto tid_acc = newt->static_fields().at("tid").new_accessor<int64_t>();
	auto comm_acc = newt->static_fields().at("comm").new_accessor<std::string>();
	auto fdtable_acc = newt->static_fields()
	                           .at("file_descriptors")
	                           .new_accessor<libsinsp::state::base_table*>();
	ASSERT_NE(newtinfo, nullptr);
	ASSERT_EQ(newt->dynamic_fields(), table->dynamic_fields());
	ASSERT_EQ(newt->static_fields(), *table->static_fields());
	ASSERT_EQ(newt->static_fields().size(), s_threadinfo_static_fields_count);
	newtinfo->m_tid = 999;
	newtinfo->m_comm = "test";
	ASSERT_EQ(newt->get_static_field(tid_acc), (int64_t)999);
	ASSERT_EQ(newt->get_static_field(comm_acc), "test");
	ASSERT_NE(newt->get_static_field(fdtable_acc), nullptr);
	ASSERT_EQ(newt->get_static_field(fdtable_acc)->name(), "file_descriptors");
	ASSERT_NO_THROW(table->add_entry(999, std::move(newt)));
	ASSERT_EQ(table->entries_count(), 1);
	auto addedt = table->get_entry(999);
	ASSERT_NE(addedt, nullptr);
	ASSERT_EQ(addedt->get_static_field(tid_acc), (int64_t)999);
	ASSERT_EQ(addedt->get_static_field(comm_acc), "test");
	ASSERT_NE(addedt->get_static_field(fdtable_acc), nullptr);
	ASSERT_EQ(addedt->get_static_field(fdtable_acc)->name(), "file_descriptors");

	// add a dynamic field to table
	std::string tmpstr;
	auto dynf_acc = table->dynamic_fields()
	                        ->add_field<std::string>("some_new_field")
	                        .new_accessor<std::string>();
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 1);
	ASSERT_EQ(addedt->dynamic_fields()->fields().size(), 1);
	addedt->get_dynamic_field(dynf_acc, tmpstr);
	ASSERT_EQ(tmpstr, "");
	addedt->set_dynamic_field(dynf_acc, std::string("hello"));
	addedt->get_dynamic_field(dynf_acc, tmpstr);
	ASSERT_EQ(tmpstr, "hello");

	// add another thread
	newt = table->new_entry();
	newt->set_static_field(tid_acc, (int64_t)1000);
	ASSERT_NO_THROW(table->add_entry(1000, std::move(newt)));
	addedt = table->get_entry(1000);
	ASSERT_EQ(addedt->get_static_field(tid_acc), (int64_t)1000);
	addedt->get_dynamic_field(dynf_acc, tmpstr);
	ASSERT_EQ(tmpstr, "");
	addedt->set_dynamic_field(dynf_acc, std::string("world"));
	addedt->get_dynamic_field(dynf_acc, tmpstr);
	ASSERT_EQ(tmpstr, "world");

	// loop over entries
	int count = 0;
	table->foreach_entry([&count, tid_acc](libsinsp::state::table_entry& e) {
		auto tid = e.get_static_field(tid_acc);
		if(tid == 999 || tid == 1000) {
			count++;
		}
		return true;
	});
	ASSERT_EQ(count, 2);

	// remove and clear entries
	ASSERT_EQ(table->entries_count(), 2);
	ASSERT_EQ(table->erase_entry(1000), true);
	ASSERT_EQ(table->entries_count(), 1);
	table->clear_entries();
	ASSERT_EQ(table->entries_count(), 0);
}

TEST(thread_manager, fdtable_access) {
	// note: used for regression checks, keep this updated as we make new fields available
	static const int s_fdinfo_static_fields_count = 32;

	sinsp inspector;
	auto& reg = inspector.get_table_registry();

	ASSERT_EQ(reg->tables().size(), 1);
	ASSERT_NE(reg->tables().find("threads"), reg->tables().end());

	auto table = reg->get_table<int64_t>("threads");
	ASSERT_EQ(table->name(), "threads");
	ASSERT_EQ(table->entries_count(), 0);
	ASSERT_EQ(table->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	ASSERT_EQ(table->dynamic_fields()->fields().size(), 0);

	auto field = table->static_fields()->find("file_descriptors");
	ASSERT_NE(field, table->static_fields()->end());
	ASSERT_EQ(field->second.readonly(), true);
	ASSERT_EQ(field->second.valid(), true);
	ASSERT_EQ(field->second.name(), "file_descriptors");
	ASSERT_EQ(field->second.info(), libsinsp::state::typeinfo::of<libsinsp::state::base_table*>());

	ASSERT_EQ(table->entries_count(), 0);

	// add two new entries to the thread table
	ASSERT_NE(table->add_entry(0, table->new_entry()), nullptr);
	auto entry = table->get_entry(0);
	ASSERT_NE(entry, nullptr);
	ASSERT_EQ(table->entries_count(), 1);

	ASSERT_NE(table->add_entry(1, table->new_entry()), nullptr);
	auto entry2 = table->get_entry(1);
	ASSERT_NE(entry2, nullptr);
	ASSERT_EQ(table->entries_count(), 2);

	// getting the fd tables from the newly created threads
	auto subtable_acc = field->second.new_accessor<libsinsp::state::base_table*>();
	auto subtable = dynamic_cast<sinsp_fdtable*>(entry->get_static_field(subtable_acc));
	auto subtable2 = dynamic_cast<sinsp_fdtable*>(entry2->get_static_field(subtable_acc));

	ASSERT_NE(subtable, nullptr);
	ASSERT_NE(subtable2, nullptr);

	ASSERT_EQ(subtable->name(), "file_descriptors");
	ASSERT_EQ(subtable->entries_count(), 0);
	ASSERT_EQ(subtable->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	ASSERT_EQ(subtable->static_fields()->size(), s_fdinfo_static_fields_count);
	ASSERT_EQ(subtable->dynamic_fields()->fields().size(), 0);

	// getting an existing field
	auto sfield = subtable->static_fields()->find("pid");
	ASSERT_NE(sfield, subtable->static_fields()->end());
	ASSERT_EQ(sfield->second.readonly(), false);
	ASSERT_EQ(sfield->second.valid(), true);
	ASSERT_EQ(sfield->second.name(), "pid");
	ASSERT_EQ(sfield->second.info(), libsinsp::state::typeinfo::of<int64_t>());

	// adding a new dynamic field
	const auto& dfield = subtable->dynamic_fields()->add_field<std::string>("str_val");
	ASSERT_EQ(dfield, subtable->dynamic_fields()->fields().find("str_val")->second);
	ASSERT_EQ(dfield.readonly(), false);
	ASSERT_EQ(dfield.valid(), true);
	ASSERT_EQ(dfield.index(), 0);
	ASSERT_EQ(dfield.name(), "str_val");
	ASSERT_EQ(dfield.info(), libsinsp::state::typeinfo::of<std::string>());

	// checking if the new field has been added
	ASSERT_EQ(subtable->dynamic_fields()->fields().size(), 1);
	ASSERT_NE(subtable->dynamic_fields()->fields().find("str_val"),
	          subtable->dynamic_fields()->fields().end());

	// checking if the new field has been added to the other subtable
	ASSERT_EQ(subtable2->dynamic_fields()->fields().size(), 1);
	ASSERT_NE(subtable2->dynamic_fields()->fields().find("str_val"),
	          subtable2->dynamic_fields()->fields().end());

	auto sfieldacc = sfield->second.new_accessor<int64_t>();
	auto dfieldacc = dfield.new_accessor<std::string>();

	// adding new entries to the subtable
	uint64_t max_iterations = 4096;  // note: configured max entries in fd tables
	for(uint64_t i = 0; i < max_iterations; i++) {
		ASSERT_EQ(subtable->entries_count(), i);

		// get non-existing entry
		ASSERT_EQ(subtable->get_entry(i), nullptr);

		// creating and adding a fd to the table
		auto t = subtable->add_entry(i, subtable->new_entry());
		ASSERT_NE(t, nullptr);
		ASSERT_NE(subtable->get_entry(i), nullptr);
		ASSERT_EQ(subtable->entries_count(), i + 1);

		// read and write from newly-created fd (existing field)
		int64_t tmp = -1;
		t->get_static_field(sfieldacc, tmp);
		ASSERT_EQ(tmp, 0);
		tmp = 5;
		t->set_static_field(sfieldacc, tmp);
		tmp = 0;
		t->get_static_field(sfieldacc, tmp);
		ASSERT_EQ(tmp, 5);

		// read and write from newly-created fd (added field)
		std::string tmpstr = "test";
		t->get_dynamic_field(dfieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "");
		tmpstr = "hello";
		t->set_dynamic_field(dfieldacc, tmpstr);
		tmpstr = "";
		t->get_dynamic_field(dfieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "hello");
	}

	// full iteration
	auto it = [&](libsinsp::state::table_entry& e) -> bool {
		int64_t tmp;
		std::string tmpstr;
		e.get_static_field(sfieldacc, tmp);
		EXPECT_EQ(tmp, 5);
		e.get_dynamic_field(dfieldacc, tmpstr);
		EXPECT_EQ(tmpstr, "hello");
		return true;
	};
	ASSERT_TRUE(subtable->foreach_entry(it));

	// iteration with break-out
	ASSERT_FALSE(subtable->foreach_entry(
	        [&](libsinsp::state::table_entry& e) -> bool { return false; }));

	// iteration with error
	ASSERT_ANY_THROW(subtable->foreach_entry(
	        [&](libsinsp::state::table_entry& e) -> bool { throw sinsp_exception("some error"); }));

	// erasing an unknown fd
	ASSERT_EQ(subtable->erase_entry(max_iterations), false);
	ASSERT_EQ(subtable->entries_count(), max_iterations);

	// erase one of the newly-created fd
	ASSERT_EQ(subtable->erase_entry(0), true);
	ASSERT_EQ(subtable->entries_count(), max_iterations - 1);

	// clear all
	ASSERT_NO_THROW(subtable->clear_entries());
	ASSERT_EQ(subtable->entries_count(), 0);
}

TEST(thread_manager, env_vars_access) {
	sinsp inspector;
	auto& reg = inspector.get_table_registry();

	ASSERT_EQ(reg->tables().size(), 1);
	ASSERT_NE(reg->tables().find("threads"), reg->tables().end());

	auto table = reg->get_table<int64_t>("threads");
	EXPECT_EQ(table->name(), "threads");
	EXPECT_EQ(table->entries_count(), 0);
	EXPECT_EQ(table->key_info(), libsinsp::state::typeinfo::of<int64_t>());
	EXPECT_EQ(table->dynamic_fields()->fields().size(), 0);

	auto field = table->static_fields()->find("env");
	ASSERT_NE(field, table->static_fields()->end());
	EXPECT_EQ(field->second.readonly(), true);
	EXPECT_EQ(field->second.valid(), true);
	EXPECT_EQ(field->second.name(), "env");
	EXPECT_EQ(field->second.info(), libsinsp::state::typeinfo::of<libsinsp::state::base_table*>());

	ASSERT_EQ(table->entries_count(), 0);

	// add two new entries to the thread table
	ASSERT_NE(table->add_entry(1, table->new_entry()), nullptr);
	auto entry = table->get_entry(1);
	ASSERT_NE(entry, nullptr);
	ASSERT_EQ(table->entries_count(), 1);

	// getting the fd tables from the newly created threads
	auto subtable_acc = field->second.new_accessor<libsinsp::state::base_table*>();
	auto subtable =
	        dynamic_cast<libsinsp::state::stl_container_table_adapter<std::vector<std::string>>*>(
	                entry->get_static_field(subtable_acc));
	ASSERT_NE(subtable, nullptr);
	EXPECT_EQ(subtable->name(), "env");
	EXPECT_EQ(subtable->entries_count(), 0);
	EXPECT_EQ(subtable->key_info(), libsinsp::state::typeinfo::of<uint64_t>());
	EXPECT_EQ(subtable->static_fields()->size(), 0);
	EXPECT_EQ(subtable->dynamic_fields()->fields().size(), 1);

	// getting an existing field
	auto sfield = subtable->dynamic_fields()->fields().find("value");
	ASSERT_NE(sfield, subtable->dynamic_fields()->fields().end());
	EXPECT_EQ(sfield->second.readonly(), false);
	EXPECT_EQ(sfield->second.valid(), true);
	EXPECT_EQ(sfield->second.name(), "value");
	EXPECT_EQ(sfield->second.info(), libsinsp::state::typeinfo::of<std::string>());

	auto fieldacc = sfield->second.new_accessor<std::string>();

	// adding new entries to the subtable
	uint64_t max_iterations = 10;
	for(uint64_t i = 0; i < max_iterations; i++) {
		ASSERT_EQ(subtable->entries_count(), i);

		// get non-existing entry
		ASSERT_EQ(subtable->get_entry(i), nullptr);

		// creating and adding a fd to the table
		auto t = subtable->add_entry(i, subtable->new_entry());
		ASSERT_NE(t, nullptr);
		ASSERT_NE(subtable->get_entry(i), nullptr);
		ASSERT_EQ(subtable->entries_count(), i + 1);

		// read and write from newly-created entry
		std::string tmpstr = "test";
		t->get_dynamic_field(fieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "");
		tmpstr = "hello";
		t->set_dynamic_field(fieldacc, tmpstr);
		tmpstr = "";
		t->get_dynamic_field(fieldacc, tmpstr);
		ASSERT_EQ(tmpstr, "hello");
	}

	// full iteration
	auto it = [&](libsinsp::state::table_entry& e) -> bool {
		std::string tmpstr = "test";
		e.get_dynamic_field(fieldacc, tmpstr);
		EXPECT_EQ(tmpstr, "hello");
		return true;
	};
	ASSERT_TRUE(subtable->foreach_entry(it));

	// iteration with break-out
	ASSERT_FALSE(subtable->foreach_entry(
	        [&](libsinsp::state::table_entry& e) -> bool { return false; }));

	// iteration with error
	ASSERT_ANY_THROW(subtable->foreach_entry(
	        [&](libsinsp::state::table_entry& e) -> bool { throw sinsp_exception("some error"); }));

	// erasing an unknown fd
	ASSERT_EQ(subtable->erase_entry(max_iterations), false);
	ASSERT_EQ(subtable->entries_count(), max_iterations);

	// erase one of the newly-created fd
	ASSERT_EQ(subtable->erase_entry(0), true);
	ASSERT_EQ(subtable->entries_count(), max_iterations - 1);

	// check that changes are reflected in thread's table
	auto tinfo = inspector.m_thread_manager->get_thread_ref(1);
	ASSERT_NE(tinfo, nullptr);

	ASSERT_EQ(tinfo->m_env.size(), max_iterations - 1);
	for(const auto& v : tinfo->m_env) {
		EXPECT_EQ(v, "hello");
	}

	// clear all
	ASSERT_NO_THROW(subtable->clear_entries());
	EXPECT_EQ(subtable->entries_count(), 0);
	EXPECT_EQ(tinfo->m_env.size(), 0);
}
