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
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <chrono>
#ifndef _WIN32
#include <getopt.h>
#endif  // _WIN32
#include <csignal>
#include <libsinsp/sinsp.h>
#include <libscap/scap_engines.h>
#include <functional>
#include <memory>
#include "util.h"
#include <libsinsp/filter/ppm_codes.h>
#include <libsinsp/state/table_registry.h>
#include <unordered_set>
#include <memory>
#include <thread>
#include <json/json.h>

#ifndef _WIN32
extern "C" {
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
}
#endif  // _WIN32

using namespace std;

#if __linux__
// Utility function to calculate CPU usage
int get_cpu_usage_percent();
#endif  // __linux__

// Functions used for dumping to stdout
void raw_dump(sinsp&, sinsp_evt* ev);
void formatted_dump(sinsp&, sinsp_evt* ev);

libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp& inspector);
std::function<void(sinsp&, sinsp_evt*)> dump = formatted_dump;
static bool g_interrupted = false;
static const uint8_t g_backoff_timeout_secs = 2;
static bool g_all_threads = false;
static bool ppm_sc_modifies_state = false;
static bool ppm_sc_repair_state = false;
static bool ppm_sc_state_remove_io_sc = false;
static bool enable_glogger = false;
static bool perftest = false;
static string table_mode = "";
static string engine_string;
static string filter_string = "";
static string file_path = "";
static string bpf_path = "";
static string gvisor_config_path = "/etc/docker/runsc_falco_config.json";
static unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
static uint16_t cpus_for_each_buffer = DEFAULT_CPU_FOR_EACH_BUFFER;
static bool all_cpus = false;
static uint64_t max_events = UINT64_MAX;
static std::shared_ptr<sinsp_plugin> plugin;
static std::string open_params;  // for source plugins, its open params
static std::unique_ptr<filter_check_list> filter_list;
static std::shared_ptr<sinsp_filter_factory> filter_factory;

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error);

const char* state_type_to_string(ss_plugin_state_type type) {
	switch(type) {
	case SS_PLUGIN_ST_INT8:
		return "int8";
	case SS_PLUGIN_ST_INT16:
		return "int16";
	case SS_PLUGIN_ST_INT32:
		return "int32";
	case SS_PLUGIN_ST_INT64:
		return "int64";
	case SS_PLUGIN_ST_UINT8:
		return "uint8";
	case SS_PLUGIN_ST_UINT16:
		return "uint16";
	case SS_PLUGIN_ST_UINT32:
		return "uint32";
	case SS_PLUGIN_ST_UINT64:
		return "uint64";
	case SS_PLUGIN_ST_STRING:
		return "string";
	case SS_PLUGIN_ST_TABLE:
		return "table";
	case SS_PLUGIN_ST_BOOL:
		return "bool";
	default:
		return "unknown";
	}
}

void print_all_tables(sinsp& inspector) {
	auto& reg = inspector.get_table_registry();
	const auto& tables = reg->tables();

	std::cout << "Available tables (" << tables.size() << "):\n\n";
	for(const auto& [table_name, table] : tables) {
		std::cout << "Table: " << table_name << "\n";
		std::cout << "  Key type: " << table->key_info().name() << std::endl;

		// Create a temporary owner to call list_fields
		libsinsp::state::sinsp_table_owner owner;
		uint32_t nfields = 0;
		const auto* fields = table->list_fields(&owner, &nfields);

		std::cout << "  Fields (" << nfields << "):" << std::endl;
		for(uint32_t i = 0; i < nfields; i++) {
			const auto& field = fields[i];
			std::cout << "    " << field.name
			          << " (type: " << state_type_to_string(field.field_type)
			          << ", read_only: " << (field.read_only ? "true" : "false") << ")"
			          << std::endl;
		}

		std::cout << std::endl;
	}
}

// Table iteration
struct table_iteration_state {
	const ss_plugin_table_fieldinfo* fields;
	uint32_t nfields;
	libsinsp::state::sinsp_table_owner* owner;
	libsinsp::state::base_table* table;
	std::vector<ss_plugin_table_field_t*>* field_accessors;
	Json::Value* table_obj;
	uint32_t n_items{0};
};

Json::Value serialize_table(const std::string& table_name, libsinsp::state::base_table* table);

ss_plugin_bool table_iterate_entries(void* s, ss_plugin_table_entry_t* entry) {
	auto* state = static_cast<table_iteration_state*>(s);

	Json::Value entry_obj;

	std::map<ss_plugin_state_type, std::function<void(Json::Value&, ss_plugin_state_data&)>>
	        type_to_json_converter = {
	                {SS_PLUGIN_ST_INT8,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = (int)field_data.s8;
	                 }},
	                {SS_PLUGIN_ST_INT16,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = field_data.s16;
	                 }},
	                {SS_PLUGIN_ST_INT32,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = field_data.s32;
	                 }},
	                {SS_PLUGIN_ST_INT64,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = (Json::Value::Int64)field_data.s64;
	                 }},
	                {SS_PLUGIN_ST_UINT8,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = (unsigned)field_data.u8;
	                 }},
	                {SS_PLUGIN_ST_UINT16,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = field_data.u16;
	                 }},
	                {SS_PLUGIN_ST_UINT32,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = field_data.u32;
	                 }},
	                {SS_PLUGIN_ST_UINT64,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = (Json::Value::UInt64)field_data.u64;
	                 }},
	                {SS_PLUGIN_ST_STRING,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = field_data.str ? field_data.str : "";
	                 }},
	                {SS_PLUGIN_ST_BOOL,
	                 [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 field = field_data.b;
	                 }},
	                {SS_PLUGIN_ST_TABLE, [](Json::Value& field, ss_plugin_state_data& field_data) {
		                 if(field_data.table != nullptr) {
			                 libsinsp::state::table_input_adapter subtable(field_data.table);
			                 field = serialize_table(subtable.name(),
			                                         (libsinsp::state::base_table*)&subtable);
		                 } else {
			                 field = "<error: table is null>";
		                 }
	                 }}};

	for(uint32_t i = 0; i < state->nfields; i++) {
		auto& field = entry_obj[state->fields[i].name];
		try {
			ss_plugin_state_data field_data;
			auto rc = state->table->read_entry_field(state->owner,
			                                         entry,
			                                         (*state->field_accessors)[i],
			                                         &field_data);
			if(rc == SS_PLUGIN_SUCCESS) {
				auto field_type = state->fields[i].field_type;
				if(auto it = type_to_json_converter.find(field_type);
				   it != type_to_json_converter.end()) {
					it->second(field, field_data);
				} else {
					std::string error{"<unsupported type: "};
					error += state_type_to_string(field_type);
					error += ">";
					field = error;
				}
			} else {
				field = "<error>";
			}
		} catch(const std::exception& e) {
			std::string error{"<error: "};
			error += e.what();
			error += ">";
			field = error;
		}
	}

	(*state->table_obj)["entries"].append(entry_obj);
	state->n_items++;
	// We're recycling `-n` option here
	return (state->n_items < max_events);
}

Json::Value serialize_table(const std::string& table_name, libsinsp::state::base_table* table) {
	Json::Value table_obj;
	table_obj["name"] = table_name;
	table_obj["entries"] = Json::Value(Json::arrayValue);

	// Create a temporary owner to call list_fields
	libsinsp::state::sinsp_table_owner owner;
	uint32_t nfields = 0;
	const auto* fields = table->list_fields(&owner, &nfields);

	std::vector<ss_plugin_table_field_t*> field_accessors;
	for(uint32_t i = 0; i < nfields; i++) {
		auto field_accessor = table->get_field(&owner, fields[i].name, fields[i].field_type);
		field_accessors.push_back(field_accessor);
	}

	table_iteration_state state{fields, nfields, &owner, table, &field_accessors, &table_obj};
	table->iterate_entries(&owner, &table_iterate_entries, &state);
	return table_obj;
}

void print_table_entries(sinsp& inspector) {
	auto& reg = inspector.get_table_registry();
	const auto& tables = reg->tables();

	Json::Value root;
	Json::Value tables_array(Json::arrayValue);

	for(const auto& [table_name, table] : tables) {
		tables_array.append(serialize_table(table_name, table));
	}

	root["tables"] = tables_array;
	Json::StreamWriterBuilder builder;
	builder["indentation"] = "  ";
	std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
	writer->write(root, &std::cout);
	std::cout << std::endl;
}

#define EVENT_HEADER                        \
	"%evt.num %evt.time cat=%evt.category " \
	"proc=%proc.name(%proc.pid.%thread.tid) "
#define EVENT_TRAILER "%evt.dir %evt.type %evt.args"

#define EVENT_DEFAULTS EVENT_HEADER EVENT_TRAILER
#define PROCESS_DEFAULTS \
	EVENT_HEADER "ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] " EVENT_TRAILER

#define PLUGIN_DEFAULTS "%evt.num %evt.time [%evt.pluginname] %evt.plugininfo"

#define JSON_PROCESS_DEFAULTS                                                     \
	"*%evt.num %evt.time %evt.category %proc.ppid %proc.pid %evt.type %proc.exe " \
	"%proc.cmdline %evt.args"

std::string default_output = EVENT_DEFAULTS;
std::string process_output = PROCESS_DEFAULTS;
std::string net_output = PROCESS_DEFAULTS " %fd.name";
std::string plugin_output = PLUGIN_DEFAULTS;

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> plugin_evt_formatter = nullptr;

static void sigint_handler(int signum) {
	g_interrupted = true;
}

static void usage() {
	string usage = R"(Usage: sinsp-example [options]

Overview: Goal of sinsp-example binary is to test and debug sinsp functionality and print events to STDOUT. All drivers are supported.

Options:
  -h, --help                                 Print this page.
  -f <filter>, --filter <filter>             Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields).
  -j, --json                                 Use JSON as the output format.
  -a, --all-threads                          Output information about all threads, not just the main one.
  -b <path>, --bpf <path>                    eBPF probe.
  -m, --modern_bpf                           Modern eBPF probe.
  -k, --kmod                                 Kernel module
  -G <config_path>, --gvisor <config_path>   Gvisor engine
  -s <path>, --scap_file <path>              Scap file
  -p <path>, --plugin <path>                 Plugin. Path can follow the pattern "filepath.so|init_cfg|open_params". Must come after the "-s" option when reading events from a file.
  -d <dim>, --buffer_dim <dim>               Dimension in bytes that every buffer will have.
  -c <num>, --cpus-for-each-buffer <num>     (modern eBPF probe only) Allocate a ring buffer every <num> CPU(s) (default: 1).
  -A, --all-cpus                             (modern eBPF probe only) Allocate ring buffers for all available CPUs (default: allocate ring buffers for online CPU(s) only).
  -o <fields>, --output-fields <fields>      Output fields string (see <filter> for supported display fields) that overwrites default output fields for all events. * at the beginning prints JSON keys with null values, else no null fields are printed.
  -E, --exclude-users                        Don't create the user/group tables
  -n, --num-events                           Number of events to be retrieved (no limit by default)
  -z, --ppm-sc-modifies-state                Select ppm sc codes from filter AST plus enforce sinsp state ppm sc codes via `sinsp_state_sc_set`, requires valid filter expression.
  -x, --ppm-sc-repair-state                  Select ppm sc codes from filter AST plus enforce sinsp state ppm sc codes via `sinsp_repair_state_sc_set`, requires valid filter expression.
  -q, --remove-io-sc-state                   Remove ppm sc codes belonging to `io_sc_set` from `sinsp_state_sc_set` sinsp state enforcement, defaults to false and only applies when choosing `-z` option, used for e2e testing of sinsp state.
  -g, --enable-glogger                       Enable libs g_logger, set to SEV_DEBUG. For a different severity adjust the test binary source and re-compile.
  -r, --raw                                  raw event ouput
  -t, --perftest                             Run in performance test mode
  -T, --tables                               -T or -Tbrief print tables descriptions. -Tlist print table entries, if -n is specified, print only the first n entries.
)";
	cout << usage << endl;
}

static void select_engine(const char* select) {
	if(!engine_string.empty()) {
		std::cerr << "While selecting " << select
		          << ": another engine was previously selected: " << engine_string << endl;
		exit(EXIT_FAILURE);
	}
	engine_string = select;
}

#ifndef _WIN32
// Parse CLI options.
void parse_CLI_options(sinsp& inspector, int argc, char** argv) {
	static struct option long_options[] = {
	        {"help", no_argument, nullptr, 'h'},
	        {"filter", required_argument, nullptr, 'f'},
	        {"json", no_argument, nullptr, 'j'},
	        {"all-threads", no_argument, nullptr, 'a'},
	        {"bpf", required_argument, nullptr, 'b'},
	        {"modern_bpf", no_argument, nullptr, 'm'},
	        {"kmod", no_argument, nullptr, 'k'},
	        {"scap_file", required_argument, nullptr, 's'},
	        {"plugin", required_argument, nullptr, 'p'},
	        {"buffer_dim", required_argument, nullptr, 'd'},
	        {"cpus-for-each-buffer", required_argument, nullptr, 'c'},
	        {"all-cpus", no_argument, nullptr, 'A'},
	        {"output-fields", required_argument, nullptr, 'o'},
	        {"exclude-users", no_argument, nullptr, 'E'},
	        {"num-events", required_argument, nullptr, 'n'},
	        {"ppm-sc-modifies-state", no_argument, nullptr, 'z'},
	        {"ppm-sc-repair-state", no_argument, nullptr, 'x'},
	        {"remove-io-sc-state", no_argument, nullptr, 'q'},
	        {"enable-glogger", no_argument, nullptr, 'g'},
	        {"raw", no_argument, nullptr, 'r'},
	        {"gvisor", optional_argument, nullptr, 'G'},
	        {"perftest", no_argument, nullptr, 't'},
	        {"tables", optional_argument, nullptr, 'T'},
	        {nullptr, 0, nullptr, 0}};

	bool format_set = false;
	int op;
	int long_index = 0;
	while((op = getopt_long(argc,
	                        argv,
	                        "hf:jab:mks:p:d:c:Ao:En:zxqgrtT::G::",
	                        long_options,
	                        &long_index)) != -1) {
		switch(op) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'f':
			filter_string = optarg;
			break;
		case 'j':
			dump = formatted_dump;
			if(!format_set) {
				default_output = DEFAULT_OUTPUT_STR;
				process_output = JSON_PROCESS_DEFAULTS;
				net_output = JSON_PROCESS_DEFAULTS " %fd.name";
				plugin_output = PLUGIN_DEFAULTS;
			}
			inspector.set_buffer_format(sinsp_evt::PF_JSON);
			break;
		case 'a':
			g_all_threads = true;
			break;
		case 'b':
			select_engine(BPF_ENGINE);
			bpf_path = optarg;
			break;
		case 'G':
			engine_string = GVISOR_ENGINE;
			if(optarg != nullptr) {
				gvisor_config_path = optarg;
			}
			break;
		case 'm':
			select_engine(MODERN_BPF_ENGINE);
			break;
		case 'k':
			select_engine(KMOD_ENGINE);
			break;
		case 's':
			select_engine(SAVEFILE_ENGINE);
			file_path = optarg;
			break;
		case 'p': {
			std::string pluginpath = optarg;
			size_t cpos = pluginpath.find('|');
			std::string init_config;
			// Extract init config from string if present
			if(cpos != std::string::npos) {
				init_config = pluginpath.substr(cpos + 1);
				pluginpath = pluginpath.substr(0, cpos);
			}
			cpos = init_config.find('|');
			if(cpos != std::string::npos) {
				open_params = init_config.substr(cpos + 1);
				init_config = init_config.substr(0, cpos);
			}
			plugin = inspector.register_plugin(pluginpath);
			if(std::string err; !plugin->init(init_config, err)) {
				std::cerr << "Error while initing plugin: " << err << std::endl;
				exit(EXIT_FAILURE);
			}
			if(plugin->caps() & CAP_SOURCING) {
				if(engine_string != SAVEFILE_ENGINE) {
					select_engine(SOURCE_PLUGIN_ENGINE);
				}
				filter_list->add_filter_check(inspector.new_generic_filtercheck());
			}
			if(plugin->caps() & CAP_EXTRACTION) {
				filter_list->add_filter_check(sinsp_plugin::new_filtercheck(plugin));
			}
			break;
		}
		case 'd':
			buffer_bytes_dim = strtoul(optarg, nullptr, 10);
			break;
		case 'c': {
			const auto value = strtoul(optarg, nullptr, 10);
			if(value > UINT16_MAX) {
				std::cerr << "The number of CPUs for each ring buffer cannot be greater than "
				          << UINT16_MAX << std::endl;
				exit(EXIT_FAILURE);
			}
			cpus_for_each_buffer = static_cast<uint16_t>(value);
			break;
		}
		case 'A':
			all_cpus = true;
			break;
		case 'o':
			default_output = optarg;
			process_output = optarg;
			net_output = optarg;
			plugin_output = optarg;
			format_set = true;
			break;
		case 'E':
			inspector.set_import_users(false);
			break;
		case 'n':
			max_events = std::atol(optarg);
			break;
		case 'z':
			ppm_sc_modifies_state = true;
			break;
		case 'x':
			ppm_sc_repair_state = true;
			break;
		case 'q':
			ppm_sc_state_remove_io_sc = true;
			break;
		case 'g':
			enable_glogger = true;
			break;
		case 'r':
			dump = raw_dump;
			break;
		case 't':
			perftest = true;
			break;
		case 'T':
			table_mode = optarg ? optarg : "brief";
			if(table_mode != "brief" && table_mode != "list") {
				std::cerr << "Invalid table mode: " << table_mode << ". Use 'brief' or 'list'."
				          << std::endl;
				exit(EXIT_FAILURE);
			}
			break;
		default:
			break;
		}
	}
}
#endif  // _WIN32

libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp& inspector) {
	auto ast = inspector.get_filter_ast();
	if(ast != nullptr) {
		return libsinsp::filter::ast::ppm_sc_codes(ast.get());
	}

	return {};
}

void open_engine(sinsp& inspector, libsinsp::events::set<ppm_sc_code> events_sc_codes) {
	std::cout << "-- Try to open: '" + engine_string + "' engine." << std::endl;
	libsinsp::events::set<ppm_sc_code>
	        ppm_sc;  // empty set activaes each available ppm sc in the kernel

	/* Select sc codes for active tracing in the kernel.
	 * Include all ppm sc codes from filter AST.
	 * Provide more e2e testing options.
	 * Demonstrate ppm sc API usage.
	 */
	if(ppm_sc_repair_state && !events_sc_codes.empty()) {
		ppm_sc = libsinsp::events::sinsp_repair_state_sc_set(events_sc_codes);
		if(!ppm_sc.empty()) {
			auto events_sc_names = libsinsp::events::sc_set_to_sc_names(ppm_sc);
			printf("-- Activated (%ld) ppm sc names in kernel using `sinsp_repair_state_sc_set` "
			       "enforcement: %s\n",
			       events_sc_names.size(),
			       concat_set_in_order(events_sc_names).c_str());
		}
	}

	if(ppm_sc_modifies_state && !events_sc_codes.empty()) {
		ppm_sc = libsinsp::events::sinsp_state_sc_set();
		if(ppm_sc_state_remove_io_sc) {
			/* Currently used for testing sinsp_state_sc_set() without I/O sc codes.
			 * Approach may change in the future. */
			ppm_sc = ppm_sc.diff(libsinsp::events::io_sc_set());
		}
		ppm_sc = ppm_sc.merge(events_sc_codes);
		if(!ppm_sc.empty()) {
			auto events_sc_names = libsinsp::events::sc_set_to_sc_names(ppm_sc);
			printf("-- Activated (%ld) ppm sc names in kernel using `sinsp_state_sc_set` "
			       "enforcement: %s\n",
			       events_sc_names.size(),
			       concat_set_in_order(events_sc_names).c_str());
		}
	}

	if(false) {
	}
#ifdef HAS_ENGINE_KMOD
	else if(!engine_string.compare(KMOD_ENGINE)) {
		inspector.open_kmod(buffer_bytes_dim, ppm_sc);
	}
#endif
#ifdef HAS_ENGINE_BPF
	else if(!engine_string.compare(BPF_ENGINE)) {
		if(bpf_path.empty()) {
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine"
			          << std::endl;
			exit(EXIT_FAILURE);
		} else {
			std::cerr << bpf_path << std::endl;
		}
		inspector.open_bpf(bpf_path.c_str(), buffer_bytes_dim, ppm_sc);
	}
#endif
#ifdef HAS_ENGINE_SAVEFILE
	else if(!engine_string.compare(SAVEFILE_ENGINE)) {
		if(file_path.empty()) {
			std::cerr << "You must specify the path to the file if you use the 'savefile' engine"
			          << std::endl;
			exit(EXIT_FAILURE);
		}
		inspector.open_savefile(file_path.c_str(), 0);
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	else if(!engine_string.compare(MODERN_BPF_ENGINE)) {
		inspector.open_modern_bpf(buffer_bytes_dim, cpus_for_each_buffer, !all_cpus, ppm_sc);
	}
#endif
#ifdef HAS_ENGINE_SOURCE_PLUGIN
	else if(!engine_string.compare(SOURCE_PLUGIN_ENGINE)) {
		inspector.open_plugin(plugin->name(),
		                      "",
		                      plugin->id() == 0 ? sinsp_plugin_platform::SINSP_PLATFORM_FULL
		                                        : sinsp_plugin_platform::SINSP_PLATFORM_HOSTINFO);
	}
#endif
#ifdef HAS_ENGINE_GVISOR
	else if(!engine_string.compare(GVISOR_ENGINE)) {
		inspector.open_gvisor(gvisor_config_path, "", false, -1);
	}
#endif
	else {
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "-- Engine '" + engine_string + "' correctly opened." << std::endl;
}

#ifdef __linux__
#define insmod(fd, opts, flags) syscall(__NR_finit_module, fd, opts, flags)
#define rmmod(name, flags) syscall(__NR_delete_module, name, flags)

static void remove_module() {
	if(rmmod("scap", 0) != 0) {
		cerr << "[ERROR] Failed to remove kernel module" << strerror(errno) << endl;
	}
}

static bool insert_module() {
	// Check if we are configured to run with the kernel module
	if(engine_string.compare(KMOD_ENGINE))
		return true;

	char* driver_path = getenv("KERNEL_MODULE");
	if(driver_path == nullptr || *driver_path == '\0') {
		// We don't have a path set, assuming the kernel module is already there
		return true;
	}

	int res;
	int fd = open(driver_path, O_RDONLY);
	if(fd < 0)
		goto error;

	res = insmod(fd, "", 0);
	if(res != 0)
		goto error;

	atexit(remove_module);
	close(fd);

	return true;

error:
	cerr << "[ERROR] Failed to insert kernel module: " << strerror(errno) << endl;

	if(fd > 0) {
		close(fd);
	}

	return false;
}
#endif  // __linux__

static std::string format_suggested_field(const filtercheck_field_info* info) {
	std::ostringstream out;

	// Replace "foo.bar" with "foo_bar"
	auto name = info->m_name;
	std::replace(name.begin(), name.end(), '.', '_');

	// foo_bar=%foo.bar
	out << name << "=%" << info->m_name;
	return out.str();
}

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or
//   evt.type=fork or evt.type=vfork))"
//
int main(int argc, char** argv) {
	sinsp inspector;

	filter_list.reset(new sinsp_filter_check_list());
	filter_factory.reset(new sinsp_filter_factory(&inspector, *filter_list.get()));

#ifndef _WIN32
	parse_CLI_options(inspector, argc, argv);
	if(engine_string.empty()) {
		// Default for backward compat
		select_engine(KMOD_ENGINE);
	}

#ifdef __linux__
	// Try inserting the kernel module
	bool res = insert_module();
	if(!res) {
		return -1;
	}
#endif  // __linux__

	signal(SIGPIPE, sigint_handler);
#endif  // _WIN32

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	if(enable_glogger) {
		std::cout << "-- Enabled g_logger.'" << std::endl;
		libsinsp_logger()->set_severity(sinsp_logger::SEV_DEBUG);
		libsinsp_logger()->add_stdout_log();
	}

	if(!filter_string.empty()) {
		try {
			sinsp_filter_compiler compiler(filter_factory, filter_string);
			std::unique_ptr<sinsp_filter> s = compiler.compile();
			inspector.set_filter(std::move(s), filter_string);
		} catch(const sinsp_exception& e) {
			cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
		}
	}

	auto events_sc_codes = extract_filter_sc_codes(inspector);
	if(!events_sc_codes.empty()) {
		auto events_sc_names = libsinsp::events::sc_set_to_sc_names(events_sc_codes);
		printf("-- Filter AST (%ld) ppm sc names: %s\n",
		       events_sc_codes.size(),
		       concat_set_in_order(events_sc_names).c_str());
	}

	std::vector<const filter_check_info*> fields;
	filter_list->get_all_fields(fields);
	for(const auto& fld : fields) {
		for(int i = 0; i < fld->m_nfields; i++) {
			const auto fldinfo = fld->m_fields[i];
			if(fldinfo.is_format_suggested()) {
				auto fmt = format_suggested_field(&fldinfo);
				default_output += " " + fmt;
				process_output += " " + fmt;
				net_output += " " + fmt;
				plugin_output += " " + fmt;
			}
		}
	}

	open_engine(inspector, events_sc_codes);

	if(table_mode == "brief") {
		print_all_tables(inspector);
		return 0;
	}
	if(table_mode == "list") {
		print_table_entries(inspector);
		return 0;
	}

	std::cout << "-- Start capture" << std::endl;
	double max_throughput = 0.0;

	inspector.start_capture();

	default_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, default_output, *filter_list.get());
	process_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, process_output, *filter_list.get());
	net_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, net_output, *filter_list.get());
	plugin_evt_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, plugin_output, *filter_list.get());

	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	uint64_t num_events = 0, last_events = 0;
	uint64_t last_ts_ns = 0;
	uint64_t cpu_total = 0;
	uint64_t num_samples = 0;
	while(!g_interrupted && num_events < max_events) {
		sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg) {
			cout << "[ERROR] " << error_msg << endl;
		});
		if(ev != nullptr) {
			uint64_t ts_ns = ev->get_ts();
			sinsp_threadinfo* thread = ev->get_thread_info();
			++num_events;
			uint64_t evt_diff = num_events - last_events;
			if(perftest) {
#if __linux__
				// Perftest mode does not print individual events but instead prints a running
				// throughput every second
				if(ts_ns - last_ts_ns > 1'000'000'000) {
					int cpu_usage = get_cpu_usage_percent();
					cpu_total += cpu_usage;
					++num_samples;
					long double curr_throughput = evt_diff / (long double)1000;
					std::cout << "Events: " << (num_events - last_events)
					          << " Events/ms: " << curr_throughput << " CPU: " << cpu_usage
					          << "%                      \r" << std::flush;
					if(curr_throughput > max_throughput) {
						max_throughput = curr_throughput;
					}
					last_ts_ns = ts_ns;
					last_events = num_events;
#else   // __linux__
				if(ts_ns - last_ts_ns > 1'000'000'000) {
					++num_samples;
					long double curr_throughput = evt_diff / (long double)1000;
					std::cout << "Events: " << (num_events - last_events)
					          << " Events/ms: " << curr_throughput << "                      \r"
					          << std::flush;
					if(curr_throughput > max_throughput) {
						max_throughput = curr_throughput;
					}
					last_ts_ns = ts_ns;
					last_events = num_events;
#endif  // __linux__
				}
			} else if(!thread || g_all_threads || thread->is_main_thread()) {
				dump(inspector, ev);
			}
		}
	}
	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	const auto duration =
	        std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();

	inspector.stop_capture();

	std::cout
	        << "-- Stop capture                                                                    "
	        << std::endl;
	std::cout << "Retrieved events: " << std::to_string(num_events) << std::endl;
	std::cout << "Time spent: " << duration << "ms" << std::endl;
	if(duration > 0) {
		std::cout << "Events/ms: " << num_events / (long double)duration << std::endl;
	}
	if(max_throughput > 0) {
		std::cout << "Max throughput observed: " << max_throughput << " events / ms" << std::endl;
	}
	if(num_samples > 0) {
		std::cout << "Average CPU usage: " << cpu_total / num_samples << "%" << std::endl;
	}

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error) {
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if(res == SCAP_SUCCESS) {
		return ev;
	}
	if(res == SCAP_EOF) {
		std::cout << "-- EOF" << std::endl;
		g_interrupted = true;
		return nullptr;
	}

	if(res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT) {
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
	}

	return nullptr;
}

void formatted_dump(sinsp&, sinsp_evt* ev) {
	std::string output;
	if(ev->get_category() == EC_PROCESS) {
		process_formatter->tostring(ev, output);
	} else if(ev->get_category() == EC_NET || ev->get_category() == EC_IO_READ ||
	          ev->get_category() == EC_IO_WRITE) {
		net_formatter->tostring(ev, output);
	} else if(ev->get_info()->category & EC_PLUGIN) {
		plugin_evt_formatter->tostring(ev, output);
	} else {
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}

static void hexdump(const unsigned char* buf, size_t len) {
	bool in_ascii = false;

	putc('[', stdout);
	for(size_t i = 0; i < len; ++i) {
		if(isprint(buf[i])) {
			if(!in_ascii) {
				in_ascii = true;
				if(i > 0) {
					putc(' ', stdout);
				}
				putc('"', stdout);
			}
			putc(buf[i], stdout);
		} else {
			if(in_ascii) {
				in_ascii = false;
				fputs("\" ", stdout);
			} else if(i > 0) {
				putc(' ', stdout);
			}
			printf("%02x", buf[i]);
		}
	}

	if(in_ascii) {
		putc('"', stdout);
	}
	putc(']', stdout);
}

void raw_dump(sinsp& inspector, sinsp_evt* ev) {
	string date_time;
	sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

	cout << "ts=" << date_time;
	cout << " tid=" << ev->get_tid();
	cout << " type=" << (ev->get_direction() == SCAP_ED_IN ? '>' : '<') << get_event_type_name(ev);
	cout << " category=" << get_event_category_name(ev->get_category());
	cout << " nparams=" << ev->get_num_params();

	for(size_t i = 0; i < ev->get_num_params(); ++i) {
		const sinsp_evt_param* p = ev->get_param(i);
		const struct ppm_param_info* pi = ev->get_param_info(i);
		cout << ' ' << i << ':' << pi->name << '=';
		hexdump((const unsigned char*)p->m_val, p->m_len);
	}

	cout << endl;
}
