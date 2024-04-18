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
#endif // _WIN32
#include <csignal>
#include <libsinsp/sinsp.h>
#include <libscap/scap_engines.h>
#include <functional>
#include <memory>
#include "util.h"
#include <libsinsp/filter/ppm_codes.h>
#include <unordered_set>
#include <memory>

#ifndef _WIN32
extern "C" {
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
}
#endif // _WIN32

using namespace std;


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
static string engine_string = KMOD_ENGINE; /* Default for backward compatibility. */
static string filter_string = "";
static string file_path = "";
static string bpf_path = "";
static unsigned long buffer_bytes_dim = DEFAULT_DRIVER_BUFFER_BYTES_DIM;
static uint64_t max_events = UINT64_MAX;
static sinsp_filter_check_list s_filterlist;

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error);

#define EVENT_HEADER "%evt.num %evt.time cat=%evt.category container=%container.id proc=%proc.name(%proc.pid.%thread.tid) "
#define EVENT_TRAILER "%evt.dir %evt.type %evt.args"

#define EVENT_DEFAULTS EVENT_HEADER EVENT_TRAILER
#define PROCESS_DEFAULTS EVENT_HEADER "ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] " EVENT_TRAILER

#define JSON_PROCESS_DEFAULTS "*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline %evt.args"

std::string default_output = EVENT_DEFAULTS;
std::string process_output = PROCESS_DEFAULTS;
std::string net_output = PROCESS_DEFAULTS " %fd.name";

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;

static void sigint_handler(int signum)
{
	g_interrupted = true;
}

static void usage()
{
	string usage = R"(Usage: sinsp-example [options]

Overview: Goal of sinsp-example binary is to test and debug sinsp functionality and print events to STDOUT. All drivers are supported.

Options:
  -h, --help                                 Print this page.
  -f <filter>, --filter <filter>             Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields).
  -j, --json                                 Use JSON as the output format.
  -a, --all-threads                          Output information about all threads, not just the main one.
  -b <path>, --bpf <path>                    BPF probe.
  -m, --modern_bpf                           modern BPF probe.
  -k, --kmod                                 Kernel module
  -s <path>, --scap_file <path>              Scap file
  -d <dim>, --buffer_dim <dim>               Dimension in bytes that every per-CPU buffer will have.
  -o <fields>, --output-fields <fields>      Output fields string (see <filter> for supported display fields) that overwrites default output fields for all events. * at the beginning prints JSON keys with null values, else no null fields are printed.
  -E, --exclude-users                        Don't create the user/group tables
  -n, --num-events                           Number of events to be retrieved (no limit by default)
  -z, --ppm-sc-modifies-state                Select ppm sc codes from filter AST plus enforce sinsp state ppm sc codes via `sinsp_state_sc_set`, requires valid filter expression.
  -x, --ppm-sc-repair-state                  Select ppm sc codes from filter AST plus enforce sinsp state ppm sc codes via `sinsp_repair_state_sc_set`, requires valid filter expression.
  -q, --remove-io-sc-state                   Remove ppm sc codes belonging to `io_sc_set` from `sinsp_state_sc_set` sinsp state enforcement, defaults to false and only applies when choosing `-z` option, used for e2e testing of sinsp state.
  -g, --enable-glogger                       Enable libs g_logger, set to SEV_DEBUG. For a different severity adjust the test binary source and re-compile.
  -r, --raw                                  raw event ouput
)";
	cout << usage << endl;
}

#ifndef _WIN32
// Parse CLI options.
void parse_CLI_options(sinsp& inspector, int argc, char** argv)
{
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"filter", required_argument, 0, 'f'},
		{"json", no_argument, 0, 'j'},
		{"all-threads", no_argument, 0, 'a'},
		{"bpf", required_argument, 0, 'b'},
		{"modern_bpf", no_argument, 0, 'm'},
		{"kmod", no_argument, 0, 'k'},
		{"scap_file", required_argument, 0, 's'},
		{"buffer_dim", required_argument, 0, 'd'},
		{"output-fields", required_argument, 0, 'o'},
		{"exclude-users", no_argument, 0, 'E'},
		{"num-events", required_argument, 0, 'n'},
		{"ppm-sc-modifies-state", no_argument, 0, 'z'},
		{"ppm-sc-repair-state", no_argument, 0, 'x'},
		{"remove-io-sc-state", no_argument, 0, 'q'},
		{"enable-glogger", no_argument, 0, 'g'},
		{"raw", no_argument, 0, 'r'},
		{0, 0, 0, 0}};

	bool format_set = false;
	int op;
	int long_index = 0;
	while((op = getopt_long(argc, argv,
				"hf:jab:mks:d:o:En:zxqgr",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'f':
			filter_string = optarg;
			break;
		case 'j':
			dump = formatted_dump;
			if(!format_set)
			{
				default_output = DEFAULT_OUTPUT_STR;
				process_output = JSON_PROCESS_DEFAULTS;
				net_output = JSON_PROCESS_DEFAULTS " %fd.name";
			}
			inspector.set_buffer_format(sinsp_evt::PF_JSON);
			break;
		case 'a':
			g_all_threads = true;
			break;
		case 'b':
			engine_string = BPF_ENGINE;
			bpf_path = optarg;
			break;
		case 'm':
			engine_string = MODERN_BPF_ENGINE;
			break;
		case 'k':
			engine_string = KMOD_ENGINE;
			break;
		case 's':
			engine_string = SAVEFILE_ENGINE;
			file_path = optarg;
			break;
		case 'd':
			buffer_bytes_dim = strtoul(optarg, NULL, 10);
			break;
		case 'o':
			default_output = optarg;
			process_output = optarg;
			net_output = optarg;
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
		default:
			break;
		}
	}
}
#endif // _WIN32

libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp& inspector)
{
	auto ast = inspector.get_filter_ast();
	if(ast != nullptr)
	{
		return libsinsp::filter::ast::ppm_sc_codes(ast.get());
	}

	return {};
}

void open_engine(sinsp& inspector, libsinsp::events::set<ppm_sc_code> events_sc_codes)
{
	std::cout << "-- Try to open: '" + engine_string + "' engine." << std::endl;
	libsinsp::events::set<ppm_sc_code> ppm_sc; // empty set activaes each available ppm sc in the kernel

	/* Select sc codes for active tracing in the kernel.
	 * Include all ppm sc codes from filter AST.
	 * Provide more e2e testing options.
	 * Demonstrate ppm sc API usage.
	 */
	if (ppm_sc_repair_state && !events_sc_codes.empty())
	{
		ppm_sc = libsinsp::events::sinsp_repair_state_sc_set(events_sc_codes);
		if (!ppm_sc.empty())
		{
			auto events_sc_names = libsinsp::events::sc_set_to_sc_names(ppm_sc);
			printf("-- Activated (%ld) ppm sc names in kernel using `sinsp_repair_state_sc_set` enforcement: %s\n", events_sc_names.size(), concat_set_in_order(events_sc_names).c_str());
		}
	}

	if (ppm_sc_modifies_state && !events_sc_codes.empty())
	{
		ppm_sc = libsinsp::events::sinsp_state_sc_set();
		if (ppm_sc_state_remove_io_sc)
		{
			/* Currently used for testing sinsp_state_sc_set() without I/O sc codes.
			 * Approach may change in the future. */
			ppm_sc = ppm_sc.diff(libsinsp::events::io_sc_set());

		}
		ppm_sc = ppm_sc.merge(events_sc_codes);
		if (!ppm_sc.empty())
		{
			auto events_sc_names = libsinsp::events::sc_set_to_sc_names(ppm_sc);
			printf("-- Activated (%ld) ppm sc names in kernel using `sinsp_state_sc_set` enforcement: %s\n", events_sc_names.size(), concat_set_in_order(events_sc_names).c_str());
		}
	}

	if(false)
	{

	}
#ifdef HAS_ENGINE_KMOD
	else if(!engine_string.compare(KMOD_ENGINE))
	{
		inspector.open_kmod(buffer_bytes_dim, ppm_sc);
	}
#endif
#ifdef HAS_ENGINE_BPF
	else if(!engine_string.compare(BPF_ENGINE))
	{
		if(bpf_path.empty())
		{
			std::cerr << "You must specify the path to the bpf probe if you use the 'bpf' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		else
		{
			std::cerr << bpf_path << std::endl;
		}
		inspector.open_bpf(bpf_path.c_str(), buffer_bytes_dim, ppm_sc);
	}
#endif
#ifdef HAS_ENGINE_SAVEFILE
	else if(!engine_string.compare(SAVEFILE_ENGINE))
	{
		if(file_path.empty())
		{
			std::cerr << "You must specify the path to the file if you use the 'savefile' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		inspector.open_savefile(file_path.c_str(), 0);
	}
#endif
#ifdef HAS_ENGINE_MODERN_BPF
	else if(!engine_string.compare(MODERN_BPF_ENGINE))
	{
		inspector.open_modern_bpf(buffer_bytes_dim, DEFAULT_CPU_FOR_EACH_BUFFER, true, ppm_sc);
	}
#endif
	else
	{
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "-- Engine '" + engine_string + "' correctly opened." << std::endl;
}

#ifdef __linux__
#define insmod(fd, opts, flags) syscall(__NR_finit_module, fd, opts, flags)
#define rmmod(name, flags) syscall(__NR_delete_module, name, flags)

static void remove_module()
{
	if (rmmod("scap", 0) != 0)
	{
		cerr << "[ERROR] Failed to remove kernel module" << strerror(errno) << endl;
	}
}

static bool insert_module()
{
	// Check if we are configured to run with the kernel module
	if(engine_string.compare(KMOD_ENGINE))
		return true;

	char *driver_path = getenv("KERNEL_MODULE");
	if (driver_path == NULL || *driver_path == '\0')
	{
		// We don't have a path set, assuming the kernel module is already there
		return true;
	}

	int res;
	int fd = open(driver_path, O_RDONLY);
	if (fd < 0)
		goto error;

	res = insmod(fd, "", 0);
	if (res != 0)
		goto error;

	atexit(remove_module);
	close(fd);

	return true;

error:
	cerr << "[ERROR] Failed to insert kernel module: " << strerror(errno) << endl;

	if (fd > 0)
	{
		close(fd);
	}

	return false;
}
#endif // __linux__

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
//
int main(int argc, char** argv)
{
	sinsp inspector;

#ifndef _WIN32
	parse_CLI_options(inspector, argc, argv);

#ifdef __linux__
	// Try inserting the kernel module
	bool res = insert_module();
	if (!res)
	{
		return -1;
	}
#endif // __linux__

	signal(SIGPIPE, sigint_handler);
#endif // _WIN32

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	if (enable_glogger)
	{
		std::cout << "-- Enabled g_logger.'" << std::endl;
		libsinsp_logger()->set_severity(sinsp_logger::SEV_DEBUG);
		libsinsp_logger()->add_stdout_log();
	}

	if(!filter_string.empty())
	{
		try
		{
			inspector.set_filter(filter_string);
		}
		catch(const sinsp_exception& e)
		{
			cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
		}
	}

	auto events_sc_codes = extract_filter_sc_codes(inspector);
	if(!events_sc_codes.empty())
	{
		auto events_sc_names = libsinsp::events::sc_set_to_sc_names(events_sc_codes);
		printf("-- Filter AST (%ld) ppm sc names: %s\n", events_sc_codes.size(), concat_set_in_order(events_sc_names).c_str());
	}

	open_engine(inspector, events_sc_codes);

	std::cout << "-- Start capture" << std::endl;

	inspector.start_capture();

	default_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, default_output, s_filterlist);
	process_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, process_output, s_filterlist);
	net_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, net_output, s_filterlist);

	std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
	uint64_t num_events = 0;
	while(!g_interrupted && num_events < max_events)
	{
		sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
					  { cout << "[ERROR] " << error_msg << endl; });
		if(ev != nullptr)
		{
			sinsp_threadinfo* thread = ev->get_thread_info();
			if(!thread || g_all_threads || thread->is_main_thread())
			{
				dump(inspector, ev);
				num_events++;
			}
		}
	}
	std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
	const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();

	inspector.stop_capture();

	std::cout << "-- Stop capture" << std::endl;
	std::cout << "Retrieved events: " << std::to_string(num_events) << std::endl;
	std::cout << "Time spent: " << duration << "ms" << std::endl;
	if (duration > 0)
	{
		std::cout << "Events/ms: " << num_events / (long double)duration << std::endl;
	}

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);

	if (res == SCAP_SUCCESS)
	{
		return ev;
	}
	if (res == SCAP_EOF)
	{
		std::cout << "-- EOF" << std::endl;
		g_interrupted = true;
		return nullptr;
	}

	if(res != SCAP_TIMEOUT && res != SCAP_FILTERED_EVENT)
	{
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
	}

	return nullptr;
}

void formatted_dump(sinsp&, sinsp_evt* ev)
{
	std::string output;
	if(ev->get_category() == EC_PROCESS)
	{
		process_formatter->tostring(ev, output);
	}
	else if(ev->get_category() == EC_NET || ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
	{
		net_formatter->tostring(ev, output);
	}
	else
	{
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}

static void hexdump(const unsigned char* buf, size_t len)
{
	bool in_ascii = false;

	putc('[', stdout);
	for(size_t i = 0; i < len; ++i)
	{
		if(isprint(buf[i]))
		{
			if(!in_ascii)
			{
				in_ascii = true;
				if(i > 0)
				{
					putc(' ', stdout);
				}
				putc('"', stdout);
			}
			putc(buf[i], stdout);
		}
		else
		{
			if(in_ascii)
			{
				in_ascii = false;
				fputs("\" ", stdout);
			}
			else if(i > 0)
			{
				putc(' ', stdout);
			}
			printf("%02x", buf[i]);
		}
	}

	if(in_ascii)
	{
		putc('"', stdout);
	}
	putc(']', stdout);
}

void raw_dump(sinsp& inspector, sinsp_evt* ev)
{
	string date_time;
	sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

	cout << "ts=" << date_time;
	cout << " tid=" << ev->get_tid();
	cout << " type=" << (ev->get_direction() == SCAP_ED_IN ? '>' : '<')  << get_event_type_name(ev);
	cout << " category=" << get_event_category_name(ev->get_category());
	cout << " nparams=" << ev->get_num_params();

	for(size_t i = 0; i < ev->get_num_params(); ++i)
	{
		const sinsp_evt_param *p = ev->get_param(i);
		const struct ppm_param_info *pi = ev->get_param_info(i);
		cout << ' ' << i << ':' << pi->name << '=';
		hexdump((const unsigned char*)p->m_val, p->m_len);
	}

	cout << endl;
}
