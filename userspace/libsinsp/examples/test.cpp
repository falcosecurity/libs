/*
Copyright (C) 2021 The Falco Authors.

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

#include <iostream>
#ifndef WIN32
#include <getopt.h>
#endif
#include <csignal>
#include <sinsp.h>
#include <functional>
#include "util.h"

using namespace std;

#define KMOD "kmod"
#define BPF "bpf"
#define UDIG "udig"
#define NODRIVER "nodriver"
#define SCAPFILE "scap-file"
#define SOURCE_PLUGIN "plugin"
#define GVISOR "gvisor"
#define MODERN_BPF "modern-bpf"
#define TEST_INPUT "test-input"

// Functions used for dumping to stdout
void plaintext_dump(sinsp& inspector);
void json_dump(sinsp& inspector);

std::function<void(sinsp& inspector)> dump;
static bool g_interrupted = false;
static const uint8_t g_backoff_timeout_secs = 2;
static bool g_all_threads = false;
string engine_string = "kmod";
string filter_string = "";
string scap_file_path = "";
string bpf_path = "";
uint64_t buffer_dim = 0;

sinsp_evt* get_event(sinsp& inspector);

#define PROCESS_DEFAULTS "*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline %evt.args"

// Formatters used with JSON output
static sinsp_evt_formatter* default_formatter = nullptr;
static sinsp_evt_formatter* process_formatter = nullptr;
static sinsp_evt_formatter* net_formatter = nullptr;

static void sigint_handler(int signum)
{
	g_interrupted = true;
}

static void usage()
{
	string usage = R"(Usage: sinsp-example [options]

Options:
  -h, --help                                 Print this page.
  -f <filter>, --filter <filter>             Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields).
  -j, --json                                 Use JSON as the output format.
  -a, --all-threads                          Output information about all threads, not just the main one.
  -e <engine_name>, --engine <engine_name>   Specify the engine name to open possible values are: "kmod", "bpf", "udig", "nodriver", "scap-file", "gvisor", "modern_bpf", "test_input". 
  -b <path>, --bpf-path <path>               BPF probe path.
  -d <dim>, --buffer-dim <dim>               Buffer dimension.
  -s <path>, --scap-file-path <path>         Scap file path.
)";
	cout << usage << endl;
}

#ifndef WIN32
// Parse CLI options.
void parse_CLI_options(sinsp& inspector, int argc, char** argv)
{
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"filter", required_argument, 0, 'f'},
		{"json", no_argument, 0, 'j'},
		{"all-threads", no_argument, 0, 'a'},
		{"engine", required_argument, 0, 'e'},
		{"bpf-path", required_argument, 0, 'b'},
		{"buffer-dim", required_argument, 0, 'd'},
		{"scap-file-path", required_argument, 0, 's'},
		{0, 0, 0, 0}};

	int op;
	int long_index = 0;
	while((op = getopt_long(argc, argv,
				"hf:ja:e:b:d:s:",
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
			// Initialize JSON formatters
			default_formatter = new sinsp_evt_formatter(&inspector, DEFAULT_OUTPUT_STR);
			process_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS);
			net_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS " %fd.name");

			inspector.set_buffer_format(sinsp_evt::PF_JSON);
			dump = json_dump;
			break;
		case 'a':
			g_all_threads = true;
			break;
		case 'e':
			engine_string = optarg;
			break;
		case 'b':
			bpf_path = optarg;
			break;
		case 'd':
			buffer_dim = strtoul(optarg, NULL, 10);
			break;
		case 's':
			scap_file_path = optarg;
			break;
		default:
			break;
		}
	}
}
#endif /* WIN32 */

void open_engine(sinsp& inspector)
{
	std::cout << "-- Try to open: '" + engine_string + "' engine." << std::endl;

	if(!engine_string.compare(KMOD))
	{
		inspector.open_kmod(buffer_dim);
	}
	else if(!engine_string.compare(BPF))
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
		inspector.open_bpf(buffer_dim, bpf_path.c_str());
	}
	else if(!engine_string.compare(UDIG))
	{
		inspector.open_udig(buffer_dim);
	}
	else if(!engine_string.compare(NODRIVER))
	{
		inspector.open_nodriver();
	}
	else if(!engine_string.compare(SCAPFILE))
	{
		if(scap_file_path.empty())
		{
			std::cerr << "You must specify the path to the 'scap-file' if you use the 'scap-file' engine" << std::endl;
			exit(EXIT_FAILURE);
		}
		inspector.open_savefile(scap_file_path.c_str(), 0);
	}
	else if(!engine_string.compare(SOURCE_PLUGIN))
	{
		std::cerr << "Not supported right now." << std::endl;
		exit(EXIT_SUCCESS);
	}
	else if(!engine_string.compare(GVISOR))
	{
		std::cerr << "Not supported right now." << std::endl;
		exit(EXIT_SUCCESS);
	}
	else if(!engine_string.compare(MODERN_BPF))
	{
		inspector.open_modern_bpf(buffer_dim);
	}
	else if(!engine_string.compare(TEST_INPUT))
	{
		std::cerr << "Not supported right now." << std::endl;
		exit(EXIT_SUCCESS);
	}
	else
	{
		std::cerr << "Unknown engine" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "-- Engine '" + engine_string + "' correctly opened." << std::endl;
}

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
//
int main(int argc, char** argv)
{
	sinsp inspector;
	dump = plaintext_dump;

#ifndef WIN32
	parse_CLI_options(inspector, argc, argv);
	signal(SIGPIPE, sigint_handler);
#endif

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	open_engine(inspector);

	std::cout << "-- Start capture" << std::endl;

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

	while(!g_interrupted)
	{
		dump(inspector);
	}

	// Cleanup JSON formatters
	delete default_formatter;
	delete process_formatter;
	delete net_formatter;

	return 0;
}

sinsp_evt* get_event(sinsp& inspector, std::function<void(const std::string&)> handle_error)
{
	sinsp_evt* ev = nullptr;

	int32_t res = inspector.next(&ev);


	if(res == SCAP_SUCCESS)
	{
		return ev;
	}

	if(res != SCAP_TIMEOUT)
	{
		handle_error(inspector.getlasterr());
		std::this_thread::sleep_for(std::chrono::seconds(g_backoff_timeout_secs));
	}

	return nullptr;
}

void plaintext_dump(sinsp& inspector)
{

	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << "[ERROR] " << error_msg << endl; });

	if(ev == nullptr)
	{
		return;
	}

	sinsp_threadinfo* thread = ev->get_thread_info();
	if(thread)
	{
		string cmdline;
		sinsp_threadinfo::populate_cmdline(cmdline, thread);

		if(g_all_threads || thread->is_main_thread())
		{
			string date_time;
			sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

			bool is_host_proc = thread->m_container_id.empty();
			cout << "[" << date_time << "]:["
			     << (is_host_proc ? "HOST" : thread->m_container_id) << "]:";

			cout << "[CAT=";

			if(ev->get_category() == EC_PROCESS)
			{
				cout << "PROCESS]:";
			}
			else if(ev->get_category() == EC_NET)
			{
				cout << get_event_category(ev->get_category()) << "]:";
				sinsp_fdinfo_t* fd_info = ev->get_fd_info();

				// event subcategory should contain SC_NET if ipv4/ipv6
				if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
				{
					cout << "[" << fd_info->tostring() << "]:";
				}
			}
			else if(ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
			{
				cout << get_event_category(ev->get_category()) << "]:";

				sinsp_fdinfo_t* fd_info = ev->get_fd_info();
				if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
				{
					cout << "[" << fd_info->tostring() << "]:";
				}
			}
			else
			{
				cout << get_event_category(ev->get_category()) << "]:";
			}

			sinsp_threadinfo* p_thr = thread->get_parent_thread();
			int64_t parent_pid = -1;
			if(nullptr != p_thr)
			{
				parent_pid = p_thr->m_pid;
			}

			cout << "[PPID=" << parent_pid << "]:"
			     << "[PID=" << thread->m_pid << "]:"
			     << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
			     << "[EXE=" << thread->get_exepath() << "]:"
			     << "[CMD=" << cmdline << "]"
			     << endl;
		}
	}
	else
	{
		cout << "[EVENT]:[" << get_event_category(ev->get_category()) << "]:"
		     << ev->get_name() << endl;
	}
}

void json_dump(sinsp& inspector)
{
	// Initialize JSON formatters
	static sinsp_evt_formatter* default_formatter = new sinsp_evt_formatter(&inspector, DEFAULT_OUTPUT_STR);
	static sinsp_evt_formatter* process_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS);
	static sinsp_evt_formatter* net_formatter = new sinsp_evt_formatter(&inspector, PROCESS_DEFAULTS " %fd.name");

	sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg)
				  { cout << R"({"error": ")" << error_msg << R"("})" << endl; });

	if(ev == nullptr)
	{
		return;
	}

	std::string output;
	sinsp_threadinfo* thread = ev->get_thread_info();

	if(thread)
	{
		if(g_all_threads || thread->is_main_thread())
		{
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
		}
		else
		{
			// Prevent empty lines from being printed
			return;
		}
	}
	else
	{
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}
