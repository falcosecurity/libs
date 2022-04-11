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
#include <iomanip>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sinsp.h>
#include <functional>
#include "util.h"

using namespace std;

static bool g_interrupted;
static const uint8_t g_backoff_timeout_secs = 2;

sinsp_evt* get_event(sinsp& inspector);

#define PROCESS_DEFAULTS "*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe %proc.cmdline %evt.args"

// Formatters used with JSON output
static sinsp_evt_formatter* default_formatter = nullptr;
static sinsp_evt_formatter* process_formatter = nullptr;
static sinsp_evt_formatter* net_formatter = nullptr;

// Functions used for dumping to stdout
void plaintext_dump(sinsp& inspector);
void json_dump(sinsp& inspector);

static void sigint_handler(int signum)
{
    g_interrupted = true;
}

static void usage()
{
    string usage = R"(Usage: sinsp-example [options]

Options:
  -h, --help                    Print this page
  -f <filter>                   Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields)
  -j, --json                    Use JSON as the output format
)";
    cout << usage << endl;
}

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
//
int main(int argc, char **argv)
{
    sinsp inspector;

    // Parse configuration options.
    static struct option long_options[] = {
            {"help",      no_argument, 0, 'h'},
            {"json",      no_argument, 0, 'j'},
            {0,   0,         0,  0}
    };

    int op;
    int long_index = 0;
    string filter_string;
    std::function<void (sinsp& inspector)> dump = plaintext_dump;
    while((op = getopt_long(argc, argv,
                            "hr:s:f:j",
                            long_options, &long_index)) != -1)
    {
        switch(op)
        {
            case 'h':
                usage();
                return EXIT_SUCCESS;
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
            default:
                break;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, sigint_handler);

    inspector.open();

    if(!filter_string.empty())
    {
        try
        {
            inspector.set_filter(filter_string);
        }
        catch(const sinsp_exception &e) {
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

sinsp_evt* get_event(sinsp& inspector, std::function<void (const std::string&)> handle_error)
{
    sinsp_evt* ev = nullptr;
    int32_t res = inspector.next(&ev);

    if (res == SCAP_SUCCESS)
    {
        return ev;
    }

    if(res != SCAP_TIMEOUT)
    {
        handle_error(inspector.getlasterr());
        sleep(g_backoff_timeout_secs);
    }

    return nullptr;
}

void plaintext_dump(sinsp& inspector)
{
    sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg) {
        cout << "[ERROR] " << error_msg << endl;
    });

    if (ev == nullptr)
    {
        return;
    }

    sinsp_threadinfo* thread = ev->get_thread_info();
    if(thread)
    {
        string cmdline;
        sinsp_threadinfo::populate_cmdline(cmdline, thread);

        if(thread->is_main_thread())
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

            sinsp_threadinfo *p_thr = thread->get_parent_thread();
            int64_t parent_pid;
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

    sinsp_evt* ev = get_event(inspector, [](const std::string& error_msg) {
        cout << R"({"error": ")" << error_msg << R"("})" << endl;
    });

    if (ev == nullptr)
    {
        return;
    }

    std::string output;
    sinsp_threadinfo* thread = ev->get_thread_info();

    if (thread)
    {
        if(thread->is_main_thread())
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
    }
    else
    {
        default_formatter->tostring(ev, output);
    }

    cout << output << std::endl;
}
