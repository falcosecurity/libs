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

#include "../sys_call_test.h"
#include "docker_utils.h"

#include <gtest/gtest.h>

#include <libsinsp/sinsp_cgroup.h>
#include <string>

using namespace std;

TEST_F(sys_call_test, container_cgroups)
{
	int ctid;
	bool done = false;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		ctid = fork();

		if (ctid >= 0)
		{
			if (ctid == 0)
			{
				sleep(1);
				// _exit prevents asan from complaining for a false positive memory leak.
				_exit(0);
			}
			else
			{
				wait(NULL);
			}
		}
		else
		{
			FAIL();
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		if (param.m_evt->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			sinsp_threadinfo sinsp_tinfo(nullptr);
			char buf[100];

			sinsp_threadinfo* tinfo = param.m_evt->get_thread_info();
			ASSERT_TRUE(tinfo != NULL);
			const auto& cgroups = tinfo->cgroups();
			ASSERT_TRUE(cgroups.size() > 0);

			snprintf(buf, sizeof(buf), "/proc/%d/", ctid);

			sinsp_tinfo.m_tid = ctid;
			sinsp_cgroup::instance().lookup_cgroups(sinsp_tinfo);

			const auto& sinsp_cgroups = sinsp_tinfo.cgroups();
			ASSERT_TRUE(sinsp_cgroups.size() > 0);

			map<string, string> cgroups_kernel;
			for (uint32_t j = 0; j < cgroups.size(); ++j)
			{
				cgroups_kernel.insert(pair<string, string>(cgroups[j].first, cgroups[j].second));
			}

			map<string, string> cgroups_proc;
			for (uint32_t j = 0; j < sinsp_cgroups.size(); ++j)
			{
				cgroups_proc.insert(
				    pair<string, string>(sinsp_cgroups[j].first, sinsp_cgroups[j].second));
			}

			ASSERT_TRUE(cgroups_kernel.size() > 0);
			ASSERT_TRUE(cgroups_proc.size() > 0);

			for (const auto& [subsys, path] : cgroups_proc)
			{
				printf(" proc cgroup[%s] == <%s>\n", subsys.c_str(), path.c_str());
			}

			for (const auto& [subsys, path] : cgroups_kernel)
			{
				printf(" kernel cgroup[%s] == <%s>\n", subsys.c_str(), path.c_str());
			}

			for (auto& [proc_subsys, proc_path] : cgroups_proc)
			{
				auto it_kernel = cgroups_kernel.find(proc_subsys);
				if (it_kernel != cgroups_kernel.end())
				{
					EXPECT_EQ(it_kernel->first, proc_subsys);
					EXPECT_EQ(it_kernel->second, proc_path);
				}
			}

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_TRUE(done);
}

static int clone_callback(void* arg)
{
	sleep(5);
	return 0;
}

TEST_F(sys_call_test, container_clone_nspid)
{
	int ctid;
	int flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD | CLONE_NEWPID;
	bool done = false;

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		const int STACK_SIZE = 65536; /* Stack size for cloned child */
		char* stack;                  /* Start of stack buffer area */
		char* stack_top;              /* End of stack buffer area */

		stack = (char*)malloc(STACK_SIZE);
		if (stack == NULL)
		{
			FAIL();
		}
		stack_top = stack + STACK_SIZE;

		ctid = clone(clone_callback, stack_top, flags, NULL);
		if (ctid == -1)
		{
			FAIL();
		}
		else if (ctid == 0)
		{
			free(stack);
			_exit(0);
		}
		else
		{
			free(stack);
			waitpid(ctid, NULL, 0);
		}
	};

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_evt* e = param.m_evt;
		if (e->get_type() == PPME_SYSCALL_CLONE_20_X)
		{
			sinsp_threadinfo* tinfo = param.m_evt->get_thread_info();
			ASSERT_TRUE(tinfo != NULL);
			ASSERT_TRUE(tinfo->m_vtid == 1);
			ASSERT_TRUE(tinfo->m_vpid == 1);

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_clone_nspid_ioctl)
{
	int ctid;
	int flags = CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | SIGCHLD | CLONE_NEWPID;
	bool done = false;

	const int STACK_SIZE = 65536;
	char* stack;
	char* stack_top;

	stack = (char*)malloc(STACK_SIZE);
	if (stack == NULL)
	{
		FAIL();
	}
	stack_top = stack + STACK_SIZE;

	ctid = clone(clone_callback, stack_top, flags, NULL);
	if (ctid == -1)
	{
		FAIL();
	}

	//
	// FILTER
	//
	event_filter_t filter = [&](sinsp_evt* evt) { return evt->get_tid() == ctid; };

	//
	// TEST CODE
	//
	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector) { wait(NULL); };

	//
	// OUTPUT VALDATION
	//
	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->get_thread_info();
		if (tinfo)
		{
			EXPECT_EQ(1, tinfo->m_vtid);
			EXPECT_EQ(1, tinfo->m_vpid);

			done = true;
		}
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_TRUE(done);
	free(stack);
}

static void run_container_docker_test(bool fork_after_container_start)
{
	bool done = false;

	if (!dutils_check_docker())
	{
		printf("Docker not running, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		return (evt->get_type() == PPME_CONTAINER_JSON_E ||
		        evt->get_type() == PPME_CONTAINER_JSON_2_E);
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		ASSERT_TRUE(system("docker kill libsinsp_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v libsinsp_docker > /dev/null 2>&1 || true") == 0);

#ifdef __s390x__
		if (system("docker run -d --name libsinsp_docker s390x/busybox") != 0)
#else
		if (system("docker run -d --name libsinsp_docker busybox") != 0)
#endif
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		ASSERT_TRUE(system("docker kill libsinsp_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v libsinsp_docker > /dev/null 2>&1") == 0);

		if (fork_after_container_start)
		{
			int child_pid = fork();

			ASSERT_TRUE(child_pid >= 0) << "Could not fork" << strerror(errno);
			if (child_pid == 0)
			{
				// _exit prevents asan from complaining for a false positive memory leak.
				_exit(0);
			}
			else
			{
				wait(NULL);
			}
		}
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->get_thread_info();
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		ASSERT_TRUE(tinfo->m_container_id.length() == 12);

		const auto container_info =
		    param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		EXPECT_EQ(sinsp_container_lookup::state::SUCCESSFUL, container_info->get_lookup_status());
		EXPECT_EQ(sinsp_container_type::CT_DOCKER, container_info->m_type);
		EXPECT_EQ("libsinsp_docker", container_info->m_name);
#ifdef __s390x__
		EXPECT_EQ("s390x/busybox", container_info->m_image);
#else
		EXPECT_EQ("busybox", container_info->m_image);
#endif

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_docker)
{
	bool fork_after_container_start = false;

	run_container_docker_test(fork_after_container_start);
}

// This test intentionally does a fork after starting the container
// and then calls exit(), which closes all FILEs, calls destructors
// for static globals, etc. Best practices recommend calling _exit()
// in forked children instead of exit(), as _exit() skips all those
// teardown steps, but this test verifies that even if a child calls
// exit(), that there aren't any conflicts/races in the static
// globals, etc.
//
// It may be the case someday that there are globals that we don't
// control or have to keep global that cause conflicts on duplicate
// exit(), in which case this test will start
// hanging/failing/crashing. If this happens, we should remove this
// test.

TEST_F(sys_call_test, container_docker_fork)
{
	bool fork_after_container_start = true;

	run_container_docker_test(fork_after_container_start);
}

TEST_F(sys_call_test, container_docker_bad_socket)
{
	bool done = false;

	if (!dutils_check_docker())
	{
		printf("Docker not running, skipping test\n");
		return;
	}

	before_open_t setup = [&](sinsp* inspector)
	{
		inspector->set_docker_socket_path("/invalid/path");
	};

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		if (evt->get_type() == PPME_CONTAINER_JSON_E || evt->get_type() == PPME_CONTAINER_JSON_2_E)
		{
			return true;
		}
		auto tinfo = evt->get_thread_info();
		if (tinfo)
		{
			return !tinfo->m_container_id.empty();
		}
		return false;
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		ASSERT_TRUE(system("docker kill libsinsp_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v libsinsp_docker > /dev/null 2>&1 || true") == 0);

#ifdef __s390x__
		if (system("docker run -d --name libsinsp_docker s390x/busybox sh -c 'while true; do "
		           "sleep 1; done'") != 0)
#else
		if (system("docker run -d --name libsinsp_docker busybox sh -c 'while true; do sleep 1; "
		           "done'") != 0)
#endif
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		ASSERT_TRUE(system("docker kill libsinsp_docker > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("docker rm -v libsinsp_docker > /dev/null 2>&1") == 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		// can't get a container event for failed lookup
		ASSERT_NE(PPME_CONTAINER_JSON_E, param.m_evt->get_type());
		ASSERT_NE(PPME_CONTAINER_JSON_2_E, param.m_evt->get_type());

		sinsp_threadinfo* tinfo = param.m_evt->get_thread_info(false);
		ASSERT_TRUE(tinfo->m_container_id.length() == 12);
		ASSERT_TRUE(param.m_inspector->m_container_manager.container_exists(tinfo->m_container_id));
		const auto container_info =
		    param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		if (container_info && container_info->m_type == CT_DOCKER)
		{
			EXPECT_EQ(sinsp_container_lookup::state::FAILED, container_info->get_lookup_status());
			done = true;
		}
	};

	before_close_t cleanup = [&](sinsp* inspector)
	{ inspector->set_docker_socket_path("/var/run/docker.sock"); };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });
	ASSERT_TRUE(done);
}

TEST_F(sys_call_test, container_libvirt)
{
	bool done = false;

	if (system("virsh --help > /dev/null 2>&1") != 0)
	{
		printf("libvirt not installed, skipping test\n");
		return;
	}

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		sinsp_threadinfo* tinfo = evt->get_thread_info();
		if (tinfo)
		{
			return !tinfo->m_container_id.empty() && tinfo->m_comm == "sh";
		}

		return false;
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector)
	{
		FILE* f = fopen("/tmp/conf.xml", "w");
		ASSERT_TRUE(f != NULL);
		fprintf(f,
		        "<domain type='lxc'>\n"
		        "   <name>libvirt-container</name>\n"
		        "   <memory>128000</memory>\n"
		        "   <os>\n"
		        "      <type>exe</type>\n"
		        "      <init>/bin/sh</init>\n"
		        "   </os>\n"
		        "   <devices>\n"
		        "      <console type='pty'/>\n"
		        "   </devices>\n"
		        "</domain>");
		fclose(f);

		ASSERT_TRUE(
		    system("virsh -c lxc:/// undefine libvirt-container > /dev/null 2>&1 || true") == 0);
		ASSERT_TRUE(system("virsh -c lxc:/// destroy libvirt-container > /dev/null 2>&1 || true") ==
		            0);

		if (system("virsh -c lxc:/// define /tmp/conf.xml") != 0)
		{
			ASSERT_TRUE(false);
		}

		if (system("virsh -c lxc:/// start libvirt-container") != 0)
		{
			ASSERT_TRUE(false);
		}

		sleep(2);

		ASSERT_TRUE(system("virsh -c lxc:/// undefine libvirt-container > /dev/null 2>&1") == 0);
		ASSERT_TRUE(system("virsh -c lxc:/// destroy libvirt-container > /dev/null 2>&1") == 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		sinsp_threadinfo* tinfo = param.m_evt->get_thread_info();
		ASSERT_TRUE(tinfo != NULL);
		ASSERT_TRUE(tinfo->m_vtid != tinfo->m_tid);
		ASSERT_TRUE(tinfo->m_vpid != tinfo->m_pid);

		unsigned int lxc_id;
		ASSERT_TRUE(tinfo->m_container_id.find("libvirt\\x2dcontainer") != string::npos ||
		            sscanf(tinfo->m_container_id.c_str(), "lxc-%u-libvirt-container", &lxc_id) ==
		                1);

		const auto container_info =
		    param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		ASSERT_TRUE(container_info != NULL);

		ASSERT_TRUE(container_info->m_type == sinsp_container_type::CT_LIBVIRT_LXC);
		ASSERT_TRUE(container_info->m_name == tinfo->m_container_id);
		ASSERT_TRUE(container_info->m_image.empty());

		done = true;
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_TRUE(done);
}

class container_state
{
public:
	container_state()
	    : container_w_health_probe(false),
	      root_cmd_seen(false),
	      second_cmd_seen(false),
	      healthcheck_seen(false){};
	virtual ~container_state(){};

	bool container_w_health_probe;
	bool root_cmd_seen;
	bool second_cmd_seen;
	bool healthcheck_seen;
};

static std::string capture_stats(sinsp* inspector)
{
	scap_stats st;
	inspector->get_capture_stats(&st);

	std::stringstream ss;

	ss << "capture stats: dropped=" << st.n_drops << " buf=" << st.n_drops_buffer
	   << " pf=" << st.n_drops_pf << " bug=" << st.n_drops_bug;

	return ss.str();
}

static void update_container_state(sinsp* inspector,
                                   sinsp_evt* evt,
                                   container_state& cstate,
                                   sinsp_threadinfo::command_category expected_cat)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if (tinfo == NULL)
	{
		return;
	}

	if (inspector->m_container_manager.container_exists(tinfo->m_container_id))
	{
		std::string cmdline;

		sinsp_threadinfo::populate_cmdline(cmdline, tinfo);

		const auto container_info =
		    inspector->m_container_manager.get_container(tinfo->m_container_id);

		if (container_info && !container_info->m_health_probes.empty())
		{
			cstate.container_w_health_probe = true;
		}

		// This is the container's initial command. In the test case
		// where the health check is the same command, we will see this
		// command twice--the first time it should not be identified as
		// a health check, and the second time it should.
		if (cmdline == "sh -c /bin/sleep 10")
		{
			if (!cstate.root_cmd_seen)
			{
				cstate.root_cmd_seen = true;

				ASSERT_EQ(tinfo->m_category, sinsp_threadinfo::CAT_CONTAINER)
				    << capture_stats(inspector);
			}
			else
			{
				// In some cases, it can take so long for the async fetch of container info to
				// complete (1.5 seconds) that a healthcheck proc might be run before the container
				// info has been updated. So only require the threadinfo category to match once
				// the container info has a health probe.
				if (cstate.container_w_health_probe)
				{
					cstate.healthcheck_seen = true;
					ASSERT_EQ(tinfo->m_category, expected_cat) << capture_stats(inspector);
				}
			}
		}

		// Child process of the above sh command. Same handling as above,
		// will see twice only when health check is same as root command.
		if (cmdline == "sleep 10")
		{
			if (!cstate.second_cmd_seen)
			{
				cstate.second_cmd_seen = true;
				ASSERT_EQ(tinfo->m_category, sinsp_threadinfo::CAT_CONTAINER)
				    << capture_stats(inspector);
			}
			else
			{
				// See above caveat about slow container info fetches
				if (cstate.container_w_health_probe)
				{
					// Should inherit container healthcheck property from parent.
					ASSERT_EQ(tinfo->m_category, expected_cat) << capture_stats(inspector);
				}
			}
		}

		// Commandline for the health check of the healthcheck containers,
		// in direct exec and shell formats.
		if (cmdline == "ut-health-check" || cmdline == "sh -c /bin/ut-health-check")
		{
			cstate.healthcheck_seen = true;

			ASSERT_EQ(tinfo->m_category, expected_cat) << capture_stats(inspector);
		}
	}
}

// Start up a container with the provided dockerfile, and track the
// state of the initial command for the container, a child proces of
// that initial command, and a health check (if one is configured).
static void healthcheck_helper(
    const char* dockerfile,
    bool expect_healthcheck,
	const char* build_extra_args,
	const char* run_extra_args,
	std::vector<std::string>& labels,
    sinsp_threadinfo::command_category expected_cat = sinsp_threadinfo::CAT_HEALTHCHECK)
{
	container_state cstate;
	bool exited_early = false;
	std::string capture_stats_str = "(Not Collected Yet)";

	if (!dutils_check_docker())
	{
		return;
	}

	dutils_kill_container("cont_health_ut");
	dutils_kill_image("cont_health_ut_img");
	std::string docker_res(LIBSINSP_TEST_RESOURCES_PATH "/docker/");
	docker_helper dhelper(docker_res + dockerfile, "cont_health_ut_img", labels, build_extra_args, run_extra_args);

	ASSERT_TRUE(dhelper.build_image() == 0);

	before_open_t setup = [&](sinsp* inspector)
	{};

	event_filter_t filter = [&](sinsp_evt* evt)
	{
		sinsp_threadinfo* tinfo = evt->get_thread_info();

		return (strcmp(evt->get_name(), "execve") == 0 && evt->get_direction() == SCAP_ED_OUT &&
		        tinfo->m_container_id != "");
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		// Setting dropping mode preserves the execs but
		// reduces the chances that we'll drop events during
		// the docker fetch.
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->start_dropping_mode(1);
		}

		int rc = dhelper.run_container("cont_health_ut", "/bin/sh -c '/bin/sleep 10'");

		ASSERT_TRUE(exited_early || (rc == 0));
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		update_container_state(param.m_inspector, param.m_evt, cstate, expected_cat);

		// Exit as soon as we've seen all the initial commands
		// and the health check (if expecting one)
		if (!exited_early && cstate.root_cmd_seen && cstate.second_cmd_seen &&
		    (cstate.healthcheck_seen || !expect_healthcheck))
		{
			exited_early = true;
			dutils_kill_container("cont_health_ut");
		}
	};

	before_close_t cleanup = [&](sinsp* inspector)
	{ capture_stats_str = capture_stats(inspector); };

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup, cleanup); });

	ASSERT_TRUE(cstate.root_cmd_seen) << capture_stats_str;
	ASSERT_TRUE(cstate.second_cmd_seen) << capture_stats_str;
	ASSERT_EQ(cstate.container_w_health_probe, expect_healthcheck) << capture_stats_str;
	ASSERT_EQ(cstate.healthcheck_seen, expect_healthcheck) << capture_stats_str;
}

//  Run container w/o health check, should not find any health check
//  for the container. Should not identify either the entrypoint
//  or a second process spawned after as a health check process.
TEST_F(sys_call_test, docker_container_no_healthcheck)
{
	std::vector<std::string> labels{};
	healthcheck_helper("Dockerfile.no_healthcheck", false, "", "", labels);
}

// A container with HEALTHCHECK=none should behave identically to one
// without any container at all.
TEST_F(sys_call_test, docker_container_none_healthcheck)
{
	std::vector<std::string> labels{};
	healthcheck_helper("Dockerfile.none_healthcheck", false, "", "", labels);
}

//  Run container w/ health check. Should find health check for
//  container but not identify entrypoint or second process after as
//  a health check process. Should identify at least one health
//  check executed for container.
TEST_F(sys_call_test, docker_container_healthcheck)
{
	std::vector<std::string> labels{};
	healthcheck_helper("Dockerfile", true, "", "", labels);
}

//  Run container w/ health check and entrypoint having identical
//  cmdlines. Should identify healthcheck but not entrypoint as a
//  health check process.
TEST_F(sys_call_test, docker_container_healthcheck_cmd_overlap)
{
	std::vector<std::string> labels{};
	healthcheck_helper("Dockerfile", true, "", "", labels);
}

// A health check using shell exec instead of direct exec.
TEST_F(sys_call_test, docker_container_healthcheck_shell)
{
	std::vector<std::string> labels{};
	healthcheck_helper("Dockerfile", true, "", "--health-cmd 'sh -c \"/bin/ut-health-check\"' --health-interval 0.5s", labels);
}

// A health check where the container has docker labels that make it
// look like it was started in k8s.
TEST_F(sys_call_test, docker_container_liveness_probe)
{
	const char* label= R""""(annotation.kubectl.kubernetes.io/last-applied-configuration="{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"mysql-app\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"env\":[{\"name\":\"MYSQL_ROOT_PASSWORD\",\"value\":\"no\"}],\"image\":\"user/mysql:healthcheck\",\"livenessProbe\":{\"exec\":{\"command\":[\"/bin/ut-health-check\"]},\"initialDelaySeconds\":5,\"periodSeconds\":5},\"name\":\"mysql\"}]}}\n")"""";
	std::vector<std::string> labels{std::string(label)};
	healthcheck_helper("Dockerfile",
	                   true,
					   "",
					   "",
					   labels,
	                   sinsp_threadinfo::CAT_LIVENESS_PROBE);
}

TEST_F(sys_call_test, docker_container_readiness_probe)
{
	const char* label = R""""(annotation.kubectl.kubernetes.io/last-applied-configuration="{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"mysql-app\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"env\":[{\"name\":\"MYSQL_ROOT_PASSWORD\",\"value\":\"no\"}],\"image\":\"user/mysql:healthcheck\",\"readinessProbe\":{\"exec\":{\"command\":[\"/bin/ut-health-check\"]},\"initialDelaySeconds\":5,\"periodSeconds\":5},\"name\":\"mysql\"}]}}\n")"""";
	std::vector<std::string> labels{std::string(label)};
	healthcheck_helper("Dockerfile",
	                   true,
					   "",
					   "",
					   labels,
	                   sinsp_threadinfo::CAT_READINESS_PROBE);
}

TEST_F(sys_call_test, docker_container_large_json)
{
	bool saw_container_evt = false;

	if (!dutils_check_docker())
	{
		return;
	}

	std::string repeated_string = std::string(4096,'a');

	std::vector<std::string> labels;
	labels.emplace_back("url2=" + repeated_string);
	labels.emplace_back("summary2=" + repeated_string);
	labels.emplace_back("vcs-type2=" + repeated_string);
	labels.emplace_back("vcs-ref2=" + repeated_string);
	labels.emplace_back("description2=" + repeated_string);
	labels.emplace_back("io.k8s.description2=" + repeated_string);

	dutils_kill_container("large_container_ut");
	dutils_kill_image("large_container_ut_img");
	std::string docker_res(LIBSINSP_TEST_RESOURCES_PATH "/docker/");
	docker_helper dhelper(docker_res + "Dockerfile", "large_container_ut_img", labels, "", "");

	ASSERT_TRUE(dhelper.build_image() == 0);

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_CONTAINER_JSON_E ||
		       evt->get_type() == PPME_CONTAINER_JSON_2_E;
	};

	run_callback_t test = [&](concurrent_object_handle<sinsp> inspector_handle)
	{
		// set container label max to huge value
		{
			std::scoped_lock inspector_handle_lock(inspector_handle);
			inspector_handle->set_container_labels_max_len(60000);
		}
		int rc = dhelper.run_container("large_container_ut", "/bin/sh -c '/bin/sleep 3'");

		ASSERT_TRUE(rc == 0);
	};

	captured_event_callback_t callback = [&](const callback_param& param)
	{
		saw_container_evt = true;

		sinsp_threadinfo* tinfo = param.m_evt->get_thread_info();
		ASSERT_TRUE(tinfo != NULL);

		const auto container_info =
		    param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);

		ASSERT_NE(nullptr, container_info);
		ASSERT_EQ(container_info->m_type, CT_DOCKER);

		ASSERT_STREQ(container_info->m_name.c_str(), "large_container_ut");
		ASSERT_STREQ(container_info->m_image.c_str(), "large_container_ut_img");

		std::unordered_set<std::string> labels = {
		    "url2",
		    "summary2",
		    "vcs-type2",
		    "vcs-ref2",
		    "description2",
		    "io.k8s.description2",
		};

		const std::string aaaaaa(4096, 'a');

		for (const auto& label : container_info->m_labels)
		{
			EXPECT_EQ(1, labels.erase(label.first));
			EXPECT_EQ(4096, label.second.size());
			EXPECT_EQ(aaaaaa, label.second);
		}

		EXPECT_TRUE(labels.empty());

		// reset the value
		param.m_inspector->set_container_labels_max_len(100);
	};

	ASSERT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter); });
	ASSERT_TRUE(saw_container_evt);
}
