#include "../sys_call_test.h"
#include "../subprocess.h"

#include <gtest/gtest.h>

static const std::string cri_container_id = "aec4c703604b";
static const std::string fake_cri_socket = "/tmp/fake-cri.sock";
static const std::string fake_docker_socket = "/tmp/fake-docker.sock";
static const std::string default_docker_socket = "/var/run/docker.sock";

struct exp_container_event_info {
	sinsp_container_type type;
	sinsp_container_lookup::state state;
};

class container_cri : public sys_call_test {
protected:
	void fake_cri_test(const std::string& pb_prefix,
	                   const std::string& runtime,
	                   const std::function<void(const callback_param& param,
	                                            std::atomic<bool>& done)>& callback,
	                   bool extra_queries = true);

	void fake_cri_test_timing(const std::string& pb_prefix,
	                          const std::string& delay_arg,
	                          const std::string& runtime,
	                          float docker_delay,
	                          bool async,
	                          const exp_container_event_info& exp_info,
	                          uint64_t container_engine_mask = 0,
	                          int64_t test_duration = 10);
};

TEST_F(container_cri, fake_cri_no_server) {
	std::atomic<bool> done(false);

	event_filter_t filter = [&](sinsp_evt* evt) {
		// we never get the PPME_CONTAINER_JSON_E event if the lookup fails
		sinsp_threadinfo* tinfo = evt->get_tinfo();
		if(tinfo) {
			return tinfo->m_exe == "/bin/echo" && !tinfo->m_container_id.empty();
		}

		return false;
	};

	run_callback_t test = [&](sinsp* inspector) {
		subprocess handle(LIBSINSP_TEST_PATH "/test_helper", {"cri_container_echo"});
		handle.in() << "\n";
		handle.wait();
	};

	captured_event_callback_t callback = [&](const callback_param& param) {
		sinsp_threadinfo* tinfo = param.m_evt->get_tinfo();
		EXPECT_TRUE(tinfo != NULL);

		EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		const auto container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);

		// This can either be null or a container with incomplete metadata
		EXPECT_TRUE(
		        (container_info == nullptr ||
		         container_info->get_lookup_status() != sinsp_container_lookup::state::SUCCESSFUL));

		done = true;
	};

	before_capture_t setup = [&](sinsp* inspector) {
		inspector->set_cri_socket_path(fake_cri_socket);
	};

	EXPECT_NO_FATAL_FAILURE({ event_capture::run(test, callback, filter, setup); });
	EXPECT_TRUE(done);
}

void container_cri::fake_cri_test(
        const std::string& pb_prefix,
        const std::string& runtime,
        const std::function<void(const callback_param& param, std::atomic<bool>& done)>& callback,
        bool extra_queries) {
	std::atomic<bool> done(false);
	unlink(fake_cri_socket.c_str());
	subprocess fake_cri_handle(LIBSINSP_TEST_PATH "/fake_cri/fake_cri",
	                           {"unix://" + fake_cri_socket, pb_prefix, runtime});
	pid_t fake_cri_pid = fake_cri_handle.get_pid();

	auto start_time = time(NULL);

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_CONTAINER_JSON_E ||
		       evt->get_type() == PPME_CONTAINER_JSON_2_E;
	};

	run_callback_t test = [&](sinsp* inspector) {
		subprocess handle(LIBSINSP_TEST_PATH "/test_helper", {"cri_container_echo"});
		handle.in() << "\n";
		handle.wait();
		while(!done && time(NULL) < start_time + 10) {
			usleep(100000);
		}
	};

	captured_event_callback_t cri_callback = [&](const callback_param& param) {
		callback(param, done);
	};

	before_capture_t setup = [&](sinsp* inspector) {
		inspector->set_cri_socket_path(fake_cri_socket);
		inspector->set_docker_socket_path("");
		inspector->set_cri_extra_queries(extra_queries);
	};

	after_capture_t cleanup = [&](sinsp* inspector) {
		inspector->set_docker_socket_path(default_docker_socket);
	};

	EXPECT_NO_FATAL_FAILURE({ event_capture::run(test, cri_callback, filter, setup, cleanup); });

	// The fake server had to stay running the whole time in order
	// for the test to be succesful
	// Needed to reap the zombine if it exited
	waitpid(fake_cri_pid, NULL, WNOHANG);
	EXPECT_TRUE(fake_cri_handle.is_alive());

	EXPECT_TRUE(done);

	fake_cri_handle.kill();
}

TEST_F(container_cri, fake_cri) {
	fake_cri_test(
	        LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	        "containerd",
	        [&](const callback_param& param, std::atomic<bool>& done) {
		        sinsp_threadinfo* tinfo = param.m_evt->get_tinfo();
		        EXPECT_TRUE(tinfo != NULL);

		        EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		        const auto container_info =
		                param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		        EXPECT_NE(container_info, nullptr);

		        EXPECT_EQ(sinsp_container_type::CT_CONTAINERD, container_info->m_type);
		        EXPECT_EQ("falco", container_info->m_name);
		        EXPECT_EQ("docker.io/falcosecurity/falco:latest", container_info->m_image);
		        EXPECT_EQ("sha256:8d0619a4da278dfe2772f75aa3cc74df0a250385de56085766035db5c9a062ed",
		                  container_info->m_imagedigest);
		        EXPECT_EQ("4bc0e14060f4263acf658387e76715bd836a13b9ba44f48465bd0633a412dbd0",
		                  container_info->m_imageid);
		        EXPECT_EQ(1073741824, container_info->m_memory_limit);
		        EXPECT_EQ(102, container_info->m_cpu_shares);
		        EXPECT_EQ(0, container_info->m_cpu_quota);
		        EXPECT_EQ(100000, container_info->m_cpu_period);

		        done = true;
	        });
}

TEST_F(container_cri, fake_cri_crio_extra_queries) {
	fake_cri_test(
	        LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_crio",
	        "cri-o",
	        [&](const callback_param& param, std::atomic<bool>& done) {
		        sinsp_threadinfo* tinfo = param.m_evt->get_tinfo();
		        EXPECT_TRUE(tinfo != NULL);

		        EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		        const auto container_info =
		                param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		        EXPECT_NE(container_info, nullptr);

		        EXPECT_EQ(sinsp_container_type::CT_CRIO, container_info->m_type);
		        EXPECT_EQ("falco", container_info->m_name);
		        EXPECT_EQ("docker.io/falcosecurity/falco:crio", container_info->m_image);
		        EXPECT_EQ("sha256:5241704b37e01f7bbca0ef6a90f5034731eba85320afd2eb9e4bce7ab09165a2",
		                  container_info->m_imagedigest);
		        EXPECT_EQ("4e01602047d456fa783025a26b4b4c59b6527d304f9983fbd63b8d9a3bec53dc",
		                  container_info->m_imageid);

		        done = true;
	        });
}

TEST_F(container_cri, fake_cri_crio) {
	fake_cri_test(
	        LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_crio",
	        "cri-o",
	        [&](const callback_param& param, std::atomic<bool>& done) {
		        sinsp_threadinfo* tinfo = param.m_evt->get_tinfo();
		        EXPECT_TRUE(tinfo != NULL);

		        EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		        const auto container_info =
		                param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		        EXPECT_NE(container_info, nullptr);

		        EXPECT_EQ(sinsp_container_type::CT_CRIO, container_info->m_type);
		        EXPECT_EQ(sinsp_container_lookup::state::SUCCESSFUL,
		                  container_info->get_lookup_status());
		        EXPECT_EQ("falco", container_info->m_name);
		        EXPECT_EQ("docker.io/falcosecurity/falco:crio", container_info->m_image);
		        EXPECT_EQ("sha256:5241704b37e01f7bbca0ef6a90f5034731eba85320afd2eb9e4bce7ab09165a2",
		                  container_info->m_imagedigest);
		        EXPECT_EQ("", container_info->m_imageid);  // no extra queries -> no image id

		        done = true;
	        },
	        false);
}

TEST_F(container_cri, fake_cri_unknown_runtime) {
	fake_cri_test(
	        LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	        "unknown-runtime",
	        [&](const callback_param& param, std::atomic<bool>& done) {
		        sinsp_threadinfo* tinfo = param.m_evt->get_tinfo();
		        EXPECT_TRUE(tinfo != NULL);

		        EXPECT_EQ(cri_container_id, tinfo->m_container_id);

		        const auto container_info =
		                param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		        EXPECT_NE(container_info, nullptr);

		        EXPECT_EQ(sinsp_container_type::CT_CRI, container_info->m_type);
		        EXPECT_EQ("falco", container_info->m_name);
		        EXPECT_EQ("docker.io/falcosecurity/falco:latest", container_info->m_image);
		        EXPECT_EQ("sha256:8d0619a4da278dfe2772f75aa3cc74df0a250385de56085766035db5c9a062ed",
		                  container_info->m_imagedigest);
		        EXPECT_EQ("4bc0e14060f4263acf658387e76715bd836a13b9ba44f48465bd0633a412dbd0",
		                  container_info->m_imageid);

		        done = true;
	        });
}

namespace {
void verify_cri_container_info(const sinsp_container_info& container_info) {
	EXPECT_EQ("falco", container_info.m_name);
	EXPECT_EQ("docker.io/falcosecurity/falco:latest", container_info.m_image);
	EXPECT_EQ("sha256:8d0619a4da278dfe2772f75aa3cc74df0a250385de56085766035db5c9a062ed",
	          container_info.m_imagedigest);
	EXPECT_EQ("4bc0e14060f4263acf658387e76715bd836a13b9ba44f48465bd0633a412dbd0",
	          container_info.m_imageid);
	EXPECT_EQ(1073741824, container_info.m_memory_limit);
	EXPECT_EQ(102, container_info.m_cpu_shares);
	EXPECT_EQ(0, container_info.m_cpu_quota);
	EXPECT_EQ(100000, container_info.m_cpu_period);
}

void verify_docker_container_info(const sinsp_container_info& container_info) {
	EXPECT_EQ("nginx", container_info.m_name);
	EXPECT_EQ("568c4670fa800978e08e4a51132b995a54f8d5ae83ca133ef5546d092b864acf",
	          container_info.m_imageid);
}

void verify_container_info(const std::string& container_id,
                           const exp_container_event_info& exp_info,
                           const sinsp_container_info& container_info) {
	EXPECT_EQ(cri_container_id, container_id);

	EXPECT_EQ(container_info.get_lookup_status(), exp_info.state);
	EXPECT_EQ(container_info.m_type, exp_info.type);
	if(exp_info.state == sinsp_container_lookup::state::SUCCESSFUL) {
		if(container_info.m_type == CT_CONTAINERD) {
			verify_cri_container_info(container_info);
		} else if(container_info.m_type == CT_DOCKER) {
			verify_docker_container_info(container_info);
		} else {
			FAIL() << "Unexpected container type " << (int)container_info.m_type;
		}
	}
}

}  // namespace

void container_cri::fake_cri_test_timing(const std::string& pb_prefix,
                                         const std::string& delay_arg,
                                         const std::string& runtime,
                                         float docker_delay,
                                         bool async,
                                         const exp_container_event_info& exp_info,
                                         uint64_t container_engine_mask,
                                         int64_t test_duration) {
	std::atomic<bool> saw_container_event(false);
	std::atomic<bool> saw_container_callback(false);
	unlink(fake_cri_socket.c_str());
	subprocess fake_cri_handle(LIBSINSP_TEST_PATH "/fake_cri/fake_cri",
	                           {delay_arg, "unix://" + fake_cri_socket, pb_prefix, runtime});
	pid_t fake_cri_pid = fake_cri_handle.get_pid();

	subprocess fake_docker_handle("/usr/bin/env",
	                              {"python3",
	                               LIBSINSP_TEST_RESOURCES_PATH "/fake_docker.py",
	                               std::to_string(docker_delay),
	                               fake_docker_socket});
	pid_t fake_docker_pid = fake_docker_handle.get_pid();

	auto start_time = time(NULL);

	event_filter_t filter = [&](sinsp_evt* evt) {
		return evt->get_type() == PPME_CONTAINER_JSON_E ||
		       evt->get_type() == PPME_CONTAINER_JSON_2_E;
	};

	run_callback_async_t test = [&]() {
		subprocess handle(LIBSINSP_TEST_PATH "/test_helper", {"cri_container_echo"});
		handle.in() << "\n";
		handle.wait();
		while(time(NULL) < start_time + test_duration) {
			usleep(100000);
		}
	};

	captured_event_callback_t container_event_callback = [&](const callback_param& param) {
		EXPECT_FALSE(saw_container_event) << "Received more than one container event";

		sinsp_threadinfo* tinfo = param.m_evt->get_tinfo();
		EXPECT_TRUE(tinfo != NULL);

		const auto container_info =
		        param.m_inspector->m_container_manager.get_container(tinfo->m_container_id);
		EXPECT_NE(container_info, nullptr);

		verify_container_info(tinfo->m_container_id, exp_info, *(container_info.get()));

		saw_container_event = true;
	};

	before_capture_t setup = [&](sinsp* inspector) {
		inspector->set_docker_socket_path(fake_docker_socket);
		inspector->set_cri_socket_path(fake_cri_socket);
		inspector->set_cri_extra_queries(false);
		inspector->set_cri_async(async);
		if(container_engine_mask != 0) {
			inspector->set_container_engine_mask(container_engine_mask);
		}
		inspector->m_container_manager.subscribe_on_new_container(
		        [&](const sinsp_container_info& container, sinsp_threadinfo* tinfo) {
			        EXPECT_FALSE(saw_container_callback)
			                << "Received more than one on_new_container callback";

			        verify_container_info(tinfo->m_container_id, exp_info, container);
			        saw_container_callback = true;
		        });
	};

	before_capture_t cleanup = [&](sinsp* inspector) {
		inspector->set_docker_socket_path(default_docker_socket);
	};

	EXPECT_NO_FATAL_FAILURE(
	        { event_capture::run(test, container_event_callback, filter, setup, cleanup); });

	// We only expect to see a container event when the lookup succeeds
	if(exp_info.state == sinsp_container_lookup::state::SUCCESSFUL) {
		EXPECT_TRUE(saw_container_event) << "Did not see expected container event";
	} else {
		EXPECT_FALSE(saw_container_event) << "Received container event but did not expect one";
	}

	// We always expect an on_new_container callback
	EXPECT_TRUE(saw_container_callback) << "Did not see expected on_new_container callback";

	// The fake servers had to stay running the whole time in order
	// for the test to be succesful
	// Needed to reap the zombine if it exited
	waitpid(fake_cri_pid, NULL, WNOHANG);
	EXPECT_TRUE(fake_cri_handle.is_alive());
	waitpid(fake_docker_pid, NULL, WNOHANG);
	EXPECT_TRUE(fake_docker_handle.is_alive());

	fake_cri_handle.kill();
	fake_docker_handle.kill();
}

TEST_F(container_cri, fake_cri_then_docker) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--nodelay",
	                     "containerd",
	                     0.5,
	                     true,
	                     exp_info);
}

TEST_F(container_cri, fake_docker_then_cri) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--slow",
	                     "containerd",
	                     0.0,
	                     true,
	                     exp_info);
}

TEST_F(container_cri, fake_cri_fail_then_docker) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     1.0,
	                     true,
	                     exp_info);
}

TEST_F(container_cri, fake_docker_then_cri_fail) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     0.0,
	                     true,
	                     exp_info);
}

TEST_F(container_cri, fake_cri_then_docker_fail) {
	exp_container_event_info exp_info{CT_CONTAINERD, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--nodelay",
	                     "containerd",
	                     -0.5,
	                     true,
	                     exp_info);
}

TEST_F(container_cri, fake_docker_fail_then_cri) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--slow",
	                     "containerd",
	                     -0.1,
	                     true,
	                     exp_info);
}

TEST_F(container_cri, fake_cri_fail) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::FAILED};

	// Run long enough for cri lookup to exhaust all retries
	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     -2.0,
	                     true,
	                     exp_info,
	                     1 << CT_CONTAINERD,
	                     40);
}

TEST_F(container_cri, docker_fail) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::FAILED};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     -0.1,
	                     true,
	                     exp_info,
	                     1 << CT_DOCKER);
}

TEST_F(container_cri, fake_cri_then_docker_sync) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--nodelay",
	                     "containerd",
	                     0.5,
	                     false,
	                     exp_info);
}

TEST_F(container_cri, fake_docker_then_cri_sync) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--slow",
	                     "containerd",
	                     0.0,
	                     false,
	                     exp_info);
}

TEST_F(container_cri, fake_cri_fail_then_docker_sync) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     1.0,
	                     false,
	                     exp_info);
}

TEST_F(container_cri, fake_docker_then_cri_fail_sync) {
	exp_container_event_info exp_info = {CT_DOCKER, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     0.0,
	                     false,
	                     exp_info);
}

TEST_F(container_cri, fake_cri_then_docker_fail_sync) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--nodelay",
	                     "containerd",
	                     -0.5,
	                     false,
	                     exp_info);
}

TEST_F(container_cri, fake_docker_fail_then_cri_sync) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::SUCCESSFUL};

	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--slow",
	                     "containerd",
	                     -0.1,
	                     false,
	                     exp_info);
}

TEST_F(container_cri, fake_cri_fail_sync) {
	exp_container_event_info exp_info = {CT_CONTAINERD, sinsp_container_lookup::state::FAILED};

	// Run long enough for cri lookup to exhaust all retries
	fake_cri_test_timing(LIBSINSP_TEST_RESOURCES_PATH "/fake_cri_falco",
	                     "--veryslow",
	                     "containerd",
	                     -2.0,
	                     false,
	                     exp_info,
	                     1 << CT_CONTAINERD);
}
