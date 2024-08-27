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

#include <gtest/gtest.h>

#include <libsinsp/runc.cpp>

using namespace libsinsp::runc;

constexpr const cgroup_layout CRI_CGROUP_LAYOUT[] = {
    {"/", ""},                   // non-systemd containerd
    {"/crio-", ""},              // non-systemd cri-o
    {"/containerd-", ".scope"},  // systemd containerd (?)
    {"/crio-", ".scope"},        // systemd cri-o
    {":cri-containerd:", ""},    // unknown containerd seen in the wild
    {nullptr, nullptr}};

constexpr const cgroup_layout DOCKER_CGROUP_LAYOUT[] = {{"/", ""},  // non-systemd docker
                                                        {"/docker-", ".scope"},  // systemd docker
                                                        {nullptr, nullptr}};

class container_cgroup : public testing::Test
{
};

TEST_F(container_cgroup, containerd_cgroupfs)
{
	std::string container_id;
	const std::string cgroup =
	    "/kubepods/besteffort/podac04f3f2-1f2c-11e9-b015-1ebee232acfa/"
	    "605439acbd4fb18c145069289094b17f17e0cfa938f78012d4960bc797305f22";
	const std::string expected_container_id = "605439acbd4f";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, crio_cgroupfs)
{
	std::string container_id;
	const std::string cgroup =
	    "/kubepods/besteffort/pod63b3ebfc-2890-11e9-8154-16bf8ef8d9dc/"
	    "crio-73bfe475650de66df8e2affdc98d440dcbe84f8df83b6f75a68a82eb7026136a";
	const std::string expected_container_id = "73bfe475650d";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, crio_systemd)
{
	std::string container_id;
	const std::string cgroup =
	    "/kubepods.slice/kubepods-besteffort.slice/"
	    "kubepods-besteffort-pod63b3ebfc_2890_11e9_8154_16bf8ef8d9dc.slice/"
	    "crio-17d8c9eacc629f9945f304d89e9708c0c619649a484a215b240628319548a09f.scope";
	const std::string expected_container_id = "17d8c9eacc62";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, docker_cgroupfs)
{
	std::string container_id;
	const std::string cgroup =
	    "/docker/7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe5392991e3b12251e6b8";
	const std::string expected_container_id = "7951fb549ab9";

	EXPECT_EQ(true, match_container_id(cgroup, DOCKER_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, docker_systemd)
{
	std::string container_id;
	const std::string cgroup =
	    "/docker.slice/"
	    "docker-7951fb549ab99e0722a949b6c121634e1f3a36b5bacbe5392991e3b12251e6b8.scope";
	const std::string expected_container_id = "7951fb549ab9";

	EXPECT_EQ(true, match_container_id(cgroup, DOCKER_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}

TEST_F(container_cgroup, containerd_unknown)
{
	std::string container_id;
	const std::string cgroup =
	    "/kubepods-burstable-podbd12dd3393227d950605a2444b13c27a.slice:cri-containerd:"
	    "d52db56a9c80d536a91354c0951c061187ca46249e64865a12703003d8f42366";
	const std::string expected_container_id = "d52db56a9c80";

	EXPECT_EQ(true, match_container_id(cgroup, CRI_CGROUP_LAYOUT, container_id));
	EXPECT_EQ(expected_container_id, container_id);
}
