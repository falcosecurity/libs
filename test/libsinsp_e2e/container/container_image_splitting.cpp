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

#include <libsinsp/utils.h>

#include <list>
#include <string>

using namespace std;

static list<vector<string>> with_splitting_testcases = {
    //	 input host            port     name               tag       digest
    {"busybox", "", "", "busybox", "", ""},
    {"busybox:latest", "", "", "busybox", "latest", ""},
    {"busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "",
     "",
     "busybox",
     "1.27.2",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"my.host.name/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "my.host.name",
     "",
     "busybox",
     "1.27.2",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"my.host.name:12345/library/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "my.host.name",
     "12345",
     "library/busybox",
     "1.27.2",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"localhost:12345/library/busybox:1.27.2@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "localhost",
     "12345",
     "library/busybox",
     "1.27.2",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"}};

static list<vector<string>> without_splitting_testcases = {
    //       input repo                            tag       digest
    {"busybox", "busybox", "", ""},
    {"local.host:5000/libs/test", "local.host:5000/libs/test", "", ""},
    {"libs/test:dev", "libs/test", "dev", ""},
    {"local.host:5000/libs:1.0", "local.host:5000/libs", "1.0", ""},
    {"libs@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "libs",
     "",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"local.host:5000/nginx@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "local.host:5000/nginx",
     "",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"libs:1.0@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "libs",
     "1.0",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    {"local.host:5000/nginx:alpine@sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709",
     "local.host:5000/nginx",
     "alpine",
     "sha256:da39a3ee5e6b4b0d3255bfef95601890afd80709"}};

#define CHECK_VALUE(name, actual, expected)                             \
    ASSERT_EQ(actual, expected) << "Expected " << name " '" << expected \
    << "' did not match actual value '" << actual << "'"

TEST(container_image_splitting_test, with_repo_splitting)
{
	for (auto& testcase : with_splitting_testcases)
	{
		string hostname;
		string port;
		string name;
		string tag;
		string digest;

		sinsp_utils::split_container_image(testcase[0], hostname, port, name, tag, digest);

		CHECK_VALUE("hostname", hostname, testcase[1]);
		CHECK_VALUE("port", port, testcase[2]);
		CHECK_VALUE("name", name, testcase[3]);
		CHECK_VALUE("tag", tag, testcase[4]);
		CHECK_VALUE("digest", digest, testcase[5]);
	}
}

TEST(container_image_splitting_test, without_repo_splitting)
{
	for (auto& testcase : without_splitting_testcases)
	{
		string hostname, port;
		string repo;
		string tag;
		string digest;

		sinsp_utils::split_container_image(testcase[0], hostname, port, repo, tag, digest, false);

		CHECK_VALUE("repo", repo, testcase[1]);
		CHECK_VALUE("tag", tag, testcase[2]);
		CHECK_VALUE("digest", digest, testcase[3]);
	}
}
