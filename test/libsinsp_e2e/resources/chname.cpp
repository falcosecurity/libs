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

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>

#include <chrono>
#include <functional>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

void run()
{
	while (true)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

void changer(char** argv)
{
	char pname[] = "sysdig";
	memcpy((void*)argv[0], pname, sizeof(pname));
	while (true)
	{
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}
}

int main(int argc, char** argv)
{
	char pname[] = "savonarola";
	prctl(PR_SET_NAME, (unsigned long)&pname, 0, 0, 0);
	std::vector<std::shared_ptr<std::thread>> threads;
	for (int j = 0; j < 20; ++j)
	{
		threads.push_back(std::make_shared<std::thread>(run));
	}

	auto binded_changer = std::bind(changer, argv);
	std::thread changer(binded_changer);
	run();
}
