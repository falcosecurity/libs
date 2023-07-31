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

#include "sinsp.h"

#include <gtest/gtest.h>

using namespace std;

#ifdef __x86_64__
TEST(savefile, proclist)
{
	sinsp inspector;
	inspector.open_savefile(RESOURCE_DIR "/sample.scap");

	ASSERT_EQ(inspector.m_thread_manager->get_thread_count(), 94);
}
#endif