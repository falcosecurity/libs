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
#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, thread_pool)
{
    open_inspector();

    auto& tp = m_inspector.m_thread_pool;
    
    ASSERT_NE(tp, nullptr);
    ASSERT_EQ(tp->routines_num(), 0);

    // subscribe a routine that keeps running until unsubscribed
    auto r = tp->subscribe([]
        {
            return true;
        });

    // check if the routine has been subscribed
    ASSERT_NE(r, nullptr);
    ASSERT_EQ(tp->routines_num(), 1);

    // check if the routine has been unsubscribed
    tp->unsubscribe(r);
    ASSERT_EQ(tp->routines_num(), 0);

    // subscribe a routine that keeps running until a condition is met (returns false)
    int count = 0;
    r = tp->subscribe([&count]
        {
            if(count >= 1000)
            {
                return false;
            }
            count++;
            usleep(500);
            return true;
        });
    ASSERT_EQ(tp->routines_num(), 1);

    // the routine above keeps increasing a counter every 500 microsenconds, until the counter reaches 1000
    // we give the routine enough time to finish, then we check if it has been unsubscribed
    sleep(1);
    ASSERT_EQ(count, 1000);
    ASSERT_EQ(tp->routines_num(), 0); 

    // all the remaining routines should be unsubscribed when the inspector is closed 
    r = tp->subscribe([]
        {
            return true;
        });
    ASSERT_EQ(tp->routines_num(), 1);
    m_inspector.close();
    ASSERT_EQ(tp->routines_num(), 0);
}