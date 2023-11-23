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

#include "mpsc_priority_queue.h"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>

TEST(mpsc_priority_queue, order_consistency)
{
    struct val
    {
        int v;
        int order;
    };

    struct val_less
	{
		bool operator()(const val& l, const val& r)
		{
			return std::greater_equal<int>{}(l.v, r.v);
		}
	};
    
    using val_t = std::unique_ptr<val>;

    mpsc_priority_queue<val_t, val_less> q;
    for (int i = 0; i < 100; i++)
    {
        for (int j = 0; j < 100; j++)
        {
            // j is used only for tracking the order in which elements
            // are pushed for checking it later
            q.push(val_t{new val{i,j}});
        }
    }

    val_t cur{nullptr};
    val_t prev{nullptr};
    while (!q.empty())
    {
        ASSERT_TRUE(q.try_pop(cur));
        if (prev != nullptr)
        {
            ASSERT_GE(cur->v, prev->v);
            if (cur->v == prev->v)
            {
                ASSERT_GT(cur->order, prev->order);
            }
        }
        prev = std::move(cur);
    }

}

// note: emscripten does not support launching threads
#ifndef __EMSCRIPTEN__

TEST(mpsc_priority_queue, single_concurrent_producer)
{
    using val_t = std::unique_ptr<int>;
    const int max_value = 1000;

    mpsc_priority_queue<val_t, std::greater_equal<int>> q;

    // single producer
    auto p = std::thread([&](){
        for (int i = 0; i < max_value; i++)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
            q.push(std::make_unique<int>(i));
        }
    });

    // single consumer
    val_t v;
    int i = 0;
    int failed = 0;
    while (i < max_value)
    {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        if (q.empty())
        {
            continue;
        }
        
        if (!q.try_pop(v))
        {
            failed++;
            continue;
        }

        failed += (*v.get() != i) ? 1 : 0;
        i++;
    }

    // wait for producer to stop
    p.join();

    // check we received everything in order
    ASSERT_EQ(failed, 0);
}

TEST(mpsc_priority_queue, multi_concurrent_producers)
{
    using val_t = std::unique_ptr<int>;
	const int num_values = 1000;
    const int num_producers = 10;

    mpsc_priority_queue<val_t, std::greater_equal<int>> q;
    std::atomic<int> counter{1};

    // multiple producer
    std::vector<std::thread> producers;
    for (int i = 0; i < num_producers; i++)
    {
        producers.emplace_back([&](){
            for (int i = 0; i <= num_values; i++)
            {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                q.push(std::make_unique<int>(counter++));
            }
        });
    }

    // single consumer
    val_t v;
    int i = 0;
    int failed = 0;
    int last_val = 0;
    while (i < num_values * num_producers)
    {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
        if (q.empty())
        {
            continue;
        }

        if (!q.try_pop_if(v, [&](const int& n) { return n >= last_val; }))
        {
            failed++;
            continue;
        }

        last_val = *v.get();
        i++;
    }

    // wait for producers to stop
    for (int i = 0; i < num_producers; i++)
    {
        producers[i].join();
    }

    // check we received everything in order
    ASSERT_EQ(failed, 0);
}

#endif // __EMSCRIPTEN__
