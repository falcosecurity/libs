#include "libsinsp/token_bucket.h"
#include <gtest/gtest.h>
#include <memory>

// token bucket default ctor
TEST(token_bucket, constructor)
{
	auto tb = std::make_shared<token_bucket>();

	EXPECT_EQ(tb->get_tokens(), 1);

	// initialising with specific time, rate 2 tokens/sec
	auto max = 2.0;
	uint64_t now = 1;
	tb->init(1.0, max, now);
	EXPECT_EQ(tb->get_last_seen(), now);
	EXPECT_EQ(tb->get_tokens(), max);
	
}

// token bucket ctor with custom timer
TEST(token_bucket, constructor_custom_timer)
{
	auto t = []() -> uint64_t { return 22; };
	auto tb = std::make_shared<token_bucket>(t);

	EXPECT_EQ(tb->get_tokens(), 1);
	EXPECT_EQ(tb->get_last_seen(), 22);
}

// token bucket with 2 tokens/sec rate, max 10 tokens
TEST(token_bucket, two_token_per_sec_ten_max)
{
	auto tb = std::make_shared<token_bucket>();
	tb->init(2.0, 10, 1);

	// claiming 5 tokens
	{
		bool claimed = tb->claim(5, 1000000001);
		EXPECT_EQ(tb->get_last_seen(), 1000000001);
		EXPECT_EQ(tb->get_tokens(), 5.0);
		EXPECT_TRUE(claimed);
	}

	// claiming all the 7 remaining tokens	
	{ 
		bool claimed = tb->claim(7, 2000000001);
		EXPECT_EQ(tb->get_last_seen(), 2000000001);
		EXPECT_EQ(tb->get_tokens(), 0.0);
		EXPECT_TRUE(claimed);
	}

	// claiming 1 token more than the 2 available fails		
	{
		bool claimed = tb->claim(3, 3000000001);
		EXPECT_EQ(tb->get_last_seen(),3000000001);
		EXPECT_EQ(tb->get_tokens(), 2.0);
		EXPECT_FALSE(claimed);
	}
}

// token bucket default initialization
TEST(token_bucket, default_init)
{
	token_bucket tb;
	EXPECT_EQ(tb.get_tokens(), 1);
}
