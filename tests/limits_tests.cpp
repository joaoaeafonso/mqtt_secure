#include <memory>

#include "msec/limits/rate_limit_layer.hpp"
#include "test_support.hpp"

namespace msec::limits {
namespace {

using namespace std::chrono_literals;
using test::message;

class RateLimitTest : public ::testing::Test {
protected:
    std::unique_ptr<RateLimitLayer> make(RateLimitConfig config) {
        auto layer = RateLimitLayer::create(config, clock_);
        EXPECT_TRUE(layer.has_value());
        return layer ? std::move(*layer) : nullptr;
    }
    std::shared_ptr<test::FakeClock> clock_ = std::make_shared<test::FakeClock>();
};

TEST_F(RateLimitTest, UnlimitedByDefault) {
    auto layer = make({});
    for (int i = 0; i < 1000; ++i) {
        ASSERT_TRUE(layer->on_inbound(message("a", "x")).has_value());
    }
}

TEST_F(RateLimitTest, AllowsBurstThenRefillsAtRate) {
    auto layer = make({.messages_per_second = 10});
    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(layer->on_inbound(message("a", "x")).has_value()) << i;
    }
    EXPECT_EQ(layer->on_inbound(message("a", "x")).error().code, ErrorCode::RateLimited);
    clock_->advance(100ms);  // one token
    EXPECT_TRUE(layer->on_inbound(message("a", "x")).has_value());
    EXPECT_FALSE(layer->on_inbound(message("a", "x")).has_value());
}

TEST_F(RateLimitTest, TopicsHaveIndependentBudgets) {
    auto layer = make({.messages_per_second = 1});
    EXPECT_TRUE(layer->on_inbound(message("a", "x")).has_value());
    EXPECT_FALSE(layer->on_inbound(message("a", "x")).has_value());
    EXPECT_TRUE(layer->on_inbound(message("b", "x")).has_value());
}

TEST_F(RateLimitTest, OutboundIsNeverLimited) {
    auto layer = make({.messages_per_second = 1});
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(layer->on_outbound(message("a", "x")).has_value());
    }
}

TEST_F(RateLimitTest, RateCanChangeAtRuntime) {
    auto layer = make({.messages_per_second = 1});
    EXPECT_TRUE(layer->on_inbound(message("a", "x")).has_value());
    EXPECT_FALSE(layer->on_inbound(message("a", "x")).has_value());
    layer->set_rate(0);
    EXPECT_TRUE(layer->on_inbound(message("a", "x")).has_value());
}

TEST_F(RateLimitTest, MemoryStaysBoundedUnderTopicFlood) {
    auto layer = make({.messages_per_second = 1, .max_tracked_topics = 4});
    for (int i = 0; i < 100; ++i) {
        (void)layer->on_inbound(message("flood/" + std::to_string(i), "x"));
    }
    // Untracked topics share one bucket, so the flood cannot mint budget.
    EXPECT_FALSE(layer->on_inbound(message("flood/new", "x")).has_value());
}

TEST(RateLimitFactory, RejectsInvalidConfig) {
    EXPECT_FALSE(RateLimitLayer::create({}, nullptr).has_value());
    EXPECT_FALSE(RateLimitLayer::create({.messages_per_second = -1},
                                        std::make_shared<test::FakeClock>())
                     .has_value());
}

}  // namespace
}  // namespace msec::limits
