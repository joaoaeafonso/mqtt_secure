#include <vector>

#include "msec/mqtt/loopback_broker.hpp"
#include "msec/mqtt/topic_filter.hpp"
#include "test_support.hpp"

namespace msec::mqtt {
namespace {

TEST(TopicFilter, Matching) {
    EXPECT_TRUE(topic_matches("a/b/c", "a/b/c"));
    EXPECT_TRUE(topic_matches("a/+/c", "a/b/c"));
    EXPECT_TRUE(topic_matches("a/#", "a/b/c"));
    EXPECT_TRUE(topic_matches("a/#", "a"));  // '#' includes the parent level
    EXPECT_TRUE(topic_matches("#", "a/b"));
    EXPECT_FALSE(topic_matches("a/+", "a/b/c"));
    EXPECT_FALSE(topic_matches("a/b", "a/b/c"));
    EXPECT_FALSE(topic_matches("#", "$SYS/broker"));  // §4.7.2
    EXPECT_TRUE(topic_matches("$SYS/#", "$SYS/broker"));
}

TEST(TopicFilter, Validation) {
    EXPECT_TRUE(validate_topic_filter("a/+/c").has_value());
    EXPECT_TRUE(validate_topic_filter("a/#").has_value());
    EXPECT_FALSE(validate_topic_filter("a/b+").has_value());
    EXPECT_FALSE(validate_topic_filter("a/#/c").has_value());
    EXPECT_FALSE(validate_topic_filter("").has_value());
}

TEST(Loopback, RoutesToMatchingSubscribersOnly) {
    auto broker = LoopbackBroker::create();
    auto pub = LoopbackClient::create(broker);
    auto sub = LoopbackClient::create(broker);
    ASSERT_TRUE(pub->connect({}).has_value());
    ASSERT_TRUE(sub->connect({}).has_value());

    std::vector<std::string> received;
    sub->set_message_handler([&](Message m) { received.push_back(m.topic.str()); });
    ASSERT_TRUE(sub->subscribe("sensors/+/temp", QoS::AtLeastOnce).has_value());

    ASSERT_TRUE(pub->publish(test::message("sensors/r1/temp", "1")).has_value());
    ASSERT_TRUE(pub->publish(test::message("sensors/r1/hum", "2")).has_value());
    EXPECT_EQ(received, std::vector<std::string>{"sensors/r1/temp"});
}

TEST(Loopback, PublishRequiresConnection) {
    auto client = LoopbackClient::create(LoopbackBroker::create());
    EXPECT_EQ(client->publish(test::message("t", "x")).error().code, ErrorCode::NotConnected);
}

}  // namespace
}  // namespace msec::mqtt
