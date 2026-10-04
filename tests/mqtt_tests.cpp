#include <vector>

#include "msec/mqtt/access_control.hpp"
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

// ------------------------------------------------------- access control ---

AccessControlList zoned_acl() {
    AccessControlList acl;
    EXPECT_TRUE(acl.allow_all("open/#", Access::ReadWrite).has_value());
    EXPECT_TRUE(acl.allow("sensor-1", "restricted/sensors/room1/#", Access::Write).has_value());
    EXPECT_TRUE(acl.allow("gateway", "restricted/sensors/#", Access::Read).has_value());
    return acl;
}

TEST(AccessControl, DeniesByDefaultAndMatchesPerClient) {
    const auto acl = zoned_acl();
    EXPECT_TRUE(acl.can_publish("sensor-1", "restricted/sensors/room1/temp"));
    EXPECT_FALSE(acl.can_publish("sensor-1", "restricted/sensors/room2/temp"));
    EXPECT_FALSE(acl.can_read("sensor-1", "restricted/sensors/room1/temp"));  // write-only
    EXPECT_TRUE(acl.can_read("gateway", "restricted/sensors/room1/temp"));
    EXPECT_FALSE(acl.can_publish("gateway", "restricted/sensors/room1/temp"));
    EXPECT_FALSE(acl.can_read("mallory", "restricted/sensors/room1/temp"));
    EXPECT_TRUE(acl.can_read("mallory", "open/telemetry"));
    EXPECT_TRUE(acl.can_publish("", "open/telemetry"));  // any client, even anonymous
    EXPECT_FALSE(acl.can_publish("sensor-1", "elsewhere"));
}

TEST(AccessControl, RejectsInvalidRules) {
    AccessControlList acl;
    EXPECT_FALSE(acl.allow("", "a/#", Access::Read).has_value());
    EXPECT_FALSE(acl.allow_all("a/#/b", Access::Read).has_value());
}

TEST(Loopback, AclBlocksUnauthorizedPublish) {
    auto broker = LoopbackBroker::create(zoned_acl());
    auto mallory = LoopbackClient::create(broker);
    ASSERT_TRUE(mallory->connect({.client_id = "mallory"}).has_value());
    EXPECT_EQ(mallory->publish(test::message("restricted/sensors/room1/temp", "99")).error().code,
              ErrorCode::PermissionDenied);
    EXPECT_TRUE(mallory->publish(test::message("open/telemetry", "hi")).has_value());
}

TEST(Loopback, WildcardSubscriberOnlyReceivesReadableTopics) {
    auto broker = LoopbackBroker::create(zoned_acl());
    auto sensor = LoopbackClient::create(broker);
    auto gateway = LoopbackClient::create(broker);
    auto mallory = LoopbackClient::create(broker);
    ASSERT_TRUE(sensor->connect({.client_id = "sensor-1"}).has_value());
    ASSERT_TRUE(gateway->connect({.client_id = "gateway"}).has_value());
    ASSERT_TRUE(mallory->connect({.client_id = "mallory"}).has_value());

    std::vector<std::string> gateway_got;
    std::vector<std::string> mallory_got;
    gateway->set_message_handler([&](Message m) { gateway_got.push_back(m.topic.str()); });
    mallory->set_message_handler([&](Message m) { mallory_got.push_back(m.topic.str()); });
    ASSERT_TRUE(gateway->subscribe("#", QoS::AtLeastOnce).has_value());
    ASSERT_TRUE(mallory->subscribe("#", QoS::AtLeastOnce).has_value());

    ASSERT_TRUE(sensor->publish(test::message("restricted/sensors/room1/temp", "1")).has_value());
    ASSERT_TRUE(sensor->publish(test::message("open/telemetry", "2")).has_value());

    EXPECT_EQ(gateway_got,
              (std::vector<std::string>{"restricted/sensors/room1/temp", "open/telemetry"}));
    EXPECT_EQ(mallory_got, std::vector<std::string>{"open/telemetry"});
}

TEST(Loopback, PublishRequiresConnection) {
    auto client = LoopbackClient::create(LoopbackBroker::create());
    EXPECT_EQ(client->publish(test::message("t", "x")).error().code, ErrorCode::NotConnected);
}

}  // namespace
}  // namespace msec::mqtt
