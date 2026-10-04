#include <memory>

#include "msec/data/in_memory_repository.hpp"
#include "msec/data/persistence_layer.hpp"
#include "test_support.hpp"

namespace msec::data {
namespace {

using test::message;

TEST(InMemoryRepository, EvictsOldestWhenFull) {
    InMemoryMessageRepository repo{2};
    const auto now = std::chrono::system_clock::now();
    ASSERT_TRUE(repo.store(message("t", "1"), Direction::Inbound, now).has_value());
    ASSERT_TRUE(repo.store(message("t", "2"), Direction::Inbound, now).has_value());
    ASSERT_TRUE(repo.store(message("t", "3"), Direction::Inbound, now).has_value());

    EXPECT_EQ(repo.size(), 2U);
    const auto latest = repo.latest(10);
    ASSERT_TRUE(latest.has_value());
    ASSERT_EQ(latest->size(), 2U);
    EXPECT_EQ(bytes_to_string((*latest)[0].message.payload), "3");
    EXPECT_EQ(bytes_to_string((*latest)[1].message.payload), "2");
}

TEST(InMemoryRepository, FindByTopic) {
    InMemoryMessageRepository repo{10};
    const auto now = std::chrono::system_clock::now();
    ASSERT_TRUE(repo.store(message("a", "1"), Direction::Inbound, now).has_value());
    ASSERT_TRUE(repo.store(message("b", "2"), Direction::Inbound, now).has_value());
    ASSERT_TRUE(repo.store(message("a", "3"), Direction::Inbound, now).has_value());

    const auto found = repo.find_by_topic(test::topic("a"), 10);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->size(), 2U);
}

TEST(PersistenceLayer, StoresAccordingToConfig) {
    auto repo = std::make_shared<InMemoryMessageRepository>(10);
    auto layer = PersistenceLayer::create(repo, std::make_shared<test::FakeClock>(),
                                          {.store_inbound = true, .store_outbound = false});
    ASSERT_TRUE(layer.has_value());

    ASSERT_TRUE((*layer)->on_outbound(message("t", "out")).has_value());
    ASSERT_TRUE((*layer)->on_inbound(message("t", "in")).has_value());
    EXPECT_EQ(repo->size(), 1U);
}

TEST(PersistenceLayer, RejectsMissingDependencies) {
    EXPECT_FALSE(PersistenceLayer::create(nullptr, std::make_shared<test::FakeClock>()).has_value());
}

}  // namespace
}  // namespace msec::data
