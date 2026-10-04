#include <memory>
#include <string>
#include <vector>

#include "msec/core/pipeline.hpp"
#include "msec/core/secure_buffer.hpp"
#include "msec/core/switchable_layer.hpp"
#include "test_support.hpp"

namespace msec {
namespace {

using test::message;

TEST(Topic, AcceptsValidNames) {
    EXPECT_TRUE(Topic::create("sensors/room1/temp").has_value());
    EXPECT_TRUE(Topic::create("/leading/slash").has_value());
}

TEST(Topic, RejectsInvalidNames) {
    EXPECT_EQ(Topic::create("").error().code, ErrorCode::InvalidArgument);
    EXPECT_FALSE(Topic::create("sensors/+/temp").has_value());
    EXPECT_FALSE(Topic::create("sensors/#").has_value());
    EXPECT_FALSE(Topic::create(std::string_view{"a\0b", 3}).has_value());
    EXPECT_FALSE(Topic::create(std::string(Topic::kMaxLength + 1, 'a')).has_value());
}

TEST(SecureBuffer, MoveTransfersOwnership) {
    SecureBuffer a{to_bytes("secret")};
    SecureBuffer b{std::move(a)};
    EXPECT_EQ(b.size(), 6U);
    EXPECT_TRUE(a.empty());  // NOLINT(bugprone-use-after-move): verifying moved-from state
}

TEST(SecureZero, ZeroesMemory) {
    Bytes data = to_bytes("secret");
    secure_zero(data);
    for (const auto b : data) {
        EXPECT_EQ(b, std::byte{0});
    }
}

/// Appends its name to a shared trace on every pass; optionally fails.
class TracingLayer final : public ILayer {
public:
    TracingLayer(std::string name, std::vector<std::string>& trace, bool fail = false)
        : name_{std::move(name)}, trace_{trace}, fail_{fail} {}
    [[nodiscard]] std::string_view name() const noexcept override { return name_; }
    [[nodiscard]] Result<Message> on_outbound(Message m) override { return pass("out", std::move(m)); }
    [[nodiscard]] Result<Message> on_inbound(Message m) override { return pass("in", std::move(m)); }

private:
    Result<Message> pass(const std::string& dir, Message m) {
        trace_.push_back(dir + ":" + name_);
        if (fail_) {
            return make_error(ErrorCode::AuthenticationFailed, "boom");
        }
        return m;
    }
    std::string name_;
    std::vector<std::string>& trace_;
    bool fail_;
};

TEST(Pipeline, OutboundTopDownInboundBottomUp) {
    std::vector<std::string> trace;
    auto pipeline = Pipeline::Builder{}
                        .add(std::make_unique<TracingLayer>("A", trace))
                        .add(std::make_unique<TracingLayer>("B", trace))
                        .build();
    ASSERT_TRUE(pipeline.has_value());

    ASSERT_TRUE(pipeline->process_outbound(message("t", "x")).has_value());
    ASSERT_TRUE(pipeline->process_inbound(message("t", "x")).has_value());
    EXPECT_EQ(trace, (std::vector<std::string>{"out:A", "out:B", "in:B", "in:A"}));
}

TEST(Pipeline, FailureStopsProcessingAndNamesLayer) {
    std::vector<std::string> trace;
    auto pipeline = Pipeline::Builder{}
                        .add(std::make_unique<TracingLayer>("A", trace, /*fail=*/true))
                        .add(std::make_unique<TracingLayer>("B", trace))
                        .build();
    ASSERT_TRUE(pipeline.has_value());

    const auto result = pipeline->process_outbound(message("t", "x"));
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, ErrorCode::AuthenticationFailed);
    EXPECT_EQ(result.error().message, "[A] boom");
    EXPECT_EQ(trace, std::vector<std::string>{"out:A"});
}

TEST(Pipeline, RejectsNullAndDuplicateLayers) {
    std::vector<std::string> trace;
    EXPECT_FALSE(Pipeline::Builder{}.add(nullptr).build().has_value());
    EXPECT_FALSE(Pipeline::Builder{}
                     .add(std::make_unique<TracingLayer>("A", trace))
                     .add(std::make_unique<TracingLayer>("A", trace))
                     .build()
                     .has_value());
}

TEST(SwitchableLayer, PassesThroughWhileDisabled) {
    std::vector<std::string> trace;
    auto layer = SwitchableLayer::create(std::make_unique<TracingLayer>("A", trace, /*fail=*/true),
                                         /*enabled=*/false);
    ASSERT_TRUE(layer.has_value());
    auto& toggle = **layer;
    EXPECT_EQ(toggle.name(), "A");

    EXPECT_TRUE(toggle.on_outbound(message("t", "x")).has_value());
    EXPECT_TRUE(toggle.on_inbound(message("t", "x")).has_value());
    EXPECT_TRUE(trace.empty());

    toggle.set_enabled(true);
    EXPECT_FALSE(toggle.on_inbound(message("t", "x")).has_value());
    EXPECT_EQ(trace, std::vector<std::string>{"in:A"});
}

TEST(SwitchableLayer, RenamesSoTheSameLayerCanAppearTwice) {
    std::vector<std::string> trace;
    auto first = SwitchableLayer::create(std::make_unique<TracingLayer>("A", trace), true, "A-top");
    auto second = SwitchableLayer::create(std::make_unique<TracingLayer>("A", trace), true, "A-bottom");
    ASSERT_TRUE(first.has_value() && second.has_value());
    auto pipeline = Pipeline::Builder{}.add(std::move(*first)).add(std::move(*second)).build();
    ASSERT_TRUE(pipeline.has_value());
    EXPECT_EQ(pipeline->layer_names(), (std::vector<std::string_view>{"A-top", "A-bottom"}));
    EXPECT_FALSE(SwitchableLayer::create(nullptr).has_value());
}

}  // namespace
}  // namespace msec
