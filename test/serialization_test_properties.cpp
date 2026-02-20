#include "elog_entry.hpp"
#include "elog_serialize.hpp"
#include "serialization_tests.hpp"

#include <filesystem>
#include <fstream>

namespace phosphor
{
namespace logging
{
namespace test
{

TEST_F(TestSerialization, testDeserializeCorruptFile)
{
    auto id = 101;
    auto e = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, manager);
    auto corruptPath = TestSerialization::dir / "corrupt_entry";
    {
        // Use corrupt data with zero size for the first string (message) so
        // Cereal does not attempt huge allocations (e.g. under Valgrind).
        // Use only 28 bytes so the stream ends before the next field (vector
        // size); deserialize then fails and returns false.
        std::ofstream f(corruptPath, std::ios::binary);
        const char zeros[28] = {0};
        f.write(zeros, sizeof(zeros));
    }
    EXPECT_TRUE(std::filesystem::exists(corruptPath));
    bool result = deserialize(corruptPath, *e);
    EXPECT_FALSE(result);
}

TEST_F(TestSerialization, testProperties)
{
    auto id = 99;
    phosphor::logging::AssociationList assocations{};
    std::map<std::string, std::string> testData = {{"additional", "1"},
                                                   {"data", "yes"}};
    uint64_t timestamp{100};
    std::string message{"test error"};
    std::string fwLevel{"level42"};
    std::string inputPath = getEntrySerializePath(id, TestSerialization::dir);
    auto input = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, timestamp,
        Entry::Level::Informational, std::move(message), std::move(testData),
        std::move(assocations), fwLevel, inputPath, manager);
    auto path = serialize(*input, TestSerialization::dir);
    EXPECT_EQ(path, inputPath);

    auto idStr = path.filename();
    id = std::stol(idStr.c_str());
    auto output = std::make_unique<Entry>(
        bus, std::filesystem::path(OBJ_ENTRY) / idStr, id, manager);
    deserialize(path, *output);

    EXPECT_EQ(input->id(), output->id());
    EXPECT_EQ(input->severity(), output->severity());
    EXPECT_EQ(input->timestamp(), output->timestamp());
    EXPECT_EQ(input->message(), output->message());
    EXPECT_EQ(input->additionalData(), output->additionalData());
    EXPECT_EQ(input->resolved(), output->resolved());
    EXPECT_EQ(input->associations(), output->associations());
    EXPECT_EQ(input->version(), output->version());
    EXPECT_EQ(input->purpose(), output->purpose());
    EXPECT_EQ(input->updateTimestamp(), output->updateTimestamp());
}

TEST_F(TestSerialization, testPropertiesWithResolutionAndEventId)
{
    auto id = 98;
    phosphor::logging::AssociationList assocs{};
    std::map<std::string, std::string> testData = {{"key", "value"}};
    std::string inputPath = getEntrySerializePath(id, TestSerialization::dir);
    auto input = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, 200,
        Entry::Level::Error, "msg", std::move(testData), std::move(assocs),
        "fw", inputPath, manager);

    input->resolution("resolved by test");
    input->eventId("evid-123");

    auto path = serialize(*input, TestSerialization::dir);
    auto output = std::make_unique<Entry>(
        bus, std::filesystem::path(OBJ_ENTRY) / std::to_string(id), id,
        manager);
    deserialize(path, *output);

    EXPECT_EQ(output->resolution(), "resolved by test");
    EXPECT_EQ(output->eventId(), "evid-123");
}

} // namespace test
} // namespace logging
} // namespace phosphor
