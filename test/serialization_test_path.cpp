#include "elog_entry.hpp"
#include "elog_serialize.hpp"
#include "serialization_tests.hpp"

#include <filesystem>
#include <fstream>
#include <map>

namespace phosphor
{
namespace logging
{
namespace test
{

TEST_F(TestSerialization, testPath)
{
    auto id = 99;
    auto e = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, manager);
    auto path = serialize(*e, TestSerialization::dir);
    EXPECT_EQ(path.c_str(), TestSerialization::dir / std::to_string(id));
}

TEST_F(TestSerialization, testGetEntrySerializePath)
{
    auto path = getEntrySerializePath(123, TestSerialization::dir);
    EXPECT_EQ(path.parent_path(), TestSerialization::dir);
    EXPECT_EQ(path.filename(), "123");
}

TEST_F(TestSerialization, testGetEntrySerializePathZeroId)
{
    auto path = getEntrySerializePath(0, TestSerialization::dir);
    EXPECT_EQ(path.filename(), "0");
}

TEST_F(TestSerialization, testDeserializeNonExistentFile)
{
    auto id = 102;
    auto e = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, manager);
    auto nonExistentPath = TestSerialization::dir / "nonexistent_file";
    EXPECT_FALSE(deserialize(nonExistentPath, *e));
}

TEST_F(TestSerialization, testDeserializeEmptyPath)
{
    auto id = 103;
    auto e = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, manager);
    std::filesystem::path emptyPath;
    EXPECT_FALSE(deserialize(emptyPath, *e));
}

TEST_F(TestSerialization, testGetEntrySerializePathLargeId)
{
    auto path = getEntrySerializePath(999999, TestSerialization::dir);
    EXPECT_EQ(path.parent_path(), TestSerialization::dir);
    EXPECT_EQ(path.filename(), "999999");
}

TEST_F(TestSerialization, testSerializePathsAreUnique)
{
    std::vector<std::filesystem::path> paths;

    for (int i = 300; i < 305; ++i)
    {
        auto path = getEntrySerializePath(i, TestSerialization::dir);
        paths.push_back(path);
    }

    for (size_t i = 0; i < paths.size(); ++i)
    {
        for (size_t j = i + 1; j < paths.size(); ++j)
        {
            EXPECT_NE(paths[i], paths[j])
                << "Paths " << i << " and " << j << " are not unique";
        }
    }
}

TEST_F(TestSerialization, testSerializeUsesCorrectDirectory)
{
    for (int id = 400; id < 403; ++id)
    {
        auto path = getEntrySerializePath(id, TestSerialization::dir);
        EXPECT_EQ(path.parent_path(), TestSerialization::dir);
    }
}

TEST_F(TestSerialization, testSerializePathFormat)
{
    uint32_t testIds[] = {1, 99, 100, 999, 10000};

    for (auto id : testIds)
    {
        auto path = getEntrySerializePath(id, TestSerialization::dir);

        EXPECT_TRUE(path.has_filename());
        EXPECT_EQ(path.filename(), std::to_string(id));
        EXPECT_TRUE(path.has_parent_path());
    }
}

TEST_F(TestSerialization, testSerializeSingleArgUsesEntryPath)
{
    auto id = 200;
    std::string serialPath =
        (TestSerialization::dir / std::to_string(id)).string();
    auto e = std::make_unique<Entry>(
        bus, std::string(OBJ_ENTRY) + '/' + std::to_string(id), id, 100,
        Entry::Level::Informational, "msg",
        std::map<std::string, std::string>{},
        phosphor::logging::AssociationList{}, "fw", serialPath, manager);
    auto path = serialize(*e);
    EXPECT_EQ(path.string(), serialPath);
    EXPECT_TRUE(std::filesystem::exists(path));
}

} // namespace test
} // namespace logging
} // namespace phosphor
