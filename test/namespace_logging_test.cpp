#include "config.h"

#include "log_manager.hpp"

#include <filesystem>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace logging
{
namespace test
{

namespace fs = std::filesystem;

class TestNamespaceLogging : public testing::Test
{
  public:
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    phosphor::logging::internal::Manager manager;

    TestNamespaceLogging() : manager(mockedBus, OBJ_INTERNAL){};

    ~TestNamespaceLogging()
    {
    }
};

std::size_t countFilesinDirectory(std::filesystem::path path)
{
    return (std::size_t)std::distance(std::filesystem::directory_iterator{path},
                                      std::filesystem::directory_iterator{});
}

TEST_F(TestNamespaceLogging, testBinCreation)
{
    // Create the Bin
    std::string binName = "tempBin";
    auto binErrorCapacity = 10;
    auto binInfoCapacity = 20;
    auto bin = phosphor::logging::internal::Bin(
        binName, binErrorCapacity, binInfoCapacity,
        std::string(ERRLOG_PERSIST_PATH) + "/" + binName, true);

    // Add Bin to the Manager
    manager.addBin(bin);

    // Test 0: Check if EntryID is reset
    EXPECT_EQ(manager.lastEntryID(), 0);

    // Create Error in Bin 'binName'
    manager.create("Test Error", Entry::Level::Informational,
                   {{DEFAULT_BIN_KEY, binName}});

    // Test 1: Check if the error falls in the correct Bin
    EXPECT_EQ(manager.binEntryMap[manager.lastEntryID()], binName);

    // Test 2: Check for the correct info entry size of the bin
    EXPECT_EQ(manager.getBin("tempBin").infoEntries.size(), 1);

    // Test 3: Make sure one new entry was created
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              1);

    // Erase all entries
    manager.eraseAll();

    // Test 4: Make sure entries got erased
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              0);

}

TEST_F(TestNamespaceLogging, testEraseAll)
{
    // Create the Bin
    std::string binName = "tempBin";
    auto binErrorCapacity = 10;
    auto binInfoCapacity = 20;
    auto bin = phosphor::logging::internal::Bin(
        binName, binErrorCapacity, binInfoCapacity,
        std::string(ERRLOG_PERSIST_PATH) + "/" + binName, true);

    // Add Bin to the Manager
    manager.addBin(bin);

    // Test 0: Check if EntryID is reset
    EXPECT_EQ(manager.lastEntryID(), 0);

    for (size_t i = 0; i < ERROR_CAP + binErrorCapacity; i++)
    {
        manager.create("Test Informational Error Event",
                       Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Test Error Event", Entry::Level::Error,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Test Error Event", Entry::Level::Error, {});
        manager.create("Test Error Event", Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    }

    manager.eraseAll();

    EXPECT_EQ(manager.lastEntryID(), 0);

    // Test 1: Test default bin sizes are 0
    EXPECT_EQ(manager.getRealErrSize() + manager.getInfoErrSize(), 0);

    // Test 2; Test 'binName' bin sizes are 0
    EXPECT_EQ(manager.getRealErrSize(std::string(binName)) +
                  manager.getInfoErrSize(std::string(binName)),
              0);

    // Test 3: Test 'binName' FS files are 0
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              0);
}

TEST_F(TestNamespaceLogging, testBinCapacity)
{
    // Create the Bin
    std::string binName = "tempBin";
    auto binErrorCapacity = 10;
    auto binInfoCapacity = 20;
    auto bin = phosphor::logging::internal::Bin(
        binName, binErrorCapacity, binInfoCapacity,
        std::string(ERRLOG_PERSIST_PATH) + "/" + binName, true);

    // Add Bin to the Manager
    manager.addBin(bin);

    // Create errors
    // - N Informational Logs in Bin 'binName'
    // - N Error Logs in Bin 'binName'
    // - N Error Logs in default bin
    // - N Informational Logs in default bin
    for (size_t i = 0; i < ERROR_CAP + binErrorCapacity; i++)
    {
        manager.create("Test Informational Error Event",
                       Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Test Error Event", Entry::Level::Error,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Test Error Event", Entry::Level::Error, {});
        manager.create("Test Error Event", Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    }

    // Test 1: Test Bin Information Error Capacity
    EXPECT_EQ(manager.getInfoErrSize(std::string(binName)), binInfoCapacity);

    // Test 2: Test Bin Real Error Capacity
    EXPECT_EQ(manager.getRealErrSize(std::string(binName)), binErrorCapacity);

    // Test 3: Negative Test Information Error Capacity
    EXPECT_NE(manager.getInfoErrSize(std::string(binName)),
              ERROR_CAP + binErrorCapacity + 1);

    // Test 4: Negative Test Real Error Capacity
    EXPECT_NE(manager.getRealErrSize(std::string(binName)),
              ERROR_CAP + binErrorCapacity);

    // Test 5: Test default bin Information Error Capacity
    EXPECT_EQ(manager.getInfoErrSize(), ERROR_INFO_CAP);

    // Test 6: Test default bin Real Error Capacity
    EXPECT_EQ(manager.getRealErrSize(), ERROR_CAP);

    // Test 7: Check EntryID
    EXPECT_EQ(manager.lastEntryID(), 4 * (ERROR_CAP + binErrorCapacity));

    // Test 8: Count number of FS entries in created in bin
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              binInfoCapacity + binErrorCapacity);

    manager.eraseAll();
}

TEST_F(TestNamespaceLogging, testLogPersistency)
{
    // Create the Bin
    std::string binName = "tempBin";
    auto binErrorCapacity = 10;
    auto binInfoCapacity = 20;
    auto bin = phosphor::logging::internal::Bin(
        binName, binErrorCapacity, binInfoCapacity,
        std::string(ERRLOG_PERSIST_PATH) + "/" + binName, false);

    // Add Bin to the Manager
    manager.addBin(bin);

    // Test 0: Check if EntryID is reset
    EXPECT_EQ(manager.lastEntryID(), 0);

    // Create Informational log in Bin 'binName'
    manager.create("Test Error", Entry::Level::Informational,
                   {{DEFAULT_BIN_KEY, binName}});

    // Test 1: Check if the error falls in the correct Bin
    EXPECT_EQ(manager.binEntryMap[manager.lastEntryID()], binName);

    // Test 2: Check for the correct info entry size of the bin
    EXPECT_EQ(manager.getBin("tempBin").infoEntries.size(), 1);

    // Test 3: Since log is informational it should not be present in directory
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              0);
    manager.eraseAll();
    // Create Error log in Bin 'binName'
    manager.create("Test Error", Entry::Level::Error,
                   {{DEFAULT_BIN_KEY, binName}});
    // Test 4: Check if the error falls in the correct Bin
    EXPECT_EQ(manager.binEntryMap[manager.lastEntryID()], binName);

    // Test 5: Check for the correct info entry size of the bin
    EXPECT_EQ(manager.getBin("tempBin").errorEntries.size(), 1);

    // Test 6: Since log is error it should be present in directory
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              1);
}

} // namespace test
} // namespace logging
} // namespace phosphor
