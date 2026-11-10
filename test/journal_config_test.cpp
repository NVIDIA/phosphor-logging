// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// All rights reserved.
#include "config.h"

#include "phosphor-journal-config/conf.hpp"
#include "phosphor-journal-config/journal.hpp"

#include <stdlib.h>

#include <sdbusplus/test/sdbus_mock.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace journal_config
{
namespace test
{

namespace fs = std::filesystem;

using ::testing::_;
using ::testing::NiceMock;

const std::vector<std::pair<std::string_view, Level>> namedMaxLevelStoreTokens =
    {
        {"emerg", Level::Emergency},    {"alert", Level::Alert},
        {"crit", Level::Critical},      {"err", Level::Error},
        {"warning", Level::Warning},    {"notice", Level::Notice},
        {"info", Level::Informational}, {"debug", Level::Debug},
};

TEST(TestMaxLevelStoreMapping, testNamedTokenRoundTrip)
{
    for (const auto& [maxLevelStore, entryLevel] : namedMaxLevelStoreTokens)
    {
        auto mappedEntryLevel = maxLevelStoreToEntryLevel(maxLevelStore);
        EXPECT_EQ(mappedEntryLevel, entryLevel) << maxLevelStore;

        auto mappedMaxLevelStore = entryLevelToMaxLevelStore(entryLevel);
        EXPECT_EQ(mappedMaxLevelStore, maxLevelStore);
    }

    EXPECT_EQ(maxLevelStoreToEntryLevel("Emergency"), std::nullopt);
    EXPECT_EQ(entryLevelToMaxLevelStore(static_cast<Level>(8)), std::nullopt);
}

class TestMaxLevelStoreFile : public testing::Test
{
  public:
    void SetUp() override
    {
        char dirTemplate[] = "/tmp/journal-config-XXXXXX";
        auto* created = mkdtemp(dirTemplate);
        ASSERT_NE(created, nullptr);
        tempDir = created;
    }

    void TearDown() override
    {
        std::error_code ec;
        fs::remove_all(tempDir, ec);
    }

    fs::path tempDir;
};

TEST_F(TestMaxLevelStoreFile, testReadUsesLastValidNamedToken)
{
    auto dropInPath = tempDir / "drop-in.conf";

    // Test 0: missing file
    EXPECT_FALSE(readMaxLevelStore(dropInPath.string()));

    std::ofstream dropIn(dropInPath);
    ASSERT_TRUE(dropIn);
    dropIn << "# comment\n[Journal]\nMaxLevelSyslog=debug\n"
              "MaxLevelStore=6\nMaxLevelStore=err\nMaxLevelStore=bogus\n"
              "MaxLevelStore=Emergency\n  MaxLevelStore  =  notice  \n";
    dropIn.close();

    // Test 1: last named token wins; other keys, numeric 0–7, unknown
    // names, and surrounding whitespace are ignored.
    EXPECT_EQ(readMaxLevelStore(dropInPath.string()), "notice");
}

TEST_F(TestMaxLevelStoreFile, testWriteCreatesNestedDropIn)
{
    auto dropInPath =
        tempDir / "journald.conf.d" / "phosphor-journal-maxlevel.conf";

    ASSERT_TRUE(writeMaxLevelStore(dropInPath.string(), "err"));
    EXPECT_FALSE(fs::exists(dropInPath.string() + ".tmp"));
    EXPECT_EQ(readMaxLevelStore(dropInPath.string()), "err");
}

class MockJournalConfig : public JournalConfig
{
  public:
    MockJournalConfig(sdbusplus::bus_t& bus, std::string_view overrideFile,
                      std::string_view packagedFile) :
        JournalConfig(bus, BUSPATH_JOURNAL_CONFIG, nullptr, overrideFile,
                      packagedFile)
    {}

    MOCK_METHOD(void, restartJournald, (), (override));
    MOCK_METHOD(void, sendLowestSeverityModified, (Level lowestSeverity),
                (override));
};

class TestJournalConfig : public TestMaxLevelStoreFile
{
  public:
    void SetUp() override
    {
        TestMaxLevelStoreFile::SetUp();
        overrideFile = tempDir / "phosphor-journal-maxlevel.conf";
        packagedFile = tempDir / "journald-maxlevel-policy.conf";
        ASSERT_TRUE(writeMaxLevelStore(packagedFile.string(), "info"));
    }

    void TearDown() override
    {
        journalConfig.reset();
        TestMaxLevelStoreFile::TearDown();
    }

    void createJournalConfig()
    {
        journalConfig = std::make_unique<MockJournalConfig>(
            bus, overrideFile.string(), packagedFile.string());
    }

    NiceMock<sdbusplus::SdBusMock> sdbusMock;
    sdbusplus::bus_t bus = sdbusplus::get_mocked_new(&sdbusMock);
    fs::path overrideFile;
    fs::path packagedFile;
    std::unique_ptr<MockJournalConfig> journalConfig;
};

TEST_F(TestJournalConfig, testCtorPrefersOverrideThenPackaged)
{
    // Test 0: no override file, use packaged policy
    createJournalConfig();
    EXPECT_EQ(journalConfig->lowestSeverity(), Level::Informational);

    // Test 1: override file with a named token wins
    journalConfig.reset();
    ASSERT_TRUE(writeMaxLevelStore(overrideFile.string(), "err"));
    createJournalConfig();
    EXPECT_EQ(journalConfig->lowestSeverity(), Level::Error);

    // Test 2: override file with no named token falls back to packaged
    journalConfig.reset();
    {
        std::ofstream overrideDropIn(overrideFile);
        ASSERT_TRUE(overrideDropIn);
        overrideDropIn << "MaxLevelStore=bogus\n";
    }
    createJournalConfig();
    EXPECT_EQ(journalConfig->lowestSeverity(), Level::Informational);
}

TEST_F(TestJournalConfig, testCtorThrowsWhenPackagedMissingOrInvalid)
{
    // Test 0: packaged file missing
    journalConfig.reset();
    fs::remove(packagedFile);
    EXPECT_THROW(createJournalConfig(), std::runtime_error);

    // Test 1: packaged file has no named MaxLevelStore
    {
        std::ofstream packagedDropIn(packagedFile);
        ASSERT_TRUE(packagedDropIn);
        packagedDropIn << "MaxLevelStore=6\n";
    }
    EXPECT_THROW(createJournalConfig(), std::runtime_error);
}

TEST_F(TestJournalConfig, testLowestSeveritySet)
{
    createJournalConfig();

    // Test 0: first Set writes the override even when the value already
    // matches packaged policy
    EXPECT_CALL(*journalConfig, restartJournald()).Times(1);
    EXPECT_CALL(*journalConfig,
                sendLowestSeverityModified(Level::Informational))
        .Times(1);
    EXPECT_EQ(journalConfig->lowestSeverity(Level::Informational),
              Level::Informational);
    EXPECT_EQ(readMaxLevelStore(overrideFile.string()), "info");

    // Test 1: later Set of the same value skips write, restart, and event
    EXPECT_CALL(*journalConfig, restartJournald()).Times(0);
    EXPECT_CALL(*journalConfig, sendLowestSeverityModified(_)).Times(0);
    EXPECT_EQ(journalConfig->lowestSeverity(Level::Informational),
              Level::Informational);

    // Test 2: Set of a new value restarts journald and sends the event
    EXPECT_CALL(*journalConfig, restartJournald()).Times(1);
    EXPECT_CALL(*journalConfig, sendLowestSeverityModified(Level::Debug))
        .Times(1);
    EXPECT_EQ(journalConfig->lowestSeverity(Level::Debug), Level::Debug);
}

TEST_F(TestJournalConfig, testLowestSeverityUnmappedLevel)
{
    createJournalConfig();
    EXPECT_CALL(*journalConfig, restartJournald()).Times(0);
    EXPECT_CALL(*journalConfig, sendLowestSeverityModified(_)).Times(0);
    EXPECT_THROW(
        journalConfig->lowestSeverity(static_cast<Level>(8)),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
    EXPECT_FALSE(fs::exists(overrideFile));
    EXPECT_EQ(journalConfig->lowestSeverity(), Level::Informational);
}

} // namespace test
} // namespace journal_config
} // namespace phosphor
