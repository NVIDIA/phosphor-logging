/**
 * Unit tests for bin.hpp (Bin class) - gcovr.cfg coverage target
 */
#include "config.h"

#include "bin.hpp"
#include "paths.hpp"

#include <cstdint>
#include <string>

#include <gtest/gtest.h>

/**
 * Test default constructor initializes with config and paths::error()
 */
TEST(BinTest, DefaultConstructor)
{
    phosphor::logging::internal::Bin b;

    EXPECT_EQ(b.name, DEFAULT_BIN_NAME);
    EXPECT_EQ(b.errorCap, static_cast<uint32_t>(ERROR_CAP));
    EXPECT_EQ(b.errorInfoCap, static_cast<uint32_t>(ERROR_INFO_CAP));
    EXPECT_EQ(b.persistLocation, phosphor::logging::paths::error().string());
    EXPECT_TRUE(b.errorEntries.empty());
    EXPECT_TRUE(b.infoEntries.empty());
    EXPECT_TRUE(b.persistInfoLog);
    EXPECT_EQ(b.defaultCapacity, 0u);
}

/**
 * Test parameterized constructor
 */
TEST(BinTest, ParameterizedConstructor)
{
    const std::string name = "test_bin";
    const uint32_t errCap = 100;
    const uint32_t errInfoCap = 50;
    const std::string loc = "/tmp/test_persist";
    const bool persistInfoLog = false;
    const uint32_t defaultCapacity = 10;

    phosphor::logging::internal::Bin b(name, errCap, errInfoCap, loc,
                                       persistInfoLog, defaultCapacity);

    EXPECT_EQ(b.name, name);
    EXPECT_EQ(b.errorCap, errCap);
    EXPECT_EQ(b.errorInfoCap, errInfoCap);
    EXPECT_EQ(b.persistLocation, loc);
    EXPECT_TRUE(b.errorEntries.empty());
    EXPECT_TRUE(b.infoEntries.empty());
    EXPECT_FALSE(b.persistInfoLog);
    EXPECT_EQ(b.defaultCapacity, defaultCapacity);
}

/**
 * Test parameterized constructor with empty location
 */
TEST(BinTest, ParameterizedConstructorEmptyLocation)
{
    phosphor::logging::internal::Bin b("ns", 1, 2, "", true, 0);

    EXPECT_EQ(b.name, "ns");
    EXPECT_EQ(b.persistLocation, "");
}

/**
 * Test that jsonPath is default-initialized (empty) for both constructors
 */
TEST(BinTest, JsonPathDefaultInitialized)
{
    phosphor::logging::internal::Bin b1;
    EXPECT_TRUE(b1.jsonPath.empty());

    phosphor::logging::internal::Bin b2("b", 1, 1, "/path", true, 0);
    EXPECT_TRUE(b2.jsonPath.empty());
}

/**
 * Test errorEntries and infoEntries mutation and access (branch coverage for
 * bin.hpp)
 */
TEST(BinTest, ErrorEntriesAndInfoEntriesMutation)
{
    phosphor::logging::internal::Bin b("ns", 10, 5, "/tmp", true, 0);

    EXPECT_TRUE(b.errorEntries.empty());
    EXPECT_TRUE(b.infoEntries.empty());

    b.errorEntries.insert(1);
    b.errorEntries.insert(2);
    b.infoEntries.insert(10);

    EXPECT_EQ(b.errorEntries.size(), 2u);
    EXPECT_EQ(b.infoEntries.size(), 1u);
    EXPECT_NE(b.errorEntries.find(1), b.errorEntries.end());
    EXPECT_NE(b.infoEntries.find(10), b.infoEntries.end());

    b.errorEntries.erase(1);
    EXPECT_EQ(b.errorEntries.size(), 1u);
}

/**
 * Test jsonPath assignment and defaultCapacity (branch coverage for bin.hpp)
 */
TEST(BinTest, JsonPathAndDefaultCapacityAssignment)
{
    phosphor::logging::internal::Bin b("SEL", 5, 5, "/var/log", false, 100);

    EXPECT_EQ(b.defaultCapacity, 100u);
    EXPECT_FALSE(b.persistInfoLog);

    b.jsonPath = "/etc/phosphor/sel_config.json";
    EXPECT_EQ(b.jsonPath, "/etc/phosphor/sel_config.json");
}
