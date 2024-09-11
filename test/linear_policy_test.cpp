/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#include "log_manager.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <filesystem>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace logging
{
namespace test
{

namespace fs = std::filesystem;
class TestPolicy : public testing::Test
{};

class MockPolicy : public phosphor::logging::internal::Manager
{
  public:
    MockPolicy(sdbusplus::bus::bus& bus, const char* objPath) :
        Manager(bus, objPath){};

    std::string getSelPolicy() override
    {
        return "xyz.openbmc_project.Logging.Settings.Policy.Linear";
    }

    ~MockPolicy() {}
};

std::size_t countFilesinDirectory(std::filesystem::path path)
{
    return (std::size_t)std::distance(std::filesystem::directory_iterator{path},
                                      std::filesystem::directory_iterator{});
}

auto bus = sdbusplus::bus::new_default();
MockPolicy manager(bus, OBJ_INTERNAL);

TEST_F(TestPolicy, testLinearPolicy)
{
    // Create the Bin
    std::string binName = "LinearPolicyTest";
    auto binErrorCapacity = 15;
    auto binInfoCapacity = 20;
    auto totalCapacity = 500;
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
    for (size_t i = 0; i < (size_t)totalCapacity; i++)
    {
        manager.create("create Informational Error Event",
                       Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Create Error Event", Entry::Level::Error,
                       {{DEFAULT_BIN_KEY, binName}});
    }

    // Test 1: Test  Information size
    // As max capacity is 20, 'Informational Size' must be 20.
    EXPECT_EQ(manager.getInfoErrSize(std::string(binName)), binInfoCapacity);

    // Test 2: Test  Error Size
    // As max capacity is 20, 'Error Size' must be 15.
    EXPECT_EQ(manager.getRealErrSize(std::string(binName)), binErrorCapacity);

    // Creating 5 more entries
    for (size_t i = 0; i < 5; i++)
    {
        manager.create("create Informational Error Event",
                       Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Create Error Event", Entry::Level::Error,
                       {{DEFAULT_BIN_KEY, binName}});
    }

    /* Test capacity after adding 5 more entries.
       the size should not increase and Capacity must be Max.
       Repeat TEST 2 and 3 again */

    // Test 3: Test  Information size
    // As max capacity is 20, 'Informational Size' must be 20.
    EXPECT_EQ(manager.getInfoErrSize(std::string(binName)), binInfoCapacity);

    // Test 4: Test  Error Size
    // As max capacity is 15, 'Error Size' must be 15.
    EXPECT_EQ(manager.getRealErrSize(std::string(binName)), binErrorCapacity);

    // Deleting 6  oldest entries
    //  3 entries deleted from 'Informational' and 3 from 'Error'
    for (size_t i = 0; i < 6; i++)
    {
        manager.erase(i + 1);
    }

    // Test 5: Test  Information size after deleting 3 entries
    // Now 'Information Size' become 17
    EXPECT_EQ(manager.getInfoErrSize(std::string(binName)),
              binInfoCapacity - 3);

    // Test 6: Test  Error Size after deleting 3
    //  Now 'Error Size' become  12
    EXPECT_EQ(manager.getRealErrSize(std::string(binName)),
              binErrorCapacity - 3);

    // Add 6 entries 3 each for 'Informational' and 'Error'
    for (size_t i = 0; i < 3; i++)
    {
        manager.create("create Informational Error Event",
                       Entry::Level::Informational,
                       {{DEFAULT_BIN_KEY, binName}});
        manager.create("Create Error Event", Entry::Level::Error,
                       {{DEFAULT_BIN_KEY, binName}});
    }

    // Test 7: Test  Information size
    // After adding 3 Informational entries, 'Informational Size' become to 20.
    EXPECT_EQ(manager.getInfoErrSize(std::string(binName)), binInfoCapacity);

    // Test 8: Test  Error Size
    //   After adding 3 Error entries, 'Error Size' become 15
    EXPECT_EQ(manager.getRealErrSize(std::string(binName)), binErrorCapacity);

    // Test 9: Count number of FS entries in created in bin
    EXPECT_EQ(countFilesinDirectory(
                  fs::path(std::string(ERRLOG_PERSIST_PATH) + "/" + binName)),
              binInfoCapacity + binErrorCapacity);

    manager.eraseAll();
}
} // namespace test
} // namespace logging
} // namespace phosphor
