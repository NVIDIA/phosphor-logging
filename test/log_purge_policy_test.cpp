/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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

#include <sys/stat.h>

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

class TestLogPurgePolicy : public testing::Test
{
  public:
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    std::string rwConfigJsonPath = fs::temp_directory_path() / ("test_log_purge_json_" + std::to_string(std::rand()));
    phosphor::logging::internal::Manager manager;

    TestLogPurgePolicy() :
        manager(mockedBus, OBJ_INTERNAL)
    {
    };

    ~TestLogPurgePolicy()
    {
        try
        {
            fs::remove(rwConfigJsonPath);
        }
        catch (const std::exception& e)
        {
        }
    }
};

std::string getTempJsonPath()
{
    return fs::temp_directory_path() / ("test_log_purge_json_" + std::to_string(std::rand()));
}

TEST(TestLogPurgePolicy, testSettingAndPersistence)
{
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    std::string rwConfigJsonPath = getTempJsonPath();

    {
        phosphor::logging::internal::Manager manager1(mockedBus, OBJ_INTERNAL);
        EXPECT_EQ(manager1.parseRWConfigJson(rwConfigJsonPath), 0);
        // Test 0: Setting should start disabled
        EXPECT_FALSE(manager1.getAutoPurgeResolved());

        manager1.setAutoPurgeResolved(true);
        // Test 1: Setting should become enabled
        EXPECT_TRUE(manager1.getAutoPurgeResolved());
    }
    {
        phosphor::logging::internal::Manager manager2(mockedBus, OBJ_INTERNAL);
        EXPECT_EQ(manager2.parseRWConfigJson(rwConfigJsonPath), 0);
        // Test 2: Setting should start enabled if the persistent file exists
        EXPECT_TRUE(manager2.getAutoPurgeResolved());

        manager2.setAutoPurgeResolved(false);
        // Test 3: Setting should return to false
        EXPECT_FALSE(manager2.getAutoPurgeResolved());
    }
    {
        phosphor::logging::internal::Manager manager3(mockedBus, OBJ_INTERNAL);
        EXPECT_EQ(manager3.parseRWConfigJson(rwConfigJsonPath), 0);
        // Test 4: Setting should be false if previously set to false
        EXPECT_FALSE(manager3.getAutoPurgeResolved());
    }

    fs::remove(rwConfigJsonPath);
}

TEST(TestLogPurgePolicy, testInvalidRWJson)
{
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    std::string rwConfigJsonPath = getTempJsonPath();
    {
        std::ofstream output(rwConfigJsonPath, std::ios_base::trunc);
        output.close();
        phosphor::logging::internal::Manager manager1(mockedBus, OBJ_INTERNAL);
        // Test 0: the R/W JSON is empty
        EXPECT_ANY_THROW(manager1.parseRWConfigJson(rwConfigJsonPath));
    }
    {
        std::ofstream output(rwConfigJsonPath, std::ios_base::trunc);
        output << "{Y$%AB4: \"test\", 123467{{}";
        output.close();
        phosphor::logging::internal::Manager manager2(mockedBus, OBJ_INTERNAL);
        // Test 1: the R/W JSON contains malformed JSON
        EXPECT_ANY_THROW(manager2.parseRWConfigJson(rwConfigJsonPath));
    }
    {
        std::ofstream output(rwConfigJsonPath, std::ios_base::trunc);
        output << "{\"blah\": 123, \"foo\": \"BAR\"}";
        output.close();
        phosphor::logging::internal::Manager manager3(mockedBus, OBJ_INTERNAL);
        // Test 2: the R/W JSON contains JSON without the log purge policy key
        //         In this case, the default setting of false should apply
        EXPECT_EQ(manager3.parseRWConfigJson(rwConfigJsonPath), 0);
        EXPECT_FALSE(manager3.getAutoPurgeResolved());
    }

    fs::remove(rwConfigJsonPath);
}

TEST(TestLogPurgePolicy, testRWJsonWriteError)
{
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    {
        std::string rwConfigJsonPath = getTempJsonPath();
        std::ofstream output(rwConfigJsonPath, std::ios_base::trunc);
        output.close();
        phosphor::logging::internal::Manager manager1(mockedBus, OBJ_INTERNAL);
        // expect throw as file exists but is empty
        EXPECT_ANY_THROW(manager1.parseRWConfigJson(rwConfigJsonPath));
        manager1.setAutoPurgeResolved(false);

        chmod(rwConfigJsonPath.c_str(), S_IRUSR);
        // Test 1: there is an error opening the file for writing when storing "enabled"
        EXPECT_NO_THROW(manager1.setAutoPurgeResolved(true));

        // Test 2: there is an error opening the file for writing when storing "disabled"
        EXPECT_NO_THROW(manager1.setAutoPurgeResolved(false));

        fs::remove(rwConfigJsonPath);
    }
    {
        auto dir = fs::temp_directory_path() /
            ("testRWJsonWriteError" + std::to_string(std::rand()));
        std::string restrictedFile = dir / std::to_string(std::rand());
        chmod(dir.c_str(), S_IRUSR);
        phosphor::logging::internal::Manager manager2(mockedBus, OBJ_INTERNAL);
        manager2.parseRWConfigJson(restrictedFile);
        // Test 3: the parent directory prevents creating the file
        EXPECT_NO_THROW(manager2.setAutoPurgeResolved(false));
        EXPECT_NO_THROW(manager2.setAutoPurgeResolved(true));
        fs::remove_all(dir);
    }
}

TEST(TestLogPurgePolicy, testEnableThenDisableImmediate)
{
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    std::string rwConfigJsonPath = getTempJsonPath();
    phosphor::logging::internal::Manager manager(mockedBus, OBJ_INTERNAL);
    manager.parseRWConfigJson(rwConfigJsonPath);
    manager.setAutoPurgeResolved(false);

    manager.eraseAll();

    // Create 3 log entries, 2 resolved, 1 not
    manager.create("Test Error Event", Entry::Level::Error,
                    {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    manager.create("Test Error Event 2", Entry::Level::Error,
                    {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    manager.create("Test Error Event 3", Entry::Level::Error,
                    {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    EXPECT_TRUE(manager.entries.at(1));
    EXPECT_TRUE(manager.entries.at(2));
    EXPECT_TRUE(manager.entries.at(3));
    manager.entries.at(1)->resolved(true);
    manager.entries.at(3)->resolved(true);

    EXPECT_TRUE(manager.entries.at(1)->resolved());
    EXPECT_FALSE(manager.entries.at(2)->resolved());
    EXPECT_TRUE(manager.entries.at(3)->resolved());

    // Test 0: when log purge is disabled, resolving logs
    // doesn't mark them for deletion
    EXPECT_EQ(manager.getPendingLogDeleteCount(), 0);

    manager.setAutoPurgeResolved(true);

    // Test 1: After enabling log purge policy, resolved logs should
    // be pending deletion
    EXPECT_EQ(manager.getPendingLogDeleteCount(), 2);

    manager.setAutoPurgeResolved(false);

    // Test 2: After disabling log purge policy again, resolved logs
    // that still exist (in this case they do because the event loop
    // was not set up) should no longer be pending deletion.
    EXPECT_EQ(manager.getPendingLogDeleteCount(), 0);

    fs::remove(rwConfigJsonPath);
}

TEST(TestLogPurgePolicy, testRuntimeEnable)
{
    sdbusplus::SdBusMock sdbusMock;
    sdbusplus::bus::bus mockedBus = sdbusplus::get_mocked_new(&sdbusMock);
    std::string rwConfigJsonPath = getTempJsonPath();
    phosphor::logging::internal::Manager manager(mockedBus, OBJ_INTERNAL);
    manager.parseRWConfigJson(rwConfigJsonPath);
    manager.setAutoPurgeResolved(false);

    manager.eraseAll();

    // Create 3 log entries, 2 resolved, 1 not
    manager.create("Test Error Event", Entry::Level::Error,
                    {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    manager.create("Test Error Event 2", Entry::Level::Error,
                    {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    manager.create("Test Error Event 3", Entry::Level::Error,
                    {{DEFAULT_BIN_KEY, DEFAULT_BIN_NAME}});
    EXPECT_TRUE(manager.entries.at(1));
    EXPECT_TRUE(manager.entries.at(2));
    EXPECT_TRUE(manager.entries.at(3));
    manager.entries.at(1)->resolved(true);
    manager.entries.at(3)->resolved(true);

    manager.setAutoPurgeResolved(true);

    // TODO: run event loop and test for 
    auto event = sdeventplus::Event::get_default();
    constexpr int MAX_LOOPS = 3;  // we expect 2 dispatches, 3rd should time out
    int loop_ret = -1;
    for (int i = 0; i < MAX_LOOPS; i++)
    {
        // timeout 1sec
        loop_ret = event.run(sdeventplus::SdEventDuration(1000000));
        if (!loop_ret)
        {
            // There was nothing to dispatch, event.run() timed out
            break;
        }
    }
    // Test 1: The event loop should be done processing after 3 iterations
    EXPECT_EQ(loop_ret, 0);

    // Test 2: Resolved events should be purged
    EXPECT_THROW(manager.entries.at(1), std::out_of_range);
    EXPECT_NO_THROW(manager.entries.at(2));
    EXPECT_THROW(manager.entries.at(3), std::out_of_range);
    EXPECT_EQ(manager.entries.size(), 1);
}

} // namespace test
} // namespace logging
} // namespace phosphor
