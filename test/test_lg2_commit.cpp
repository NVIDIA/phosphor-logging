/**
 * Copyright © 2026 Test Coverage Improvement
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../lib/lg2_commit.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sdbusplus/exception.hpp>
#include <sys/syslog.h>
#include <xyz/openbmc_project/Logging/Entry/client.hpp>

#include <string>

namespace lg2
{
namespace details
{

// External symbols that need to be tested
// Declare the functions we want to test
extern auto severity_from_syslog(int s)
    -> sdbusplus::client::xyz::openbmc_project::logging::Entry<>::Level;

} // namespace details
} // namespace lg2

using Entry = sdbusplus::client::xyz::openbmc_project::logging::Entry<>;

class Lg2CommitTest : public ::testing::Test
{
  protected:
    // Helper to access the internal severity_from_syslog function
    auto testSeverityFromSyslog(int syslogLevel) -> Entry::Level
    {
        return lg2::details::severity_from_syslog(syslogLevel);
    }
};

/**
 * Test severity_from_syslog conversion function
 */
TEST_F(Lg2CommitTest, SeverityFromSyslogDebug)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_DEBUG), Entry::Level::Debug);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogInfo)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_INFO), Entry::Level::Informational);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogNotice)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_NOTICE), Entry::Level::Notice);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogWarning)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_WARNING), Entry::Level::Warning);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogError)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_ERR), Entry::Level::Error);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogCritical)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_CRIT), Entry::Level::Critical);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogAlert)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_ALERT), Entry::Level::Alert);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogEmergency)
{
    EXPECT_EQ(testSeverityFromSyslog(LOG_EMERG), Entry::Level::Emergency);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogInvalidDefault)
{
    // Invalid syslog value should default to Emergency
    EXPECT_EQ(testSeverityFromSyslog(999), Entry::Level::Emergency);
}

TEST_F(Lg2CommitTest, SeverityFromSyslogNegativeDefault)
{
    // Negative value should default to Emergency
    EXPECT_EQ(testSeverityFromSyslog(-1), Entry::Level::Emergency);
}

/**
 * Edge case tests for severity conversion
 */
TEST_F(Lg2CommitTest, SeverityAllValidSyslogLevels)
{
    // Test all valid syslog levels
    std::vector<std::pair<int, Entry::Level>> validLevels = {
        {LOG_EMERG, Entry::Level::Emergency},
        {LOG_ALERT, Entry::Level::Alert},
        {LOG_CRIT, Entry::Level::Critical},
        {LOG_ERR, Entry::Level::Error},
        {LOG_WARNING, Entry::Level::Warning},
        {LOG_NOTICE, Entry::Level::Notice},
        {LOG_INFO, Entry::Level::Informational},
        {LOG_DEBUG, Entry::Level::Debug},
    };

    for (const auto& [syslogLevel, expectedLevel] : validLevels)
    {
        EXPECT_EQ(testSeverityFromSyslog(syslogLevel), expectedLevel)
            << "Failed for syslog level: " << syslogLevel;
    }
}

TEST_F(Lg2CommitTest, SeverityBoundaryValues)
{
    // Test boundary values
    EXPECT_EQ(testSeverityFromSyslog(0), Entry::Level::Emergency);
    EXPECT_EQ(testSeverityFromSyslog(INT_MAX), Entry::Level::Emergency);
    EXPECT_EQ(testSeverityFromSyslog(INT_MIN), Entry::Level::Emergency);
}
