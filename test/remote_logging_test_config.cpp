#include "remote_logging_tests.hpp"

#include <fstream>
#include <string>

namespace phosphor
{

namespace rsyslog_config::internal
{
extern std::optional<std::tuple<
    std::string, uint32_t, NetworkClient::TransportProtocol, bool, bool,
    std::vector<RsyslogClient::FacilityType>, RsyslogClient::SeverityType>>
    parseConfig(std::istream& ss);
}

namespace logging
{
namespace test
{

std::string getConfig(const char* filePath)
{
    std::fstream stream(filePath, std::fstream::in);
    std::string line;
    while (std::getline(stream, line))
    {
        // Find the forwarding/action line (starts with selector "*.")
        if (line.rfind("*.", 0) == 0)
        {
            // If there is a template suffix (e.g., ";RFC5424withIP"), ignore it
            auto pos = line.find(';');
            if (pos != std::string::npos)
            {
                return line.substr(0, pos);
            }
            return line;
        }
    }
    return {};
}

TEST_F(TestRemoteLogging, testOnlyAddress)
{
    config->enabled(true);
    config->severity(RsyslogClient::SeverityType::All);
    config->address("1.1.1.1");
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* /dev/null");
}

TEST_F(TestRemoteLogging, testOnlyPort)
{
    config->enabled(true);
    config->severity(RsyslogClient::SeverityType::All);
    config->port(100);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* /dev/null");
}

TEST_F(TestRemoteLogging, testGoodConfig)
{
    config->enabled(true);
    config->severity(RsyslogClient::SeverityType::All);
    config->address("1.1.1.1");
    config->port(100);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* @@1.1.1.1:100");
}

TEST_F(TestRemoteLogging, testClearAddress)
{
    config->enabled(true);
    config->severity(RsyslogClient::SeverityType::All);
    config->address("1.1.1.1");
    config->port(100);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* @@1.1.1.1:100");
    config->address("");
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* /dev/null");
}

TEST_F(TestRemoteLogging, testClearPort)
{
    config->enabled(true);
    config->severity(RsyslogClient::SeverityType::All);
    config->address("1.1.1.1");
    config->port(100);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* @@1.1.1.1:100");
    config->port(0);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* /dev/null");
}

TEST_F(TestRemoteLogging, testGoodIPv6Config)
{
    config->enabled(true);
    config->severity(RsyslogClient::SeverityType::All);
    config->address("abcd:ef01::01");
    config->port(50000);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* @@[abcd:ef01::01]:50000");
}

TEST_F(TestRemoteLogging, parseConfigGoodIpv6)
{
    // A good case
    std::string str = "*.* @@[abcd:ef01::01]:50000";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    if (!ret)
    {
        GTEST_FAIL() << "remote logging config should be present";
        return;
    }
    const auto& val = *ret;
    EXPECT_EQ(std::get<0>(val), "abcd:ef01::01");
    EXPECT_EQ(std::get<1>(val), 50000);
}

TEST_F(TestRemoteLogging, parseConfigBadIpv6WithoutRightBracket)
{
    // Bad case: without ]
    std::string str = "*.* @@[abcd:ef01::01:50000";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    EXPECT_FALSE(ret);
}

TEST_F(TestRemoteLogging, parseConfigBadIpv6WithoutLeftBracket)
{
    // Bad case: without [
    std::string str = "*.* @@abcd:ef01::01]:50000";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    EXPECT_FALSE(ret);
}

TEST_F(TestRemoteLogging, parseConfigBadIpv6WithoutPort)
{
    // Bad case: without port
    std::string str = "*.* @@[abcd:ef01::01]:";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    EXPECT_FALSE(ret);
}

TEST_F(TestRemoteLogging, parseConfigBadIpv6InvalidPort)
{
    // Bad case: without port
    std::string str = "*.* @@[abcd:ef01::01]:xxx";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    EXPECT_FALSE(ret);
}

TEST_F(TestRemoteLogging, parseConfigBadIpv6WihtoutColon)
{
    // Bad case: invalid IPv6 address
    std::string str = "*.* @@[abcd:ef01::01]";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    EXPECT_FALSE(ret);
}

TEST_F(TestRemoteLogging, parseConfigBadEmpty)
{
    // Bad case: invalid IPv6 address
    std::string str = "";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    EXPECT_FALSE(ret);
}

TEST_F(TestRemoteLogging, parseConfigTCP)
{
    // A good case
    std::string str = "*.* @@[abcd:ef01::01]:50000";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    if (!ret)
    {
        GTEST_FAIL() << "remote logging config should be present";
        return;
    }
    const auto& val = *ret;
    EXPECT_EQ(std::get<2>(val),
              phosphor::rsyslog_config::NetworkClient::TransportProtocol::TCP);
}

TEST_F(TestRemoteLogging, parseConfigUdp)
{
    // A good case
    std::string str = "*.* @[abcd:ef01::01]:50000";
    std::stringstream ss(str);
    auto ret = phosphor::rsyslog_config::internal::parseConfig(ss);
    if (!ret)
    {
        GTEST_FAIL() << "remote logging config should be present";
        return;
    }
    const auto& val = *ret;
    EXPECT_EQ(std::get<2>(val),
              phosphor::rsyslog_config::NetworkClient::TransportProtocol::UDP);
}

TEST_F(TestRemoteLogging, createUdpConfig)
{
    // A good case
    config->address("abcd:ef01::01");
    config->port(50000);
    config->transportProtocol(
        phosphor::rsyslog_config::NetworkClient::TransportProtocol::UDP);
    EXPECT_EQ(getConfig(configFilePath.c_str()), "*.* @[abcd:ef01::01]:50000");
}

} // namespace test
} // namespace logging
} // namespace phosphor
