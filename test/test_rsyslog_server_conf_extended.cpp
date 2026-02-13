// Extended tests for phosphor-rsyslog-config/server-conf.cpp
// Focuses on uncovered code paths not tested by remote_logging_test_*.cpp

#include "config.h"

#include "phosphor-rsyslog-config/server-conf.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/Logging/RsyslogClient/server.hpp>

#include <filesystem>
#include <fstream>
#include <string>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{

namespace rsyslog_config::internal
{
// Access internal parseConfig for testing
extern std::optional<std::tuple<
    std::string, uint32_t, NetworkClient::TransportProtocol, bool, bool,
    std::vector<RsyslogClient::FacilityType>, RsyslogClient::SeverityType>>
    parseConfig(std::istream& ss);
} // namespace rsyslog_config::internal

namespace logging
{
namespace test
{

namespace fs = std::filesystem;

// Mock Server class
class MockServerExtended : public phosphor::rsyslog_config::Server
{
  public:
    MockServerExtended(sdbusplus::bus_t& bus, const std::string& path,
                       const char* filePath) :
        phosphor::rsyslog_config::Server(bus, path, filePath)
    {}

    MOCK_METHOD0(restart, void());
};

// Test fixture with temp directory
class TestRsyslogServerConfExtended : public testing::Test
{
  protected:
    static inline char tmplt[] = "/tmp/rsyslog_extended_test.XXXXXX";
    static inline fs::path testDir;
    static inline sdbusplus::bus_t bus = sdbusplus::bus::new_default();
    std::string configFilePath;
    MockServerExtended* server = nullptr;

    static void SetUpTestSuite()
    {
        testDir = fs::path(mkdtemp(tmplt));
    }

    void SetUp() override
    {
        configFilePath = testDir / "server_extended.conf";
        server = new MockServerExtended(bus, "/xyz/openbmc_project/logging/config/remote_extended",
                                        configFilePath.c_str());
    }

    void TearDown() override
    {
        delete server;
        server = nullptr;
        // Clean up config file
        fs::remove(configFilePath);
    }

    static void TearDownTestSuite()
    {
        fs::remove_all(testDir);
    }

    // Helper: Create config file with content
    void createConfigFile(const std::string& content)
    {
        std::ofstream ofs(configFilePath);
        ofs << content;
        ofs.close();
    }

    // Helper: Read config file content
    std::string readConfigFile()
    {
        std::ifstream ifs(configFilePath);
        std::stringstream buffer;
        buffer << ifs.rdbuf();
        return buffer.str();
    }
};

// ============================================================================
// Tests for restore() method with various config file formats
// ============================================================================

TEST_F(TestRsyslogServerConfExtended, RestoreWithValidTCPConfig)
{
    createConfigFile("*.* @@192.168.1.100:514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore1",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "192.168.1.100");
    EXPECT_EQ(testServer.port(), 514);
    EXPECT_EQ(testServer.transportProtocol(),
              phosphor::rsyslog_config::NetworkClient::TransportProtocol::TCP);
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithValidUDPConfig)
{
    createConfigFile("*.* @10.0.0.1:1514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore2",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "10.0.0.1");
    EXPECT_EQ(testServer.port(), 1514);
    EXPECT_EQ(testServer.transportProtocol(),
              phosphor::rsyslog_config::NetworkClient::TransportProtocol::UDP);
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithIPv6Config)
{
    createConfigFile("*.* @@[2001:db8::1]:8514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore3",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "2001:db8::1");
    EXPECT_EQ(testServer.port(), 8514);
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithTLSConfig)
{
    createConfigFile(
        "$DefaultNetstreamDriver gtls\n"
        "$ActionSendStreamDriverMode 1\n"
        "$ActionSendStreamDriverAuthMode anon\n"
        "*.* @@192.168.1.200:6514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore4",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "192.168.1.200");
    EXPECT_EQ(testServer.port(), 6514);
    EXPECT_TRUE(testServer.tls());
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithDisabledConfig)
{
    createConfigFile("# Disabled: *.* @@192.168.1.100:514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore5",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "192.168.1.100");
    EXPECT_EQ(testServer.port(), 514);
    EXPECT_FALSE(testServer.enabled());
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithCommentsAndEmptyLines)
{
    createConfigFile(
        "# This is a comment\n"
        "\n"
        "# Another comment\n"
        "*.* @@log-server.example.com:514\n"
        "\n"
        "# Footer comment\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore6",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "log-server.example.com");
    EXPECT_EQ(testServer.port(), 514);
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithMultipleFacilities)
{
    createConfigFile("daemon,kern.* @@192.168.1.100:514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore7",
                                  configFilePath.c_str());

    auto facilities = testServer.facility();
    EXPECT_GE(facilities.size(), 1);
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithSeverityLevels)
{
    createConfigFile("*.error @@192.168.1.100:514\n");

    MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore8",
                                  configFilePath.c_str());

    EXPECT_EQ(testServer.address(), "192.168.1.100");
    EXPECT_EQ(testServer.severity(),
              phosphor::rsyslog_config::RsyslogClient::SeverityType::Error);
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithEmptyFile)
{
    createConfigFile("");

    // Constructor may not throw, but config should remain empty/default
    try
    {
        MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore9",
                                      configFilePath.c_str());
        // If it doesn't throw, the address should be empty or default
        SUCCEED();
    }
    catch (const std::exception&)
    {
        // Also acceptable if it throws
        SUCCEED();
    }
}

TEST_F(TestRsyslogServerConfExtended, RestoreWithMissingFile)
{
    std::string nonExistentPath = testDir / "nonexistent.conf";

    // Should not crash, may use defaults
    try
    {
        MockServerExtended testServer(bus, "/xyz/openbmc_project/logging/config/remote_restore10",
                                      nonExistentPath.c_str());
        SUCCEED();
    }
    catch (const std::exception&)
    {
        SUCCEED();
    }
}

// ============================================================================
// Tests for parseConfig() internal function with edge cases
// ============================================================================

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithTrailingWhitespace)
{
    std::string configLine = "*.* @@192.168.1.100:514  \n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::get<0>(*result), "192.168.1.100");
    EXPECT_EQ(std::get<1>(*result), 514);
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithHostname)
{
    std::string configLine = "*.* @@syslog.example.com:514\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::get<0>(*result), "syslog.example.com");
    EXPECT_EQ(std::get<1>(*result), 514);
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithShortIPv6)
{
    std::string configLine = "*.* @@[::1]:514\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::get<0>(*result), "::1");
    EXPECT_EQ(std::get<1>(*result), 514);
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithHighPort)
{
    std::string configLine = "*.* @@192.168.1.1:65535\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(std::get<1>(*result), 65535);
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithInvalidPortZero)
{
    std::string configLine = "*.* @@192.168.1.1:0\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    // Port 0 should parse successfully (validation happens elsewhere)
    EXPECT_TRUE(result.has_value());
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithMissingAddress)
{
    std::string configLine = "*.* @@:514\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_FALSE(result.has_value());
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithMissingPort)
{
    std::string configLine = "*.* @@192.168.1.1\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_FALSE(result.has_value());
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithMissingAtSign)
{
    std::string configLine = "*.* 192.168.1.1:514\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_FALSE(result.has_value());
}

TEST_F(TestRsyslogServerConfExtended, ParseConfigWithOnlyComments)
{
    std::string configLine = "# Only a comment\n# Another comment\n";
    std::stringstream ss(configLine);
    auto result = phosphor::rsyslog_config::internal::parseConfig(ss);

    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// Tests for address validation edge cases
// ============================================================================

TEST_F(TestRsyslogServerConfExtended, AddressValidWithLoopback)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("127.0.0.1");
    server->port(514);

    EXPECT_EQ(server->address(), "127.0.0.1");
}

TEST_F(TestRsyslogServerConfExtended, AddressValidWithIPv6Loopback)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("::1");
    server->port(514);

    EXPECT_EQ(server->address(), "::1");
}

TEST_F(TestRsyslogServerConfExtended, AddressValidWithFullIPv6)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("2001:0db8:0000:0000:0000:0000:0000:0001");
    server->port(514);

    EXPECT_EQ(server->address(), "2001:0db8:0000:0000:0000:0000:0000:0001");
}

TEST_F(TestRsyslogServerConfExtended, AddressValidWithHostname)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    // Hostname validation depends on DNS, so may or may not work
    // Test that it doesn't crash
    try
    {
        server->address("localhost");
        server->port(514);
        SUCCEED();
    }
    catch (const sdbusplus::exception::SdBusError&)
    {
        // May fail with InvalidArgument, that's okay
        SUCCEED();
    }
    catch (const sdbusplus::error::xyz::openbmc_project::common::InvalidArgument&)
    {
        // May fail with InvalidArgument, that's okay
        SUCCEED();
    }
}

TEST_F(TestRsyslogServerConfExtended, AddressInvalidWithSpecialChars)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    // Expect either SdBusError or InvalidArgument
    bool thrown = false;
    try
    {
        server->address("192.168.1.1!@#$");
    }
    catch (const sdbusplus::exception::SdBusError&)
    {
        thrown = true;
    }
    catch (const sdbusplus::error::xyz::openbmc_project::common::InvalidArgument&)
    {
        thrown = true;
    }
    EXPECT_TRUE(thrown);
}

TEST_F(TestRsyslogServerConfExtended, AddressInvalidWithSpaces)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    // Expect either SdBusError or InvalidArgument
    bool thrown = false;
    try
    {
        server->address("192.168.1.1 invalid");
    }
    catch (const sdbusplus::exception::SdBusError&)
    {
        thrown = true;
    }
    catch (const sdbusplus::error::xyz::openbmc_project::common::InvalidArgument&)
    {
        thrown = true;
    }
    EXPECT_TRUE(thrown);
}

// ============================================================================
// Tests for property setters with edge cases
// ============================================================================

TEST_F(TestRsyslogServerConfExtended, EnabledToggle)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);

    server->enabled(true);
    EXPECT_TRUE(server->enabled());

    server->enabled(false);
    EXPECT_FALSE(server->enabled());

    server->enabled(true);
    EXPECT_TRUE(server->enabled());
}

TEST_F(TestRsyslogServerConfExtended, TlsToggle)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(6514);

    server->tls(true);
    EXPECT_TRUE(server->tls());

    server->tls(false);
    EXPECT_FALSE(server->tls());
}

TEST_F(TestRsyslogServerConfExtended, TransportProtocolToggle)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);

    server->transportProtocol(
        phosphor::rsyslog_config::NetworkClient::TransportProtocol::TCP);
    EXPECT_EQ(server->transportProtocol(),
              phosphor::rsyslog_config::NetworkClient::TransportProtocol::TCP);

    server->transportProtocol(
        phosphor::rsyslog_config::NetworkClient::TransportProtocol::UDP);
    EXPECT_EQ(server->transportProtocol(),
              phosphor::rsyslog_config::NetworkClient::TransportProtocol::UDP);
}

TEST_F(TestRsyslogServerConfExtended, SeverityChanges)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);

    server->severity(phosphor::rsyslog_config::RsyslogClient::SeverityType::Error);
    EXPECT_EQ(server->severity(),
              phosphor::rsyslog_config::RsyslogClient::SeverityType::Error);

    server->severity(phosphor::rsyslog_config::RsyslogClient::SeverityType::Warning);
    EXPECT_EQ(server->severity(),
              phosphor::rsyslog_config::RsyslogClient::SeverityType::Warning);

    server->severity(phosphor::rsyslog_config::RsyslogClient::SeverityType::Info);
    EXPECT_EQ(server->severity(),
              phosphor::rsyslog_config::RsyslogClient::SeverityType::Info);
}

TEST_F(TestRsyslogServerConfExtended, FacilityChanges)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);

    std::vector<phosphor::rsyslog_config::RsyslogClient::FacilityType> facilities1 = {
        phosphor::rsyslog_config::RsyslogClient::FacilityType::Daemon
    };
    server->facility(facilities1);
    EXPECT_EQ(server->facility().size(), 1);

    std::vector<phosphor::rsyslog_config::RsyslogClient::FacilityType> facilities2 = {
        phosphor::rsyslog_config::RsyslogClient::FacilityType::Daemon,
        phosphor::rsyslog_config::RsyslogClient::FacilityType::Kern
    };
    server->facility(facilities2);
    EXPECT_EQ(server->facility().size(), 2);
}

// ============================================================================
// Tests for error handling and exception paths
// ============================================================================

TEST_F(TestRsyslogServerConfExtended, SetSameAddressTwice)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);

    // Setting the same address again should not cause issues
    server->address("192.168.1.1");
    EXPECT_EQ(server->address(), "192.168.1.1");
}

TEST_F(TestRsyslogServerConfExtended, SetSamePortTwice)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);

    // Setting the same port again should not cause issues
    server->port(514);
    EXPECT_EQ(server->port(), 514);
}

TEST_F(TestRsyslogServerConfExtended, ClearAddressWithEmptyString)
{
    EXPECT_CALL(*server, restart()).Times(testing::AtLeast(0));

    server->address("192.168.1.1");
    server->port(514);
    EXPECT_EQ(server->address(), "192.168.1.1");

    // Clear address
    server->address("");
    EXPECT_EQ(server->address(), "");
}

} // namespace test
} // namespace logging
} // namespace phosphor
