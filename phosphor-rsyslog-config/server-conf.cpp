#include "server-conf.hpp"

#include "utils.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>

#include <fstream>
#if __has_include("../../usr/include/phosphor-logging/elog-errors.hpp")
#include "../../usr/include/phosphor-logging/elog-errors.hpp"
#else
#include <phosphor-logging/elog-errors.hpp>
#endif
#include <arpa/inet.h>
#include <netdb.h>

#include <stdplus/net/addr/ip.hpp>
#include <stdplus/util/string.hpp>

#include <map>
#include <optional>
#include <string>
#include <variant>

namespace phosphor
{
namespace rsyslog_config
{

namespace utils = phosphor::rsyslog_utils;
using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;

namespace internal
{

bool isIPv6Address(const std::string& addr)
{
    struct in6_addr result;
    return inet_pton(AF_INET6, addr.c_str(), &result) == 1;
}

std::string mapSeverityStr(const std::string& severityStr)
{
    if (severityStr == "error")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.SeverityType.Error";
    }
    else if (severityStr == "warning")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.SeverityType.Warning";
    }
    else if (severityStr == "info")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.SeverityType.Info";
    }
    else if (severityStr == "*")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.SeverityType.All";
    }
    lg2::error("No matching severity string defaulting to ALL");
    return "xyz.openbmc_project.Logging.RsyslogClient.SeverityType.All";
}

std::string mapFacilityStr(const std::string& facilityStr)
{
    if (facilityStr == "daemon")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.FacilityType.Daemon";
    }
    else if (facilityStr == "kern")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.FacilityType.Kern";
    }
    else if (facilityStr == "*")
    {
        return "xyz.openbmc_project.Logging.RsyslogClient.FacilityType.All";
    }

    lg2::error("No matching faciltiy string defaulting to ALL");
    return "xyz.openbmc_project.Logging.RsyslogClient.FacilityType.All";
}

std::optional<std::tuple<
    std::string, uint32_t, NetworkClient::TransportProtocol, bool, bool,
    std::vector<RsyslogClient::FacilityType>, RsyslogClient::SeverityType>>
    parseConfig(std::istream& ss)
{
    std::string line;
    std::string serverAddress;
    std::string serverPort;
    NetworkClient::TransportProtocol serverTransportProtocol =
        NetworkClient::TransportProtocol::TCP;
    bool tls = false;
    bool clientModeEnabled = true;
    std::vector<RsyslogClient::FacilityType> facilities;
    std::optional<RsyslogClient::SeverityType> severity =
        RsyslogClient::SeverityType::All;
    std::optional<RsyslogClient::FacilityType> facility =
        RsyslogClient::FacilityType::All;
    while (std::getline(ss, line))
    {
        // Detect and remove the "Disabled" marker
        if (line.starts_with("# Disabled: "))
        {
            clientModeEnabled = false;
            line = line.substr(12); // Remove "# Disabled: " marker
        }

        // Ignore empty lines and comments
        if (line.empty() || line.at(0) == '#')
            continue;

        // Check for TLS-specific lines
        if (line == "$DefaultNetstreamDriver gtls" ||
            line == "$ActionSendStreamDriverAuthMode anon" ||
            line == "$ActionSendStreamDriverMode 1")
        {
            tls = true;
            continue;
        }

        //"*.* @@<address>:<port>" or
        //"*.* @@[<ipv6-address>:<port>"
        auto start = line.find('@');
        if (start == std::string::npos)
        {
            continue;
        }

        // Split the line by space and extract the first part
        auto firstSpace = line.find(' ');
        if (firstSpace == std::string::npos)
            return {}; // Invalid format: No space found

        std::string firstPart = line.substr(0, firstSpace);

        // Extract facilities and severity from the first part
        auto dotPos = firstPart.find('.');
        if (dotPos == std::string::npos)
            return {}; // Invalid format: No dot found

        // Extract facilities (comma-separated)
        std::string facilitiesStr = firstPart.substr(0, dotPos);
        std::istringstream facilitiesStream(facilitiesStr);
        std::string facilityStr;
        while (std::getline(facilitiesStream, facilityStr, ','))
        {
            facility = RsyslogClient::convertStringToFacilityType(
                mapFacilityStr(facilityStr));
            facilities.push_back(*facility);
        }
        // Extract severity (part after the dot)
        std::string severityStr = firstPart.substr(dotPos + 1);
        severity = RsyslogClient::convertStringToSeverityType(
            mapSeverityStr(severityStr));

        // Skip "*.* @@" or "*.* @"
        if (line.at(start + 1) == '@')
        {
            serverTransportProtocol = NetworkClient::TransportProtocol::TCP;
            start += 2;
        }
        else
        {
            serverTransportProtocol = NetworkClient::TransportProtocol::UDP;
            start++;
        }

        // Check if there is "[]", and make IPv6 address from it
        auto posColonLeft = line.find('[');
        auto posColonRight = line.find(']');
        if (posColonLeft != std::string::npos ||
            posColonRight != std::string::npos)
        {
            // It contains [ or ], so it should be an IPv6 address
            if (posColonLeft == std::string::npos ||
                posColonRight == std::string::npos)
            {
                // There either '[' or ']', invalid config
                return {};
            }
            if (line.size() < posColonRight + 2 ||
                line.at(posColonRight + 1) != ':')
            {
                // There is no ':', or no more content after ':', invalid config
                return {};
            }
            serverAddress =
                line.substr(posColonLeft + 1, posColonRight - posColonLeft - 1);
            serverPort = line.substr(posColonRight + 2);
        }
        else
        {
            auto pos = line.find(':');
            if (pos == std::string::npos)
            {
                // There is no ':', invalid config
                return {};
            }
            serverAddress = line.substr(start, pos - start);
            serverPort = line.substr(pos + 1);
        }
    }

    if (serverAddress.empty() || serverPort.empty())
    {
        return {};
    }
    try
    {
        return std::make_tuple(std::move(serverAddress), std::stoul(serverPort),
                               serverTransportProtocol, tls, clientModeEnabled,
                               facilities, *severity);
    }
    catch (const std::exception& ex)
    {
        log<level::ERR>("Invalid config", entry("ERR=%s", ex.what()));
        return {};
    }
}
} // namespace internal

std::string Server::address(std::string value)
{
    using Argument = xyz::openbmc_project::common::InvalidArgument;
    std::string result{};

    try
    {
        auto serverAddress = address();
        if (serverAddress == value)
        {
            return serverAddress;
        }
        if (!value.empty())
        {
            // Check for valid IPv4/IPv6 address and address string is not empty
            try
            {
                stdplus::fromStr<stdplus::InAnyAddr>(value);
            }
            catch (const std::exception& e)
            {
                log<level::ERR>("Invalid IP address",
                                entry("NET_IP=%s", value.c_str()),
                                entry("ERROR=%s", e.what()));
                elog<InvalidArgument>(Argument::ARGUMENT_NAME("Address"),
                                      Argument::ARGUMENT_VALUE(value.c_str()));
            }
        }
        if (!value.empty() && !addressValid(value))
        {
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("Address"),
                                  Argument::ARGUMENT_VALUE(value.c_str()));
        }

        writeConfig(value, port(), transportProtocol(), tls(), enabled(),
                    severity(), facility(), rfcformat(),
                    configFilePath.c_str());
        result = NetworkClient::address(value);
    }
    catch (const InvalidArgument& e)
    {
        throw;
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }

    return result;
}

uint16_t Server::port(uint16_t value)
{
    uint16_t result{};

    try
    {
        auto serverPort = port();
        if (serverPort == value)
        {
            return serverPort;
        }

        writeConfig(address(), value, transportProtocol(), tls(), enabled(),
                    severity(), facility(), rfcformat(),
                    configFilePath.c_str());
        result = NetworkClient::port(value);
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }

    return result;
}

bool Server::tls(bool value)
{
    bool result{};

    try
    {
        auto serverTls = RsyslogClient::tls();
        if (serverTls == value)
        {
            return serverTls;
        }

        writeConfig(address(), port(), transportProtocol(), value, enabled(),
                    severity(), facility(), rfcformat(),
                    configFilePath.c_str());
        result = RsyslogClient::tls(value);
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }

    return result;
}

bool Server::enabled(bool value)
{
    bool result{};

    try
    {
        auto serverEnabled = RsyslogClient::enabled();
        if (serverEnabled == value)
        {
            return serverEnabled;
        }

        writeConfig(address(), port(), transportProtocol(), tls(), value,
                    severity(), facility(), rfcformat(),
                    configFilePath.c_str());
        result = RsyslogClient::enabled(value);
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }

    return result;
}

RsyslogClient::SeverityType Server::severity(RsyslogClient::SeverityType value)
{
    RsyslogClient::SeverityType currentSeverity;
    try
    {
        currentSeverity = RsyslogClient::severity();
        if (currentSeverity == value)
        {
            return currentSeverity;
        }

        // Validate input severities
        if (value != RsyslogClient::SeverityType::Error &&
            value != RsyslogClient::SeverityType::Warning &&
            value != RsyslogClient::SeverityType::Info &&
            value != RsyslogClient::SeverityType::All)
        {
            log<level::ERR>("Invalid severity provided.");
            elog<InternalFailure>();
        }

        auto currentFacility = RsyslogClient::facility();

        // Write the new severity with the current facility
        writeConfig(address(), port(), transportProtocol(), tls(), enabled(),
                    value, currentFacility, rfcformat(),
                    configFilePath.c_str());
        RsyslogClient::severity(value);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return value;
}

std::vector<RsyslogClient::FacilityType> Server::facility(
    std::vector<RsyslogClient::FacilityType> value)
{
    std::vector<RsyslogClient::FacilityType> currentFacility;
    try
    {
        currentFacility = RsyslogClient::facility();

        // If the new value matches the current value, return without changes
        if (currentFacility == value)
        {
            return currentFacility;
        }

        // Validate input facilities
        for (const auto& facility : value)
        {
            if (facility != RsyslogClient::FacilityType::Daemon &&
                facility != RsyslogClient::FacilityType::Kern &&
                facility != RsyslogClient::FacilityType::All)
            {
                log<level::ERR>("Invalid facility provided.");
                elog<InternalFailure>();
            }
        }

        // Ensure severity is set (it should not be empty)
        auto currentSeverity = RsyslogClient::severity();

        // Write the new facility with the current severity
        writeConfig(address(), port(), transportProtocol(), tls(), enabled(),
                    currentSeverity, value, rfcformat(),
                    configFilePath.c_str());

        // Update facilities
        RsyslogClient::facility(value);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }
    return value;
}

NetworkClient::TransportProtocol Server::transportProtocol(
    NetworkClient::TransportProtocol value)
{
    TransportProtocol result{};

    try
    {
        auto serverTransportProtocol = transportProtocol();
        if (serverTransportProtocol == value)
        {
            return serverTransportProtocol;
        }

        writeConfig(address(), port(), value, tls(), enabled(), severity(),
                    facility(), rfcformat(), configFilePath.c_str());
        result = NetworkClient::transportProtocol(value);
    }
    catch (const InternalFailure& e)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>(e.what());
        elog<InternalFailure>();
    }

    return result;
}

RsyslogClient::RfcFormatType Server::rfcformat(
    RsyslogClient::RfcFormatType value)
{
    auto current = RsyslogClient::rfcformat();
    if (current == value)
    {
        return current;
    }

    // Persist in config with the new format
    writeConfig(address(), port(), transportProtocol(), tls(), enabled(),
                severity(), facility(), value, configFilePath.c_str());

    return RsyslogClient::rfcformat(value);
}

void Server::writeConfig(
    const std::string& serverAddress, uint16_t serverPort,
    NetworkClient::TransportProtocol serverTransportProtocol, bool tls,
    bool enabled, RsyslogClient::SeverityType severity,
    std::vector<RsyslogClient::FacilityType> facilities,
    RsyslogClient::RfcFormatType rfcFormat, const char* filePath)
{
    std::fstream stream(filePath, std::fstream::out);

    auto writeLine = [&](const std::string& line) {
        if (!enabled)
        {
            stream << "# Disabled: " << line << std::endl;
        }
        else
        {
            stream << line << std::endl;
        }
    };

    if (serverPort && !serverAddress.empty())
    {
        if (!enabled)
        {
            // dummy action to avoid error 2103 on startup
            stream << "*.* /dev/null" << std::endl;
        }

        // Load legacy modules
        writeLine("$ModLoad imuxsock");
        writeLine("$ModLoad omfwd");

        if (tls)
        {
            writeLine("$DefaultNetstreamDriver gtls");
            writeLine("$ActionSendStreamDriverAuthMode anon");
            writeLine("$ActionSendStreamDriverMode 1");
        }

        // When RFC5424, define a template with IP fallback and use it
        if (rfcFormat == RsyslogClient::RfcFormatType::RFC5424)
        {
            std::string ipForTemplate;
            if (!bmcIPv4Address.empty())
            {
                ipForTemplate = bmcIPv4Address;
            }
            else if (!bmcIPv6Address.empty())
            {
                ipForTemplate = bmcIPv6Address;
            }
            else
            {
                ipForTemplate = "%fromhost-ip%";
            }
            writeLine(
                "$template RFC5424withIP,\"<%pri%>1 %timestamp:::date-rfc3339% " +
                ipForTemplate +
                " %hostname% %app-name% %procid% %msgid% %msg%\\n\"");
        }

        // Build selector
        std::string severityStr;
        switch (severity)
        {
            case RsyslogClient::SeverityType::Error:
                severityStr = "error";
                break;
            case RsyslogClient::SeverityType::Warning:
                severityStr = "warning";
                break;
            case RsyslogClient::SeverityType::Info:
                severityStr = "info";
                break;
            case RsyslogClient::SeverityType::All:
            default:
                severityStr = "*";
                break;
        }

        // Convert facilities to a comma-separated string
        std::string facilityStr;
        for (const auto& facility : facilities)
        {
            switch (facility)
            {
                case RsyslogClient::FacilityType::Daemon:
                    facilityStr += (facilityStr.empty() ? "" : ",") +
                                   std::string("daemon");
                    break;
                case RsyslogClient::FacilityType::Kern:
                    facilityStr += (facilityStr.empty() ? "" : ",") +
                                   std::string("kern");
                    break;
                case RsyslogClient::FacilityType::All:
                default:
                    facilityStr = std::string("*");
                    break;
            }
            // If the 'All' case is hit, exit the loop
            if (facility == RsyslogClient::FacilityType::All)
            {
                break;
            }
        }
        // Assign '*' if facilityStr is empty
        if (facilityStr.empty())
        {
            facilityStr = "*";
        }

        std::string type =
            (serverTransportProtocol == NetworkClient::TransportProtocol::UDP)
                ? "@"
                : "@@";

        std::string templateSuffix =
            (rfcFormat == RsyslogClient::RfcFormatType::RFC5424)
                ? ";RFC5424withIP"
                : ";RSYSLOG_TraditionalForwardFormat";

        if (internal::isIPv6Address(serverAddress))
        {
            writeLine(facilityStr + "." + severityStr + " " + type + "[" +
                      serverAddress + "]:" + std::to_string(serverPort) +
                      templateSuffix);
        }
        else
        {
            writeLine(facilityStr + "." + severityStr + " " + type +
                      serverAddress + ":" + std::to_string(serverPort) +
                      templateSuffix);
        }
    }
    else // this is a disable request
    {
        // dummy action to avoid error 2103 on startup
        stream << "*.* /dev/null" << std::endl;
    }

    stream << std::endl;

    restart();
}

bool Server::addressValid(const std::string& address)
{
    addrinfo hints{};
    addrinfo* res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    auto result = getaddrinfo(address.c_str(), nullptr, &hints, &res);
    if (result)
    {
        log<level::ERR>("bad address", entry("ADDRESS=%s", address.c_str()),
                        entry("ERRNO=%d", result));
        return false;
    }

    freeaddrinfo(res);
    return true;
}

void Server::restore(const char* filePath)
{
    std::fstream stream(filePath, std::fstream::in);

    auto ret = internal::parseConfig(stream);
    if (ret)
    {
        NetworkClient::address(std::get<0>(*ret));
        NetworkClient::port(std::get<1>(*ret));
        NetworkClient::transportProtocol(std::get<2>(*ret));

        // rsyslog-specific changes
        RsyslogClient::tls(std::get<3>(*ret));
        RsyslogClient::enabled(std::get<4>(*ret));
        RsyslogClient::facility(std::get<5>(*ret));
        RsyslogClient::severity(std::get<6>(*ret));
    }
}

void Server::restart()
{
    utils::restart();
}

std::string Server::networkInterfacePrefix() const
{
    std::string ethernetInterface = "/xyz/openbmc_project/network/";
    ethernetInterface += std::string(RSYSLOG_ETHERNET_INTERFACE);
    ethernetInterface += "/";
    return ethernetInterface;
}

bool Server::pathIsOnConfiguredInterface(const std::string& path) const
{
    return path.starts_with(networkInterfacePrefix());
}

template <typename Variant>
void Server::handleIpProps(const std::map<std::string, Variant>& props)
{
    auto typeIt = props.find("Type");
    if (typeIt == props.end())
        return;

    const std::string* typeStr = std::get_if<std::string>(&typeIt->second);
    if (typeStr == nullptr)
        return;

    auto addrIt = props.find("Address");
    if (addrIt == props.end())
        return;

    if (const std::string* addr = std::get_if<std::string>(&addrIt->second))
    {
        if (*typeStr == "xyz.openbmc_project.Network.IP.Protocol.IPv4")
        {
            bmcIPv4Address = *addr;
        }
        else if (*typeStr == "xyz.openbmc_project.Network.IP.Protocol.IPv6")
        {
            bmcIPv6Address = *addr;
        }
    }
}

void Server::onInterfacesAdded(sdbusplus::message_t& msg)
{
    sdbusplus::message::object_path objPath;
    std::map<
        std::string,
        std::map<std::string,
                 std::variant<bool, uint32_t, int64_t, std::string,
                              std::vector<uint8_t>, std::vector<std::string>,
                              std::map<std::string, std::string>, uint64_t>>>
        ifaces;
    msg.read(objPath, ifaces);

    const std::string& pathStr = objPath.str;
    if (!pathIsOnConfiguredInterface(pathStr))
        return;

    auto it = ifaces.find("xyz.openbmc_project.Network.IP");
    if (it == ifaces.end())
        return;

    const auto& props = it->second;
    handleIpProps(props);
    restart();
}

void Server::onIPPropertiesChanged(sdbusplus::message_t& msg)
{
    std::string interface;
    std::map<std::string,
             std::variant<bool, uint32_t, int64_t, std::string,
                          std::vector<uint8_t>, std::vector<std::string>,
                          std::map<std::string, std::string>, uint64_t>>
        changedProps;
    std::vector<std::string> invalidated;
    // Filter to the configured interface by checking the message path
    const char* pathCstr = msg.get_path();
    if (pathCstr == nullptr)
    {
        return;
    }
    std::string pathStr(pathCstr);
    if (!pathIsOnConfiguredInterface(pathStr))
    {
        return;
    }

    msg.read(interface, changedProps, invalidated);
    if (interface != "xyz.openbmc_project.Network.IP")
        return;

    handleIpProps(changedProps);
    restart();
}

} // namespace rsyslog_config
} // namespace phosphor
