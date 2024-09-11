#include "config.h"

#include "conf.hpp"

#include "utils.hpp"

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <unordered_map>

namespace phosphor
{
namespace rsyslog_config
{
using namespace phosphor::logging;
using namespace sdbusplus::xyz::openbmc_project::Common::Error;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

constexpr size_t MAX_ENTRIES = 10;
constexpr size_t MAX_LOGTYPES = 4;
constexpr size_t INVALID_INDEX = static_cast<size_t>(-1);

const std::unordered_map<RsyslogFwd::LogType, std::string> logTypeStringMap = {
    {RsyslogFwd::LogType::AuditLog, "AuditLog"},
    {RsyslogFwd::LogType::SEL, "SEL"},
    {RsyslogFwd::LogType::Syslog, "Syslog"},
    {RsyslogFwd::LogType::SOL, "SOL"}};

const std::unordered_map<RsyslogFwd::TransportProtocol, std::string>
    transportProtocolStringMap = {{RsyslogFwd::TransportProtocol::TCP, "tcp"},
                                  {RsyslogFwd::TransportProtocol::UDP, "udp"}};

const std::unordered_map<RsyslogFwd::NetworkProtocol, std::string>
    networkProtocolStringMap = {{RsyslogFwd::NetworkProtocol::IPv4, "inet"},
                                {RsyslogFwd::NetworkProtocol::IPv6, "inet6"}};

/* Converts enum values to strings */
template <typename T>
std::string
    enumToString(T value,
                 const std::unordered_map<T, std::string>& enumStringMap)
{
    auto it = enumStringMap.find(value);
    if (it != enumStringMap.end())
    {
        return it->second;
    }
    return "Unknown";
}

/* Converts strings to enum values */
template <typename T>
T stringToEnum(const std::string& str,
               const std::unordered_map<T, std::string>& enumStringMap)
{
    for (const auto& pair : enumStringMap)
    {
        if (pair.second == str)
        {
            return pair.first;
        }
    }
    /* Returns default enum value if not found */
    return static_cast<T>(0);
}

void Conf::createRsyslogFwdIndex(
    size_t index, RsyslogFwd::LogType logType, bool enabled,
    RsyslogFwd::TransportProtocol transportProtocol,
    RsyslogFwd::NetworkProtocol networkProtocol, std::string address,
    uint16_t port)
{
    /* Checks if action already exists */
    if (actionExists(index, logType))
    {
        log<level::ERR>("RsyslogFwd Object already exists",
                        entry("INDEX=%d", index),
                        entry("LOG_TYPE=%d", logType));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("Index"),
            Argument::ARGUMENT_VALUE(std::to_string(index).c_str()));
        return;
    }

    /* Adds RsyslogFwd with specific index */
    if (addRsyslogFwdObject(index, logType, enabled, transportProtocol,
                            networkProtocol, address, port))
    {
        /* Overrides config files */
        if (overrideConfigFile(logType))
        {
            rsyslog_utils::restart();
        }
    }
}

size_t Conf::createRsyslogFwd(RsyslogFwd::LogType logType, bool enabled,
                              RsyslogFwd::TransportProtocol transportProtocol,
                              RsyslogFwd::NetworkProtocol networkProtocol,
                              std::string address, uint16_t port)
{
    size_t avalIndex = INVALID_INDEX;

    /* Finds the first index available of logType in database */
    for (size_t index = 0; index < MAX_ENTRIES; index++)
    {
        if (!actionExists(index, logType))
        {
            avalIndex = index;
            break;
        }
    }

    /* No available index was found for logType */
    if (avalIndex == INVALID_INDEX)
    {
        log<level::ERR>("No available index was found for logType",
                        entry("LOG_TYPE=%d", logType));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("LogType"),
            Argument::ARGUMENT_VALUE(
                enumToString(logType, logTypeStringMap).c_str()));
        return INVALID_INDEX;
    }

    /* Adds RsyslogFwd with specific index */
    if (addRsyslogFwdObject(avalIndex, logType, enabled, transportProtocol,
                            networkProtocol, address, port))
    {
        /* Overrides config files */
        if (overrideConfigFile(logType))
        {
            rsyslog_utils::restart();
            return avalIndex;
        }
    }

    return INVALID_INDEX;
}

void Conf::removeRsyslogFwd(size_t index, RsyslogFwd::LogType logType)
{
    /* Finds the relevant ptr in fwdActions */
    auto it = std::find_if(fwdActions.begin(), fwdActions.end(),
                           [index, logType](const auto& fwdActionPtr) {
        return (fwdActionPtr->index() == index) &&
               (fwdActionPtr->logType() == logType);
    });

    if (it == fwdActions.end())
    {
        log<level::ERR>("RsyslogFwd was not found", entry("INDEX=%d", index),
                        entry("LOG_TYPE=%d", logType));
        return;
    }

    /* Removes the RsyslogFwd object */
    fwdActions.erase(it);
}

bool Conf::actionExists(size_t index, RsyslogFwd::LogType logType)
{
    auto it = std::find_if(fwdActions.begin(), fwdActions.end(),
                           [index, logType](const auto& fwdActionPtr) {
        return fwdActionPtr->index() == index &&
               fwdActionPtr->logType() == logType;
    });

    return (it != fwdActions.end()) ? true : false;
}

bool Conf::addRsyslogFwdObject(size_t index, RsyslogFwd::LogType logType,
                               bool enabled,
                               RsyslogFwd::TransportProtocol transportProtocol,
                               RsyslogFwd::NetworkProtocol networkProtocol,
                               std::string address, uint16_t port)
{
    /* Checks if index is valid */
    if (index >= MAX_ENTRIES)
    {
        log<level::ERR>("Invalid index", entry("INDEX=%d", index));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("Index"),
            Argument::ARGUMENT_VALUE(std::to_string(index).c_str()));
        return false;
    }

    /* Checks if there are too many entries from type logType */
    size_t count = 0;
    for (auto& fwdActionPtr : fwdActions)
    {
        if (fwdActionPtr->logType() == logType)
        {
            count++;
        }
    }
    if (count >= MAX_ENTRIES)
    {
        log<level::ERR>("Too many entries of logType", entry("COUNT=%d", count),
                        entry("LOG_TYPE=%d", logType));
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("LogType"),
            Argument::ARGUMENT_VALUE(
                enumToString(logType, logTypeStringMap).c_str()));
        return false;
    }

    /* Creates RsyslogFwd */
    std::string logTypeStr = enumToString(logType, logTypeStringMap);
    std::string objPath = BUSPATH_FWD_LOGGING_CONFIG_PREFIX + logTypeStr + "_" +
                          std::to_string(index);
    try
    {
        auto fwdActionPtr = std::make_unique<RsyslogFwdAction>(
            bus, objPath, index, logType, enabled, transportProtocol,
            networkProtocol, address, port, this);

        /* Updates RsyslogFwd */
        fwdActions.emplace_back(std::move(fwdActionPtr));
        return true;
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to create RsyslogFwd object",
                        entry("EXCEPTION=%s", e.what()));
        elog<InternalFailure>();
    }

    return false;
}

bool Conf::overrideConfigFile(RsyslogFwd::LogType logType)
{
    std::string logTypeStr = enumToString(logType, logTypeStringMap);
    std::string filePath = std::string(RSYSLOG_FWD_ACTIONS_CONF_DIR_PATH) +
                           "/fwd_" + logTypeStr + ".conf";

    /* Removes the file */
    std::filesystem::remove(filePath);

    /* Checks if fwd_<logType>.conf is necessary */
    bool fileHasContent = false;
    for (auto& fwdActionPtr : fwdActions)
    {
        if (fwdActionPtr->logType() == logType)
        {
            fileHasContent = true;
            break;
        }
    }
    if (!fileHasContent)
    {
        return true;
    }

    /* Creates a new file */
    std::ofstream configFile(filePath);
    if (!configFile.is_open())
    {
        log<level::ERR>("Failed to open file for writing");
        elog<InternalFailure>();
        return false;
    }

    configFile
        << "# Do not edit this file. It is auto-generated by phosphor-rsyslog-config\n\n";
    configFile << "ruleset(name=\"" << logTypeStr << "Ruleset\") {\n";

    for (auto& fwdActionPtr : fwdActions)
    {
        if (fwdActionPtr->logType() == logType)
        {
            if (!fwdActionPtr->enabled())
            {
                configFile << "#";
            }
            configFile << "  action(type=\"omfwd\" target=\""
                       << fwdActionPtr->address() << "\" protocol=\""
                       << enumToString(fwdActionPtr->transportProtocol(),
                                       transportProtocolStringMap)
                       << "\" port=\"" << fwdActionPtr->port()
                       << "\" template=\"ConsoleTemplate\") # index="
                       << fwdActionPtr->index() << " addressFamily=\""
                       << enumToString(fwdActionPtr->networkProtocol(),
                                       networkProtocolStringMap)
                       << "\"\n";
        }
    }
    configFile << "}\n";
    configFile.close();

    /* Restart rsyslog service */
    return true;
}

bool Conf::createObjectsFromConfigFiles()
{
    std::regex actionRegex(
        R"(^\s*(#)?  action\(type=\"omfwd\" target=\"([^"]+)\" protocol=\"([^"]+)\" port=\"(\d+)\" template=\"ConsoleTemplate\"\)\s*#\s*index=(\d+)\s*addressFamily=\"([^"]+)\"\s*$)");

    for (const auto& entry :
         std::filesystem::directory_iterator(RSYSLOG_FWD_ACTIONS_CONF_DIR_PATH))
    {
        /* Reads all fwd_<LogType>.conf files */
        std::string filenameStr = entry.path().filename().string();
        if (std::filesystem::is_regular_file(entry.path()) &&
            filenameStr.starts_with("fwd_"))
        {
            std::ifstream configFile(entry.path());
            if (!configFile.is_open())
            {
                log<level::ERR>("Failed to open file for reading");
                elog<InternalFailure>();
                return false;
            }

            std::string logTypeName =
                filenameStr.substr(4);         /* Removes "fwd_" prefix */
            logTypeName = logTypeName.substr(
                0, logTypeName.find(".conf")); /* Removes ".conf" suffix */
            RsyslogFwd::LogType logType = stringToEnum(logTypeName,
                                                       logTypeStringMap);

            std::string line;
            while (std::getline(configFile, line))
            {
                std::smatch match;
                if (std::regex_match(line, match, actionRegex))
                {
                    bool enabled = (match[1].str() != "#");
                    std::string address = match[2].str();
                    RsyslogFwd::TransportProtocol transportProtocol =
                        stringToEnum(match[3].str(),
                                     transportProtocolStringMap);
                    uint16_t port =
                        static_cast<uint16_t>(std::stoi(match[4].str()));
                    size_t index =
                        static_cast<size_t>(std::stoi(match[5].str()));
                    RsyslogFwd::NetworkProtocol networkProtocol =
                        stringToEnum(match[6].str(), networkProtocolStringMap);

                    if (index < MAX_ENTRIES)
                    {
                        addRsyslogFwdObject(index, logType, enabled,
                                            transportProtocol, networkProtocol,
                                            address, port);
                    }
                }
            }
        }
    }
    return true;
}

} // namespace rsyslog_config
} // namespace phosphor
