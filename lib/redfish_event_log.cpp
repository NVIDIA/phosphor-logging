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

#include <phosphor-logging/asio_connection.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/redfish_event_log.hpp>

#include <map>
namespace phosphor
{

namespace logging
{

std::unordered_map<MESSAGE_TYPE, const std::string> messageMap = {
    {MESSAGE_TYPE::RESOURCE_CREATED, "ResourceEvent.1.2.ResourceCreated"},
    {MESSAGE_TYPE::RESOURCE_DELETED, "ResourceEvent.1.2.ResourceRemoved"},
    {MESSAGE_TYPE::PROPERTY_VALUE_MODIFIED, "Base.1.15.PropertyValueModified"},
    {MESSAGE_TYPE::REBOOT_REASON, "OpenBMC.0.4.BMCRebootReason"}};

std::unordered_map<Entry::Level, const std::string> severityMap = {
    {Entry::Level::Emergency,
     "xyz.openbmc_project.Logging.Entry.Level.Emergency"},
    {Entry::Level::Alert, "xyz.openbmc_project.Logging.Entry.Level.Alert"},
    {Entry::Level::Critical,
     "xyz.openbmc_project.Logging.Entry.Level.Critical"},
    {Entry::Level::Notice, "xyz.openbmc_project.Logging.Entry.Level.Notice"},
    {Entry::Level::Informational,
     "xyz.openbmc_project.Logging.Entry.Level.Informational"},
    {Entry::Level::Warning, "xyz.openbmc_project.Logging.Entry.Level.Warning"},
    {Entry::Level::Error, "xyz.openbmc_project.Logging.Entry.Level.Error"},
    {Entry::Level::Debug, "xyz.openbmc_project.Logging.Entry.Level.Debug"}};

void sendEvent(const std::shared_ptr<sdbusplus::asio::connection>& connObject,
               MESSAGE_TYPE message, Entry::Level severity,
               const std::vector<std::string>& dbusPropertyValueList,
               const std::string& dbusObjectPath)
{
    if (connObject == nullptr)
    {
        log<level::ERR>("Connection object is null");
        return;
    }
    constexpr auto IFACE_INTERNAL(
        "xyz.openbmc_project.Logging.Internal.Manager");

    std::map<std::string, std::string> addData;
    addData["REDFISH_MESSAGE_ID"] = messageMap[message];
    if (dbusPropertyValueList.size() > 0)
    {
        std::string args;
        // Use an iterator to iterate through the vector
        for (auto it = dbusPropertyValueList.begin();
             it != dbusPropertyValueList.end(); ++it)
        {
            args += *it;
            // If it's not the last element, add a comma
            if (std::next(it) != dbusPropertyValueList.end())
            {
                args.push_back(',');
            }
        }
        addData["REDFISH_MESSAGE_ARGS"] = args;
    }
    addData["REDFISH_ORIGIN_OF_CONDITION"] = dbusObjectPath;
    connObject->async_method_call(
        [](boost::system::error_code ec) {
        if (ec)
        {
            log<level::ERR>("Failed to create RF event log ");
        }
        else
        {
            log<level::INFO>("Successfully created RF event log ");
        }
    },
        BUSNAME_LOGGING, OBJ_INTERNAL, IFACE_INTERNAL, "RFSendEvent",
        messageMap[message], severityMap[severity], addData);
}

void sendEvent(MESSAGE_TYPE message, Entry::Level severity,
               const std::vector<std::string>& dbusPropertyValueList,
               const std::string& dbusObjectPath)
{
    auto& connObject = AsioConnection::getAsioConnection();
    if (connObject == nullptr)
    {
        log<level::ERR>("Connection object is null");
        return;
    }

    constexpr auto IFACE_INTERNAL(
        "xyz.openbmc_project.Logging.Internal.Manager");

    std::map<std::string, std::string> addData;
    addData["REDFISH_MESSAGE_ID"] = messageMap[message];
    if (dbusPropertyValueList.size() > 0)
    {
        std::string args;
        // Use an iterator to iterate through the vector
        for (auto it = dbusPropertyValueList.begin();
             it != dbusPropertyValueList.end(); ++it)
        {
            args += *it;
            // If it's not the last element, add a comma
            if (std::next(it) != dbusPropertyValueList.end())
            {
                args.push_back(',');
            }
        }
        addData["REDFISH_MESSAGE_ARGS"] = args;
    }
    addData["REDFISH_ORIGIN_OF_CONDITION"] = dbusObjectPath;
    connObject->async_method_call(
        [](boost::system::error_code ec) {
        if (ec)
        {
            log<level::ERR>("Failed to create RF event log ");
        }
        else
        {
            log<level::INFO>("Successfully created RF event log ");
        }
    },
        BUSNAME_LOGGING, OBJ_INTERNAL, IFACE_INTERNAL, "RFSendEvent",
        messageMap[message], severityMap[severity], addData);
}

} // namespace logging
} // namespace phosphor
