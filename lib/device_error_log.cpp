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
#include <phosphor-logging/device_error_log.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>

#include <iomanip>
#include <map>
#include <sstream>

namespace nv
{

namespace lg2
{

void CommitDeviceError(uint8_t deviceAddress, int64_t errorCode,
                       ErrorClass errorClass,
                       std::map<std::string, std::string> additionalData)
{
    auto& connObject = phosphor::logging::AsioConnection::getAsioConnection();
    if (connObject == nullptr)
    {
        ::lg2::error("Connection object is null");
        return;
    }

    // Validate that REDFISH_MESSAGE_ID is provided (required for proper Redfish
    // logging)
    auto it = additionalData.find("REDFISH_MESSAGE_ID");
    if (it == additionalData.end() || it->second.empty())
    {
        // Log error to journal and return - don't use arbitrary default message
        ::lg2::error(
            "CommitDeviceError called without REDFISH_MESSAGE_ID - cannot create log entry: address={ADDR}, code={CODE}, class={CLASS}",
            "ADDR", deviceAddress, "CODE", errorCode, "CLASS",
            static_cast<int>(errorClass));
        return;
    }
    std::string messageId = it->second;

    // Add PLATFORM_* fields directly to additionalData (no extra map needed)
    additionalData["PLATFORM_DEVICE_ADDRESS"] = std::to_string(deviceAddress);
    additionalData["PLATFORM_DEVICE_ERROR"] = std::to_string(errorCode);
    additionalData["PLATFORM_DEVICE_CLASS"] =
        std::to_string(static_cast<int>(errorClass));
    additionalData["namespace"] = "DeviceErrorLog";

    // Capture error details for logging in callback
    auto redfishMsgArgs = additionalData.find("REDFISH_MESSAGE_ARGS");
    std::string redfishArgs =
        (redfishMsgArgs != additionalData.end()) ? redfishMsgArgs->second : "";

    Entry::Level severity = Entry::Level::Error;
    if (auto severityIt = additionalData.find("REDFISH_SEVERITY");
        severityIt != additionalData.end())
    {
        severity = Entry::convertStringToLevel(severityIt->second)
                       .value_or(Entry::Level::Error);
    }

    if (auto resolutionIt = additionalData.find("REDFISH_RESOLUTION");
        resolutionIt != additionalData.end())
    {
        additionalData["xyz.openbmc_project.Logging.Entry.Resolution"] =
            resolutionIt->second;
    }

    connObject->async_method_call(
        [deviceAddress, errorCode, errorClass, messageId,
         redfishArgs](boost::system::error_code ec) {
            if (ec)
            {
                ::lg2::error(
                    "Failed to commit device error log: {MSG}, address={ADDR}, code={CODE}, class={CLASS}, redfishId={RFID}, redfishArgs={RFARGS}",
                    "MSG", ec.message(), "ADDR", deviceAddress, "CODE",
                    errorCode, "CLASS", static_cast<int>(errorClass), "RFID",
                    messageId, "RFARGS", redfishArgs);
            }
            else
            {
                ::lg2::info(
                    "Successfully committed device error log: address={ADDR}, code={CODE}, class={CLASS}, redfishId={RFID}, redfishArgs={RFARGS}",
                    "ADDR", deviceAddress, "CODE", errorCode, "CLASS",
                    static_cast<int>(errorClass), "RFID", messageId, "RFARGS",
                    redfishArgs);
            }
        },
        BUSNAME_LOGGING, OBJ_LOGGING, "xyz.openbmc_project.Logging.Create",
        "Create", messageId, severity, additionalData);
}

} // namespace lg2
} // namespace nv
