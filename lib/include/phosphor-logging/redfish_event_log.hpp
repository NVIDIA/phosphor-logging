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
#pragma once
#include "xyz/openbmc_project/Logging/Entry/server.hpp"

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>

#include <string>
#include <unordered_map>
#include <vector>

namespace phosphor
{

namespace logging
{

using namespace sdbusplus::xyz::openbmc_project::Logging::server;

enum class MESSAGE_TYPE
{
    RESOURCE_CREATED,
    RESOURCE_DELETED,
    PROPERTY_VALUE_MODIFIED,
    REBOOT_REASON
};

/**
 * @brief dbus log when resource created/modified/deleted.
 * @param[in] connObject  - boost asio connection object.
 * The components which do have the connection object then it can be re-used
 * the connection  object must be static so that it can't go out of scope.
 * @param[in] message  - Message enums RESOURCE_CREATED, RESOURCE_DELETED,
 * PROPERTY_VALUE_MODIFIED etc.
 * @param[in] severity - serverity level
 * @param[in] dbusPropertyValueList - arguments like dbus property name and
 * value. needs to be in the format of ["propertyName,propertyValue"]
 * @param[in] dbusObjectPath - The dbus object path of resource
 * @example - usage example for PROPERTY_VALUE_MODIFIED
 *            Here propertyName is 'ModulePowerCap' and propertyValue is '450'
 * std::vector<std::string> dbusPropertyValueList = {"ModulePowerCap",
 * std::to_string(450)}; std::string dbusObjectPath =
 * "/xyz/openbmc_project/inventory/system/processors/GPU_0"; sendEvent(conn,
 * MESSAGE_TYPE::PROPERTY_VALUE_MODIFIED, Entry::Level::Alert,
 * dbusPropertyValueList,dbusObjectPath);
 *
 * @example - usage example for RESOURCE_CREATED
 *            Here propertyName and propertyValue is not required therefore
 * dbusPropertyValueList is empty std::vector<std::string> dbusPropertyValueList
 * {}; std::string dbusObjectPath =
 * "/xyz/openbmc_project/VirtualMedia/Legacy/USB1";
 * sendEvent(conn,MESSAGE_TYPE::RESOURCE_CREATED,
 * Entry::Level::Informational, dbusPropertyValueList, dbusObjectPath);
 *
 * @example - usage example for RESOURCE_DELETED
 *            Here propertyName and propertyValue is not required therefore
 * dbusPropertyValueList is empty std::vector<std::string> dbusPropertyValueList
 * {}; std::string dbusObjectPath =
 * "/xyz/openbmc_project/VirtualMedia/Legacy/USB1"";
 * sendEvent(conn,MESSAGE_TYPE::RESOURCE_DELETED,
 * Entry::Level::Informational, dbusPropertyValueList,dbusObjectPath);
 *
 * @example - usage example for REBOOT_REASON
 *            Hereonly propertyValue is required therefore dbusPropertyValueList
 * is having only propertyValue std::vector<std::string> dbusPropertyValueList
 * {"FactoryReset"}; std::string ooc =
 * "/xyz/openbmc_project/state/bmc0/Mananger.ResetToDefaults";
 * sendEvent(conn,MESSAGE_TYPE::REBOOT_REASON,
 * Entry::Level::Informational, dbusPropertyValueList,dbusObjectPath);
 * @note - device name is optional and required only for Chassis components
 */
void sendEvent(const std::shared_ptr<sdbusplus::asio::connection>& connObject,
               MESSAGE_TYPE message, Entry::Level severity,
               const std::vector<std::string>& dbusPropertyValueList,
               const std::string& dbusObjectPath);

/**
 * @brief dbus log when resource created/modified/deleted.
 * This API specially for components which don't have the
 * sdbusplus::asio::connection object.
 * @param[in] message  - Message enums RESOURCE_CREATED, RESOURCE_DELETED,
 * PROPERTY_VALUE_MODIFIED etc.
 * @param[in] severity - serverity level
 * @param[in] dbusPropertyValueList - arguments like dbus property name and
 * value. needs to be in the format of ["propertyName,propertyValue"]
 * @param[in] dbusObjectPath - The dbus object path of resource
 * @example - usage example for PROPERTY_VALUE_MODIFIED
 *            Here propertyName is 'UserEnabled' and propertyValue is 'true'
 * std::vector<std::string> dbusPropertyValueList = {"UserEnabled", "true"};
 * std::string dbusObjectPath = "/xyz/openbmc_project/user/ + <username>";
 * sendEvent(MESSAGE_TYPE::PROPERTY_VALUE_MODIFIED,
 * Entry::Level::Alert, dbusPropertyValueList,dbusObjectPath);
 *
 * @example - usage example for RESOURCE_CREATED
 *            Here propertyName and propertyValue is not required therefore
 * dbusPropertyValueList is empty std::vector<std::string> dbusPropertyValueList
 * {}; std::string dbusObjectPath = "/xyz/openbmc_project/user/ + <username>";
 * sendEvent(MESSAGE_TYPE::RESOURCE_CREATED,
 * Entry::Level::Informational, dbusPropertyValueList, dbusObjectPath);
 *
 * @example - usage example for RESOURCE_DELETED
 *            Here propertyName and propertyValue is not required therefore
 * dbusPropertyValueList is empty std::vector<std::string> dbusPropertyValueList
 * {}; std::string dbusObjectPath = "/xyz/openbmc_project/user/ + <username>";
 * sendEvent(MESSAGE_TYPE::RESOURCE_DELETED,
 * Entry::Level::Informational, dbusPropertyValueList,dbusObjectPath);
 *
 * @example - usage example for REBOOT_REASON
 *            Hereonly propertyValue is required therefore dbusPropertyValueList
 * is having only propertyValue std::vector<std::string> dbusPropertyValueList
 * {"FactoryReset"}; std::string ooc =
 * "/xyz/openbmc_project/state/bmc0/Mananger.ResetToDefaults";
 * sendEvent(MESSAGE_TYPE::REBOOT_REASON,
 * Entry::Level::Informational, dbusPropertyValueList,dbusObjectPath);
 * @note - device name is optional and required only for Chassis components
 */
void sendEvent(MESSAGE_TYPE message, Entry::Level severity,
               const std::vector<std::string>& dbusPropertyValueList,
               const std::string& dbusObjectPath);

} // namespace logging
} // namespace phosphor
