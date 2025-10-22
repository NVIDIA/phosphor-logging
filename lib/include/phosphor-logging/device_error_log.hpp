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
#include <com/nvidia/State/DeviceState/server.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/server/manager.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace nv
{

namespace lg2
{

using namespace sdbusplus::xyz::openbmc_project::Logging::server;

// Use PDI-generated ErrorClass enum directly (no internal enum conversion)
using ErrorClass =
    sdbusplus::server::com::nvidia::state::DeviceState::ErrorClass;

// Error codes organized by error class
namespace ErrorCode
{
// Power Status error codes
namespace PowerStatus
{
constexpr int64_t POWER_ON = 0x01;
constexpr int64_t POWER_OFF = 0x02;
} // namespace PowerStatus

// Recovery Status error codes
namespace Recovery
{
constexpr int64_t IN_RECOVERY = 0x01;
constexpr int64_t NOT_IN_RECOVERY = 0x02;
} // namespace Recovery

// Physical Interface Status error codes
namespace PhysicalInterface
{
constexpr int64_t PRESENT = 0x01;
constexpr int64_t ABSENT = 0x02;
} // namespace PhysicalInterface

// MCTP Status error codes
namespace MCTP
{
constexpr int64_t PING_SUCCESS = 0x01;
constexpr int64_t MCTP_TRANSPORT_FAIL_PING_TIMEOUT = 0x02;
constexpr int64_t UUID_DISCOVERY_TIMEOUT = 0x03;
constexpr int64_t USB_TX_MEMORY_ALLOC_FAILURE = 0x04;
} // namespace MCTP
} // namespace ErrorCode

/**
 * @brief Error class to priority mapping (PDI enum-based)
 *
 * Lower number = higher priority (more critical).
 * This is the single source of truth for error class priorities,
 * used by both the public API and internal error database.
 */
inline const std::unordered_map<ErrorClass, uint8_t> errorClassPriority = {
    {ErrorClass::Power, 0},
    {ErrorClass::Recovery, 0},
    {ErrorClass::PhysicalInterface, 1},
    {ErrorClass::MCTP, 1}};

/**
 * @brief Commit a device error log for platform error logging.
 * @param[in] deviceAddress - The EID of the device reporting the error (0-255)
 * @param[in] errorCode - The error code
 * @param[in] errorClass - The error class enumeration (PDI ErrorClass)
 * @param[in] additionalData - Additional key-value pairs to add to the log data
 *                             Caller should populate fields like
 *                             REDFISH_MESSAGE_ID, REDFISH_MESSAGE_ARGS, etc.
 *                             using GetRedfishErrorInfo() before calling.
 * @example - usage example for device error logging
 *            uint8_t deviceAddr = 16;  // EID 16
 *            int64_t errCode =
 * ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT; auto info =
 * GetRedfishErrorInfo(errCode, ErrorClass::MCTP); std::map<std::string,
 * std::string> data = {
 *                {"REDFISH_MESSAGE_ID", info.redfishMessageId},
 *                {"REDFISH_MESSAGE_ARGS", "GPU0, info.errorMessage"},
 *            };
 *            CommitDeviceError(deviceAddr, errCode,
 *                              ErrorClass::MCTP, data);
 */
void CommitDeviceError(uint8_t deviceAddress, int64_t errorCode,
                       ErrorClass errorClass,
                       std::map<std::string, std::string> additionalData = {});

} // namespace lg2
} // namespace nv
