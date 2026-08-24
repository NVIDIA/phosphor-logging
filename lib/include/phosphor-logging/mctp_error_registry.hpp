/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION &
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

/**
 * @file mctp_error_registry.hpp
 * @brief MCTP Error to Redfish Registry Mapping
 *
 * This file provides functionality to convert MCTP transport layer errors
 * to structured Redfish registry messages for standardized error reporting.
 *
 * =============================================================================
 * ERROR CODE REFERENCE
 * =============================================================================
 *
 * Common errno values used in MCTP error mappings:
 *
 * Error Code | Value | Description
 * -----------|-------|--------------------------------------------------------
 * EPERM      |   1   | Operation not permitted
 * ENOENT     |   2   | No such file or directory / endpoint not found
 * EINTR      |   4   | Interrupted system call
 * EIO        |   5   | I/O error
 * ENXIO      |   6   | No such device or address / no ACK
 * EAGAIN     |  11   | Try again / arbitration loss
 * ENOMEM     |  12   | Out of memory (Host controller error)
 * EBUSY      |  16   | Device or resource busy / all tags in use
 * ENODEV     |  19   | No such device / device was removed
 * EINVAL     |  22   | Invalid argument (SERIAL Tx)
 * EPIPE      |  32   | Broken pipe / endpoint in stall state
 * EPROTO     |  71   | Protocol error / fragmentation error (Rx)
 * EMSGSIZE   |  90   | Message too long / exceeds 64 KiB limit (Rx)
 * ECONNRESET |  104  | Connection reset / URB unlinked
 * ETIMEDOUT  |  110  | Connection timed out / Tx timeout / fragmentation
 *            |       | timeout (Rx)
 * EHOSTUNREACH| 113  | No route to host / host unreachable
 * ECOMM      |  70   | Communication error on send
 * ESHUTDOWN  |  108  | Cannot send after transport endpoint shutdown
 *
 * Note: I2C binding specific error codes:
 *   - TX: ETIMEDOUT (110) - I2C transfer timed out (DEVICE)
 *   - RX: ETIMEDOUT (110) - Fragmentation timeout (DEVICE)
 *
 * Note: SERIAL binding specific error codes:
 *   - TX: EINVAL (22) - Invalid argument (HOST_CONTROLLER)
 *   - TX: ETIMEDOUT (110) - End device failure (same as I2C)
 *   - RX: EPROTO (71) - Fragmentation error (same as I2C)
 *   - RX: EMSGSIZE (90) - Message exceeds 64 KiB (same as I2C)
 *   - RX: ETIMEDOUT (110) - Fragmentation timeout (same as I2C)
 *
 * For known errno values, every description ends with the errno name, e.g.
 * "... (ETIMEDOUT)". Codes with no mapping use the strerror() text instead,
 * e.g. "Connection timed out (ETIMEDOUT)". Unknown errno values have no name,
 * so only the strerror() text is used, e.g. "Unknown error 9999".
 *
 * =============================================================================
 * BINDING TYPE REFERENCE
 * =============================================================================
 *
 * MCTP Binding Types (must match kernel MCTP definitions):
 *
 * Binding    | Value | Description              | Error Map Available
 * -----------|-------|--------------------------|--------------------
 * I2C        | 0x01  | I2C/SMBus binding        | Yes
 * PCIE       | 0x02  | PCIe VDM binding         | No (strerror fallback)
 * USB        | 0x03  | USB binding              | Yes
 * KCS        | 0x04  | KCS binding              | No (future)
 * SERIAL     | 0x05  | Serial binding           | Yes
 * I3C        | 0x06  | I3C binding              | No (future)
 * SYNC       | 0xFF  | MCTP core/sync API       | Yes
 *
 * =============================================================================
 * DIRECTION REFERENCE
 * =============================================================================
 *
 * Direction  | Value | Description
 * -----------|-------|-------------------------------------------------------
 * TX         |   0   | Transmit direction (sending data)
 * RX         |   1   | Receive direction (receiving data)
 *
 * =============================================================================
 * ERROR CATEGORY REFERENCE
 * =============================================================================
 *
 * Category           | Registry Used              | Device Error Flag
 * -------------------|----------------------------|-----------------
 * HOST_CONTROLLER    | BmcDriverErrorsDetected    | false (BMC issue)
 * DEVICE             | DeviceDriverErrorsDetected | true (Device issue)
 *
 * =============================================================================
 * USAGE EXAMPLE
 * =============================================================================
 *
 * // Example 1: USB device disconnection
 * auto registry = errorToRedfishRegistry(
 *     19,              // ENODEV
 *     Direction::TX,
 *     Binding::USB,
 *     0x15,            // Endpoint ID
 *     "FirmwareUpdate",
 *     "/redfish/v1/UpdateService/FirmwareInventory/GPU0"
 * );
 *
 * // Example 2: SYNC API timeout
 * auto registry = errorToRedfishRegistry(
 *     113,             // EHOSTUNREACH
 *     Direction::TX,
 *     Binding::SYNC,
 *     0x20,            // Endpoint ID
 *     "MessageTransmit"
 * );
 *
 * if (registry) {
 *     // Use registry->registryId, registry->args, registry->severity, etc.
 * }
 *
 * =============================================================================
 */
#pragma once

#include <xyz/openbmc_project/Logging/Entry/server.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace phosphor
{
namespace logging
{
namespace mctp
{

// Alias for logging severity level
using Level = sdbusplus::server::xyz::openbmc_project::logging::Entry::Level;

/**
 * @brief MCTP binding types (must match kernel definitions)
 */
enum class Binding : uint8_t
{
    I2C = 0x01,    // I2C/SMBus
    PCIE = 0x02,   // PCIe VDM
    USB = 0x03,    // USB
    KCS = 0x04,    // KCS
    SERIAL = 0x05, // Serial
    I3C = 0x06,    // I3C
    SYNC = 0xFF    // MCTP core/sync API failures (binding-independent)
};

/**
 * @brief MCTP direction
 */
enum class Direction : uint8_t
{
    TX = 0,
    RX = 1
};

/**
 * @brief Redfish registry information for MCTP errors
 */
struct RedfishRegistry
{
    std::string registryId;
    std::vector<std::string> args;
    Level severity;
    std::string resolution;
    bool isDeviceError;  // true = remote device error, false = BMC/host
                         // controller error
    std::string errorId; // RAS catalog error name
                         // (e.g., "FWUP_I2C_DEVICE_TX_BUS_BUSY"); empty if
                         // unmapped or the catalog has no name for it
};

/**
 * @brief Convert MCTP error to Redfish registry information
 *
 * This function maps MCTP transport errors from the kernel error queue
 * to structured Redfish registry messages for standardized logging and
 * event reporting.
 *
 * @param[in] errorCode - Linux errno value (ENODEV, ETIMEDOUT, EHOSTUNREACH,
 * etc.)
 * @param[in] direction - MCTP direction (TX or RX)
 * @param[in] binding - MCTP binding type:
 *                      - USB: USB binding-specific errors
 *                      - I2C: I2C binding-specific errors
 *                      - SERIAL: SPI-SPB binding-specific errors
 *                      - SYNC: MCTP core/sync API errors (binding-independent)
 *                      Other bindings (e.g. PCIE) have no error map and
 *                      always take the unmapped path.
 * @param[in] endpointid - Endpoint ID
 * @param[in] driverOperation - Driver operation string (e.g., "FirmwareUpdate")
 * @param[in] deviceRedfishName - Optional device Redfish name, used as the
 *                                device name (Args[1]) for both device and
 *                                host controller errors. If absent or empty,
 *                                the name falls back to "EID_0xNN".
 *
 * @return RedfishRegistry structure filled with registry information. A value
 *         is always returned; the std::optional return type is kept for API
 *         compatibility with existing callers. An unmapped error code/
 *         direction/binding combination is reported with the
 *         DeviceDriverErrorsDetected registry, the device power-cycle
 *         resolution, the strerror() text followed by the errno name (for
 *         known errno values) as the description, and an empty errorId.
 *
 * @example Usage for USB binding error:
 * auto registry = mctp::errorToRedfishRegistry(
 *     ENODEV,
 *     Direction::TX,
 *     Binding::USB,
 *     0x15,
 *     "FirmwareUpdate",
 *     "/redfish/v1/UpdateService/FirmwareInventory/GPU0"
 * );
 *
 * @example Usage for SYNC API error:
 * auto registry = mctp::errorToRedfishRegistry(
 *     EHOSTUNREACH,
 *     Direction::TX,
 *     Binding::SYNC,
 *     0x15,
 *     "MessageTransmit"
 * );
 *
 * if (registry) {
 *     // Use registry->registryId, registry->args, etc.
 * }
 */
std::optional<RedfishRegistry> errorToRedfishRegistry(
    uint32_t errorCode, Direction direction, Binding binding,
    uint8_t endpointid, const std::string& driverOperation,
    const std::optional<std::string>& deviceRedfishName = std::nullopt);

/**
 * @brief Get device name string from EID
 *
 * Formats EID into a human-readable device name string.
 *
 * @param[in] eid - MCTP Endpoint ID
 * @return Device name string (e.g., "EID_0x15")
 */
std::string getDeviceNameByEid(uint8_t eid);

} // namespace mctp
} // namespace logging
} // namespace phosphor
