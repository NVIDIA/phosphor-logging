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

#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/mctp_error_registry.hpp>

#include <cerrno>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace phosphor
{
namespace logging
{
namespace mctp
{

// Redfish registry constants
constexpr auto NVIDIA_DEVICE_DRIVER_ERROR_REGISTRY =
    "NvidiaResourceEvent.1.0.DeviceDriverErrorsDetected";
constexpr auto NVIDIA_BMC_DRIVER_ERROR_REGISTRY =
    "NvidiaResourceEvent.1.0.BmcDriverErrorsDetected";

// Resolution messages (from Redfish registry)
constexpr auto RESOLUTION_BMC_REBOOT =
    "If problem persists, perform BMC reboot.";
constexpr auto RESOLUTION_DEVICE_POWER_CYCLE =
    "If problem persists, perform power cycle of the system to recover the device.";

// RAS catalog error names (Server-RAS-Catalog "Error List" sheet, 'Error Name'
// column). Using the name rather than the numeric id matches the convention
// used by nsmd and by callers consuming Oem.Nvidia.ErrorId downstream.
// Only names for mappings already present in the tables below are defined.
namespace RasErrorName
{
// USB
constexpr auto FWUP_USB_HOST_CONTROLLER_TX_MEM_ALLOC_FAIL =
    "FWUP_USB_HOST_CONTROLLER_TX_MEMORY_ALLOCATION_FAILURE";
constexpr auto FWUP_USB_HOST_CONTROLLER_TX_WRITE_ERROR =
    "FWUP_USB_HOST_CONTROLLER_TX_CONTROLLER_WRITE_ERROR";
constexpr auto FWUP_USB_TX_DRIVER_UNLINK_FAIL =
    "FWUP_USB_DEVICE_TX_DRIVER_UNLINK_FAILURE";
constexpr auto FWUP_USB_TX_ENDPOINT_MISSING =
    "FWUP_USB_DEVICE_TX_DEVICE_ENDPOINT_MISSING";
constexpr auto FWUP_USB_TX_DISCONNECTION_FAIL =
    "FWUP_USB_DEVICE_TX_DISCONNECTION_FAILURE";
constexpr auto FWUP_USB_TX_STALL_FAIL = "FWUP_USB_DEVICE_TX_STALL_FAILURE";
constexpr auto FWUP_USB_TX_SHUTDOWN_FAIL =
    "FWUP_USB_DEVICE_TX_SHUTDOWN_FAILURE";
constexpr auto FWUP_USB_TX_PROTOCOL_FAIL =
    "FWUP_USB_DEVICE_TX_PROTOCOL_FAILURE";
constexpr auto FWUP_USB_RX_FRAGMENTATION =
    "FWUP_USB_DEVICE_RX_FRAGMENTATION_FAILURE";
constexpr auto FWUP_USB_RX_MESSAGE_SIZE =
    "FWUP_USB_DEVICE_RX_MESSAGE_SIZE_FAILURE";
constexpr auto FWUP_USB_RX_FRAG_TIMEOUT =
    "FWUP_USB_DEVICE_RX_FRAGMENTATION_TIMEOUT_FAILURE";
// I2C
constexpr auto FWUP_I2C_HOST_CONTROLLER_TX_MEM_ALLOC_FAIL =
    "FWUP_I2C_HOST_CONTROLLER_TX_MEMORY_ALLOCATION_FAILURE";
constexpr auto FWUP_I2C_TX_BUS_BUSY = "FWUP_I2C_DEVICE_TX_BUS_BUSY";
constexpr auto FWUP_I2C_TX_ARBITRATION_FAIL =
    "FWUP_I2C_DEVICE_TX_ARBITRATION_FAILURE";
constexpr auto FWUP_I2C_TX_ACK_FAIL = "FWUP_I2C_DEVICE_TX_ACK_FAILURE";
constexpr auto FWUP_I2C_TX_PROTOCOL_FAIL =
    "FWUP_I2C_DEVICE_TX_PROTOCOL_FAILURE";
constexpr auto FWUP_I2C_RX_FRAGMENTATION =
    "FWUP_I2C_DEVICE_RX_FRAGMENTATION_FAILURE";
constexpr auto FWUP_I2C_RX_MESSAGE_SIZE =
    "FWUP_I2C_DEVICE_RX_MESSAGE_SIZE_FAILURE";
constexpr auto FWUP_I2C_RX_FRAG_TIMEOUT =
    "FWUP_I2C_DEVICE_RX_FRAGMENTATION_TIMEOUT_FAILURE";
} // namespace RasErrorName

// Error category flags
enum class ErrorCategory
{
    HOST_CONTROLLER, // Error from host controller - use src_eid
    DEVICE           // Error from device - use dest_eid
};

// Error mapping entry
struct ErrorMapping
{
    uint32_t errorCode;
    Binding binding;
    Direction direction;
    ErrorCategory category;
    std::string description;
    std::string resolution;
    std::string errorId{}; // RAS catalog error name; empty if unmapped
};

// USB Error Mappings
static const std::vector<ErrorMapping> usbErrorMap = {
    // USB Tx Host Controller Errors
    {ENOMEM, Binding::USB, Direction::TX, ErrorCategory::HOST_CONTROLLER,
     "USB Tx failed due to host controller error - insufficient memory for USB "
     "internal structures",
     RESOLUTION_BMC_REBOOT,
     RasErrorName::FWUP_USB_HOST_CONTROLLER_TX_MEM_ALLOC_FAIL},
    {ECOMM, Binding::USB, Direction::TX, ErrorCategory::HOST_CONTROLLER,
     "USB Tx failed due host controller error - USB Host Controller Tx buffer "
     "overflow (FIFO full)",
     RESOLUTION_BMC_REBOOT,
     RasErrorName::FWUP_USB_HOST_CONTROLLER_TX_WRITE_ERROR},
    // USB Tx Device Errors
    {ECONNRESET, Binding::USB, Direction::TX, ErrorCategory::DEVICE,
     "USB Tx failed due to device error - URB was asynchronously unlinked "
     "(killed) by driver due to device connection reset",
     RESOLUTION_DEVICE_POWER_CYCLE,
     RasErrorName::FWUP_USB_TX_DRIVER_UNLINK_FAIL},
    {ENOENT, Binding::USB, Direction::TX, ErrorCategory::DEVICE,
     "USB Tx failed due device error - specified interface or endpoint does "
     "not exist or is not enabled state",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_TX_ENDPOINT_MISSING},
    {ENODEV, Binding::USB, Direction::TX, ErrorCategory::DEVICE,
     "USB Tx failed due to device error - device was removed",
     RESOLUTION_DEVICE_POWER_CYCLE,
     RasErrorName::FWUP_USB_TX_DISCONNECTION_FAIL},
    {EPIPE, Binding::USB, Direction::TX, ErrorCategory::DEVICE,
     "USB Tx failed due to device error - endpoint is in stall state",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_TX_STALL_FAIL},
    {ESHUTDOWN, Binding::USB, Direction::TX, ErrorCategory::DEVICE,
     "USB Tx failed due to device error - physical disconnection",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_TX_SHUTDOWN_FAIL},
    {EPROTO, Binding::USB, Direction::TX, ErrorCategory::DEVICE,
     "USB Tx Failed due to device (OR bus) error - USB protocol "
     "violation leading to ACK failure",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_TX_PROTOCOL_FAIL},
    // USB Rx Device Errors
    {EPROTO, Binding::USB, Direction::RX, ErrorCategory::DEVICE,
     "USB Rx Failed due to device error - fragmentation error to reassemble "
     "packets from the device",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_RX_FRAGMENTATION},
    {EMSGSIZE, Binding::USB, Direction::RX, ErrorCategory::DEVICE,
     "USB Rx Failed due to device error - reassembled message exceeds 64KB "
     "limit",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_RX_MESSAGE_SIZE},
    {ETIMEDOUT, Binding::USB, Direction::RX, ErrorCategory::DEVICE,
     "USB Rx Failed due to device error - fragmentation timeout",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_USB_RX_FRAG_TIMEOUT},
};

// SYNC API Error Mappings (MCTP core layer - binding-independent)
static const std::vector<ErrorMapping> syncApiErrorMap = {
    // SYNC API Tx Device Errors
    {EHOSTUNREACH, Binding::SYNC, Direction::TX, ErrorCategory::DEVICE,
     "MCTP Sync API Tx failed due to device error - device is not reachable ",
     RESOLUTION_DEVICE_POWER_CYCLE},
    {ENODEV, Binding::SYNC, Direction::TX, ErrorCategory::DEVICE,
     "MCTP Sync API Tx failed due to device error - device was removed or "
     "not present",
     RESOLUTION_DEVICE_POWER_CYCLE},
    // SYNC API Tx Host Controller Errors
    {ENOMEM, Binding::SYNC, Direction::TX, ErrorCategory::HOST_CONTROLLER,
     "MCTP Sync API Tx failed due to host controller error - insufficient "
     "memory for MCTP internal structures",
     RESOLUTION_BMC_REBOOT},
    {EBUSY, Binding::SYNC, Direction::TX, ErrorCategory::HOST_CONTROLLER,
     "MCTP Tx failed due to tag allocation failure", RESOLUTION_BMC_REBOOT}};

// I2C Error Mappings
static const std::vector<ErrorMapping> i2cErrorMap = {
    // I2C Tx Host Controller Errors
    {ENOMEM, Binding::I2C, Direction::TX, ErrorCategory::HOST_CONTROLLER,
     "I2C Tx failed due to host controller error - insufficient memory for I2C "
     "internal structures",
     RESOLUTION_BMC_REBOOT,
     RasErrorName::FWUP_I2C_HOST_CONTROLLER_TX_MEM_ALLOC_FAIL},
    // I2C Tx Device Errors
    {EBUSY, Binding::I2C, Direction::TX, ErrorCategory::DEVICE,
     "I2C Tx failed due to device (or bus) error - clock streching timeout "
     "(SDA/SCL stuck low)",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_TX_BUS_BUSY},
    {EAGAIN, Binding::I2C, Direction::TX, ErrorCategory::DEVICE,
     "I2C Tx failed due to device (or bus) error - arbitration loss during "
     "transaction (multi-master bus conflict)",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_TX_ARBITRATION_FAIL},
    {ENXIO, Binding::I2C, Direction::TX, ErrorCategory::DEVICE,
     "I2C Tx Failed due to device error - no acknowledgement for the I2C "
     "transaction",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_TX_ACK_FAIL},
    {EPROTO, Binding::I2C, Direction::TX, ErrorCategory::DEVICE,
     "I2C Tx Failed due to device (OR bus) error - I2C protocol violation",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_TX_PROTOCOL_FAIL},
    // I2C Rx Device Errors
    {EPROTO, Binding::I2C, Direction::RX, ErrorCategory::DEVICE,
     "I2C Rx Failed due to device error - fragmentation error to reassemble "
     "packets from the device",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_RX_FRAGMENTATION},
    {EMSGSIZE, Binding::I2C, Direction::RX, ErrorCategory::DEVICE,
     "I2C Rx Failed due to device fragmentation error - reassembled message "
     "exceeds 64KB limit",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_RX_MESSAGE_SIZE},
    {ETIMEDOUT, Binding::I2C, Direction::RX, ErrorCategory::DEVICE,
     "I2C Rx Failed due to device error - fragmentation timeout",
     RESOLUTION_DEVICE_POWER_CYCLE, RasErrorName::FWUP_I2C_RX_FRAG_TIMEOUT},
};

// Serial (SPI-SPB) Error Mappings
static const std::vector<ErrorMapping> serialErrorMap = {
    // SPI-SPB Tx Host Controller Errors
    {EINVAL, Binding::SERIAL, Direction::TX, ErrorCategory::HOST_CONTROLLER,
     "SPI-SPB Tx failed due to host controller error - BMC SPI-SPB driver "
     "initialization failure",
     RESOLUTION_BMC_REBOOT},
    // SPI-SPB Tx Device Errors
    {ETIMEDOUT, Binding::SERIAL, Direction::TX, ErrorCategory::DEVICE,
     "SPI-SPB Tx failed due to device error - end device failure (timeout)",
     RESOLUTION_DEVICE_POWER_CYCLE},
    // SPI-SPB Rx Device Errors
    {EPROTO, Binding::SERIAL, Direction::RX, ErrorCategory::DEVICE,
     "SPI-SPB Rx Failed due to device error - fragmentation error to reassemble "
     "packets from the device",
     RESOLUTION_DEVICE_POWER_CYCLE},
    {EMSGSIZE, Binding::SERIAL, Direction::RX, ErrorCategory::DEVICE,
     "SPI-SPB Rx Failed due to device fragmentation error - reassembled message "
     "exceeds 64KB limit",
     RESOLUTION_DEVICE_POWER_CYCLE},
    {ETIMEDOUT, Binding::SERIAL, Direction::RX, ErrorCategory::DEVICE,
     "SPI-SPB Rx Failed due to device error - fragmentation timeout",
     RESOLUTION_DEVICE_POWER_CYCLE},
};

std::string getDeviceNameByEid(uint8_t eid)
{
    std::ostringstream oss;
    oss << "EID_0x" << std::hex << std::uppercase << std::setw(2)
        << std::setfill('0') << static_cast<int>(eid);
    return oss.str();
}

static const ErrorMapping* findErrorMapping(
    uint32_t errorCode, Direction direction, Binding binding)
{
    const std::vector<ErrorMapping>* map = nullptr;

    // Select the appropriate error map based on binding
    switch (binding)
    {
        case Binding::USB:
            map = &usbErrorMap;
            break;
        case Binding::I2C:
            map = &i2cErrorMap;
            break;
        case Binding::SERIAL:
            map = &serialErrorMap;
            break;
        case Binding::SYNC:
            map = &syncApiErrorMap;
            break;
        default:
            return nullptr;
    }

    // Search for matching error code and direction
    for (const auto& entry : *map)
    {
        if (entry.errorCode == errorCode && entry.direction == direction)
        {
            return &entry;
        }
    }

    return nullptr;
}

std::optional<RedfishRegistry> errorToRedfishRegistry(
    uint32_t errorCode, Direction direction, Binding binding,
    uint8_t endpointid, const std::string& driverOperation,
    const std::optional<std::string>& deviceRedfishName)
{
    // Find the error mapping
    const ErrorMapping* mapping =
        findErrorMapping(errorCode, direction, binding);

    RedfishRegistry registry;
    std::string errorDescription;

    if (!mapping)
    {
        // Log unmapped error to journal
        lg2::error(
            "Unmapped MCTP error code detected - using errno description",
            "ERROR_CODE", errorCode, "DIRECTION",
            static_cast<uint8_t>(direction), "BINDING",
            static_cast<uint8_t>(binding), "ENDPOINT_ID", endpointid);

        // Use errno library to get error message
        const char* errMsg = std::strerror(errorCode);
        errorDescription = errMsg ? errMsg : "Unknown error";

        // Classify as device error and use device-specific registry
        registry.registryId = NVIDIA_DEVICE_DRIVER_ERROR_REGISTRY;
        registry.severity = Level::Critical;
        registry.resolution = RESOLUTION_DEVICE_POWER_CYCLE;
        registry.isDeviceError = true;
    }
    else
    {
        errorDescription = mapping->description;
        registry.severity = Level::Critical;
        registry.resolution = mapping->resolution;
        registry.errorId = mapping->errorId;
    }

    // Determine device name and registry ID based on error category
    std::string deviceName;

    // Check if deviceRedfishName is provided and non-empty
    bool hasValidRedfishName =
        deviceRedfishName.has_value() && !deviceRedfishName.value().empty();

    if (mapping)
    {
        if (mapping->category == ErrorCategory::HOST_CONTROLLER)
        {
            // Host controller error - the BMC is the faulty component
            // Use BMC-specific registry
            registry.registryId = NVIDIA_BMC_DRIVER_ERROR_REGISTRY;
            registry.isDeviceError = false;

            // For BMC errors, still need to identify the target device
            if (hasValidRedfishName)
            {
                deviceName = deviceRedfishName.value();
            }
            else
            {
                deviceName = getDeviceNameByEid(endpointid);
            }
        }
        else
        {
            // Device error - the remote endpoint is the faulty component
            // Use Device-specific registry
            registry.registryId = NVIDIA_DEVICE_DRIVER_ERROR_REGISTRY;
            registry.isDeviceError = true;

            if (hasValidRedfishName)
            {
                // Use provided Redfish device name for the remote device
                deviceName = deviceRedfishName.value();
            }
            else
            {
                // Fall back to EID-based name
                deviceName = getDeviceNameByEid(endpointid);
            }
        }
    }
    else
    {
        // Unmapped error - determine device name
        if (hasValidRedfishName)
        {
            deviceName = deviceRedfishName.value();
        }
        else
        {
            deviceName = getDeviceNameByEid(endpointid);
        }
    }

    // Build arguments array
    // Arg[0]: {DriverOperation} - operation type
    registry.args.push_back(driverOperation);
    // Arg[1]: {DeviceName} - device identifier
    registry.args.push_back(deviceName);
    // Arg[2]: Description
    registry.args.push_back(errorDescription);

    return registry;
}

} // namespace mctp
} // namespace logging
} // namespace phosphor
