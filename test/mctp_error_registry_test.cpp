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

#include <phosphor-logging/mctp_error_registry.hpp>

#include <cerrno>
#include <iostream>
#include <optional>
#include <string>

using namespace phosphor::logging::mctp;

namespace
{

constexpr auto deviceRegistry =
    "NvidiaResourceEvent.1.0.DeviceDriverErrorsDetected";
constexpr auto bmcRegistry = "NvidiaResourceEvent.1.0.BmcDriverErrorsDetected";
constexpr auto deviceResolution =
    "If problem persists, perform power cycle of the system to recover the device.";
constexpr auto bmcResolution = "If problem persists, perform BMC reboot.";
constexpr auto driverOperation = "RequestUpdate";
constexpr uint8_t endpointId = 0x0D;
constexpr auto eidDeviceName = "EID_0x0D";
constexpr auto redfishDeviceName = "HGX_FW_GPU_0";

// Helper function to convert Level enum to string for display
std::string levelToString(Level level)
{
    switch (level)
    {
        case Level::Emergency:
            return "Emergency";
        case Level::Alert:
            return "Alert";
        case Level::Critical:
            return "Critical";
        case Level::Error:
            return "Error";
        case Level::Warning:
            return "Warning";
        case Level::Notice:
            return "Notice";
        case Level::Informational:
            return "Informational";
        case Level::Debug:
            return "Debug";
        default:
            return "Unknown";
    }
}

struct MappingTestCase
{
    const char* name;
    uint32_t errorCode;
    Direction direction;
    Binding binding;
    bool isDeviceError;
    const char* expectedErrorId;
    const char* description;
};

// Runs one case and checks every RedfishRegistry field. On mismatch, prints
// the full result next to the expected values.
bool checkMapping(const MappingTestCase& testCase,
                  const std::optional<std::string>& deviceRedfishName,
                  const std::string& expectedDeviceName)
{
    auto registry = errorToRedfishRegistry(
        testCase.errorCode, testCase.direction, testCase.binding, endpointId,
        driverOperation, deviceRedfishName);
    const std::string expectedRegistry =
        testCase.isDeviceError ? deviceRegistry : bmcRegistry;
    const std::string expectedResolution =
        testCase.isDeviceError ? deviceResolution : bmcResolution;
    const std::string expectedArgs[] = {driverOperation, expectedDeviceName,
                                        testCase.description};

    const bool passed =
        registry && registry->args.size() == 3 &&
        registry->registryId == expectedRegistry &&
        registry->severity == Level::Critical &&
        registry->args[0] == expectedArgs[0] &&
        registry->args[1] == expectedArgs[1] &&
        registry->args[2] == expectedArgs[2] &&
        registry->resolution == expectedResolution &&
        registry->isDeviceError == testCase.isDeviceError &&
        registry->errorId == testCase.expectedErrorId;
    if (passed)
    {
        return true;
    }

    std::cerr << "FAIL: " << testCase.name << " (deviceRedfishName: "
              << (deviceRedfishName ? "'" + *deviceRedfishName + "'"
                                    : std::string("std::nullopt"))
              << ")" << std::endl;
    if (!registry)
    {
        std::cerr << "  returned std::nullopt" << std::endl;
        return false;
    }
    std::cerr << std::boolalpha;
    std::cerr << "  registryId:    '" << registry->registryId << "' (expected '"
              << expectedRegistry << "')" << std::endl;
    std::cerr << "  severity:      " << levelToString(registry->severity)
              << " (expected Critical)" << std::endl;
    std::cerr << "  resolution:    '" << registry->resolution << "' (expected '"
              << expectedResolution << "')" << std::endl;
    std::cerr << "  isDeviceError: " << registry->isDeviceError << " (expected "
              << testCase.isDeviceError << ")" << std::endl;
    std::cerr << "  errorId:       '" << registry->errorId << "' (expected '"
              << testCase.expectedErrorId << "')" << std::endl;
    std::cerr << "  args.size():   " << registry->args.size() << " (expected 3)"
              << std::endl;
    for (size_t i = 0; i < registry->args.size(); ++i)
    {
        std::cerr << "  args[" << i << "]:       '" << registry->args[i] << "'";
        if (i < 3)
        {
            std::cerr << " (expected '" << expectedArgs[i] << "')";
        }
        std::cerr << std::endl;
    }
    return false;
}

bool testCanonicalRegistryMappings()
{
    static constexpr MappingTestCase testCases[] = {
        {"USB Tx ENOMEM", ENOMEM, Direction::TX, Binding::USB, false,
         "FWUP_USB_HOST_CONTROLLER_TX_MEMORY_ALLOCATION_FAILURE",
         "USB Tx host-controller memory allocation failed (ENOMEM)"},
        {"USB Tx ECOMM", ECOMM, Direction::TX, Binding::USB, false,
         "FWUP_USB_HOST_CONTROLLER_TX_CONTROLLER_WRITE_ERROR",
         "USB Tx host-controller buffer overflow (FIFO full) (ECOMM)"},
        {"USB Tx ECONNRESET", ECONNRESET, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_DRIVER_UNLINK_FAILURE",
         "USB Tx URB was unlinked by the watchdog timeout or interface "
         "teardown (ECONNRESET)"},
        {"USB Tx ENOENT", ENOENT, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_DEVICE_ENDPOINT_MISSING",
         "USB Tx interface or endpoint does not exist or is disabled "
         "(ENOENT)"},
        {"USB Tx ENODEV", ENODEV, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_DISCONNECTION_FAILURE",
         "USB Tx device was removed (ENODEV)"},
        {"USB Tx EPIPE", EPIPE, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_STALL_FAILURE",
         "USB Tx endpoint is stalled (EPIPE)"},
        {"USB Tx ESHUTDOWN", ESHUTDOWN, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_SHUTDOWN_FAILURE",
         "USB Tx physical disconnection (ESHUTDOWN)"},
        {"USB Tx EPROTO", EPROTO, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_PROTOCOL_FAILURE",
         "USB Tx protocol violation leading to ACK failure (EPROTO)"},
        {"USB Rx EPROTO", EPROTO, Direction::RX, Binding::USB, true,
         "FWUP_USB_DEVICE_RX_FRAGMENTATION_FAILURE",
         "USB Rx fragmentation reassembly failed (EPROTO)"},
        {"USB Rx EMSGSIZE", EMSGSIZE, Direction::RX, Binding::USB, true,
         "FWUP_USB_DEVICE_RX_MESSAGE_SIZE_FAILURE",
         "USB Rx reassembled message exceeds 64 KiB (EMSGSIZE)"},
        {"USB Rx ETIMEDOUT", ETIMEDOUT, Direction::RX, Binding::USB, true,
         "FWUP_USB_DEVICE_RX_FRAGMENTATION_TIMEOUT_FAILURE",
         "USB Rx fragmentation timed out (ETIMEDOUT)"},
        {"MCTP Tx EHOSTUNREACH", EHOSTUNREACH, Direction::TX, Binding::SYNC,
         true, "",
         "MCTP Tx destination endpoint is unreachable (EHOSTUNREACH)"},
        {"MCTP Tx ENODEV", ENODEV, Direction::TX, Binding::SYNC, true, "",
         "MCTP Tx destination endpoint was removed or is not present "
         "(ENODEV)"},
        {"MCTP Tx ENOMEM", ENOMEM, Direction::TX, Binding::SYNC, false, "",
         "MCTP Tx could not allocate memory for internal transport state "
         "(ENOMEM)"},
        {"MCTP Tx EBUSY", EBUSY, Direction::TX, Binding::SYNC, false, "",
         "MCTP Tx could not allocate a message tag (EBUSY)"},
        {"I2C Tx ENOMEM", ENOMEM, Direction::TX, Binding::I2C, false,
         "FWUP_I2C_HOST_CONTROLLER_TX_MEMORY_ALLOCATION_FAILURE",
         "I2C Tx host-controller memory allocation failed (ENOMEM)"},
        {"I2C Tx EBUSY", EBUSY, Direction::TX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_TX_BUS_BUSY",
         "I2C Tx clock-stretch timeout; SDA/SCL stuck low (EBUSY)"},
        {"I2C Tx EAGAIN", EAGAIN, Direction::TX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_TX_ARBITRATION_FAILURE",
         "I2C Tx arbitration was lost during a multi-master transaction "
         "(EAGAIN)"},
        {"I2C Tx ENXIO", ENXIO, Direction::TX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_TX_ACK_FAILURE",
         "I2C Tx received no acknowledgement for the transaction (ENXIO)"},
        {"I2C Tx ETIMEDOUT", ETIMEDOUT, Direction::TX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_TX_TIMEOUT_FAILURE", "I2C Tx timed out (ETIMEDOUT)"},
        {"I2C Tx EPROTO", EPROTO, Direction::TX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_TX_PROTOCOL_FAILURE",
         "I2C Tx protocol violation (EPROTO)"},
        {"I2C Rx EPROTO", EPROTO, Direction::RX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_RX_FRAGMENTATION_FAILURE",
         "I2C Rx fragmentation reassembly failed (EPROTO)"},
        {"I2C Rx EMSGSIZE", EMSGSIZE, Direction::RX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_RX_MESSAGE_SIZE_FAILURE",
         "I2C Rx reassembled message exceeds 64 KiB (EMSGSIZE)"},
        {"I2C Rx ETIMEDOUT", ETIMEDOUT, Direction::RX, Binding::I2C, true,
         "FWUP_I2C_DEVICE_RX_FRAGMENTATION_TIMEOUT_FAILURE",
         "I2C Rx fragmentation timed out (ETIMEDOUT)"},
        {"SPI-SPB Tx EINVAL", EINVAL, Direction::TX, Binding::SERIAL, false, "",
         "SPI-SPB Tx received an invalid argument (EINVAL)"},
        {"SPI-SPB Tx ETIMEDOUT", ETIMEDOUT, Direction::TX, Binding::SERIAL,
         true, "", "SPI-SPB Tx timed out waiting for the endpoint (ETIMEDOUT)"},
        {"SPI-SPB Rx EPROTO", EPROTO, Direction::RX, Binding::SERIAL, true, "",
         "SPI-SPB Rx fragmentation reassembly failed (EPROTO)"},
        {"SPI-SPB Rx EMSGSIZE", EMSGSIZE, Direction::RX, Binding::SERIAL, true,
         "", "SPI-SPB Rx reassembled message exceeds 64 KiB (EMSGSIZE)"},
        {"SPI-SPB Rx ETIMEDOUT", ETIMEDOUT, Direction::RX, Binding::SERIAL,
         true, "", "SPI-SPB Rx fragmentation timed out (ETIMEDOUT)"},
    };

    bool allPassed = true;
    for (const auto& testCase : testCases)
    {
        allPassed &=
            checkMapping(testCase, redfishDeviceName, redfishDeviceName);
    }

    std::cout << "Canonical mapping matrix: " << (allPassed ? "PASS" : "FAIL")
              << std::endl;
    return allPassed;
}

bool testUnmappedErrors()
{
    // Unmapped combinations fall back to the device registry, the device
    // power-cycle resolution, strerror() text with the errno name appended,
    // and an empty errorId. The lookup must honor both binding and direction.
    static constexpr MappingTestCase testCases[] = {
        {"USB Tx EINVAL (no USB mapping)", EINVAL, Direction::TX, Binding::USB,
         true, "", "Invalid argument (EINVAL)"},
        {"USB Tx EBUSY (mapped for I2C and SYNC only)", EBUSY, Direction::TX,
         Binding::USB, true, "", "Device or resource busy (EBUSY)"},
        {"USB Rx ENOMEM (mapped for Tx only)", ENOMEM, Direction::RX,
         Binding::USB, true, "", "Cannot allocate memory (ENOMEM)"},
        {"PCIe Tx ETIMEDOUT (no PCIe map)", ETIMEDOUT, Direction::TX,
         Binding::PCIE, true, "", "Connection timed out (ETIMEDOUT)"},
        // glibc's strerror() format for unknown codes; other libcs differ.
        {"USB Tx unknown errno (no errno name)", 9999, Direction::TX,
         Binding::USB, true, "", "Unknown error 9999"},
    };

    bool allPassed = true;
    for (const auto& testCase : testCases)
    {
        allPassed &=
            checkMapping(testCase, redfishDeviceName, redfishDeviceName);
    }

    std::cout << "Unmapped error fallback: " << (allPassed ? "PASS" : "FAIL")
              << std::endl;
    return allPassed;
}

bool testDeviceNameFallback()
{
    // A missing or empty Redfish name falls back to the EID-based name for
    // device, host-controller and unmapped errors alike.
    static constexpr MappingTestCase testCases[] = {
        {"USB Tx ENODEV (device)", ENODEV, Direction::TX, Binding::USB, true,
         "FWUP_USB_DEVICE_TX_DISCONNECTION_FAILURE",
         "USB Tx device was removed (ENODEV)"},
        {"USB Tx ENOMEM (host controller)", ENOMEM, Direction::TX, Binding::USB,
         false, "FWUP_USB_HOST_CONTROLLER_TX_MEMORY_ALLOCATION_FAILURE",
         "USB Tx host-controller memory allocation failed (ENOMEM)"},
        {"USB Tx EINVAL (unmapped)", EINVAL, Direction::TX, Binding::USB, true,
         "", "Invalid argument (EINVAL)"},
    };
    const std::optional<std::string> missingNames[] = {std::nullopt,
                                                       std::string()};

    bool allPassed = true;
    for (const auto& testCase : testCases)
    {
        for (const auto& deviceRedfishName : missingNames)
        {
            allPassed &=
                checkMapping(testCase, deviceRedfishName, eidDeviceName);
        }
    }

    std::cout << "EID device-name fallback: " << (allPassed ? "PASS" : "FAIL")
              << std::endl;
    return allPassed;
}

bool testGetDeviceNameByEid()
{
    const bool passed = getDeviceNameByEid(0x15) == "EID_0x15" &&
                        getDeviceNameByEid(0x08) == "EID_0x08" &&
                        getDeviceNameByEid(0xFF) == "EID_0xFF";

    std::cout << "Get device name by EID: " << (passed ? "PASS" : "FAIL")
              << std::endl;
    return passed;
}

} // namespace

int main()
{
    std::cout << "=== MCTP Error Registry Unit Tests ===" << std::endl;

    bool allTestsPassed = true;
    allTestsPassed &= testCanonicalRegistryMappings();
    allTestsPassed &= testUnmappedErrors();
    allTestsPassed &= testDeviceNameFallback();
    allTestsPassed &= testGetDeviceNameByEid();

    std::cout << "=== All Tests Completed ===" << std::endl;

    return allTestsPassed ? 0 : 1;
}
