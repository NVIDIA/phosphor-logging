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

using namespace phosphor::logging::mctp;

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

void testUSBDeviceError()
{
    std::cout << "Test 1: USB Device Disconnection (ENODEV)" << std::endl;

    auto registry = errorToRedfishRegistry(
        ENODEV,          // error code
        Direction::TX,   // direction
        Binding::USB,    // binding
        0x15,            // endpointid
        "FirmwareUpdate" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testI2CHostControllerError()
{
    std::cout << "Test 2: I2C Host Controller Memory Error (ENOMEM)"
              << std::endl;

    auto registry = errorToRedfishRegistry(
        ENOMEM,           // error code
        Direction::TX,    // direction
        Binding::I2C,     // binding
        0x20,             // endpointid
        "DeviceDiscovery" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testUSBRxTimeout()
{
    std::cout << "Test 3: USB Rx Fragmentation Timeout (ETIMEDOUT)"
              << std::endl;

    auto registry = errorToRedfishRegistry(
        ETIMEDOUT,       // error code
        Direction::RX,   // direction
        Binding::USB,    // binding
        0x08,            // endpointid
        "MessageReceive" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testI2CDeviceErrorWithRedfishName()
{
    std::cout
        << "Test 4: I2C Device ACK Failure with Custom Redfish Name (ENXIO)"
        << std::endl;

    auto registry = errorToRedfishRegistry(
        ENXIO,                                             // error code
        Direction::TX,                                     // direction
        Binding::I2C,                                      // binding
        0x20,                                              // endpointid
        "FirmwareUpdate",                                  // driver operation
        "/redfish/v1/UpdateService/FirmwareInventory/GPU0" // custom device name
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testMCTPTagAllocationFailure()
{
    std::cout << "Test 5: MCTP Tag Allocation Failure (EBUSY)" << std::endl;

    auto registry = errorToRedfishRegistry(
        EBUSY,            // error code
        Direction::TX,    // direction
        Binding::USB,     // binding
        0x25,             // endpointid
        "MessageTransmit" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testUnmappedError()
{
    std::cout << "Test 6: Unmapped Error Code (EINVAL)" << std::endl;

    auto registry = errorToRedfishRegistry(
        EINVAL,         // error code - not mapped
        Direction::TX,  // direction
        Binding::USB,   // binding
        0x15,           // endpointid
        "TestOperation" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  PASS: Unmapped error handled with errno description"
                  << std::endl;
    }
    else
    {
        std::cout
            << "  FAIL: Should have returned registry with errno description"
            << std::endl;
    }
    std::cout << std::endl;
}

void testSyncApiHostUnreachable()
{
    std::cout << "Test 7: SYNC API Host Unreachable (EHOSTUNREACH)"
              << std::endl;

    auto registry = errorToRedfishRegistry(
        EHOSTUNREACH,     // error code
        Direction::TX,    // direction
        Binding::SYNC,    // binding
        0x20,             // endpointid
        "MessageTransmit" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testSyncApiMemoryError()
{
    std::cout << "Test 8: SYNC API Memory Error (ENOMEM)" << std::endl;

    auto registry = errorToRedfishRegistry(
        ENOMEM,           // error code
        Direction::TX,    // direction
        Binding::SYNC,    // binding
        0x15,             // endpointid
        "DeviceDiscovery" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testSyncApiTagBusy()
{
    std::cout << "Test 9: SYNC API Tag Busy (EBUSY)" << std::endl;

    auto registry = errorToRedfishRegistry(
        EBUSY,           // error code
        Direction::TX,   // direction
        Binding::SYNC,   // binding
        0x18,            // endpointid
        "FirmwareUpdate" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testSyncApiDeviceRemoved()
{
    std::cout << "Test 10: SYNC API Device Removed (ENODEV)" << std::endl;

    auto registry = errorToRedfishRegistry(
        ENODEV,           // error code
        Direction::TX,    // direction
        Binding::SYNC,    // binding
        0x22,             // endpointid
        "MessageTransmit" // driver operation
    );

    if (registry)
    {
        std::cout << "  Registry ID: " << registry->registryId << std::endl;
        std::cout << "  Severity: " << levelToString(registry->severity)
                  << std::endl;
        std::cout << "  Args[0]: " << registry->args[0] << std::endl;
        std::cout << "  Args[1]: " << registry->args[1] << std::endl;
        std::cout << "  Args[2]: " << registry->args[2] << std::endl;
        std::cout << "  Resolution: " << registry->resolution << std::endl;
        std::cout << "  Is Device Error: "
                  << (registry->isDeviceError ? "true" : "false") << std::endl;
        std::cout << "  Error ID: " << registry->errorId << std::endl;
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL: No registry mapping found" << std::endl;
    }
    std::cout << std::endl;
}

void testGetDeviceNameByEid()
{
    std::cout << "Test 11: Get Device Name by EID" << std::endl;

    std::string name1 = getDeviceNameByEid(0x15);
    std::string name2 = getDeviceNameByEid(0x08);
    std::string name3 = getDeviceNameByEid(0xFF);

    std::cout << "  EID 0x15 -> " << name1 << std::endl;
    std::cout << "  EID 0x08 -> " << name2 << std::endl;
    std::cout << "  EID 0xFF -> " << name3 << std::endl;

    if (name1 == "EID_0x15" && name2 == "EID_0x08" && name3 == "EID_0xFF")
    {
        std::cout << "  PASS" << std::endl;
    }
    else
    {
        std::cout << "  FAIL" << std::endl;
    }
    std::cout << std::endl;
}

int main()
{
    std::cout << "=== MCTP Error Registry Unit Tests ===" << std::endl;
    std::cout << std::endl;

    testUSBDeviceError();
    testI2CHostControllerError();
    testUSBRxTimeout();
    testI2CDeviceErrorWithRedfishName();
    testMCTPTagAllocationFailure();
    testUnmappedError();
    testSyncApiHostUnreachable();
    testSyncApiMemoryError();
    testSyncApiTagBusy();
    testSyncApiDeviceRemoved();
    testGetDeviceNameByEid();

    std::cout << "=== All Tests Completed ===" << std::endl;

    return 0;
}
