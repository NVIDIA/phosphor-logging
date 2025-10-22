#pragma once

#include "extensions/nvidia-platform-event/device_error_database.hpp"
#include "extensions/nvidia-platform-event/device_topology.hpp"

#include <phosphor-logging/device_error_log.hpp>

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace phosphor::logging::test
{

using PropertyMap = nvidia::platform::event::PropertyMap;
using ErrorClass = nv::lg2::ErrorClass;
namespace ErrorCode = nv::lg2::ErrorCode;

/**
 * @brief Structure to hold error information (test-only)
 */
struct ErrorInfo
{
    std::string redfishMessageId;
    std::string errorMessage;
};

/**
 * @brief Test error information map
 * Maps (ErrorClass, ErrorCode) pairs to Redfish message ID and error message.
 * This is test-only data used by tests to verify error handling.
 */
inline const std::map<std::pair<ErrorClass, int64_t>, ErrorInfo>
    testErrorInfoMap = {
        // Power Status
        {{ErrorClass::Power, ErrorCode::PowerStatus::POWER_ON},
         {"ResourceEvent.1.2.ResourcePoweredOn",
          "Device powered on successfully"}},
        {{ErrorClass::Power, ErrorCode::PowerStatus::POWER_OFF},
         {"ResourceEvent.1.2.ResourcePoweredOff", "Device powered off"}},

        // Recovery Status
        {{ErrorClass::Recovery, ErrorCode::Recovery::IN_RECOVERY},
         {"ResourceEvent.1.2.ResourceErrorsDetected",
          "Device entered recovery mode"}},
        {{ErrorClass::Recovery, ErrorCode::Recovery::NOT_IN_RECOVERY},
         {"ResourceEvent.1.2.ResourceErrorsCorrected",
          "Device exited recovery mode"}},

        // Physical Interface Status
        {{ErrorClass::PhysicalInterface, ErrorCode::PhysicalInterface::PRESENT},
         {"ResourceEvent.1.2.ResourceCreated", "Device detected and present"}},
        {{ErrorClass::PhysicalInterface, ErrorCode::PhysicalInterface::ABSENT},
         {"ResourceEvent.1.2.ResourceRemoved",
          "Device not detected or removed"}},

        // MCTP Status
        {{ErrorClass::MCTP, ErrorCode::MCTP::PING_SUCCESS},
         {"ResourceEvent.1.2.ResourceStatusChangedOK", "MCTP ping successful"}},
        {{ErrorClass::MCTP, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT},
         {"ResourceEvent.1.2.ResourceErrorsDetected",
          "MCTP device communication failed due to device ping timeout"}},
        {{ErrorClass::MCTP, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT},
         {"ResourceEvent.1.2.ResourceErrorsDetected",
          "MCTP device discovery failed due to timeout error to obtain UUID"}},
        {{ErrorClass::MCTP, ErrorCode::MCTP::USB_TX_MEMORY_ALLOC_FAILURE},
         {"NvidiaResourceError.1.0.DriverErrorDetected",
          "USB Host Controller Tx Failed due to insufficient memory for USB "
          "internal structures error"}},
};

/**
 * @brief Get Redfish error info for tests
 * @param errorCode The error code
 * @param errorClass The error class enumeration
 * @return ErrorInfo structure containing both redfishMessageId and errorMessage
 */
inline ErrorInfo getTestRedfishErrorInfo(int64_t errorCode,
                                         ErrorClass errorClass)
{
    auto key = std::make_pair(errorClass, errorCode);
    auto it = testErrorInfoMap.find(key);

    if (it != testErrorInfoMap.end())
    {
        return it->second;
    }

    // Return default for unknown error codes
    return {"ResourceEvent.1.2.ResourceErrorsDetected",
            "Unknown error for class " +
                std::to_string(static_cast<int>(errorClass)) + " code " +
                std::to_string(errorCode)};
}

/**
 * @brief Build test topology directly in device_error_database
 *
 * Uses real production code from device_topology module:
 * - builddeviceErrorDatabase() (parses device properties)
 * - linkDeviceHierarchy() (links parent-child relationships)
 *
 * @param devices Vector of device PropertyMap (same format as EntityManager)
 */
inline void buildTestTopology(const std::vector<PropertyMap>& devices)
{
    // Clear existing topology
    nvidia::platform::event::deviceErrorDatabase.clear();
    nvidia::platform::event::nameToEidLookup.clear();

    // Use production topology building code
    nvidia::platform::event::builddeviceErrorDatabase(devices);
    nvidia::platform::event::linkDeviceHierarchy();

    // Verify topology was built (diagnostic)
    std::cout << "[TEST TOPOLOGY] Built "
              << nvidia::platform::event::deviceErrorDatabase.size()
              << " devices:" << std::endl;
    for (const auto& [eid, store] :
         nvidia::platform::event::deviceErrorDatabase)
    {
        std::cout << "  - EID=" << (int)eid << " Name=" << store.deviceId
                  << " Parent="
                  << (store.parentEid.has_value()
                          ? std::to_string(store.parentEid.value())
                          : "NONE")
                  << std::endl;
    }
}

/**
 * @brief Get standard test topology data (4 devices)
 *
 * Topology structure mirrors real hardware:
 *
 *   BMC (0x01) - Root device
 *   ├─ Bridge (0x10) - PCIe Bridge, child of BMC
 *   │  └─ GPU (0x11) - GPU device, child of Bridge (grandchild of BMC)
 *   └─ CPU (0x20) - CPU device, child of BMC (sibling of Bridge)
 *
 * This topology tests:
 * - Root device (BMC with no parent)
 * - Parent-child relationships (BMC→Bridge, Bridge→GPU, BMC→CPU)
 * - Multi-level hierarchy (3 levels: BMC→Bridge→GPU)
 * - Sibling devices (Bridge and CPU both under BMC)
 * - Parent error precedence (Bridge errors override GPU errors)
 * - Root error precedence (BMC errors override all descendants)
 *
 * Device addresses:
 * - 0x01: BMC (root)
 * - 0x10: Bridge (parent of GPU)
 * - 0x11: GPU (child of Bridge, grandchild of BMC)
 * - 0x20: CPU (child of BMC, sibling of Bridge)
 *
 * @return Vector of PropertyMap with test device data
 */
inline std::vector<PropertyMap> getTestTopologyData()
{
    return {// BMC (0x01) - Root device
            {{"Name", std::string("BMC")},
             {"DeviceAddress", std::string("MCTP:1")},
             {"ConnectsToName", std::string("")}, // Root - no parent
             {"DeviceType", std::string("BMC")},
             {"poweredInStandby", false}},        // BMC not power-dependent

            // Bridge (0x10) - Child of BMC
            {{"Name", std::string("Bridge")},
             {"DeviceAddress", std::string("MCTP:16")}, // 0x10 = 16 decimal
             {"ConnectsToName", std::string("BMC")},    // Parent: BMC
             {"DeviceType", std::string("PCIeBridge")},
             {"poweredInStandby", false}}, // Bridge not power-dependent

            // GPU (0x11) - Child of Bridge (grandchild of BMC)
            {{"Name", std::string("GPU")},
             {"DeviceAddress", std::string("MCTP:17")}, // 0x11 = 17 decimal
             {"ConnectsToName", std::string("Bridge")}, // Parent: Bridge
             {"DeviceType", std::string("GPU")},
             {"poweredInStandby", true}}, // GPU IS power-dependent

            // CPU (0x20) - Child of BMC (sibling of Bridge)
            {{"Name", std::string("CPU")},
             {"DeviceAddress", std::string("MCTP:32")}, // 0x20 = 32 decimal
             {"ConnectsToName", std::string("BMC")},    // Parent: BMC
             {"DeviceType", std::string("CPU")},
             {"poweredInStandby", true}}}; // CPU IS power-dependent
}

/**
 * @brief Clean up test topology and D-Bus interfaces
 *
 * Call this in test TearDown() to ensure clean state between tests.
 * Clears D-Bus interfaces before clearing the registry to avoid dangling
 * pointers.
 *
 * This is test-only code - production code doesn't need cleanup functionality
 * since devices persist for the lifetime of the service.
 */
inline void cleanupTestTopology()
{
    // Step 1: Clear D-Bus interfaces from all devices
    size_t interfaceCount = 0;
    for (auto& [eid, deviceStore] :
         nvidia::platform::event::deviceErrorDatabase)
    {
        if (deviceStore.dbusInterface)
        {
            deviceStore.dbusInterface.reset(); // Destroy D-Bus interface
            interfaceCount++;
        }
    }

    std::cout << "[TEST CLEANUP] Cleared " << interfaceCount
              << " D-Bus interfaces" << std::endl;

    // Step 2: Clear the device registry
    nvidia::platform::event::deviceErrorDatabase.clear();

    // Step 3: Clear the lookup map
    nvidia::platform::event::nameToEidLookup.clear();
}

} // namespace phosphor::logging::test
