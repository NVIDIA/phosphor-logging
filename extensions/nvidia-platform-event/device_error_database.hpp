#pragma once

#include <com/nvidia/State/DeviceState/server.hpp>
#include <sdbusplus/bus.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace phosphor
{
namespace logging
{
using AdditionalDataArg = std::map<std::string, std::string>;
} // namespace logging
} // namespace phosphor

namespace nvidia
{
namespace platform
{
namespace event
{

// Forward declaration for unique_ptr member
class DeviceStatusInterface;

// Use PDI ErrorClass enum directly (same as in device_error_log.hpp)
using ErrorClass =
    sdbusplus::server::com::nvidia::state::DeviceState::ErrorClass;

/**
 * @brief Device Health Status
 *
 * Explicit status indicating whether a device has any errors present.
 */
enum class DeviceStatus
{
    Healthy, // No errors present
    Degraded // Has one or more errors
};

/**
 * @brief Custom comparator for sorting error classes by priority
 *
 * Enables std::map to maintain error classes in priority order (lowest number
 * first). This allows efficient traversal: iterate until first non-empty error
 * class found.
 */
struct ErrorClassComparator
{
    bool operator()(ErrorClass a, ErrorClass b) const;
};

/**
 * @brief Device Error Metadata Structure
 *
 * Contains all relevant information about a device error including
 * error classification, priority, and namespace organization.
 *
 * Based on Section 2 of Platform Resiliency Firmware Upgrade SADD.
 */
struct DeviceErrorMetadata
{
    uint8_t eid;           // Device EID (0-255)
    int64_t errorNumber;   // Specific error code
    ErrorClass errorClass; // Error classification (PDI enum: Power, MCTP, etc.)
    std::string errorNamespace; // Namespace (Common, PLDM T5, PLDM T2, NSM)
    int priority;               // Priority level (0=highest, 4=lowest)
    std::chrono::system_clock::time_point timestamp; // When error occurred
    std::map<std::string, std::string>
        additionalData; // All additional data (REDFISH_*, PLATFORM_*, custom
                        // fields)
};

/**
 * @brief Error Class Data with Fixed-Size FIFO Queue
 *
 * Pre-initialized for each error class. Stores errors in a fixed-size
 * FIFO queue. When full, oldest error is removed to make space for new one.
 * This ensures O(1) insertion and prevents unbounded memory growth.
 */
struct ErrorClassData
{
    ErrorClass errorClass;                  // Error class (PDI enum)
    int priority;                           // Priority level (0=highest)
    std::deque<DeviceErrorMetadata> errors; // FIFO queue of errors
    size_t maxErrors;                       // Maximum errors to store

    ErrorClassData(ErrorClass cls, int prio, size_t max) :
        errorClass(cls), priority(prio), maxErrors(max)
    {}
};

/**
 * @brief Per-Device Error Store with Pre-initialized Error Classes
 *
 * Layered structure where each device has pre-allocated buckets for all
 * error classes. Error classes are sorted by priority for efficient query.
 * This enables:
 * - O(1) error insertion (just append to appropriate class queue)
 * - O(k) highest priority lookup where k = # of error classes (iterate until
 * first non-empty)
 * - O(1) error class access
 * - O(1) clear operations
 *
 * Error classes are sorted by priority (lowest number = highest severity).
 * Query optimization: iterate in order and return first non-empty error class.
 *
 * Also contains cached topology information for runtime error processing
 * (parent precedence, power propagation) without needing external calls.
 */
struct DeviceErrorStore
{
    uint8_t eid;
    std::string deviceId;   // Device name (e.g., "GPU0", "Bridge1")
    std::optional<uint8_t>
        parentEid;          // Direct parent EID (for parent precedence)
    bool poweredInStandby;  // For power propagation logic
    std::string parentName; // used during hierarchy building
    std::map<ErrorClass, ErrorClassData, ErrorClassComparator>
        errorClasses;       // Pre-initialized for all error classes, sorted by
                            // priority
    DeviceStatus status;    // Device health status (Healthy/Degraded)
    std::shared_ptr<DeviceStatusInterface>
        dbusInterface; // D-Bus status interface (created on topology init or
                       // first error)

    DeviceErrorStore(uint8_t eid, size_t maxErrorsPerClass);
};

/**
 * @brief Device Registry (Unified Structure)
 *
 * Maps device EID to DeviceErrorStore containing:
 * - Device identity (EID, name)
 * - Cached topology info (parent, children, properties)
 * - Error storage (error classes, highest priority)
 * - D-Bus interface (created on first error)
 *
 * Key: eid (uint8_t - Device EID 0-255)
 * Value: DeviceErrorStore (complete device state)
 *
 * This is the single source of truth for all device data.
 * Populated by device_topology.cpp, used by device_error_database.cpp.
 */
inline std::map<uint8_t, DeviceErrorStore> deviceErrorDatabase;

// ============================================================================
// Core API Functions (from implementation.md)
// ============================================================================

/**
 * @brief Parse device error from AdditionalData
 *
 * Extracts device error metadata from a log's AdditionalData map.
 * Looks for these keys:
 * - PLATFORM_DEVICE_ADDRESS
 * - PLATFORM_DEVICE_ERROR
 * - PLATFORM_DEVICE_CLASS
 * - PLATFORM_ERROR_NAMESPACE
 *
 * @param additionalData Map of additional data from log entry
 * @return DeviceErrorMetadata pointer if valid, nullptr otherwise (caller must
 * delete)
 */
DeviceErrorMetadata* parseDeviceError(
    const phosphor::logging::AdditionalDataArg& additionalData);

/**
 * @brief Process and store a device error log
 *
 * Called when a new device error is logged. Adds the error to the
 * errorDatabase for the specific device.
 *
 * @param error The device error metadata
 */
void processDeviceErrorLog(const DeviceErrorMetadata& error);

/**
 * @brief Get only highest priority errors for a device
 *
 * Returns only the errors with the highest priority (lowest number) for
 * root cause analysis and customer recovery recommendations.
 *
 * Multiple errors can occur due to a single root cause. This function
 * filters to show only the most critical error(s).
 *
 * @param eid Device EID (0-255)
 * @return Vector of highest priority errors only
 */
std::vector<DeviceErrorMetadata> getDeviceStatus(uint8_t eid);

/**
 * @brief Clear all errors for a device
 *
 * Called when device recovers (e.g., comes back on MCTP). Removes all
 * errors for the device.
 *
 * @param eid Device EID (0-255)
 */
void clearDeviceErrors(uint8_t eid);

/**
 * @brief Store D-Bus connection reference for interface lifecycle
 *
 * Called once at startup to store the D-Bus connection.
 * Interfaces are created during topology initialization and when devices
 * are added via InterfacesAdded signals.
 *
 * @param bus D-Bus connection
 */
void setDbusConnection(sdbusplus::bus_t& bus);

/**
 * @brief Create D-Bus interface for a device
 *
 * Creates a DeviceStatusInterface at path /com/nvidia/state/device_status/<EID>
 * where EID is the device endpoint ID in decimal format.
 * Called during topology initialization for all discovered devices.
 * If interface already exists for this EID, this is a no-op.
 *
 * @param eid Device EID (0-255)
 */
void createDeviceStatusInterface(uint8_t eid);

/**
 * @brief Insert error into device's error database (internal helper)
 *
 * This function handles the low-level insertion of an error into a device's
 * error storage without triggering power propagation. Used by both
 * processDeviceErrorLog and power propagation functions.
 *
 * @param eid Device EID
 * @param error Error metadata to insert
 * @return true if error was inserted successfully, false otherwise
 */
bool insertErrorIntoDevice(uint8_t eid, const DeviceErrorMetadata& error);

/**
 * @brief Propagate power error to all power-dependent devices
 *
 * When a device loses power, all power-dependent devices also lose power.
 * This function iterates through all devices and creates power errors for
 * devices that have poweredInStandby=true.
 *
 * @param powerError The original power error from parent device
 */
void propagatePowerErrorToDescendants(const DeviceErrorMetadata& powerError);

/**
 * @brief Clear propagated power errors from all power-dependent devices
 *
 * When a device powers back on, clear all propagated power errors from
 * all power-dependent devices. This allows them to report their own status
 * once power is restored.
 *
 * @param parentEid The EID of the device that powered back on
 */
void clearPropagatedPowerErrorsFromDescendants(uint8_t parentEid);

/**
 * @brief Collect highest priority errors from a device (internal helper)
 *
 * Extracts errors with the highest priority from a device's error store.
 * Leverages sorted errorClasses map: iterates in priority order, finds the
 * highest priority (lowest number), and returns ALL errors from ALL error
 * classes at that priority level.
 *
 * This is a common helper used by getDeviceStatus() for both device and
 * parent error collection.
 *
 * @param deviceStore The device error store
 * @param eid Device EID (for logging)
 * @return Vector of highest priority errors, empty if no errors
 */
std::vector<DeviceErrorMetadata> collectHighestPriorityErrors(
    const DeviceErrorStore& deviceStore, uint8_t eid);

} // namespace event
} // namespace platform
} // namespace nvidia
