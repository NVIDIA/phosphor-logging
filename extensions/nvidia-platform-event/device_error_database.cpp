#include "device_error_database.hpp"

#include "device_status_interface.hpp"

#include <phosphor-logging/device_error_log.hpp>
#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>

#include <algorithm>
#include <functional>
#include <optional>

namespace nvidia
{
namespace platform
{
namespace event
{

/**
 * @brief Reference to D-Bus connection (set during initialization)
 */
static sdbusplus::bus_t* globalBus = nullptr;

bool ErrorClassComparator::operator()(ErrorClass a, ErrorClass b) const
{
    // Unknown error classes get lowest priority (highest number)
    constexpr uint8_t LOWEST_PRIORITY = std::numeric_limits<uint8_t>::max();

    // Get priorities, default to lowest if not found
    auto itA = nv::lg2::errorClassPriority.find(a);
    auto itB = nv::lg2::errorClassPriority.find(b);

    uint8_t priorityA = (itA != nv::lg2::errorClassPriority.end())
                            ? itA->second
                            : LOWEST_PRIORITY;
    uint8_t priorityB = (itB != nv::lg2::errorClassPriority.end())
                            ? itB->second
                            : LOWEST_PRIORITY;

    // Sort by priority first (lower number = higher priority = comes first)
    if (priorityA != priorityB)
    {
        return priorityA < priorityB;
    }

    // If same priority, use enum value for consistent ordering
    return static_cast<int>(a) < static_cast<int>(b);
}

DeviceErrorStore::DeviceErrorStore(uint8_t deviceEid,
                                   size_t maxErrorsPerClass) :
    eid(deviceEid), status(DeviceStatus::Healthy) // Start with no errors
{
    // Pre-initialize all error class buckets (automatically sorted by priority)
    for (const auto& [errorClass, priority] : nv::lg2::errorClassPriority)
    {
        errorClasses.emplace(
            std::piecewise_construct, std::forward_as_tuple(errorClass),
            std::forward_as_tuple(errorClass, priority, maxErrorsPerClass));
    }
}

DeviceErrorMetadata* parseDeviceError(
    const phosphor::logging::AdditionalDataArg& additionalData)
{
    // Check for required fields
    auto deviceAddressIt = additionalData.find("PLATFORM_DEVICE_ADDRESS");
    auto errorNumberIt = additionalData.find("PLATFORM_DEVICE_ERROR");
    auto errorClassIt = additionalData.find("PLATFORM_DEVICE_CLASS");
    // auto errorNamespaceIt = additionalData.find("PLATFORM_ERROR_NAMESPACE");

    // Log the parsed fields for debugging
    lg2::info(
        "Parsing device error: PLATFORM_DEVICE_ADDRESS={ADDR}, PLATFORM_DEVICE_ERROR={ERR}, PLATFORM_DEVICE_CLASS={CLASS}",
        "ADDR",
        (deviceAddressIt != additionalData.end()) ? deviceAddressIt->second
                                                  : "NOT_FOUND",
        "ERR",
        (errorNumberIt != additionalData.end()) ? errorNumberIt->second
                                                : "NOT_FOUND",
        "CLASS",
        (errorClassIt != additionalData.end()) ? errorClassIt->second
                                               : "NOT_FOUND");

    // Validate required fields
    if (deviceAddressIt == additionalData.end() ||
        errorNumberIt == additionalData.end() ||
        errorClassIt == additionalData.end()
        // errorNamespaceIt == additionalData.end()
    )
    {
        // Not a platform error log, or missing required fields
        return nullptr;
    }

    DeviceErrorMetadata* error = new DeviceErrorMetadata();
    // error->errorNamespace = errorNamespaceIt->second;
    error->timestamp = std::chrono::system_clock::now();

    // Parse numeric fields (including error class enum value)
    try
    {
        unsigned long eidValue =
            std::stoul(deviceAddressIt->second, nullptr, 0);
        if (eidValue > 255)
        {
            lg2::error("Invalid EID value {VAL}, must be 0-255", "VAL",
                       eidValue);
            delete error;
            return nullptr;
        }
        error->eid = static_cast<uint8_t>(eidValue);
        error->errorNumber = std::stoll(errorNumberIt->second, nullptr, 0);

        // Parse error class as integer enum value
        int errorClassValue = std::stoi(errorClassIt->second);
        error->errorClass = static_cast<ErrorClass>(errorClassValue);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed to parse numeric fields from AdditionalData: {ERROR}",
            "ERROR", e.what());
        delete error;
        return nullptr;
    }

    // Store ALL additional data as-is (preserves REDFISH_*, PLATFORM_*, and any
    // custom fields)
    error->additionalData = additionalData;

    // Get priority for the error class
    auto priorityIt = nv::lg2::errorClassPriority.find(error->errorClass);
    if (priorityIt != nv::lg2::errorClassPriority.end())
    {
        error->priority = priorityIt->second;
    }
    else
    {
        lg2::warning(
            "Unknown error class: {CLASS}, defaulting to lowest priority",
            "CLASS", static_cast<int>(error->errorClass));
        error->priority = 4; // Default to lowest priority
    }

    lg2::debug("Parsed device error: eid={EID}, "
               "class={CLASS}, namespace={NS}, priority={PRIO}",
               "EID", error->eid, "CLASS", error->errorClass, "NS",
               error->errorNamespace, "PRIO", error->priority);

    return error;
}

bool insertErrorIntoDevice(uint8_t eid, const DeviceErrorMetadata& error)
{
    // Find device in registry
    auto deviceIt = deviceErrorDatabase.find(eid);
    if (deviceIt == deviceErrorDatabase.end())
    {
        lg2::warning("Cannot insert error - device EID={EID} not in registry",
                     "EID", eid);
        return false;
    }

    DeviceErrorStore& deviceStore = deviceIt->second;

    // Find the error class bucket
    auto classIt = deviceStore.errorClasses.find(error.errorClass);
    if (classIt == deviceStore.errorClasses.end())
    {
        lg2::error("Unknown error class: {CLASS}", "CLASS",
                   static_cast<int>(error.errorClass));
        return false;
    }

    ErrorClassData& classData = classIt->second;

    // Add to FIFO queue, remove oldest if full
    if (classData.errors.size() >= classData.maxErrors)
    {
        classData.errors.pop_front();  // Remove oldest
    }
    classData.errors.push_back(error); // Add newest

    // Mark device as degraded (has errors)
    deviceStore.status = DeviceStatus::Degraded;

    return true;
}

void propagatePowerErrorToDescendants(const DeviceErrorMetadata& powerError)
{
    // Iterate through ALL devices in registry
    for (auto& [deviceEid, deviceStore] : deviceErrorDatabase)
    {
        // Skip the originating device itself
        if (deviceEid == powerError.eid)
        {
            continue;
        }

        // Only propagate to power-dependent devices
        if (deviceStore.poweredInStandby)
        {
            // Create power error for this device
            DeviceErrorMetadata childError = powerError;
            childError.eid = deviceEid;
            // Update REDFISH_MESSAGE_ARGS in additionalData to reflect
            // propagation
            childError.additionalData["REDFISH_MESSAGE_ARGS"] =
                "Power lost due to parent device " +
                std::to_string(powerError.eid);

            // Use helper to insert error (no recursion!)
            insertErrorIntoDevice(deviceEid, childError);
        }
    }
}

void clearPropagatedPowerErrorsFromDescendants(uint8_t parentEid)
{
    int clearedCount = 0;

    // Iterate through ALL devices in registry
    for (auto& [deviceEid, deviceStore] : deviceErrorDatabase)
    {
        // Skip the originating device itself
        if (deviceEid == parentEid)
        {
            continue;
        }

        // Only clear from power-dependent devices
        if (deviceStore.poweredInStandby)
        {
            // Clear Power errors
            auto classIt = deviceStore.errorClasses.find(ErrorClass::Power);
            if (classIt != deviceStore.errorClasses.end())
            {
                ErrorClassData& classData = classIt->second;

                if (!classData.errors.empty())
                {
                    classData.errors.clear();
                    clearedCount++;

                    // Update status: check if any errors remain in any error
                    // class
                    bool hasErrors = false;
                    for (const auto& [className, errorClassData] :
                         deviceStore.errorClasses)
                    {
                        if (!errorClassData.errors.empty())
                        {
                            hasErrors = true;
                            break;
                        }
                    }
                    deviceStore.status = hasErrors ? DeviceStatus::Degraded
                                                   : DeviceStatus::Healthy;
                }
            }
        }
    }
}

void processDeviceErrorLog(const DeviceErrorMetadata& error)
{
    // Reject errors from devices not in topology
    if (deviceErrorDatabase.find(error.eid) == deviceErrorDatabase.end())
    {
        lg2::warning(
            "Rejecting error from unknown device EID={EID} (not in topology)",
            "EID", error.eid);
        return;
    }

    // Insert error into device's error storage
    if (!insertErrorIntoDevice(error.eid, error))
    {
        lg2::error("Failed to insert error into device EID={EID}", "EID",
                   error.eid);
        return;
    }

    // Power error propagation handling
    if (error.errorClass == ErrorClass::Power)
    {
        if (error.errorNumber == nv::lg2::ErrorCode::PowerStatus::POWER_OFF)
        {
            // Device powered off - propagate error to power-dependent devices
            propagatePowerErrorToDescendants(error);
        }
        else if (error.errorNumber == nv::lg2::ErrorCode::PowerStatus::POWER_ON)
        {
            // Device powered on - clear propagated errors from power-dependent
            // devices
            clearPropagatedPowerErrorsFromDescendants(error.eid);
        }
    }
}

std::vector<DeviceErrorMetadata> collectHighestPriorityErrors(
    const DeviceErrorStore& deviceStore, uint8_t eid)
{
    std::vector<DeviceErrorMetadata> result;

    // Check if device has any errors
    if (deviceStore.status == DeviceStatus::Healthy)
    {
        return result; // Empty - no errors present
    }

    // Step 1: Find the highest priority (lowest number) that has errors
    int highestPriority = -1;
    for (const auto& [errorClass, classData] : deviceStore.errorClasses)
    {
        if (!classData.errors.empty())
        {
            highestPriority = classData.priority;
            break; // Found first non-empty class (map is sorted by priority)
        }
    }

    if (highestPriority == -1)
    {
        // Should not reach here if status is Degraded, but handle gracefully
        lg2::warning("Device EID={EID} marked as Degraded but no errors found",
                     "EID", eid);
        return result;
    }

    // Step 2: Collect ALL errors from ALL error classes at that priority level
    for (const auto& [errorClass, classData] : deviceStore.errorClasses)
    {
        if (classData.priority == highestPriority && !classData.errors.empty())
        {
            for (const auto& error : classData.errors)
            {
                result.push_back(error);
            }
        }
        else if (classData.priority > highestPriority)
        {
            // Since map is sorted, we can stop once we hit higher priority
            // numbers
            break;
        }
    }

    return result;
}

std::vector<DeviceErrorMetadata> getDeviceStatus(uint8_t eid)
{
    // Get device from registry
    auto deviceIt = deviceErrorDatabase.find(eid);
    if (deviceIt == deviceErrorDatabase.end())
    {
        return {};
    }

    const DeviceErrorStore& deviceStore = deviceIt->second;

    // If child has no errors, return empty (don't check parent)
    if (deviceStore.status == DeviceStatus::Healthy)
    {
        return {};
    }

    // Child has errors - check parent precedence
    if (deviceStore.parentEid.has_value())
    {
        uint8_t parentEid = deviceStore.parentEid.value();
        auto parentIt = deviceErrorDatabase.find(parentEid);

        if (parentIt != deviceErrorDatabase.end() &&
            parentIt->second.status == DeviceStatus::Degraded)
        {
            // Parent has errors - return parent's highest priority errors
            return collectHighestPriorityErrors(parentIt->second, parentEid);
        }
    }

    // Child has errors but parent doesn't - return device's own errors
    return collectHighestPriorityErrors(deviceStore, eid);
}

void clearDeviceErrors(uint8_t eid)
{
    auto deviceIt = deviceErrorDatabase.find(eid);
    if (deviceIt == deviceErrorDatabase.end())
    {
        return;
    }

    DeviceErrorStore& deviceStore = deviceIt->second;

    // Clear all errors - just clear each error class queue
    for (auto& [className, classData] : deviceStore.errorClasses)
    {
        classData.errors.clear();
    }
    // Reset status to Healthy (no errors)
    deviceStore.status = DeviceStatus::Healthy;
}

void setDbusConnection(sdbusplus::bus_t& bus)
{
    globalBus = &bus;
}

void createDeviceStatusInterface(uint8_t eid)
{
    if (!globalBus)
    {
        lg2::error(
            "D-Bus connection not initialized, cannot create interface for EID {EID}",
            "EID", eid);
        return;
    }

    // Find device in registry
    auto deviceIt = deviceErrorDatabase.find(eid);
    if (deviceIt == deviceErrorDatabase.end())
    {
        lg2::warning(
            "Cannot create D-Bus interface for unknown EID {EID} (not in topology)",
            "EID", eid);
        return;
    }

    DeviceErrorStore& deviceStore = deviceIt->second;

    // Check if interface already exists
    if (deviceStore.dbusInterface)
    {
        lg2::debug("DeviceStatusInterface already exists for EID {EID}", "EID",
                   eid);
        return;
    }

    // Build path: /com/nvidia/state/device_status/<decimal_eid>
    std::string path = "/com/nvidia/state/device_status/" + std::to_string(eid);

    try
    {
        auto interface =
            std::make_shared<DeviceStatusInterface>(*globalBus, path);
        deviceStore.dbusInterface = interface;
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Failed to create DeviceStatusInterface for EID {EID}: {ERROR}",
            "EID", eid, "ERROR", e.what());
    }
}

} // namespace event
} // namespace platform
} // namespace nvidia
