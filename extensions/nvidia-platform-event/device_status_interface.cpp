#include "device_status_interface.hpp"

#include <com/nvidia/State/DeviceState/common.hpp>
#include <phosphor-logging/device_error_log.hpp>
#include <phosphor-logging/lg2.hpp>

#include <stdexcept>

namespace nvidia
{
namespace platform
{
namespace event
{

PHOSPHOR_LOG2_USING;

DeviceStatusInterface::DeviceStatusInterface(sdbusplus::bus_t& bus,
                                             const std::string& path) :
    sdbusplus::server::com::nvidia::state::DeviceState(bus, path.c_str()),
    eid(extractEidFromPath(path))
{}

uint8_t DeviceStatusInterface::extractEidFromPath(const std::string& path)
{
    // Path format: "/com/nvidia/state/device_status/17" (decimal)
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos)
    {
        lg2::error("Invalid path format: {PATH}", "PATH", path);
        throw std::invalid_argument("Invalid path format - no '/' found");
    }

    std::string eidStr = path.substr(pos + 1);

    try
    {
        int eidInt = std::stoi(eidStr); // Decimal string -> int

        if (eidInt < 0 || eidInt > 255)
        {
            lg2::error("EID out of range: {EID}", "EID", eidInt);
            throw std::out_of_range("EID must be 0-255");
        }

        return static_cast<uint8_t>(eidInt);
    }
    catch (const std::invalid_argument&)
    {
        lg2::error("Invalid EID string in path: {PATH}", "PATH", path);
        throw;
    }
    catch (const std::out_of_range&)
    {
        lg2::error("EID value out of range in path: {PATH}", "PATH", path);
        throw;
    }
}

auto DeviceStatusInterface::deviceStatus() const -> std::map<
    StatusType,
    std::tuple<DeviceHealth,
               std::vector<std::tuple<int64_t, ErrorClass,
                                      std::map<std::string, std::string>>>>>
{
    using DeviceHealth =
        sdbusplus::server::com::nvidia::state::DeviceState::DeviceHealth;
    using ErrorClass =
        sdbusplus::server::com::nvidia::state::DeviceState::ErrorClass;
    using StatusType =
        sdbusplus::server::com::nvidia::state::DeviceState::StatusType;

    try
    {
        // Call existing backend function (unchanged)
        auto deviceErrors = ::nvidia::platform::event::getDeviceStatus(eid);

        // Convert to D-Bus format
        std::vector<
            std::tuple<int64_t, ErrorClass, std::map<std::string, std::string>>>
            errors;

        for (const auto& error : deviceErrors)
        {
            // Use stored additionalData (preserves all fields including
            // REDFISH_*, PLATFORM_*, custom fields)
            auto additionalData = error.additionalData;
            // Add ERROR_NUMBER for completeness
            additionalData["ERROR_NUMBER"] = std::to_string(error.errorNumber);
            // error.errorClass is already the PDI ErrorClass enum - use
            // directly
            errors.emplace_back(error.errorNumber, error.errorClass,
                                additionalData);
        }

        // Determine health for Communication StatusType
        DeviceHealth health =
            errors.empty() ? DeviceHealth::Healthy : DeviceHealth::Degraded;

        // Build result map (currently only Communication)
        std::map<
            StatusType,
            std::tuple<DeviceHealth, std::vector<std::tuple<
                                         int64_t, ErrorClass,
                                         std::map<std::string, std::string>>>>>
            result;

        result[StatusType::Communication] = std::make_tuple(health, errors);
        return result;
    }
    catch (const std::exception& e)
    {
        lg2::error("Error reading DeviceStatus for EID {EID}: {ERROR}", "EID",
                   eid, "ERROR", e.what());
        throw;
    }
}

auto DeviceStatusInterface::deviceStatus(
    std::map<
        StatusType,
        std::tuple<DeviceHealth,
                   std::vector<std::tuple<int64_t, ErrorClass,
                                          std::map<std::string, std::string>>>>>
        value)
    -> std::map<
        StatusType,
        std::tuple<DeviceHealth,
                   std::vector<std::tuple<int64_t, ErrorClass,
                                          std::map<std::string, std::string>>>>>
{
    using DeviceHealth =
        sdbusplus::server::com::nvidia::state::DeviceState::DeviceHealth;
    using StatusType =
        sdbusplus::server::com::nvidia::state::DeviceState::StatusType;

    try
    {
        // Check which StatusTypes to clear
        for (const auto& [statusType, healthAndErrors] : value)
        {
            auto [health, errors] = healthAndErrors;

            // Clear if Healthy with empty errors
            if (health == DeviceHealth::Healthy && errors.empty())
            {
                if (statusType == StatusType::Communication)
                {
                    // Call existing backend clear (clears all for now)
                    ::nvidia::platform::event::clearDeviceErrors(eid);
                }
                // Future: handle other StatusTypes when PDI adds them
            }
        }

        // After clearing, read and return updated status
        // This will auto-emit PropertiesChanged signal via base class
        return deviceStatus(); // Call getter
    }
    catch (const std::exception& e)
    {
        lg2::error("Error writing DeviceStatus for EID {EID}: {ERROR}", "EID",
                   eid, "ERROR", e.what());
        throw;
    }
}

} // namespace event
} // namespace platform
} // namespace nvidia
