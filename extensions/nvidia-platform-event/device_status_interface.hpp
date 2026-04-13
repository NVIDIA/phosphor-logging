#pragma once

#include "device_error_database.hpp"

#include <com/nvidia/State/DeviceState/server.hpp>
#include <sdbusplus/bus.hpp>

#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace nvidia
{
namespace platform
{
namespace event
{

/**
 * @brief D-Bus Interface for Device Status Query and Error Management
 *
 * This class implements the com.nvidia.State.DeviceState D-Bus interface
 * using a property-based approach. Each device has its own D-Bus object at
 * path /com/nvidia/state/device_status/<EID> (where EID is decimal).
 *
 * The interface provides:
 * - Property READ: Get current device status and errors
 * - Property WRITE: Clear errors for specific StatusTypes
 *
 * The interface bridges D-Bus property access to the internal error database.
 */
class DeviceStatusInterface :
    public sdbusplus::server::com::nvidia::state::DeviceState
{
  public:
    DeviceStatusInterface() = delete;
    DeviceStatusInterface(const DeviceStatusInterface&) = delete;
    DeviceStatusInterface& operator=(const DeviceStatusInterface&) = delete;
    DeviceStatusInterface(DeviceStatusInterface&&) = delete;
    DeviceStatusInterface& operator=(DeviceStatusInterface&&) = delete;
    ~DeviceStatusInterface() = default;

    /**
     * @brief Constructor - creates D-Bus interface object for a specific device
     *
     * @param bus D-Bus connection
     * @param path D-Bus object path (e.g.,
     * "/com/nvidia/state/device_status/17") The EID is extracted from the path
     * (decimal format)
     */
    explicit DeviceStatusInterface(sdbusplus::bus_t& bus,
                                   const std::string& path);

    /**
     * @brief Property getter: DeviceStatus (override from DeviceState)
     *
     * Called when D-Bus property is read. Retrieves current device errors
     * from the internal error database and converts to D-Bus format.
     *
     * @return Map of StatusType to (DeviceHealth, error array)
     *         Currently returns only Communication StatusType
     */
    std::map<
        StatusType,
        std::tuple<DeviceHealth,
                   std::vector<std::tuple<int64_t, ErrorClass,
                                          std::map<std::string, std::string>>>>>
        deviceStatus() const override;

    /**
     * @brief Property setter: DeviceStatus (override from DeviceState)
     *
     * Called when D-Bus property is written. Used to clear errors for
     * specific StatusTypes. Write {StatusType: (Healthy, [])} to clear.
     *
     * @param value Map of StatusType to (DeviceHealth, error array)
     *              Clears StatusTypes marked as Healthy with empty error array
     * @return Updated device status after clearing
     */
    std::map<
        StatusType,
        std::tuple<DeviceHealth,
                   std::vector<std::tuple<int64_t, ErrorClass,
                                          std::map<std::string, std::string>>>>>
        deviceStatus(
            std::map<StatusType,
                     std::tuple<DeviceHealth,
                                std::vector<std::tuple<
                                    int64_t, ErrorClass,
                                    std::map<std::string, std::string>>>>>
                value) override;

    /**
     * @brief Get the EID for this interface
     * @return Device EID (0-255)
     */
    uint8_t getEid() const
    {
        return eid;
    }

  private:
    /** @brief Device EID extracted from object path */
    uint8_t eid;

    /**
     * @brief Extract EID from D-Bus object path
     *
     * Path format: "/com/nvidia/state/device_status/<decimal_eid>"
     * Example: "/com/nvidia/state/device_status/17" -> EID 0x11
     *
     * @param path D-Bus object path
     * @return Extracted EID (0-255)
     * @throws std::invalid_argument if path format is invalid
     * @throws std::out_of_range if EID is not in valid range
     */
    static uint8_t extractEidFromPath(const std::string& path);
};

} // namespace event
} // namespace platform
} // namespace nvidia
