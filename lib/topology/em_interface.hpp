#pragma once

#include <sdbusplus/bus.hpp>
#include <sdbusplus/bus/match.hpp>
#include <sdbusplus/message.hpp>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace phosphor
{
namespace logging
{
namespace topology
{

/** @brief EntityManager service name */
static constexpr const char* ENTITY_MANAGER_SERVICE =
    "xyz.openbmc_project.EntityManager";

/** @brief PlatformDevice interface name */
static constexpr const char* PLATFORM_DEVICE_INTERFACE =
    "xyz.openbmc_project.Configuration.PlatformDevice";

// D-Bus property value variant type
using PropertyValue =
    std::variant<bool, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t,
                 uint64_t, double, std::string, std::vector<uint8_t>,
                 std::vector<std::string>>;

using PropertyMap = std::map<std::string, PropertyValue>;
using InterfaceMap = std::map<std::string, PropertyMap>;

/**
 * @brief Minimal EntityManager D-Bus interface
 *
 * Provides only EM query and signal monitoring capabilities.
 * No device storage or hierarchy building - that's handled by consumers.
 *
 * This is a thin wrapper over D-Bus calls to EntityManager, making it
 * reusable by any component that needs device information from EM.
 */
class EntityManagerInterface
{
  public:
    /**
     * @brief Construct EM interface
     *
     * @param bus D-Bus connection
     */
    explicit EntityManagerInterface(sdbusplus::bus_t& bus);

    ~EntityManagerInterface() = default;

    // Disable copy/move
    EntityManagerInterface(const EntityManagerInterface&) = delete;
    EntityManagerInterface& operator=(const EntityManagerInterface&) = delete;
    EntityManagerInterface(EntityManagerInterface&&) = delete;
    EntityManagerInterface& operator=(EntityManagerInterface&&) = delete;

    /**
     * @brief Query all PlatformDevice objects from EntityManager
     *
     * Makes ONE D-Bus call (GetManagedObjects) to retrieve all devices
     * with all their properties. This is much more efficient than calling
     * GetSubTree + multiple GetAll calls.
     *
     * @return Vector of property maps, one per device
     * @throws sdbusplus::exception on D-Bus errors
     */
    std::vector<PropertyMap> queryAllDevices();

    /**
     * @brief Setup monitoring for device additions
     *
     * Registers callback for InterfacesAdded signals from EntityManager.
     * Callback is invoked whenever EM publishes a new PlatformDevice.
     *
     * Use cases:
     * - Late device arrivals (EM still processing config files)
     * - EM config hot-reload
     * - Device hot-plug (rare)
     *
     * @param onDeviceAdded Callback function with device properties
     */
    void setupSignalMonitoring(
        std::function<void(const PropertyMap&)> onDeviceAdded);

  private:
    sdbusplus::bus_t& bus;
    std::unique_ptr<sdbusplus::bus::match_t> interfacesAddedMatch;
    std::function<void(const PropertyMap&)> deviceAddedCallback;

    /**
     * @brief Handle InterfacesAdded signal from EntityManager
     *
     * Internal signal handler - extracts PlatformDevice properties
     * and invokes user callback if provided.
     *
     * @param msg D-Bus signal message
     */
    void handleInterfacesAdded(sdbusplus::message_t& msg);
};

} // namespace topology
} // namespace logging
} // namespace phosphor
