#include "em_interface.hpp"

#include <phosphor-logging/lg2.hpp>

namespace phosphor
{
namespace logging
{
namespace topology
{

PHOSPHOR_LOG2_USING;

EntityManagerInterface::EntityManagerInterface(sdbusplus::bus_t& bus) : bus(bus)
{}

std::vector<PropertyMap> EntityManagerInterface::queryAllDevices()
{
    std::vector<PropertyMap> devices;

    try
    {
        // Call EntityManager GetManagedObjects - gets ALL objects, interfaces,
        // and properties in ONE D-Bus call (much more efficient than GetSubTree
        // + N GetAll calls)
        auto managedObjects = bus.new_method_call(
            ENTITY_MANAGER_SERVICE, "/xyz/openbmc_project/inventory",
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        auto reply = bus.call(managedObjects);

        // ManagedObjects returns: map<objectPath, map<interfaceName,
        // map<propertyName, variant>>>
        using ManagedObjectType = std::map<sdbusplus::message::object_path,
                                           std::map<std::string, PropertyMap>>;

        ManagedObjectType allObjects;
        reply.read(allObjects);

        // Filter for objects that have PlatformDevice interface
        for (const auto& [objectPath, interfaces] : allObjects)
        {
            auto platformDeviceIt = interfaces.find(PLATFORM_DEVICE_INTERFACE);
            if (platformDeviceIt != interfaces.end())
            {
                // Found a PlatformDevice - all properties already loaded!
                devices.push_back(platformDeviceIt->second);
            }
        }
    }
    catch (const std::exception& e)
    {
        // EntityManager might not be available (e.g., test environment, or not
        // started yet) Return empty list and let caller handle gracefully
        warning("EntityManager not available or query failed: {ERROR}", "ERROR",
                e.what());
        warning(
            "Returning empty device list - devices can be added later via InterfacesAdded signals");
    }

    return devices;
}

void EntityManagerInterface::setupSignalMonitoring(
    std::function<void(const PropertyMap&)> onDeviceAdded)
{
    // Store callback
    deviceAddedCallback = std::move(onDeviceAdded);

    // Monitor InterfacesAdded signals from EntityManager
    interfacesAddedMatch = std::make_unique<sdbusplus::bus::match_t>(
        bus,
        sdbusplus::bus::match::rules::interfacesAdded() +
            sdbusplus::bus::match::rules::sender(ENTITY_MANAGER_SERVICE),
        [this](sdbusplus::message_t& msg) { handleInterfacesAdded(msg); });
}

void EntityManagerInterface::handleInterfacesAdded(sdbusplus::message_t& msg)
{
    sdbusplus::message::object_path objectPath;
    InterfaceMap interfaces;

    try
    {
        msg.read(objectPath, interfaces);
    }
    catch (const std::exception& e)
    {
        error("Failed to read InterfacesAdded signal: {ERROR}", "ERROR",
              e.what());
        return;
    }

    // Check if PlatformDevice interface was added
    auto platformDeviceIt = interfaces.find(PLATFORM_DEVICE_INTERFACE);
    if (platformDeviceIt == interfaces.end())
    {
        return; // Not a PlatformDevice, ignore
    }

    // Invoke user callback with device properties
    if (deviceAddedCallback)
    {
        try
        {
            deviceAddedCallback(platformDeviceIt->second);
        }
        catch (const std::exception& e)
        {
            error("Device added callback failed: {ERROR}", "ERROR", e.what());
        }
    }
}

} // namespace topology
} // namespace logging
} // namespace phosphor
