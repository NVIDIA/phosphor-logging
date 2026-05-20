#include "config.h"

#include "device_topology.hpp"

#include "device_error_database.hpp"

#include <phosphor-logging/lg2.hpp>

#include <memory>
#include <unordered_map>

namespace nvidia
{
namespace platform
{
namespace event
{

PHOSPHOR_LOG2_USING;

// EntityManager interface instance
static std::unique_ptr<phosphor::logging::topology::EntityManagerInterface>
    emInterface;

// Track devices waiting for parent to appear
static std::unordered_map<uint8_t, std::string>
    pendingParentLinks; // childEid → parentName

int initializeTopology(sdbusplus::bus_t& bus)
{
    lg2::info("Initializing device topology");
    // Create EM interface
    emInterface =
        std::make_unique<phosphor::logging::topology::EntityManagerInterface>(
            bus);

    auto devices = emInterface->queryAllDevices();

    // Build device registry (creates DeviceErrorStore for each device)
    builddeviceErrorDatabase(devices);

    // Link parent-child relationships
    linkDeviceHierarchy();

    return deviceErrorDatabase.size();
}

void setupTopologyMonitoring(sdbusplus::bus_t& /* bus */)
{
    lg2::info("Setting up topology monitoring");
    if (!emInterface)
    {
        lg2::error(
            "EM interface not initialized, cannot setup topology monitoring");
        return;
    }

    emInterface->setupSignalMonitoring([](const PropertyMap& properties) {
        handleDeviceAdded(properties);
    });
}

void handleDeviceAdded(const PropertyMap& properties)
{
    try
    {
        // Parse mandatory properties
        auto nameIt = properties.find("Name");
        auto addrIt = properties.find("DeviceAddress");
        if (nameIt == properties.end() || addrIt == properties.end())
        {
            lg2::warning(
                "InterfacesAdded signal missing Name or DeviceAddress");
            return;
        }

        std::string deviceId = std::get<std::string>(nameIt->second);
        std::string deviceAddress = std::get<std::string>(addrIt->second);
        auto eid = parseEid(deviceAddress);

        if (!eid.has_value())
        {
            lg2::warning("Invalid DeviceAddress for device {NAME}", "NAME",
                         deviceId);
            return;
        }

        uint8_t eidValue = eid.value();

        // Check if device already exists (duplicate signal from EM)
        if (deviceErrorDatabase.count(eidValue))
        {
            lg2::debug(
                "Device {NAME} EID={EID} already exists, ignoring duplicate",
                "NAME", deviceId, "EID", (int)eidValue);
            return;
        }

        // Add device to registry (with immediate hierarchy linking)
        addDeviceToRegistry(properties, eidValue, deviceId, true);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to handle device addition: {ERROR}", "ERROR",
                   e.what());
    }
}

void addDeviceToRegistry(const PropertyMap& properties, uint8_t eid,
                         const std::string& deviceId, bool linkHierarchy)
{
    // Parse optional properties
    std::string parentName;
    if (auto it = properties.find("ConnectsToName"); it != properties.end())
    {
        parentName = std::get<std::string>(it->second);
    }

    bool poweredInStandby = true;
    if (auto it = properties.find("poweredInStandby"); it != properties.end())
    {
        poweredInStandby = std::get<bool>(it->second);
    }

    // Create device store
    DeviceErrorStore deviceStore(eid, MAX_ERRORS_PER_CLASS);
    deviceStore.deviceId = deviceId;
    deviceStore.poweredInStandby = poweredInStandby;
    deviceStore.parentName = parentName;

    // Add to registry
    deviceErrorDatabase.emplace(eid, std::move(deviceStore));
    nameToEidLookup[deviceId] = eid;

    // Link hierarchy if requested (for dynamic device addition)
    if (linkHierarchy)
    {
        linkDeviceToParent(eid, parentName);
        resolvePendingChildren(eid, deviceId);
    }

    // Create D-Bus interface immediately for this device
    createDeviceStatusInterface(eid);
}

void builddeviceErrorDatabase(const std::vector<PropertyMap>& devices)
{
    for (const auto& properties : devices)
    {
        // Parse mandatory properties
        auto nameIt = properties.find("Name");
        auto addrIt = properties.find("DeviceAddress");
        if (nameIt == properties.end() || addrIt == properties.end())
        {
            lg2::warning("Device missing Name or DeviceAddress, skipping");
            continue;
        }

        std::string deviceId = std::get<std::string>(nameIt->second);
        std::string deviceAddress = std::get<std::string>(addrIt->second);
        auto eid = parseEid(deviceAddress);

        if (!eid.has_value())
        {
            lg2::warning("Invalid DeviceAddress for {NAME}, skipping", "NAME",
                         deviceId);
            continue;
        }

        // Add device to registry (hierarchy linking done later in batch)
        addDeviceToRegistry(properties, eid.value(), deviceId, false);
    }
}

void linkDeviceHierarchy()
{
    for (auto& [eid, deviceStore] : deviceErrorDatabase)
    {
        if (deviceStore.parentName.empty())
        {
            continue; // Root device (no parent)
        }

        linkDeviceToParent(eid, deviceStore.parentName);
    }

    // Report any unresolved parent links
    if (!pendingParentLinks.empty())
    {
        lg2::warning("{COUNT} devices have unresolved parent links", "COUNT",
                     pendingParentLinks.size());
        for (const auto& [childEid, parentName] : pendingParentLinks)
        {
            lg2::warning("  Device EID={EID} waiting for parent {PARENT}",
                         "EID", (int)childEid, "PARENT", parentName);
        }
    }
}

void linkDeviceToParent(uint8_t childEid, const std::string& parentName)
{
    if (parentName.empty())
    {
        return;
    }

    // Look up parent by name
    auto parentEidIt = nameToEidLookup.find(parentName);
    if (parentEidIt != nameToEidLookup.end())
    {
        // Parent exists, link now
        uint8_t parentEid = parentEidIt->second;

        deviceErrorDatabase.at(childEid).parentEid = parentEid;
    }
    else
    {
        // Parent doesn't exist yet, pend it
        pendingParentLinks[childEid] = parentName;
    }
}

void resolvePendingChildren(uint8_t parentEid, const std::string& parentName)
{
    for (auto it = pendingParentLinks.begin(); it != pendingParentLinks.end();)
    {
        if (it->second == parentName)
        {
            uint8_t childEid = it->first;

            // Link child → parent
            deviceErrorDatabase.at(childEid).parentEid = parentEid;
            it = pendingParentLinks.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

std::optional<uint8_t> parseEid(const std::string& deviceAddress)
{
    // Format: "MCTP:17" or "PROTOCOL:EID"
    size_t colonPos = deviceAddress.find(':');
    if (colonPos == std::string::npos)
    {
        lg2::warning("Invalid DeviceAddress format: {ADDR}", "ADDR",
                     deviceAddress);
        return std::nullopt;
    }

    std::string eidStr = deviceAddress.substr(colonPos + 1);
    if (eidStr.empty())
    {
        return std::nullopt;
    }

    try
    {
        int eidValue = std::stoi(eidStr);
        if (eidValue < 0 || eidValue > 255)
        {
            lg2::warning("EID out of range: {ADDR}", "ADDR", deviceAddress);
            return std::nullopt;
        }
        return static_cast<uint8_t>(eidValue);
    }
    catch (const std::exception& e)
    {
        lg2::warning("Failed to parse EID from {ADDR}: {ERROR}", "ADDR",
                     deviceAddress, "ERROR", e.what());
        return std::nullopt;
    }
}

} // namespace event
} // namespace platform
} // namespace nvidia
