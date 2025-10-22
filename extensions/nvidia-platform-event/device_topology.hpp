#pragma once

#include <em_interface.hpp>
#include <sdbusplus/bus.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace nvidia
{
namespace platform
{
namespace event
{

// Forward declaration
using PropertyMap = phosphor::logging::topology::PropertyMap;

/**
 * @brief Initialize topology from EntityManager
 *
 * Queries EntityManager for all PlatformDevice objects, creates
 * DeviceErrorStore entries (topology fields only), and links
 * parent-child relationships.
 *
 * This is the initial topology build at startup. It makes ONE D-Bus
 * call to get all devices and builds the complete hierarchy.
 *
 * @param bus D-Bus connection
 * @return Number of devices initialized
 */
int initializeTopology(sdbusplus::bus_t& bus);

/**
 * @brief Setup monitoring for device additions at runtime
 *
 * Monitors InterfacesAdded signals to handle:
 * - Late device arrivals (EM race condition - service starts before EM
 * finishes)
 * - EM config hot-reload (admin updates config at runtime)
 * - Device hot-plug (rare - physical device added)
 *
 * Must be called AFTER initializeTopology().
 *
 * @param bus D-Bus connection
 */
void setupTopologyMonitoring(sdbusplus::bus_t& bus);

/**
 * @brief Handle device added at runtime
 *
 * Called by InterfacesAdded signal handler. Creates DeviceErrorStore
 * entry and links to parent (or pends if parent doesn't exist yet).
 *
 * This handles incremental device additions after initial build.
 *
 * @param properties Device properties from EM signal
 */
void handleDeviceAdded(const PropertyMap& properties);

/**
 * @brief Build device registry from EM query results
 *
 * Internal function - creates DeviceErrorStore entries for all devices
 * with topology fields populated (identity + parent/child info + EM
 * properties).
 *
 * @param devices Vector of property maps from EM query
 */
void builddeviceErrorDatabase(const std::vector<PropertyMap>& devices);

/**
 * @brief Link parent-child relationships
 *
 * Internal function - establishes bidirectional parent-child links
 * in DeviceErrorStore entries based on ConnectsToName property.
 *
 * Handles out-of-order devices by tracking pending parent links.
 */
void linkDeviceHierarchy();

/**
 * @brief Link device to parent (or pend if parent doesn't exist)
 *
 * Internal function - helper for hierarchy building.
 *
 * If parent exists: establishes bidirectional link immediately
 * If parent missing: tracks in pendingParentLinks for later resolution
 *
 * @param childEid Child device EID
 * @param parentName Parent device name (from ConnectsToName)
 */
void linkDeviceToParent(uint8_t childEid, const std::string& parentName);

/**
 * @brief Resolve pending children for newly arrived parent
 *
 * Internal function - links any children that were waiting for this parent.
 * Called when a parent device is added (handles out-of-order arrivals).
 *
 * @param parentEid Parent device EID
 * @param parentName Parent device name
 */
void resolvePendingChildren(uint8_t parentEid, const std::string& parentName);

/**
 * @brief Parse EID from DeviceAddress
 *
 * Internal helper - parses "MCTP:17" or "PROTOCOL:EID" format.
 *
 * @param deviceAddress DeviceAddress string from EM
 * @return Optional EID value (0-255), nullopt if invalid
 */
std::optional<uint8_t> parseEid(const std::string& deviceAddress);

/**
 * @brief Add a single device to the registry
 *
 * Parses device properties, creates DeviceErrorStore, adds to registry,
 * and creates D-Bus interface. Does NOT link hierarchy - caller handles that.
 *
 * @param properties Device properties from EntityManager
 * @param eid Device EID (already parsed)
 * @param deviceId Device name (already parsed)
 * @param linkHierarchy If true, link to parent and resolve pending children
 * immediately
 */
void addDeviceToRegistry(const PropertyMap& properties, uint8_t eid,
                         const std::string& deviceId, bool linkHierarchy);

/**
 * @brief Device Name to EID Lookup
 *
 * Helper map for resolving device names to EIDs during hierarchy building.
 * Key: Device name (e.g., "GPU0", "Bridge1")
 * Value: Device EID
 *
 * Populated by device_topology.cpp during device discovery.
 */
inline std::map<std::string, uint8_t> nameToEidLookup;

} // namespace event
} // namespace platform
} // namespace nvidia
