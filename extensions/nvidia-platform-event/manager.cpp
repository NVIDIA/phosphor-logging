#include "manager.hpp"

#include "device_topology.hpp"

#include <phosphor-logging/lg2.hpp>

#include <charconv>

namespace nvidia
{
namespace platform
{
namespace event
{

Manager::Manager(phosphor::logging::internal::Manager& logManager) :
    logManager_(logManager)
{
    try
    {
        // Get bus from log manager
        auto& bus = logManager_.getBus();

        // STEP 1: Store D-Bus connection reference for interface creation
        // MUST be done BEFORE topology initialization so that D-Bus interfaces
        // can be created during device registration
        setDbusConnection(bus);

        // STEP 2: Initialize device topology from EntityManager
        // This queries EM for all PlatformDevice objects, creates
        // DeviceErrorStore entries with topology fields, creates D-Bus
        // interfaces, and links parent-child relationships
        initializeTopology(bus);

        // STEP 3: Setup monitoring for late device arrivals
        // This handles race conditions where devices are published after we
        // query, or when EntityManager config is hot-reloaded
        setupTopologyMonitoring(bus);
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to initialize: {ERROR}", "ERROR", e.what());
        throw;
    }
}

Manager::~Manager() = default;

void Manager::handleLogCreate(
    const std::string& message, uint32_t id,
    const phosphor::logging::AdditionalDataArg& additionalData)
{
    lg2::info("NVIDIA Platform Event extension processing log {ID}: {MSG}",
              "ID", id, "MSG", message);

    // Parse device error metadata from AdditionalData
    auto error = parseDeviceError(additionalData);

    if (error != nullptr)
    {
        // Process the error through the business logic
        processDeviceErrorLog(*error);

        // Clean up
        delete error;
    }
    else
    {
        lg2::debug("Log {ID} does not contain platform device error metadata",
                   "ID", id);
    }
}

void Manager::handleLogDelete(uint32_t id)
{
    lg2::debug("NVIDIA Platform Event extension handling log delete {ID}", "ID",
               id);

    // Currently no-op
    // Future enhancement: Track logId → eid mapping
    // and remove specific error from database when log is deleted
}

} // namespace event
} // namespace platform
} // namespace nvidia
