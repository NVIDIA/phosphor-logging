/**
 * NVIDIA Platform Event Extension Entry Points
 *
 * This extension integrates with phosphor-logging to provide device-specific
 * error aggregation, priority-based classification, and recovery tracking
 * for platform resiliency firmware upgrade workflows.
 */

#include "entry_points.hpp"

#include "extensions.hpp"
#include "manager.hpp"

#include <phosphor-logging/lg2.hpp>

#include <memory>

namespace nvidia
{
namespace platform
{
namespace event
{

using namespace phosphor::logging;

// Global manager instance
std::unique_ptr<Manager> nvManager;

/**
 * @brief Startup function called when phosphor-log-manager starts
 *
 * Initializes the NVIDIA platform event extension and error database.
 */
void nvPlatformStartup(internal::Manager& logManager)
{
    try
    {
        // Create NVIDIA extension manager
        nvManager = std::make_unique<Manager>(logManager);
        lg2::info("NVIDIA Platform Event extension initialized successfully");
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to initialize NVIDIA Platform Event extension: "
                   "{ERROR}",
                   "ERROR", e.what());
    }
}

REGISTER_EXTENSION_FUNCTION(nvPlatformStartup)

/**
 * @brief Called after an event log is created
 *
 * Parses the log for device error metadata and processes it through
 * the error aggregation system.
 */
void nvPlatformEventCreate(
    const std::string& message, uint32_t id, uint64_t /* timestamp */,
    Entry::Level /* severity */, const AdditionalDataArg& additionalData,
    const AssociationEndpointsArg& /* assocs */, const FFDCArg& /* ffdc */)
{
    if (nvManager)
    {
        try
        {
            // Only pass the parameters we actually use
            nvManager->handleLogCreate(message, id, additionalData);
        }
        catch (const std::exception& e)
        {
            lg2::error("Error in nvPlatformEventCreate for log {ID}: {ERROR}",
                       "ID", id, "ERROR", e.what());
        }
    }
}

REGISTER_EXTENSION_FUNCTION(nvPlatformEventCreate)

/**
 * @brief Called after an event log is deleted
 *
 * Removes the corresponding error from the device error database.
 */
void nvPlatformDelete(uint32_t id)
{
    if (nvManager)
    {
        try
        {
            nvManager->handleLogDelete(id);
        }
        catch (const std::exception& e)
        {
            lg2::error("Error in nvPlatformDelete for log {ID}: {ERROR}", "ID",
                       id, "ERROR", e.what());
        }
    }
}

REGISTER_EXTENSION_FUNCTION(nvPlatformDelete)

} // namespace event
} // namespace platform
} // namespace nvidia
