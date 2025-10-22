#pragma once

#include "elog_entry.hpp"
#include "extensions.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nvidia
{
namespace platform
{
namespace event
{

/**
 * @brief Extension Entry Points
 *
 * These functions are registered with phosphor-logging via
 * REGISTER_EXTENSION_FUNCTION macro and are called at specific
 * lifecycle events.
 *
 * These are thin wrappers that delegate to the Manager instance.
 */

/**
 * @brief Startup hook - called when phosphor-log-manager starts
 *
 * Creates the Manager instance and initializes the extension.
 *
 * @param logManager Reference to the main logging manager
 */
void nvPlatformStartup(phosphor::logging::internal::Manager& logManager);

/**
 * @brief Create hook - called after an event log is created
 *
 * Delegates to Manager::handleLogCreate()
 *
 * @param message Log message
 * @param id Log entry ID
 * @param timestamp Timestamp of log creation
 * @param severity Log severity level
 * @param additionalData Map of additional data (contains device error metadata)
 * @param assocs Association endpoints
 * @param ffdc FFDC data
 */
void nvPlatformEventCreate(
    const std::string& message, uint32_t id, uint64_t timestamp,
    phosphor::logging::Entry::Level severity,
    const phosphor::logging::AdditionalDataArg& additionalData,
    const phosphor::logging::AssociationEndpointsArg& assocs,
    const phosphor::logging::FFDCArg& ffdc);

/**
 * @brief Delete hook - called after an event log is deleted
 *
 * Delegates to Manager::handleLogDelete()
 *
 * @param id Log entry ID being deleted
 */
void nvPlatformDelete(uint32_t id);

} // namespace event
} // namespace platform
} // namespace nvidia
