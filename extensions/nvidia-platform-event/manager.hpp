#pragma once

#include "device_error_database.hpp"
#include "extensions.hpp"
#include "log_manager.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace nvidia
{
namespace platform
{
namespace event
{

/**
 * @brief Main manager for NVIDIA Platform Event extension
 *
 * This manager acts as a bridge between phosphor-logging and the
 * device error database. It:
 * - Handles phosphor-logging lifecycle events
 * - Parses AdditionalData for device error metadata
 * - Delegates to core business logic functions
 */
class Manager
{
  public:
    explicit Manager(phosphor::logging::internal::Manager& logManager);
    ~Manager();

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;

    /**
     * @brief Handle log creation event
     *
     * Called by extension framework when a new log is created.
     * Parses the AdditionalData for device error metadata and
     * calls processDeviceErrorLog() if found.
     *
     * @param message Log message
     * @param id Log entry ID
     * @param additionalData Map of additional data (contains device error
     * metadata)
     */
    void handleLogCreate(
        const std::string& message, uint32_t id,
        const phosphor::logging::AdditionalDataArg& additionalData);

    /**
     * @brief Handle log deletion event
     *
     * Called when a log is deleted. Can be used for cleanup if needed.
     *
     * @param id Log entry ID being deleted
     */
    void handleLogDelete(uint32_t id);

  private:
    phosphor::logging::internal::Manager& logManager_;
};

} // namespace event
} // namespace platform
} // namespace nvidia
