#pragma once

#include "bin.hpp"

#include <fstream>
#include <map>
#include <optional>
#include <string>

namespace phosphor::logging::util
{

/**
 * @brief Return a value found in the /etc/os-release file
 *
 * @param[in] key - The key name, like "VERSION"
 *
 * @return std::optional<std::string> - The value
 */
std::optional<std::string> getOSReleaseValue(const std::string& key);

/**
 * @brief Synchronize unwritten journal messages to disk.
 * @details This is the same implementation as the systemd command
 *          "journalctl --sync".
 */
void journalSync();

#ifdef ENABLE_ERASE_WITH_MULTIPLE_PROCESS
/**
 * @brief Check and remove the temporary files for deletion.
 * @param[in] nspace - The namespace to check for temporary files
 * @param[in] binNameMap - Map of bin names to their configurations
 */
void removeStagedForEraseEntries(
    const std::string& nspace,
    const std::map<std::string, phosphor::logging::internal::Bin>& binNameMap);

/**
 * @brief Erase logs with multiple processes
 * @details Erases logs from disk using a child process while the parent process
 *          handles DBus operations. This allows for safe log deletion in a
 *          multi-process environment.
 *
 * @param[in] nspace - The namespace to check for temporary files
 * @param[in] binNameMap - Map of bin names to their configurations
 */
void eraseAllInChildProcess(
    const std::string& nspace,
    const std::map<std::string, phosphor::logging::internal::Bin>& binNameMap);
#endif

} // namespace phosphor::logging::util
