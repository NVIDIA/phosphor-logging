#pragma once

#include "bin.hpp"

#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <vector>

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

namespace additional_data
{
/** @brief Pull out metadata name and value from the string
 *         <metadata name>=<metadata value>
 *  @param [in] data - metadata key=value entries
 *  @return map of metadata name:value
 */
auto parse(const std::vector<std::string>& data)
    -> std::map<std::string, std::string>;
/** @brief Combine the metadata keys and values from the map
 *         into a vector of strings that look like:
 *            "<metadata name>=<metadata value>"
 *  @param [in] data - metadata key:value map
 *  @return vector of "key=value" strings
 */
auto combine(const std::map<std::string, std::string>& data)
    -> std::vector<std::string>;
} // namespace additional_data
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
