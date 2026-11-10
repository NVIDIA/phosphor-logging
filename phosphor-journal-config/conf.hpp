// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// All rights reserved.
#pragma once

#include "xyz/openbmc_project/Logging/Entry/common.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace phosphor
{
namespace journal_config
{

using Level = sdbusplus::common::xyz::openbmc_project::logging::Entry::Level;

inline constexpr auto overridePath =
    "/etc/systemd/journald.conf.d/phosphor-journal-maxlevel.conf";
inline constexpr auto packagedPath =
    "/usr/lib/systemd/journald.conf.d/journald-maxlevel-policy.conf";

/** @brief Read MaxLevelStore from a journald drop-in.
 *  @param[in] path Drop-in file path.
 *  @return The last valid named token (emerg…debug), or std::nullopt if
 *          the file cannot be read or has no valid MaxLevelStore. Numeric
 *          0–7 values are ignored.
 */
std::optional<std::string> readMaxLevelStore(std::string_view path);

/** @brief Atomically write a drop-in that contains only MaxLevelStore.
 *  @param[in] path Drop-in file path.
 *  @param[in] maxLevelStore Named journald token (emerg…debug).
 *  @return true if the file was written and renamed into place.
 */
bool writeMaxLevelStore(std::string_view path, std::string_view maxLevelStore);

/** @brief journald MaxLevelStore token -> PDI Entry.Level.
 *  @param[in] maxLevelStore Named journald token.
 *  @return Entry.Level, or std::nullopt if the token is not a named
 *          journald level (numeric 0–7 is not mapped).
 */
std::optional<Level> maxLevelStoreToEntryLevel(std::string_view maxLevelStore);

/** @brief PDI Entry.Level -> journald MaxLevelStore token.
 *  @param[in] entryLevel Entry.Level enumerator.
 *  @return emerg…debug, or std::nullopt if the enumerator has no journald
 *          token.
 */
std::optional<std::string> entryLevelToMaxLevelStore(Level entryLevel);

} // namespace journal_config
} // namespace phosphor
