/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "extensions.hpp"

#include <phosphor-logging/lg2.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace nvidia
{
namespace logging
{

using namespace phosphor::logging;

static uint16_t selRecordId;

void selStartup(internal::Manager& logManager)
{
    uint32_t lastEntryId = 0;
    uint32_t entryId = 0;
    selRecordId = 0;
    // Scans all log entries managed by logManager to find the highest
    // SEL_RECORD_ID present. It assumes that the SEL entry with the largest
    // entry ID contains the latest SEL_RECORD_ID.
    for (const auto& entry : logManager.entries)
    {
        entryId = entry.second->id();
        // Only consider entries with increasing entry IDs
        if (entryId < lastEntryId)
        {
            continue;
        }
        for (const auto& [key, value] : entry.second->additionalData())
        {
            try
            {
                if (key == "SEL_RECORD_ID")
                {
                    lastEntryId = entryId;
                    // Parse the SEL_RECORD_ID value
                    selRecordId = std::stoul(value);
                    break;
                }
            }
            catch (const std::exception& e)
            {
                lg2::error("Failed to parse SEL_RECORD_ID: {ERROR}", "ERROR",
                           e.what());
                continue;
            }
        }
    }
    selRecordId++;
    lg2::debug("Initialize SEL Record ID to {ID}", "ID", selRecordId);
    return;
}
REGISTER_EXTENSION_FUNCTION(selStartup)

void selPrepare([[maybe_unused]] internal::Manager& logManager,
                std::map<std::string, std::string>& additionalData)
{
    for (const auto& [key, value] : additionalData)
    {
        // If the key is DEFAULT_BIN_KEY and value is "SEL", add
        // SEL_RECORD_ID.
        if ((key == DEFAULT_BIN_KEY) && (value == "SEL"))
        {
            additionalData.emplace("SEL_RECORD_ID",
                                   std::to_string(selRecordId));
#ifdef ENABLE_LOG_STREAMING
            /* Creates SEL data for streaming */
            std::string msg = " SelRecordId:" + std::to_string(selRecordId);
            /* Stream SEL data */
            std::vector<uint8_t> msgVec(msg.begin(), msg.end());
            if (!logManager.logSocket.sendMessage(msgVec))
            {
                lg2::error("Failed to stream SEL data");
            }
#endif
            selRecordId++;
            // Wrap around if selRecordId exceeds uint16_t max value
            if (selRecordId >= std::numeric_limits<uint16_t>::max())
            {
                selRecordId = 1;
            }
            return;
        }
    }
}
REGISTER_EXTENSION_FUNCTION(selPrepare)

void selDeleteAll(void)
{
    selRecordId = 1;
    lg2::debug("Reset SEL Record ID to {ID}", "ID", selRecordId);
}
REGISTER_EXTENSION_FUNCTION(selDeleteAll)

} // namespace logging
} // namespace nvidia
