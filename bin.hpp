/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION &
 * AFFILIATES. All rights reserved. SPDX-License-Identifier: Apache-2.0
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
#pragma once

#include "config.h"

#include "paths.hpp"

#include <cstdint>
#include <set>
#include <string>
#include <string_view>

namespace phosphor::logging::internal
{

/** @brief Class key of a namespace name.
 *
 *  A namespace such as "GPU_0", "GPU_0_XID" or "IO_Board_2" belongs to a
 *  device class ("GPU", "GPU_XID", "IO_Board"): the name is split at '_' and
 *  the all-digit parts (the device instance numbers) are removed. A name
 *  without a number is its own class ("FWUpdate").
 *
 *  The name becomes a directory name, so only letters, digits and '_' are
 *  accepted, parts must not be empty and a number may have at most 4 digits.
 *
 *  @param[in] name - namespace name
 *  @return the class key, or an empty string when the name is not acceptable
 *          or has no part left once the numbers are removed
 */
inline std::string binClassKey(std::string_view name)
{
    constexpr size_t maxNameLen = 64;
    constexpr size_t maxDigits = 4;

    if (name.empty() || name.size() > maxNameLen)
    {
        return {};
    }

    std::string key;
    size_t pos = 0;
    while (pos <= name.size())
    {
        auto end = name.find('_', pos);
        if (end == std::string_view::npos)
        {
            end = name.size();
        }
        auto part = name.substr(pos, end - pos);
        if (part.empty())
        {
            return {};
        }

        bool allDigits = true;
        for (char c : part)
        {
            bool digit = c >= '0' && c <= '9';
            bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
            if (!digit && !alpha)
            {
                return {};
            }
            allDigits = allDigits && digit;
        }

        if (allDigits)
        {
            if (part.size() > maxDigits)
            {
                return {};
            }
        }
        else
        {
            if (!key.empty())
            {
                key += '_';
            }
            key += part;
        }
        pos = end + 1;
    }
    return key;
}

class Bin
{
  public:
    ~Bin() = default;
    Bin() :
        name(DEFAULT_BIN_NAME), errorCap(ERROR_CAP),
        errorInfoCap(ERROR_INFO_CAP),
        persistLocation(phosphor::logging::paths::error()), errorEntries({}),
        infoEntries({}), persistInfoLog(true), defaultCapacity(0) {};

    Bin(const std::string& str, uint32_t errCap, uint32_t errInfCap,
        const std::string& loc, bool persistInfoLog, uint32_t defaultCapacity) :
        name(str), errorCap(errCap), errorInfoCap(errInfCap),
        persistLocation(loc), errorEntries({}), infoEntries({}),
        persistInfoLog(persistInfoLog), defaultCapacity(defaultCapacity) {};

    std::string name;
    uint32_t errorCap;
    uint32_t errorInfoCap;
    std::string persistLocation;
    std::string jsonPath;
    std::set<uint32_t> errorEntries;
    std::set<uint32_t> infoEntries;
    bool persistInfoLog;
    uint32_t defaultCapacity;
};

} // namespace phosphor::logging::internal
