/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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

#include <cstdint>
#include <set>
#include <string>

namespace phosphor::logging::internal
{

class Bin
{
  public:
    ~Bin() = default;
    Bin() :
        name(DEFAULT_BIN_NAME), errorCap(ERROR_CAP),
        errorInfoCap(ERROR_INFO_CAP), persistLocation(ERRLOG_PERSIST_PATH),
        errorEntries({}), infoEntries({}), persistInfoLog(true){};

    Bin(const std::string& str, uint32_t errCap, uint32_t errInfCap,
        const std::string& loc, bool persistInfoLog) :
        name(str),
        errorCap(errCap), errorInfoCap(errInfCap), persistLocation(loc),
        errorEntries({}), infoEntries({}), persistInfoLog(persistInfoLog){};

    std::string name;
    uint32_t errorCap;
    uint32_t errorInfoCap;
    std::string persistLocation;
    std::string jsonPath;
    std::set<uint32_t> errorEntries;
    std::set<uint32_t> infoEntries;
    bool persistInfoLog;
};

} // namespace phosphor::logging::internal
