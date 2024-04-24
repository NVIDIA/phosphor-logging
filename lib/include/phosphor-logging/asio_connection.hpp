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
#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>

namespace phosphor
{
namespace logging
{
    class AsioConnection
    {
        public:
            AsioConnection() = delete;
            AsioConnection(const AsioConnection&) = delete;
            AsioConnection& operator=(const AsioConnection&) = delete;
            AsioConnection(AsioConnection&&) = delete;
            AsioConnection& operator=(AsioConnection&&) = delete;
            ~AsioConnection() = delete;

            /** @brief Get the asio connection. */
            static auto& getAsioConnection()
            {
                static boost::asio::io_context io;
                static auto conn = std::make_shared<sdbusplus::asio::connection>(io);
                return conn;
            }
    };
} // namespace user
} // namespace phosphor
