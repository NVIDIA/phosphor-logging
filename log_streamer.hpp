/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION &
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

#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <vector>
#include <unistd.h>

#ifndef LOG_STREAMER_H
#define LOG_STREAMER_H

namespace phosphor
{
namespace logging
{

class LogStreamer
{
public:
    LogStreamer(const std::string& socketPath) : socketPath(socketPath), sockfd(-1) {}

    LogStreamer(const LogStreamer&) = delete;
    LogStreamer& operator=(const LogStreamer&) = delete;

    LogStreamer(LogStreamer&&) = delete;
    LogStreamer& operator=(LogStreamer&&) = delete;

    ~LogStreamer()
    {
        closeSocket();
    }

    bool start();

    void stop();

    bool sendMessage(const std::vector<uint8_t>& message);
    bool sendFile(const std::string& filePath);

private:
    std::string socketPath;
    int sockfd;
    struct sockaddr_un serverAddr;

    int createSocket();

    void closeSocket();
};

} // namespace logging
} // namespace phosphor

#endif // LOG_STREAMER_H