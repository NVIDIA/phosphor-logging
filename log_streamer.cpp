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

#include <xyz/openbmc_project/Common/error.hpp>
#include <phosphor-logging/lg2.hpp>
#include "log_streamer.hpp"

#include <fstream>
#include <iostream>
#include <cstring>
#include <csignal>
#include <cstdint>

namespace phosphor
{
namespace logging
{

bool LogStreamer::start()
{
    sockfd = createSocket();
    return sockfd != -1;
}

void LogStreamer::stop()
{
    if (sockfd != -1)
    {
        closeSocket();
        lg2::info("Socket closed gracefully");
    }
}

bool LogStreamer::sendMessage(const std::vector<uint8_t>& message)
{
    /* Maximum binary size 64K */
    constexpr std::size_t MAX_MESSAGE_SIZE = 65536;

    if (sockfd == -1)
    {
        lg2::error("Socket is not connected");
        return false;
    }

    if (message.size() > MAX_MESSAGE_SIZE)
    {
        lg2::error("Message size exceeds 64K limit: {SIZE}", "SIZE", message.size());
        return false;
    }

    ssize_t bytesSent = sendto(sockfd, message.data(), message.size(), 0,
                               (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (bytesSent == -1)
    {
        lg2::error("Failed to send message: {ERROR}", "ERROR", strerror(errno));
        return false;
    }
    lg2::info("Sent {BYTES} bytes", "BYTES", bytesSent);
    return true;
}

bool LogStreamer::sendFile(const std::string& filePath)
{
    /* Opens the file in binary mode and position the file pointer at the end */
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        lg2::error("Failed to open file: {ERROR}", "ERROR", strerror(errno));
        return false;
    }

    /* Gets the size of the file */
    std::streamsize size = file.tellg();
    if (size == 0)
    {
        lg2::error("File is empty");
        return false;
    }
    file.seekg(0, std::ios::beg);

    /* Reads the entire file into a buffer */
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        lg2::error("Failed to read file: {ERROR}", "ERROR", strerror(errno));
        return false;
    }

    return sendMessage(buffer);
}

int LogStreamer::createSocket()
{
    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd == -1)
    {
        lg2::error("Failed to create socket: {ERROR}", "ERROR", strerror(errno));
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sun_family = AF_UNIX;
    strncpy(serverAddr.sun_path, socketPath.c_str(), sizeof(serverAddr.sun_path) - 1);

    return sockfd;
}

void LogStreamer::closeSocket()
{
    if (sockfd != -1)
    {
        close(sockfd);
        sockfd = -1;
    }
}

} // namespace logging
} // namespace phosphor
