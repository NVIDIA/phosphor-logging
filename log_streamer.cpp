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

#include "log_streamer.hpp"

#include <sys/time.h>

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>

namespace phosphor
{
namespace logging
{

bool LogStreamer::start()
{
    sockfd = createSocket();
    if (sockfd == -1)
    {
        return false;
    }
    stopping = false;
    sender = std::thread(&LogStreamer::senderLoop, this);
    return true;
}

void LogStreamer::stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex);
        stopping = true;
    }
    queued.notify_all();
    /* Wait until senderLoop has left sendto() before closing sockfd.
     * joinable() is false when start() failed or stop() already ran;
     * Manager and ~LogStreamer both call stop(). */
    if (sender.joinable())
    {
        sender.join();
    }
    std::lock_guard<std::mutex> lock(mutex);
    closeSocket();
}

bool LogStreamer::sendMessage(const std::vector<uint8_t>& message)
{
    /* Maximum binary size 64K */
    constexpr std::size_t MAX_MESSAGE_SIZE = 65536;
    /* Bound the queue so a stuck rsyslog cannot grow it until the BMC runs
     * out of memory. The SEL entry is already committed before sendMessage().
     */
    constexpr std::size_t maxQueueDepth = 4096;

    std::lock_guard<std::mutex> lock(mutex);
    if (stopping || sockfd == -1)
    {
        lg2::error("Socket is not connected");
        return false;
    }

    if (message.size() > MAX_MESSAGE_SIZE)
    {
        lg2::error("Message size exceeds 64K limit: {SIZE}", "SIZE",
                   message.size());
        return false;
    }

    if (queue.size() >= maxQueueDepth)
    {
        lg2::error("SEL stream queue is full, dropping {SIZE} bytes", "SIZE",
                   message.size());
        return false;
    }

    queue.push_back(message);
    queued.notify_one();
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
        lg2::error("Failed to create socket: {ERROR}", "ERROR",
                   strerror(errno));
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sun_family = AF_UNIX;
    strncpy(serverAddr.sun_path, socketPath.c_str(),
            sizeof(serverAddr.sun_path) - 1);

    /* A full rsyslog queue blocks sendto() forever, so stop() could not
     * join the sender thread. Bound that wait. */
    constexpr int sendTimeoutMs = 200;
    struct timeval sendTimeout;
    sendTimeout.tv_sec = 0;
    sendTimeout.tv_usec = sendTimeoutMs * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout,
                   sizeof(sendTimeout)) == -1)
    {
        lg2::error("Failed to set send timeout: {ERROR}", "ERROR",
                   strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void LogStreamer::closeSocket()
{
    if (sockfd != -1)
    {
        close(sockfd);
        sockfd = -1;
        lg2::info("Socket closed gracefully");
    }
}

void LogStreamer::senderLoop()
{
    std::unique_lock<std::mutex> lock(mutex);
    while (!stopping)
    {
        queued.wait(lock, [this] { return stopping || !queue.empty(); });
        if (stopping || queue.empty())
        {
            break;
        }

        std::vector<uint8_t> message = std::move(queue.front());
        queue.pop_front();
        lock.unlock();

        bool delivered = false;
        while (!delivered && !stopping)
        {
            ssize_t bytesSent =
                sendto(sockfd, message.data(), message.size(), 0,
                       (struct sockaddr*)&serverAddr, sizeof(serverAddr));
            if (bytesSent >= 0)
            {
                lg2::info("Sent {BYTES} bytes", "BYTES", bytesSent);
                delivered = true;
            }
            else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                /* ECONNREFUSED, EMSGSIZE, and other errors will not succeed
                 * by retrying this datagram. Drop it so the queue can move. */
                lg2::error("Dropping SEL stream message: {ERROR}", "ERROR",
                           strerror(errno));
                break;
            }
        }

        lock.lock();
    }
}

} // namespace logging
} // namespace phosphor
