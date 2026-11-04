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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef LOG_STREAMER_H
#define LOG_STREAMER_H

namespace phosphor
{
namespace logging
{

/** @class LogStreamer
 *  @brief Queue SEL record ids and send them to rsyslog on another thread,
 *         so Create does not block on the socket.
 */
class LogStreamer
{
  public:
    /** @brief Store the rsyslog socket path. start() opens the socket.
     *  @param[in] socketPath - Unix datagram socket rsyslog listens on.
     */
    LogStreamer(const std::string& socketPath) :
        socketPath(socketPath), sockfd(-1), stopping(false)
    {}

    LogStreamer(const LogStreamer&) = delete;
    LogStreamer& operator=(const LogStreamer&) = delete;

    LogStreamer(LogStreamer&&) = delete;
    LogStreamer& operator=(LogStreamer&&) = delete;

    /** @brief Stop the sender thread and close the socket. */
    ~LogStreamer()
    {
        stop();
    }

    /** @brief Open the socket and start the sender thread.
     *  @return true when the socket is open and the thread is running.
     */
    bool start();

    /** @brief Stop the sender thread and close the socket.
     *         Messages still in the queue are not sent.
     */
    void stop();

    /** @brief Queue one datagram for the sender thread.
     *  @param[in] message - Bytes to send. Larger than 64KB is rejected.
     *  @return false when the socket is closed, the message is too large,
     *          or the queue is full. A full queue drops this message.
     */
    bool sendMessage(const std::vector<uint8_t>& message);

    /** @brief Read a file and queue its contents as one datagram.
     *  @param[in] filePath - File to send.
     *  @return false when the file cannot be read or sendMessage() rejects it.
     */
    bool sendFile(const std::string& filePath);

  private:
    std::string socketPath;
    int sockfd;
    struct sockaddr_un serverAddr;

    std::mutex mutex;
    std::condition_variable queued;
    std::deque<std::vector<uint8_t>> queue;
    std::atomic<bool> stopping;
    std::thread sender;

    /** @brief Create the datagram socket and set a 200ms send timeout.
     *  @return The socket fd, or -1 on failure.
     */
    int createSocket();

    /** @brief Close the socket. The caller must hold mutex. */
    void closeSocket();

    /** @brief Send queued datagrams until stop().
     *         Drop a datagram when sendto() fails with anything other than
     *         EINTR, EAGAIN, or EWOULDBLOCK.
     */
    void senderLoop();
};

} // namespace logging
} // namespace phosphor

#endif // LOG_STREAMER_H
