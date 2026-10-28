/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION &
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

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace phosphor
{
namespace logging
{
namespace test
{

namespace fs = std::filesystem;

class TestLogStreamer : public testing::Test
{
  public:
    TestLogStreamer()
    {
        char tmpl[] = "/tmp/log_streamer_test.XXXXXX";
        dir = mkdtemp(tmpl);
        socketPath = (dir / "sel.sock").string();
    }

    ~TestLogStreamer() override
    {
        if (receiver != -1)
        {
            close(receiver);
        }
        fs::remove_all(dir);
    }

    TestLogStreamer(const TestLogStreamer&) = delete;
    TestLogStreamer& operator=(const TestLogStreamer&) = delete;
    TestLogStreamer(TestLogStreamer&&) = delete;
    TestLogStreamer& operator=(TestLogStreamer&&) = delete;

    /** @brief Bind a datagram socket at socketPath to receive the stream */
    void bindReceiver()
    {
        receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        ASSERT_NE(receiver, -1);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, socketPath.c_str(),
                     sizeof(addr.sun_path) - 1);
        ASSERT_EQ(bind(receiver, reinterpret_cast<sockaddr*>(&addr),
                       sizeof(addr)),
                  0);
    }

    std::vector<uint8_t> receive()
    {
        std::vector<uint8_t> buf(70000);
        auto n = recv(receiver, buf.data(), buf.size(), 0);
        buf.resize(n < 0 ? 0 : static_cast<size_t>(n));
        return buf;
    }

    fs::path dir;
    std::string socketPath;
    int receiver = -1;
};

TEST_F(TestLogStreamer, sendBeforeStartFails)
{
    LogStreamer streamer(socketPath);
    EXPECT_FALSE(streamer.sendMessage({1, 2, 3}));
}

TEST_F(TestLogStreamer, sendMessageReachesReceiver)
{
    bindReceiver();
    LogStreamer streamer(socketPath);
    ASSERT_TRUE(streamer.start());

    const std::vector<uint8_t> message{0xde, 0xad, 0xbe, 0xef};
    EXPECT_TRUE(streamer.sendMessage(message));
    EXPECT_EQ(receive(), message);
}

TEST_F(TestLogStreamer, sendMessageWithoutReceiverFails)
{
    LogStreamer streamer(socketPath);
    ASSERT_TRUE(streamer.start());
    EXPECT_FALSE(streamer.sendMessage({1}));
}

TEST_F(TestLogStreamer, oversizeMessageIsNotSent)
{
    bindReceiver();
    LogStreamer streamer(socketPath);
    ASSERT_TRUE(streamer.start());

    EXPECT_FALSE(streamer.sendMessage(std::vector<uint8_t>(65537, 0x5a)));
    EXPECT_TRUE(receive().empty());
}

TEST_F(TestLogStreamer, stopClosesTheSocket)
{
    bindReceiver();
    LogStreamer streamer(socketPath);
    ASSERT_TRUE(streamer.start());
    streamer.stop();
    EXPECT_FALSE(streamer.sendMessage({1}));
    EXPECT_TRUE(receive().empty());

    // A second stop is harmless
    streamer.stop();
}

TEST_F(TestLogStreamer, sendFileSendsItsContent)
{
    bindReceiver();
    LogStreamer streamer(socketPath);
    ASSERT_TRUE(streamer.start());

    const auto file = dir / "sel.bin";
    const std::vector<uint8_t> content{0x01, 0x00, 0x7f, 0xff, 0x10};
    std::ofstream(file, std::ios::binary)
        .write(reinterpret_cast<const char*>(content.data()),
               static_cast<std::streamsize>(content.size()));

    EXPECT_TRUE(streamer.sendFile(file.string()));
    EXPECT_EQ(receive(), content);
}

TEST_F(TestLogStreamer, sendFileMissingOrEmptyFails)
{
    bindReceiver();
    LogStreamer streamer(socketPath);
    ASSERT_TRUE(streamer.start());

    EXPECT_FALSE(streamer.sendFile((dir / "missing.bin").string()));

    const auto empty = dir / "empty.bin";
    std::ofstream(empty).close();
    EXPECT_FALSE(streamer.sendFile(empty.string()));
    EXPECT_TRUE(receive().empty());
}

} // namespace test
} // namespace logging
} // namespace phosphor
