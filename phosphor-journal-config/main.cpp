// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// All rights reserved.
#include "config.h"

#include "journal.hpp"

#include <boost/asio/io_context.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/server/manager.hpp>

#include <exception>
#include <memory>

int main(int /*argc*/, char* /*argv*/[])
{
    using namespace phosphor::logging;

    boost::asio::io_context io;
    auto conn = std::make_shared<sdbusplus::asio::connection>(io);
    sdbusplus::server::manager_t objManager(*conn, BUSPATH_JOURNAL_CONFIG);

    std::unique_ptr<phosphor::journal_config::JournalConfig> journalConfig;
    try
    {
        journalConfig =
            std::make_unique<phosphor::journal_config::JournalConfig>(
                conn, BUSPATH_JOURNAL_CONFIG);
    }
    catch (const std::exception& e)
    {
        log<level::ERR>("Failed to initialize journal config",
                        entry("ERROR=%s", e.what()));
        return 1;
    }

    conn->request_name(BUSNAME_JOURNAL_CONFIG);
    io.run();

    return 0;
}
