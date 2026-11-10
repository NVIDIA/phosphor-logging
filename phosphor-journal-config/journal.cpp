// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// All rights reserved.
#include "config.h"

#include "journal.hpp"

#include "conf.hpp"
#include "xyz/openbmc_project/Common/error.hpp"

#include <boost/system/error_code.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/redfish_event_log.hpp>

#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>

namespace phosphor
{
namespace journal_config
{

using namespace phosphor::logging;
using namespace sdbusplus::error::xyz::openbmc_project::common;
using Entry = sdbusplus::xyz::openbmc_project::Logging::server::Entry;

namespace
{

constexpr auto journaldUnit = "systemd-journald.service";

void onRestartUnit(const boost::system::error_code& restartEc)
{
    if (restartEc)
    {
        log<level::ERR>("RestartUnit(systemd-journald) failed",
                        entry("ERROR=%s", restartEc.message().c_str()));
    }
}

void onResetFailedUnit(const std::shared_ptr<sdbusplus::asio::connection>& conn,
                       const boost::system::error_code& ec)
{
    if (ec)
    {
        log<level::WARNING>("ResetFailedUnit(systemd-journald) failed",
                            entry("ERROR=%s", ec.message().c_str()));
    }
    conn->async_method_call(onRestartUnit, SYSTEMD_BUSNAME, SYSTEMD_PATH,
                            SYSTEMD_INTERFACE, "RestartUnit", journaldUnit,
                            "replace");
}

} // namespace

JournalConfig::JournalConfig(
    sdbusplus::bus_t& bus, const char* path,
    std::shared_ptr<sdbusplus::asio::connection> busConn,
    std::string_view override, std::string_view packaged) :
    JournalIface(bus, path, JournalIface::action::defer_emit),
    conn(std::move(busConn)), overrideFile(override), packagedFile(packaged)
{
    auto journaldLevel = readMaxLevelStore(overrideFile);
    if (!journaldLevel)
    {
        journaldLevel = readMaxLevelStore(packagedFile);
        if (!journaldLevel)
        {
            throw std::runtime_error(
                "Packaged journald policy has no named MaxLevelStore");
        }
    }
    auto entryLevel = maxLevelStoreToEntryLevel(*journaldLevel);
    if (!entryLevel)
    {
        log<level::ERR>("Unmapped packaged MaxLevelStore",
                        entry("PATH=%s", packagedFile.c_str()),
                        entry("VALUE=%s", journaldLevel->c_str()));
        throw std::runtime_error("Unmapped packaged MaxLevelStore");
    }

    JournalIface::lowestSeverity(*entryLevel);
    emit_object_added();
}

Level JournalConfig::lowestSeverity(Level value)
{
    std::error_code ec;
    // Skip write when the override exists and LowestSeverity is
    // unchanged. That assumes this daemon wrote the file (valid named
    // token). A hand-edited or leftover file is unsupported and is
    // not repaired.
    if (std::filesystem::exists(overrideFile, ec) &&
        JournalIface::lowestSeverity() == value)
    {
        return value;
    }
    auto maxLevelStore = entryLevelToMaxLevelStore(value);
    if (!maxLevelStore)
    {
        log<level::ERR>("Unmapped Entry.Level for journald MaxLevelStore",
                        entry("PATH=%s", overrideFile.c_str()),
                        entry("LEVEL=%d", static_cast<int>(value)));
        elog<InternalFailure>();
    }

    if (!writeMaxLevelStore(overrideFile, *maxLevelStore))
    {
        log<level::ERR>("Failed to write journald MaxLevelStore override",
                        entry("PATH=%s", overrideFile.c_str()));
        elog<InternalFailure>();
    }

    auto result = JournalIface::lowestSeverity(value);
    restartJournald();
    sendLowestSeverityModified(value);
    return result;
}

void JournalConfig::restartJournald()
{
    conn->async_method_call(
        [this](const boost::system::error_code& ec) {
            onResetFailedUnit(conn, ec);
        },
        SYSTEMD_BUSNAME, SYSTEMD_PATH, SYSTEMD_INTERFACE, "ResetFailedUnit",
        journaldUnit);
}

void JournalConfig::sendLowestSeverityModified(Level value)
{
    auto entryLevel = Entry::convertLevelToString(value);
    log<level::INFO>("Journal LowestSeverity property modified",
                     entry("PATH=%s", BUSPATH_JOURNAL_CONFIG),
                     entry("PROPERTY=%s", "LowestSeverity"),
                     entry("VALUE=%s", entryLevel.c_str()));
    sendEvent(conn, MESSAGE_TYPE::PROPERTY_VALUE_MODIFIED,
              Entry::Level::Informational, {"LowestSeverity", entryLevel},
              BUSPATH_JOURNAL_CONFIG);
}

} // namespace journal_config
} // namespace phosphor
