// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// All rights reserved.
#pragma once

#include "conf.hpp"
#include "xyz/openbmc_project/Logging/Entry/server.hpp"
#include "xyz/openbmc_project/Logging/Journal/server.hpp"

#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

#include <memory>
#include <string>
#include <string_view>

namespace phosphor
{
namespace journal_config
{

using JournalIface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Logging::server::Journal>;

/** @class JournalConfig
 *  @brief Owns D-Bus LowestSeverity, the journald MaxLevelStore override,
 *         and journald apply.
 *
 *  The override is created on the first successful Set, even if the
 *  value matches packaged policy. Until then GET uses packaged policy.
 */
class JournalConfig : public JournalIface
{
  public:
    JournalConfig() = delete;
    JournalConfig(const JournalConfig&) = delete;
    JournalConfig& operator=(const JournalConfig&) = delete;
    JournalConfig(JournalConfig&&) = delete;
    JournalConfig& operator=(JournalConfig&&) = delete;
    ~JournalConfig() override = default;

    JournalConfig(std::shared_ptr<sdbusplus::asio::connection> conn,
                  const char* path) : JournalConfig(*conn, path, conn)
    {}

    JournalConfig(sdbusplus::bus_t& bus, const char* path,
                  std::shared_ptr<sdbusplus::asio::connection> conn,
                  std::string_view overrideFile = overridePath,
                  std::string_view packagedFile = packagedPath);

    using JournalIface::lowestSeverity;

    /** @brief Persist MaxLevelStore and apply it to journald.
     *  First Set always writes the override, even when it matches the
     *  D-Bus property. Later Sets skip if the property is unchanged.
     */
    Level lowestSeverity(Level value) override;

  protected:
    /** @brief Restart systemd-journald so MaxLevelStore takes effect.
     *
     *  RestartUnit: journald reads drop-ins only at start, so the override
     *  is not applied until journald is restarted.
     *  ResetFailedUnit: rapid LowestSeverity Sets can trip systemd's
     *  start-limit on journald, and then RestartUnit is refused. Reset
     *  clears that limit.
     *  Async: do not block the daemon on systemd.
     */
    virtual void restartJournald();
    virtual void sendLowestSeverityModified(Level value);

  private:
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::string overrideFile;
    std::string packagedFile;
};

} // namespace journal_config
} // namespace phosphor
