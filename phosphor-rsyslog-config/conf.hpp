#pragma once

#include <xyz/openbmc_project/Logging/RsyslogActionsManager/server.hpp>
#include <sdbusplus/server/object.hpp>
#include <sdbusplus/bus.hpp>
#include <string>

#include "fwd-actions.hpp"

namespace phosphor
{
namespace rsyslog_config
{
using RsyslogActionsManager = sdbusplus::xyz::openbmc_project::Logging::server::RsyslogActionsManager;
using ConfInherit = sdbusplus::server::object_t<RsyslogActionsManager>;

/** @class Conf
 *  @brief Configuration for rsyslog
 *  @details A concrete implementation of the
 *  xyz.openbmc_project.Logging.RsyslogActionsManager,
 *  in order to provide fwd actions.
 */
class Conf : public ConfInherit
{
  public:
    Conf() = delete;
    Conf(const Conf&) = delete;
    Conf& operator=(const Conf&) = delete;
    Conf(Conf&&) = delete;
    Conf& operator=(Conf&&) = delete;
    virtual ~Conf() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Conf(sdbusplus::bus_t& bus, const std::string& path) :
          ConfInherit(bus, path.c_str()), bus(bus)
    {
        emit_object_added();
        createObjectsFromConfigFiles();
    }

    /**
     * @brief Creates a new RsyslogFwd object fwd_<LogType>_<Index>
     * representing an rsyslog fwd action. The index, which is used
     * as the object identifier within fwd_<LogType>, is received as an
     * argument and must be a legal value from 0 to 9.
     *
     * @param[in] Index - The index of the new action. Limited to 9.
     * @param[in] LogType - The log type of the new action.
     * @param[in] Enabled - The new fwd action is enabled/disabled.
     * @param[in] TransportProtocol - The transport protocol of the
     *                                new fwd action.
     * @param[in] NetworkProtocol - The network protocol of the
     *                              new fwd action.
     * @param[in] Address - The IP address used by the new fwd action
     *                      in IPv4 or IPv6 format.
     * @param[in] Port - The port number which is used for the transport.
     **/

    void createRsyslogFwdIndex(size_t index,
                               RsyslogFwd::LogType logType,
                               bool enabled,
                               RsyslogFwd::TransportProtocol transportProtocol,
                               RsyslogFwd::NetworkProtocol networkProtocol,
                               std::string address,
                               uint16_t port) override;

    /**
     * @brief Creates a new RsyslogFwd object fwd_<LogType>_<Index>
     * representing an rsyslog fwd action.
     *
     * @param[in] LogType - The log type of the new action.
     * @param[in] Enabled - The new fwd action is enabled/disabled.
     * @param[in] TransportProtocol - The transport protocol of the
     *                                new fwd action.
     * @param[in] NetworkProtocol - The network protocol of the
     *                              new fwd action.
     * @param[in] Address - The IP address used by the new fwd action
     *                      in IPv4 or IPv6 format.
     * @param[in] Port - The port number which is used for the transport.
     * @returns index which is used as the object identifier within fwd_<LogType>.
     * The function set the index to the first available value from 0 to 9.
     **/

    size_t createRsyslogFwd(RsyslogFwd::LogType logType,
                            bool enabled,
                            RsyslogFwd::TransportProtocol transportProtocol,
                            RsyslogFwd::NetworkProtocol networkProtocol,
                            std::string address,
                            uint16_t port) override;

    /** @brief Removes a RsyslogFwd object.
     *  @param[in] Index - The index of the action.
     *  @param[in] LogType - The log type of the action.
     */
    void removeRsyslogFwd(size_t index, RsyslogFwd::LogType logType);

    /** @brief Overrides the given LogType conf file, fwd_<logType>.conf,
     *  with the current configuration of the LogType actions.
     *  @param[in] LogType - Log type.
     *  @returns true for success, otherwise false.
     */
    bool overrideConfigFile(RsyslogFwd::LogType logType);

  private:
    /** @brief Checks if action exists by checking existing objects.
     *  @param[in] Index - The index of the action.
     *  @param[in] LogType - The log type of the action.
     *  @returns true in case action exists, otherwise false.
     */
    bool actionExists(size_t index, RsyslogFwd::LogType logType);

    /**
     * @brief An internal function to add a new RsyslogFwd object.
     *
     * @param[in] Index - The index of the new action. Limited to 9.
     * @param[in] LogType - The log type of the new action.
     * @param[in] Enabled - The new fwd action is enabled/disabled.
     * @param[in] TransportProtocol - The transport protocol of the
     *                                new fwd action.
     * @param[in] NetworkProtocol - The network protocol of the
     *                              new fwd action.
     * @param[in] Address - The IP address used by the new fwd action
     *                      in IPv4 or IPv6 format.
     * @param[in] Port - The port number which is used for the transport.
     * @returns true for success, otherwise false.
     **/
    bool addRsyslogFwdObject(size_t index,
                            RsyslogFwd::LogType logType,
                            bool enabled,
                            RsyslogFwd::TransportProtocol transportProtocol,
                            RsyslogFwd::NetworkProtocol networkProtocol,
                            std::string address,
                            uint16_t port);

    /** @brief Generates RsyslogFwd objects according to the conf files.
     *  @returns true for success, otherwise false.
     */
    bool createObjectsFromConfigFiles();

    sdbusplus::bus_t& bus;
    std::vector<std::unique_ptr<RsyslogFwdAction>> fwdActions;
};

} // namespace rsyslog_config
} // namespace phosphor