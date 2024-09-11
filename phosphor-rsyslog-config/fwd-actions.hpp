#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Logging/RsyslogFwd/server.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>

#include <string>

namespace phosphor
{
namespace rsyslog_config
{
class Conf;

using RsyslogFwd = sdbusplus::xyz::openbmc_project::Logging::server::RsyslogFwd;
using DeleteInt = sdbusplus::xyz::openbmc_project::Object::server::Delete;
using RsyslogFwdActionInherit =
    sdbusplus::server::object::object<RsyslogFwd, DeleteInt>;

/** @class FwdActions
 *  @brief Configuration for a rsyslog forward action
 *  @details A concrete implementation of the
 *  xyz.openbmc_project.Logging.RsyslogFwd API, in order to
 *  provide a fwd action.
 */
class RsyslogFwdAction : public RsyslogFwdActionInherit
{
  public:
    /** @brief Constructor
     *
     * @param[in] bus - Bus to attach to
     * @param[in] objPath - D-Bus object path
     */
    RsyslogFwdAction(sdbusplus::bus::bus& bus, const std::string& objPath,
                     size_t index, RsyslogFwd::LogType logType, bool enabled,
                     RsyslogFwd::TransportProtocol transportProtocol,
                     RsyslogFwd::NetworkProtocol networkProtocol,
                     const std::string& address, uint16_t port, Conf* parent) :
        RsyslogFwdActionInherit(
            bus, objPath.c_str(),
            RsyslogFwdActionInherit::action::emit_interface_added),
        bus(bus), parent(parent)
    {
        /* Modify without overriding conf files */
        RsyslogFwd::index(index);
        RsyslogFwd::logType(logType);
        RsyslogFwd::enabled(enabled);
        RsyslogFwd::transportProtocol(transportProtocol);
        RsyslogFwd::networkProtocol(networkProtocol);
        RsyslogFwd::address(address);
        RsyslogFwd::port(port);
    }

    void delete_() override;

    bool enabled(bool value) override;
    bool enabled() const override
    {
        return RsyslogFwd::enabled();
    }

    RsyslogFwd::TransportProtocol
        transportProtocol(RsyslogFwd::TransportProtocol value) override;
    RsyslogFwd::TransportProtocol transportProtocol() const override
    {
        return RsyslogFwd::transportProtocol();
    }

    RsyslogFwd::NetworkProtocol
        networkProtocol(RsyslogFwd::NetworkProtocol value) override;
    RsyslogFwd::NetworkProtocol networkProtocol() const override
    {
        return RsyslogFwd::networkProtocol();
    }

    std::string address(std::string value) override;
    std::string address() const override
    {
        return RsyslogFwd::address();
    }

    uint16_t port(uint16_t value) override;
    uint16_t port() const override
    {
        return RsyslogFwd::port();
    }

  private:
    sdbusplus::bus_t& bus;
    Conf* parent;
};

} // namespace rsyslog_config
} // namespace phosphor
