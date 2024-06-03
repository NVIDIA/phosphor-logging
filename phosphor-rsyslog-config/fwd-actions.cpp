#include <xyz/openbmc_project/Common/error.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/log.hpp>

#include "conf.hpp"
#include "utils.hpp"

namespace phosphor
{
namespace rsyslog_config
{
using namespace phosphor::logging;

void RsyslogFwdAction::delete_()
{
    size_t objIndex = index();
    RsyslogFwdAction::LogType objLogType = logType();

    parent->removeRsyslogFwd(objIndex, objLogType);
    if (parent->overrideConfigFile(objLogType))
    {
        rsyslog_utils::restart();
    }
}

bool RsyslogFwdAction::enabled(bool value)
{
    auto ret = RsyslogFwd::enabled(value);
    if (parent->overrideConfigFile(logType()))
    {
        rsyslog_utils::restart();
    }
    return ret;
}

RsyslogFwd::TransportProtocol RsyslogFwdAction::transportProtocol(
                                        RsyslogFwd::TransportProtocol value)
{
    auto ret = RsyslogFwd::transportProtocol(value);
    if (parent->overrideConfigFile(logType()))
    {
        rsyslog_utils::restart();
    }
    return ret;
}

RsyslogFwd::NetworkProtocol RsyslogFwdAction::networkProtocol(
                                        RsyslogFwd::NetworkProtocol value)
{
    auto ret = RsyslogFwd::networkProtocol(value);
    if (parent->overrideConfigFile(logType()))
    {
        rsyslog_utils::restart();
    }
    return ret;
}

std::string RsyslogFwdAction::address(std::string value)
{
    auto ret = RsyslogFwd::address(value);
    if (parent->overrideConfigFile(logType()))
    {
        rsyslog_utils::restart();
    }
    return ret;
}

uint16_t RsyslogFwdAction::port(uint16_t value)
{
    auto ret = RsyslogFwd::port(value);
    if (parent->overrideConfigFile(logType()))
    {
        rsyslog_utils::restart();
    }
    return ret;
}

} // namespace rsyslog_config
} // namespace phosphor