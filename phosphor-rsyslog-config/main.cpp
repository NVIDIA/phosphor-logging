#include "config.h"

#include "config_main.h"

#include "server-conf.hpp"

#include <sdbusplus/bus.hpp>

#ifdef ENABLE_RSYSLOG_FWD_ACTIONS_CONF
#include "conf.hpp"

#include <sdbusplus/server/manager.hpp>
#endif

int main(int /*argc*/, char* /*argv*/[])
{
    auto bus = sdbusplus::bus::new_default();

#ifdef ENABLE_RSYSLOG_FWD_ACTIONS_CONF
    sdbusplus::server::manager_t objManager(bus, BUSPATH_LOGGING_CONFIG);
    phosphor::rsyslog_config::Conf Conf(bus, BUSPATH_LOGGING_CONFIG);
#endif

    phosphor::rsyslog_config::Server serverConf(
        bus, BUSPATH_REMOTE_LOGGING_CONFIG, RSYSLOG_SERVER_CONFIG_FILE);

    bus.request_name(BUSNAME_SYSLOG_CONFIG);

    while (true)
    {
        bus.process_discard();
        bus.wait();
    }

    return 0;
}
