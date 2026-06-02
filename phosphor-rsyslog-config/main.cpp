#include "config.h"

#include "server-conf.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>

#include <cstdlib>

#ifdef ENABLE_RSYSLOG_FWD_ACTIONS_CONF
#include "conf.hpp"

#include <sdbusplus/server/manager.hpp>
#endif

int main(int /*argc*/, char* /*argv*/[])
try
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
catch (const std::exception& e)
{
    lg2::error("phosphor-rsyslog-config: unhandled exception: {ERR}", "ERR",
               e.what());
    return EXIT_FAILURE;
}
catch (...)
{
    lg2::error("phosphor-rsyslog-config: unknown unhandled exception");
    return EXIT_FAILURE;
}
