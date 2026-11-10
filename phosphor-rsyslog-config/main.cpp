#include "config.h"

#include "config_main.h"

#include "conf.hpp"
#include "constants.hpp"
#include "server-conf.hpp"
#include "utils.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

#include <cstdlib>

int main(int /*argc*/, char* /*argv*/[])
try
{
    auto bus = sdbusplus::bus::new_default();

    // A config saved by an older image may name the GnuTLS driver, which
    // isn't built any more; switch it to OpenSSL. Restart rsyslog only if
    // it loads that line, so TLS forwarding works again.
    using phosphor::rsyslog_config::internal::TlsMigration;
    const auto migration = phosphor::rsyslog_config::internal::migrateTlsDriver(
        RSYSLOG_SERVER_CONFIG_FILE);
    if (migration != TlsMigration::unchanged)
    {
        lg2::info("Switched rsyslog TLS driver from gtls to ossl");
    }
    if (migration == TlsMigration::active)
    {
        try
        {
            phosphor::rsyslog_utils::restart();
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to restart rsyslog after TLS driver change: "
                       "{ERR}",
                       "ERR", e.what());
        }
    }

    sdbusplus::server::manager_t objManager(bus, BUSPATH_LOGGING_CONFIG);
    phosphor::rsyslog_config::Conf Conf(bus, BUSPATH_LOGGING_CONFIG);

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
