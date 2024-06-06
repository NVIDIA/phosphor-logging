#include "config.h"

#include "bin.hpp"
#include "config_main.h"

#include "extensions.hpp"
#include "log_manager.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>

#include <filesystem>

int main(int argc, char* argv[])
{
    PHOSPHOR_LOG2_USING_WITH_FLAGS;

    auto bus = sdbusplus::bus::new_default();
    auto event = sdeventplus::Event::get_default();
    bus.attach_event(event.get(), SD_EVENT_PRIORITY_NORMAL);

    // Add sdbusplus ObjectManager for the 'root' path of the logging manager.
    sdbusplus::server::manager_t objManager(bus, OBJ_LOGGING);

    phosphor::logging::internal::Manager iMgr(bus, OBJ_INTERNAL);
    phosphor::logging::Manager mgr(bus, OBJ_LOGGING, iMgr);

    auto parseErrHandler = [argv] (std::function<uint32_t(const std::string&)> const& fn, const char* path)
    {
        int res = 0;
        try
        {
            res = fn(path);
        }
        catch (const std::exception& e)
        {
            lg2::info("Unable to parse argument. JSON file {FILE} ignored: {ERROR}",
                      "FILE", path, "ERROR", e);
        }

        if (res)
        {
            lg2::info("Unable to parse argument. JSON file {FILE} ignored.",
                      "FILE", path);
        }
    };

    if (argc == 2)
    {
        parseErrHandler([&iMgr] (auto path) {return iMgr.parseJson(path);}, argv[1]);
        parseErrHandler([&iMgr] (auto path) {return iMgr.parseRWConfigJson(path);}, RW_CONFIG_FILE_PATH);
    }

    // Restore all errors
    iMgr.restore();

    for (auto& startup : phosphor::logging::Extensions::getStartupFunctions())
    {
        try
        {
            startup(iMgr);
        }
        catch (const std::exception& e)
        {
            error("An extension's startup function threw an exception: "
                  "{ERROR}",
                  "ERROR", e);
        }
    }

    try
    {
        bus.request_name(BUSNAME_LOGGING);
    }
    catch (const sdbusplus::exception::SdBusError& e){
        error("Unable to request bus name: "
              "{ERROR}",
              "ERROR", e);
    }
#ifdef ENABLE_LOG_STREAMING
    if (!iMgr.startLogSocket())
    {
        lg2::error("Failed to start SEL Socket");
    }
#endif
    return event.loop();
}
