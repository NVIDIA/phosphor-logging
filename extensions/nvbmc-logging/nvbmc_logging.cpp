
#include "extensions.hpp"

#include <phosphor-logging/lg2.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace nvidia
{
namespace logging
{

using namespace phosphor::logging;

const constexpr char* BOOTENTRYID_FILE = "/run/bootentryid";

void nvlogStartup(internal::Manager& logManager)
{
    // Skip if the BootEntryId file already exists. Only happen on
    // phosphor-loggin restart.
    std::error_code ec;
    if (std::filesystem::exists(BOOTENTRYID_FILE, ec))
    {
        lg2::debug("File {FILE} exists. Skip.", "FILE", BOOTENTRYID_FILE);
        return;
    }

    lg2::debug("An error occurred: {EC}", "EC", ec.message());

    std::map<std::string, std::string> additionalData;
    lg2::error("Creating BMC boot up log.");
    logManager.create("BMC Boot", Severity::Informational, additionalData);

    // This LastEntryId is the BootEntryId
    auto bootEntryId = logManager.lastEntryID();

    lg2::error("The BootEntryId is {ID}.", "ID", bootEntryId);

    // Create the BootEntryId file and store the id in it in text format.
    std::ofstream fp(BOOTENTRYID_FILE, std::ios_base::app);

    if (!fp.is_open())
    {
        lg2::error("Couldn't open/create file {FILE}.", "FILE",
                   BOOTENTRYID_FILE);
        return;
    }

    fp << std::to_string(bootEntryId);
    fp.close();
    return;
}
REGISTER_EXTENSION_FUNCTION(nvlogStartup)
} // namespace logging
} // namespace nvidia
