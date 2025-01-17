#include "config.h"

#include "log_manager.hpp"

#include "elog_entry.hpp"
#include "elog_meta.hpp"
#include "elog_serialize.hpp"
#include "extensions.hpp"
#include "util.hpp"

#include <systemd/sd-bus.h>
#include <systemd/sd-journal.h>
#include <unistd.h>

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/vtable.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/State/Host/server.hpp>

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace std::chrono;
extern const std::map<
    phosphor::logging::metadata::Metadata,
    std::function<phosphor::logging::metadata::associations::Type>>
    meta;

constexpr auto FQPN_PREFIX = "xyz.openbmc_project.Logging.Entry.";
constexpr auto FQPN_DELIM = "=";

static constexpr auto mapperBusName = "xyz.openbmc_project.ObjectMapper";
static constexpr auto mapperObjPath = "/xyz/openbmc_project/object_mapper";
static constexpr auto mapperIntf = "xyz.openbmc_project.ObjectMapper";
constexpr auto dbusProperty = "org.freedesktop.DBus.Properties";
constexpr auto policyInterface = "xyz.openbmc_project.Logging.Settings";
constexpr auto policyLinear =
    "xyz.openbmc_project.Logging.Settings.Policy.Linear";
constexpr auto policyDefault =
    "xyz.openbmc_project.Logging.Settings.Policy.Circular";

using DBusInterface = std::string;
using DBusService = std::string;
using DBusPath = std::string;
using DBusInterfaceList = std::vector<DBusInterface>;
using DBusSubTree =
    std::map<DBusPath, std::map<DBusService, DBusInterfaceList>>;

namespace phosphor
{
namespace logging
{
namespace internal
{
inline auto getLevel(const std::string& errMsg)
{
    auto reqLevel = Entry::Level::Error; // Default to Error

    auto levelmap = g_errLevelMap.find(errMsg);
    if (levelmap != g_errLevelMap.end())
    {
        reqLevel = static_cast<Entry::Level>(levelmap->second);
    }

    return reqLevel;
}

/**
 * @brief Construct a new Manager:: Manager object
 *
 * @param bus
 * @param objPath
 */
Manager::Manager(sdbusplus::bus::bus& bus, const std::string& objPath) :
    details::ServerObject<details::ManagerIface>(bus, objPath.c_str()),
    busLog(bus), entryId(0), lastCreatedTimeStamp(0),
    fwVersion(readFWVersion()),
    defaultBin(DEFAULT_BIN_NAME, ERROR_CAP, ERROR_INFO_CAP, ERRLOG_PERSIST_PATH,
               true),
#ifdef ENABLE_LOG_STREAMING
    logSocket(LOG_STREAMER_SOCKET_PATH),
#endif
    _autoPurgeResolved(LOG_PURGE_POLICY_DEFAULT),
    _autoPurgeEventSource(
        sdeventplus::Event::get_default(),
        sdeventplus::Clock<sdeventplus::ClockId::Monotonic>(
            sdeventplus::Event::get_default())
            .now(),
        std::chrono::seconds{0},
        std::bind(std::mem_fn(&Manager::pendingLogDeleteCallback), this))
{
    this->addBin(this->defaultBin);
    this->_autoPurgeEventSource.set_enabled(sdeventplus::source::Enabled::Off);
}

int Manager::getRealErrSize(const std::string& binName)
{
    return binNameMap[binName].errorEntries.size();
}

int Manager::getInfoErrSize(const std::string& binName)
{
    return binNameMap[binName].infoEntries.size();
}

bool Manager::getAutoPurgeResolved()
{
    // lg2::debug("getting property, value is {VAL}", "VAL",
    // this->_autoPurgeResolved);
    return this->_autoPurgeResolved;
}

void Manager::setAutoPurgeResolved(bool confPurgeResolvedLogs)
{
    lg2::info("setting property, current value: {CURR}, set value: {NEW}",
              "CURR", this->_autoPurgeResolved, "NEW", confPurgeResolvedLogs);
    // If enabling log purge policy, mark existing resolved logs for deletion.
    // If disabling, cancel any pending deletion operation
    if (!this->_autoPurgeResolved && confPurgeResolvedLogs)
    {
        lg2::info("start scan for resolved entries");
        size_t resolvedCount = 0;
        auto iter = this->entries.begin();
        while (iter != this->entries.end())
        {
            if (iter->second->resolved())
            {
                this->addPendingLogDelete(iter->second->id());
                resolvedCount++;
            }
            ++iter;
        }
        lg2::info("finish scan for resolved entries, {COUNT} will be resolved"
                  " in the background",
                  "COUNT", resolvedCount);
    }
    else if (this->_autoPurgeResolved && !confPurgeResolvedLogs)
    {
        this->cancelPendingLogDeletion();
    }
    this->_autoPurgeResolved = confPurgeResolvedLogs;
    this->updateRWConfigJson();
}

void Manager::addPendingLogDelete(uint32_t entryId)
{
    this->_pendingPurgeEvents.push_back(entryId);
    this->_autoPurgeEventSource.set_enabled(sdeventplus::source::Enabled::On);
}

void Manager::pendingLogDeleteCallback()
{
    // Delete one event, then yield back to the event loop
    // Use vector and delete from the back instead of using a set
    // because this is O(n) overall instead of O(n log n)
    // This LIFO behavior is also needed to satisfy the usecase of
    // a log being manually resolved - that needs to be handled first.
    // lg2::debug("pendingLogDeleteCallback");
    if (this->_pendingPurgeEvents.size() > 0)
    {
        // This is guaranteed to not run off the beginning because size > 0
        auto it = this->_pendingPurgeEvents.end() - 1;
        auto entryId = *it;
        // lg2::info("pendingLogDeleteCallback: delete {EID}", "EID", entryId);
        this->erase(entryId);
        this->_pendingPurgeEvents.erase(it);
    }
    if (this->_pendingPurgeEvents.size() == 0)
    {
        // Deactivate event source iff no more pending deletes
        lg2::info("pendingLogDeleteCallback: deactivate event source");
        this->_autoPurgeEventSource.set_enabled(
            sdeventplus::source::Enabled::Off);
    }
}

void Manager::cancelPendingLogDeletion()
{
    lg2::info("cancelPendingLogDeletion: cancelled {COUNT} pending deletions",
              "COUNT", this->_pendingPurgeEvents.size());
    this->_pendingPurgeEvents.clear();
    this->_autoPurgeEventSource.set_enabled(sdeventplus::source::Enabled::Off);
}

uint32_t Manager::commit(uint64_t transactionId, std::string errMsg)
{
    auto level = getLevel(errMsg);
    _commit(transactionId, std::move(errMsg), level);
    return entryId;
}

uint32_t Manager::commitWithLvl(uint64_t transactionId, std::string errMsg,
                                uint32_t errLvl)
{
    _commit(transactionId, std::move(errMsg),
            static_cast<Entry::Level>(errLvl));
    return entryId;
}

void Manager::_commit(uint64_t transactionId [[maybe_unused]],
                      std::string&& errMsg, Entry::Level errLvl)
{
    std::vector<std::string> additionalData{};

    // When running as a test-case, the system may have a LOT of journal
    // data and we may not have permissions to do some of the journal sync
    // operations.  Just skip over them.
    if (!IS_UNIT_TEST)
    {
        static constexpr auto transactionIdVar =
            std::string_view{"TRANSACTION_ID"};
        // Length of 'TRANSACTION_ID' string.
        static constexpr auto transactionIdVarSize = transactionIdVar.size();
        // Length of 'TRANSACTION_ID=' string.
        static constexpr auto transactionIdVarOffset = transactionIdVarSize + 1;

        // Flush all the pending log messages into the journal
        util::journalSync();

        sd_journal* j = nullptr;
        int rc = sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY);
        if (rc < 0)
        {
            lg2::error("Failed to open journal: {ERROR}", "ERROR",
                       strerror(-rc));
            return;
        }

        std::string transactionIdStr = std::to_string(transactionId);
        std::set<std::string> metalist;
        auto metamap = g_errMetaMap.find(errMsg);
        if (metamap != g_errMetaMap.end())
        {
            metalist.insert(metamap->second.begin(), metamap->second.end());
        }

        // Add _PID field information in AdditionalData.
        metalist.insert("_PID");

        // Read the journal from the end to get the most recent entry first.
        // The result from the sd_journal_get_data() is of the form
        // VARIABLE=value.
        SD_JOURNAL_FOREACH_BACKWARDS(j)
        {
            const char* data = nullptr;
            size_t length = 0;

            // Look for the transaction id metadata variable
            rc = sd_journal_get_data(j, transactionIdVar.data(),
                                     (const void**)&data, &length);
            if (rc < 0)
            {
                // This journal entry does not have the TRANSACTION_ID
                // metadata variable.
                continue;
            }

            // journald does not guarantee that sd_journal_get_data() returns
            // NULL terminated strings, so need to specify the size to use to
            // compare, use the returned length instead of anything that relies
            // on NULL terminators like strlen(). The data variable is in the
            // form of 'TRANSACTION_ID=1234'. Remove the TRANSACTION_ID
            // characters plus the (=) sign to do the comparison. 'data +
            // transactionIdVarOffset' will be in the form of '1234'. 'length -
            // transactionIdVarOffset' will be the length of '1234'.
            if ((length <= (transactionIdVarOffset)) ||
                (transactionIdStr.compare(
                     0, transactionIdStr.size(), data + transactionIdVarOffset,
                     length - transactionIdVarOffset) != 0))
            {
                // The value of the TRANSACTION_ID metadata is not the requested
                // transaction id number.
                continue;
            }

            // Search for all metadata variables in the current journal entry.
            for (auto i = metalist.cbegin(); i != metalist.cend();)
            {
                rc = sd_journal_get_data(j, (*i).c_str(), (const void**)&data,
                                         &length);
                if (rc < 0)
                {
                    // Metadata variable not found, check next metadata
                    // variable.
                    i++;
                    continue;
                }

                // Metadata variable found, save it and remove it from the set.
                additionalData.emplace_back(data, length);
                i = metalist.erase(i);
            }
            if (metalist.empty())
            {
                // All metadata variables found, break out of journal loop.
                break;
            }
        }
        if (!metalist.empty())
        {
            // Not all the metadata variables were found in the journal.
            for (auto& metaVarStr : metalist)
            {
                lg2::info("Failed to find metadata: {META_FIELD}", "META_FIELD",
                          metaVarStr);
            }
        }

        sd_journal_close(j);
    }
    createEntry(errMsg, errLvl, additionalData);
}

void callFQPNsMethods(
    const std::vector<std::string>& fqpns, const std::unique_ptr<Entry>& entry,
    const std::map<std::string,
                   const std::function<std::string(Entry&, std::string&)>>&
        fnMap)
{
    auto* e = entry.get();

    for (const auto& s : fqpns)
    {
        auto key = s.substr(0, s.find(FQPN_DELIM));
        auto val = s.substr(s.find(FQPN_DELIM) + 1, s.length());
        auto it = fnMap.find(key);
        if (it != fnMap.end())
        {
            (it->second)(*e, val);
        }
    }
}

std::string Manager::getSelPolicy()
{
    if (IS_UNIT_TEST)
    {
        return policyDefault;
    }

    DBusSubTree subtree;

    auto method = this->busLog.new_method_call(mapperBusName, mapperObjPath,
                                               mapperIntf, "GetSubTree");
    method.append(std::string{"/"}, 0,
                  std::vector<std::string>{policyInterface});
    auto reply = this->busLog.call(method);
    reply.read(subtree);

    if (subtree.empty())
    {
        lg2::info("Compatible interface not on D-Bus. Continuing with default "
                  "Circular Policy");
        return policyDefault;
    }

    const auto& object = *(subtree.begin());
    const auto& policyPath = object.first;
    const auto& policyService = object.second.begin()->first;

    std::variant<std::string> property;
    method = this->busLog.new_method_call(
        policyService.c_str(), policyPath.c_str(), dbusProperty, "Get");
    method.append(policyInterface, "SelPolicy");

    try
    {
        auto reply = this->busLog.call(method);
        reply.read(property);
    }
    catch (...)
    {
        lg2::error("Error reading SelPolicy  property. Continuing with default "
                   "Circular Policy");
        return policyDefault;
    }

    return std::get<std::string>(property);
}

void Manager::createEntry(std::string errMsg, Entry::Level errLvl,
                          std::vector<std::string> additionalData,
                          const FFDCEntries& ffdc)
{
    // For the incoming entry, find the bin associated with the entry
    // Set entryBinName as default
    std::string entryBinName = DEFAULT_BIN_NAME;
    Bin* entryBin = &(binNameMap[entryBinName]);

    constexpr auto separator = '=';
    for (const auto& entryItem : additionalData)
    {
        auto found = entryItem.find(separator);
        if (std::string::npos != found)
        {
            auto key = entryItem.substr(0, found);
            auto val = entryItem.substr(found + 1, entryItem.size());
            // If key name matches and the val is a an existing bin
            if ((key == DEFAULT_BIN_KEY) &&
                (binNameMap.find(val) != binNameMap.end()))
            {
                entryBinName = val;
                entryBin = &(binNameMap[val]);
            }
        }
    }

    // lg2::info("Bin of Incoming Entry: {BIN_NAME}", "BIN_NAME", entryBinName);

    // Corresponding to the bin found, use capacity limits
    if (!Extensions::disableDefaultLogCaps())
    {
        std::string currentPolicy = getSelPolicy();
        if (currentPolicy == policyLinear)
        {
            if (errLvl < Entry::sevLowerLimit)
            {
                if (entryBin->errorEntries.size() >= entryBin->errorCap)
                {
                    lg2::info("Error Capacity limit reached: {BIN_NAME}",
                              "BIN_NAME", entryBinName);
                    return;
                }
            }
            else
            {
                if (entryBin->infoEntries.size() >= entryBin->errorInfoCap)
                {
                    lg2::info(
                        "Information Error Capacity limit reached: {BIN_NAME}",
                        "BIN_NAME", entryBinName);
                    return;
                }
            }
        }
        else
        {
            if (errLvl < Entry::sevLowerLimit)
            {
                if (entryBin->errorEntries.size() >= entryBin->errorCap)
                {
                    erase(*(entryBin->errorEntries.begin()));
                }
            }
            else
            {
                if (entryBin->infoEntries.size() >= entryBin->errorInfoCap)
                {
                    erase(*(entryBin->infoEntries.begin()));
                }
            }
        }
    }

    entryId++;
    if ((entryBinName.compare("SEL") == 0) &&
        (entryId >= std::numeric_limits<uint16_t>::max()))
    {
        // The SEL ID should be from 0x1 to 0xfffe
        entryId = entryId % std::numeric_limits<uint16_t>::max() + 1;
    }
    if (errLvl >= Entry::sevLowerLimit)
    {
        entryBin->infoEntries.insert(entryId);
    }
    else
    {
        entryBin->errorEntries.insert(entryId);
    }

    // Insert Entry into binEntryMap to track which Bin this entry went into
    binEntryMap.insert(std::make_pair(entryId, entryBinName));

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::system_clock::now().time_since_epoch())
                  .count();
    auto objPath = std::string(OBJ_ENTRY) + '/' + std::to_string(entryId);

    AssociationList objects{};

    std::map<std::string,
             const std::function<std::string(Entry&, std::string&)>>
        fnMap;
    fnMap.insert(std::make_pair(std::string(FQPN_PREFIX) + "Resolution",
                                [](Entry& entry, std::string& s) {
        return entry.resolution(s, true);
    }));
    fnMap.insert(std::make_pair(
        std::string(FQPN_PREFIX) + "EventId",
        [](Entry& entry, std::string& s) { return entry.eventId(s, true); }));

    auto foundFQPNs = processMetadata(errMsg, additionalData, fnMap, objects);

    auto e = std::make_unique<Entry>(
        busLog, objPath, entryId,
        ms, // Milliseconds since 1970
        errLvl, std::move(errMsg), std::move(additionalData),
        std::move(objects), fwVersion, getEntrySerializePath(entryId), *this);

    lastCreatedTimeStamp = ms;

    if (entryBinName.compare(DEFAULT_BIN_NAME) == 0)
    {
        entryBinName = "";
    }
    else
    {
        entryBinName = "/" + entryBinName;
    }
    callFQPNsMethods(foundFQPNs, e, fnMap);
    e->emit_object_added();

    auto entryPath = std::string(ERRLOG_PERSIST_PATH) + entryBinName;

    // lg2::info("Writing Entry on FS on Path: {ENTRY_PATH}", "ENTRY_PATH",
    //           entryPath);

    if (errLvl < Entry::sevLowerLimit || entryBin->persistInfoLog)
    {
        auto path = serialize(*e, fs::path(entryPath));
        e->path(path);
    }

    serialize(*e);

#ifdef ENABLE_LOG_STREAMING
    if (entryBinName == "/SEL")
    {
        /* Creates SEL data for streaming */
        std::string msg = " EntryId:" + std::to_string(entryId);

        /* Stream SEL data */
        std::vector<uint8_t> msgVec(msg.begin(), msg.end());
        if (!logSocket.sendMessage(msgVec))
        {
            lg2::error("Failed to stream SEL data");
        }
    }
#endif

    if (isQuiesceOnErrorEnabled() && (errLvl < Entry::sevLowerLimit) &&
        isCalloutPresent(*e))
    {
        quiesceOnError(entryId);
    }

    // Add entry before calling the extensions so that they have access to it
    entries.insert(std::make_pair(entryId, std::move(e)));

    doExtensionLogCreate(*entries.find(entryId)->second, ffdc);

    // Note: No need to close the file descriptors in the FFDC.
}

bool Manager::isQuiesceOnErrorEnabled()
{
    // When running under tests, the Logging.Settings service will not be
    // present.  Assume false.
    if (IS_UNIT_TEST)
    {
        return false;
    }

    std::variant<bool> property;

    auto method = this->busLog.new_method_call(
        "xyz.openbmc_project.Settings", "/xyz/openbmc_project/logging/settings",
        "org.freedesktop.DBus.Properties", "Get");

    method.append("xyz.openbmc_project.Logging.Settings", "QuiesceOnHwError");

    try
    {
        auto reply = this->busLog.call(method);
        reply.read(property);
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Error reading QuiesceOnHwError property: {ERROR}", "ERROR",
                   e);
        return false;
    }

    return std::get<bool>(property);
}

bool Manager::isCalloutPresent(const Entry& entry)
{
    for (const auto& c : entry.additionalData())
    {
        if (c.find("CALLOUT_") != std::string::npos)
        {
            return true;
        }
    }

    return false;
}

void Manager::findAndRemoveResolvedBlocks()
{
    for (auto& entry : entries)
    {
        if (entry.second->resolved())
        {
            checkAndRemoveBlockingError(entry.first);
        }
    }
}

void Manager::onEntryResolve(sdbusplus::message_t& msg)
{
    using Interface = std::string;
    using Property = std::string;
    using Value = std::string;
    using Properties = std::map<Property, std::variant<Value>>;

    Interface interface;
    Properties properties;

    msg.read(interface, properties);

    for (const auto& p : properties)
    {
        if (p.first == "Resolved")
        {
            findAndRemoveResolvedBlocks();
            return;
        }
    }
}

void Manager::checkAndQuiesceHost()
{
    using Host = sdbusplus::server::xyz::openbmc_project::state::Host;

    // First check host state
    std::variant<Host::HostState> property;

    auto method = this->busLog.new_method_call(
        "xyz.openbmc_project.State.Host", "/xyz/openbmc_project/state/host0",
        "org.freedesktop.DBus.Properties", "Get");

    method.append("xyz.openbmc_project.State.Host", "CurrentHostState");

    try
    {
        auto reply = this->busLog.call(method);
        reply.read(property);
    }
    catch (const sdbusplus::exception_t& e)
    {
        // Quiescing the host is a "best effort" type function. If unable to
        // read the host state or it comes back empty, just return.
        // The boot block object will still be created and the associations to
        // find the log will be present. Don't want a dependency with
        // phosphor-state-manager service
        lg2::info("Error reading QuiesceOnHwError property: {ERROR}", "ERROR",
                  e);
        return;
    }

    auto hostState = std::get<Host::HostState>(property);
    if (hostState != Host::HostState::Running)
    {
        return;
    }

    auto quiesce = this->busLog.new_method_call(
        "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager", "StartUnit");

    quiesce.append("obmc-host-graceful-quiesce@0.target");
    quiesce.append("replace");

    this->busLog.call_noreply(quiesce);
}

void Manager::quiesceOnError(const uint32_t entryId)
{
    // Verify we don't already have this entry blocking
    auto it = find_if(this->blockingErrors.begin(), this->blockingErrors.end(),
                      [&](const std::unique_ptr<Block>& obj) {
        return obj->entryId == entryId;
    });
    if (it != this->blockingErrors.end())
    {
        // Already recorded so just return
        lg2::debug(
            "QuiesceOnError set and callout present but entry already logged");
        return;
    }

    lg2::info("QuiesceOnError set and callout present");

    auto blockPath = std::string(OBJ_LOGGING) + "/block" +
                     std::to_string(entryId);
    auto blockObj = std::make_unique<Block>(this->busLog, blockPath, entryId);
    this->blockingErrors.push_back(std::move(blockObj));

    // Register call back if log is resolved
    using namespace sdbusplus::bus::match::rules;
    auto entryPath = std::string(OBJ_ENTRY) + '/' + std::to_string(entryId);
    auto callback = std::make_unique<sdbusplus::bus::match_t>(
        this->busLog,
        propertiesChanged(entryPath, "xyz.openbmc_project.Logging.Entry"),
        std::bind(std::mem_fn(&Manager::onEntryResolve), this,
                  std::placeholders::_1));

    propChangedEntryCallback.insert(
        std::make_pair(entryId, std::move(callback)));

    checkAndQuiesceHost();
}

void Manager::doExtensionLogCreate(const Entry& entry, const FFDCEntries& ffdc)
{
    // Make the association <endpointpath>/<endpointtype> paths
    std::vector<std::string> assocs;
    for (const auto& [forwardType, reverseType, endpoint] :
         entry.associations())
    {
        std::string e{endpoint};
        e += '/' + reverseType;
        assocs.push_back(e);
    }

    for (auto& create : Extensions::getCreateFunctions())
    {
        try
        {
            create(entry.message(), entry.id(), entry.timestamp(),
                   entry.severity(), entry.additionalData(), assocs, ffdc);
        }
        catch (const std::exception& e)
        {
            lg2::error(
                "An extension's create function threw an exception: {ERROR}",
                "ERROR", e);
        }
    }
}

std::vector<std::string> Manager::processMetadata(
    const std::string& /*errorName*/, std::vector<std::string>& additionalData,
    const std::map<std::string,
                   const std::function<std::string(Entry&, std::string&)>>&
        fnMap,
    AssociationList& objects) const
{
    // additionalData is a list of "metadata=value"
    constexpr auto separator = '=';
    std::vector<std::string> seenFQPNs;
    for (const auto& entryItem : additionalData)
    {
        auto found = entryItem.find(separator);
        if (std::string::npos != found)
        {
            auto metadata = entryItem.substr(0, found);

            if (fnMap.count(metadata) > 0)
            {
                seenFQPNs.push_back(entryItem);
            }

            auto iter = meta.find(metadata);
            if (meta.end() != iter)
            {
                (iter->second)(metadata, additionalData, objects);
            }
        }
    }
    const std::vector<std::string>& v = seenFQPNs;
    auto isFQPN = [&](std::string& s) {
        return std::find(v.begin(), v.end(), s) != v.end();
    };
    additionalData.erase(
        std::remove_if(additionalData.begin(), additionalData.end(), isFQPN),
        additionalData.end());
    return seenFQPNs;
}

void Manager::checkAndRemoveBlockingError(uint32_t entryId)
{
    // First look for blocking object and remove
    auto it = find_if(blockingErrors.begin(), blockingErrors.end(),
                      [&](const std::unique_ptr<Block>& obj) {
        return obj->entryId == entryId;
    });
    if (it != blockingErrors.end())
    {
        blockingErrors.erase(it);
    }

    // Now remove the callback looking for the error to be resolved
    auto resolveFind = propChangedEntryCallback.find(entryId);
    if (resolveFind != propChangedEntryCallback.end())
    {
        propChangedEntryCallback.erase(resolveFind);
    }

    return;
}

void Manager::erase(uint32_t entryId)
{
    auto entryFound = entries.find(entryId);

    if (entries.end() != entryFound)
    {
        auto binName = binEntryMap[entryId];
        auto* entryBin = &(binNameMap[binName]);
        std::string deletePath = ERRLOG_PERSIST_PATH;

        for (auto& func : Extensions::getDeleteProhibitedFunctions())
        {
            try
            {
                bool prohibited = false;
                func(entryId, prohibited);
                if (prohibited)
                {
                    return;
                }
            }
            catch (const std::exception& e)
            {
                lg2::error("An extension's deleteProhibited function threw an "
                           "exception: {ERROR}",
                           "ERROR", e);
            }
        }

        if (!(binName.compare(DEFAULT_BIN_NAME) == 0))
        {
            deletePath = std::string(ERRLOG_PERSIST_PATH) + "/" + binName;
        }

        // lg2::info("Deleting Entry of Bin: {BIN_NAME}", "BIN_NAME", binName);
        // lg2::info("Bin of Incoming Entry: {DELETE_PATH}", "DELETE_PATH",
        //           deletePath);

        // Delete the persistent representation of this error.
        fs::path errorPath(deletePath);
        errorPath /= std::to_string(entryId);
        fs::remove(errorPath);

        auto removeId = [](std::set<uint32_t>& ids, uint32_t id) {
            auto it = std::find(ids.begin(), ids.end(), id);
            if (it != ids.end())
            {
                ids.erase(it);
            }
        };
        if (entryFound->second->severity() >= Entry::sevLowerLimit)
        {
            removeId(entryBin->infoEntries, entryId);
        }
        else
        {
            removeId(entryBin->errorEntries, entryId);
        }
        entries.erase(entryFound);
        binEntryMap.erase(entryId);

        checkAndRemoveBlockingError(entryId);

        for (auto& remove : Extensions::getDeleteFunctions())
        {
            try
            {
                remove(entryId);
            }
            catch (const std::exception& e)
            {
                lg2::error("An extension's delete function threw an exception: "
                           "{ERROR}",
                           "ERROR", e);
            }
        }
    }
    else
    {
        lg2::error("Invalid entry ID ({ID}) to delete", "ID", entryId);
    }
}

void eraseSubStr(std::string& mainStr, const std::string& toErase)
{
    // Search for the substring in string
    size_t pos = mainStr.find(toErase);
    if (pos != std::string::npos)
    {
        // If found then erase it from string
        mainStr.erase(pos, toErase.length());
    }
}

void Manager::restore()
{
    auto sanity = [](const auto& id, const auto& restoredId) {
        return id == restoredId;
    };

    fs::path dir(ERRLOG_PERSIST_PATH);
    if (!fs::exists(dir) || fs::is_empty(dir))
    {
        return;
    }

    // using recursive_directory_iterator to get every directory
    for (const auto& file : std::filesystem::recursive_directory_iterator(dir))
    {
        if (fs::is_directory(file))
        {
            continue;
        }

        auto id = file.path().filename().c_str();
        long idNum;
        try
        {
            idNum = std::stol(id);
        }
        catch (const std::exception& ec)
        {
            lg2::error(
                "Exception occured while converting filename to long. File name is {ID}.",
                "ID", id);
            continue;
        }

        auto parentPath = std::string(file.path().parent_path());
        eraseSubStr(parentPath, std::string(ERRLOG_PERSIST_PATH) + "/");
        std::string restoreBinName = DEFAULT_BIN_NAME;

        if (parentPath.compare(std::string(ERRLOG_PERSIST_PATH)) != 0)
        {
            restoreBinName = parentPath;
            // If restoreBinName isn't present in the binNameMap then skip
            if (!(binNameMap.find(restoreBinName) != binNameMap.end()))
            {
                lg2::error("Found file in invalid bin during restore. "
                           "Ignoring entry {ID_NUM} in {NSPACE}. ",
                           "ID_NUM", idNum, "NSPACE", restoreBinName);
                continue;
            }
        }

        // If idNum is already in binEntryMap then ignore file
        // This prevents a dbus object creation on same path (crash)
        if (binEntryMap.find(idNum) != binEntryMap.end())
        {
            lg2::error("Duplicate file found in bin during restore. "
                       "Ignoring entry {ID_NUM} in {NSPACE} namespace. ",
                       "ID_NUM", idNum, "NSPACE", restoreBinName);
            continue;
        }

        Bin* restoreBin = &(binNameMap[restoreBinName]);

        auto e = std::make_unique<Entry>(
            busLog,
            std::string(OBJ_ENTRY) + '/' + std::string(file.path().filename()),
            idNum, *this);

        if (deserialize(file.path(), *e))
        {
            // validate the restored error entry id
            if (sanity(static_cast<uint32_t>(idNum), e->id()))
            {
                if (this->_autoPurgeResolved && e->resolved())
                {
                    // lg2::error(
                    //     "Log entry {ID_NUM} is resolved, so purging it at
                    //     bootup.", "ID_NUM", idNum);
                    fs::remove(file.path());
                    continue;
                }
                e->path(file.path(), true);
                if (e->severity() >= Entry::sevLowerLimit)
                {
                    restoreBin->infoEntries.insert(idNum);
                }
                else
                {
                    restoreBin->errorEntries.insert(idNum);
                }

                entries.insert(std::make_pair(idNum, std::move(e)));
                binEntryMap.insert(std::make_pair(idNum, restoreBinName));
            }
            else
            {
                lg2::error(
                    "Failed in sanity check while restoring error entry. "
                    "Ignoring error entry {ID_NUM}/{ENTRY_ID}.",
                    "ID_NUM", idNum, "ENTRY_ID", e->id());
            }
        }
    }

    // Prune all namespaces to capacity
    for (auto& pair : binNameMap)
    {
        lg2::info("Pruning Namespace: {NAMESPACE_NAME}", "NAMESPACE_NAME",
                  pair.first);

        Bin* restoreBin = &(pair.second);
        uint32_t eraseId;

        while (restoreBin->errorEntries.size() > restoreBin->errorCap)
        {
            eraseId = *(restoreBin->errorEntries.begin());
            erase(eraseId);
            lg2::info("Pruning Error EntryId {ENTRY_ID} in {NAMESPACE_NAME}",
                      "ENTRY_ID", eraseId, "NAMESPACE_NAME", pair.first);
        }

        while (restoreBin->infoEntries.size() > restoreBin->errorInfoCap)
        {
            eraseId = *(restoreBin->infoEntries.begin());
            erase(eraseId);
            lg2::info(
                "Pruning InfoError EntryId {ENTRY_ID} in {NAMESPACE_NAME}",
                "ENTRY_ID", eraseId, "NAMESPACE_NAME", pair.first);
        }
    }

    if (!entries.empty())
    {
        entryId = entries.rbegin()->first;
        lastCreatedTimeStamp = entries.find(entryId)->second->timestamp();
    }
}

std::string Manager::readFWVersion()
{
    auto version = util::getOSReleaseValue("VERSION_ID");

    if (!version)
    {
        lg2::error("Unable to read BMC firmware version");
    }

    return version.value_or("");
}

bool Manager::deleteAll(
    const std::string& nspace,
    sdbusplus::xyz::openbmc_project::Logging::server::Entry::Level severity)
{
    auto binPresent = false;
    Bin* thisBin;
    for (auto& pair : binNameMap)
    {
        if (pair.first == nspace)
        {
            binPresent = true;
            thisBin = &(pair.second);
            break;
        }
    }

    // If bin is not present then return error
    if (!binPresent)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::
            ResourceNotFound();
    }

    // Info Errors
    if (severity >= Entry::sevLowerLimit)
    {
        while (getInfoErrSize(nspace) != 0)
        {
            erase(*(thisBin->infoEntries.begin()));
        }
    }
    // Real Errors
    else
    {
        while (getRealErrSize(nspace) != 0)
        {
            erase(*(thisBin->errorEntries.begin()));
        }
    }

    return true;
}

// using ManagedObject = std::map<std::string, std::map<std::string,
// std::map<std::string, std::variant<std::vector<std::string>,
// bool, std::string, std::vector<uint8_t>, int64_t, uint32_t>>>>;
// This function will return filtered URI
phosphor::logging::ManagedObject
    Manager::getAll(NamespaceIface::ResolvedFilterType rfilter)
{
    phosphor::logging::ManagedObject ret_obj;

    // Iterate over all the entries
    auto iter = entries.begin();
    while (iter != entries.end())
    {
        // If looking for Resolved, but entry is not resolved then skip entry
        if (rfilter == NamespaceIface::ResolvedFilterType::Resolved &&
            !(iter->second->resolved()))
        {
            ++iter;
            continue;
        }

        // If looking for Unresolved, but entry is resolved then skip entry
        if (rfilter == NamespaceIface::ResolvedFilterType::Unresolved &&
            (iter->second->resolved()))
        {
            ++iter;
            continue;
        }

        varType v;
        propMap prop;
        objMap obj;

        // Id
        v = iter->second->id();
        prop["Id"] = v;

        // Timestamp
        v = iter->second->timestamp();
        prop["Timestamp"] = v;

        // Severity
        v = Entry::convertLevelToString(iter->second->severity());
        prop["Severity"] = v;

        // Message
        v = iter->second->message();
        prop["Message"] = v;

        // AdditionalData
        v = iter->second->additionalData();
        prop["AdditionalData"] = v;

        // Resolution
        v = iter->second->resolution();
        prop["Resolution"] = v;

        // Resolved
        v = iter->second->resolved();
        prop["Resolved"] = v;

        // ServiceProviderNotify
        v = Entry::convertNotifyToString(iter->second->serviceProviderNotify());
        prop["ServiceProviderNotify"] = v;

        // UpdateTimeStamp
        v = iter->second->updateTimestamp();
        prop["UpdateTimeStamp"] = v;
        obj.insert(obj.begin(),
                   std::make_pair("xyz.openbmc_project.Logging.Entry", prop));

        ret_obj[sdbusplus::message::object_path(
            std::string(OBJ_ENTRY) + '/' +
            std::to_string(iter->second->id()))] = obj;

        ++iter;
    }

    return ret_obj;
}

// using ManagedObject = std::map<std::string, std::map<std::string,
// std::map<std::string, std::variant<std::vector<std::string>,
// bool, std::string, std::vector<uint8_t>, int64_t, uint32_t>>>>;

phosphor::logging::ManagedObject
    Manager::getAll(const std::string& nspace,
                    NamespaceIface::ResolvedFilterType rfilter)
{
    std::string entryBinName = DEFAULT_BIN_NAME;
    Bin* thisBin = &(binNameMap[entryBinName]);

    for (auto& pair : binNameMap)
    {
        if (pair.first == nspace)
        {
            thisBin = &(pair.second);
            break;
        }
    }

    phosphor::logging::ManagedObject ret_obj;

    // Go over errorEntries
    for (auto iter = (thisBin)->errorEntries.begin();
         iter != (thisBin)->errorEntries.end(); iter++)
    {
        auto entryFound = entries.find(*iter);

        // If looking for Resolved, but entry is not resolved then skip entry
        if (rfilter == NamespaceIface::ResolvedFilterType::Resolved &&
            !(entryFound->second->resolved()))
        {
            continue;
        }

        // If looking for Unresolved, but entry is resolved then skip entry
        if (rfilter == NamespaceIface::ResolvedFilterType::Unresolved &&
            (entryFound->second->resolved()))
        {
            continue;
        }

        if (entries.end() != entryFound)
        {
            varType v;
            propMap prop;
            objMap obj;

            // Id
            v = entryFound->second->id();
            prop["Id"] = v;

            // Timestamp
            v = entryFound->second->timestamp();
            prop["Timestamp"] = v;

            // Severity
            v = Entry::convertLevelToString(entryFound->second->severity());
            prop["Severity"] = v;

            // Message
            v = entryFound->second->message();
            prop["Message"] = v;

            // AdditionalData
            v = entryFound->second->additionalData();
            prop["AdditionalData"] = v;

            // Resolution
            v = entryFound->second->resolution();
            prop["Resolution"] = v;

            // Resolved
            v = entryFound->second->resolved();
            prop["Resolved"] = v;

            // ServiceProviderNotify
            v = Entry::convertNotifyToString(
                entryFound->second->serviceProviderNotify());
            prop["ServiceProviderNotify"] = v;

            // UpdateTimeStamp
            v = entryFound->second->updateTimestamp();
            prop["UpdateTimeStamp"] = v;
            obj.insert(
                obj.begin(),
                std::make_pair("xyz.openbmc_project.Logging.Entry", prop));

            ret_obj[sdbusplus::message::object_path(
                std::string(OBJ_ENTRY) + '/' +
                std::to_string(entryFound->second->id()))] = obj;
        }
    }

    // Go over infoEntries
    for (auto iter = (thisBin)->infoEntries.begin();
         iter != (thisBin)->infoEntries.end(); iter++)
    {
        auto entryFound = entries.find(*iter);

        // If looking for Resolved, but entry is not resolved then skip entry
        if (rfilter == NamespaceIface::ResolvedFilterType::Resolved &&
            !(entryFound->second->resolved()))
        {
            continue;
        }

        // If looking for Unresolved, but entry is resolved then skip entry
        if (rfilter == NamespaceIface::ResolvedFilterType::Unresolved &&
            (entryFound->second->resolved()))
        {
            continue;
        }

        if (entries.end() != entryFound)
        {
            varType v;
            propMap prop;
            objMap obj;

            // Id
            v = entryFound->second->id();
            prop["Id"] = v;

            // Timestamp
            v = entryFound->second->timestamp();
            prop["Timestamp"] = v;

            // Severity
            v = Entry::convertLevelToString(entryFound->second->severity());
            prop["Severity"] = v;

            // Message
            v = entryFound->second->message();
            prop["Message"] = v;

            // AdditionalData
            v = entryFound->second->additionalData();
            prop["AdditionalData"] = v;

            // Resolution
            v = entryFound->second->resolution();
            prop["Resolution"] = v;

            // Resolved
            v = entryFound->second->resolved();
            prop["Resolved"] = v;

            // ServiceProviderNotify
            v = Entry::convertNotifyToString(
                entryFound->second->serviceProviderNotify());
            prop["ServiceProviderNotify"] = v;

            // UpdateTimeStamp
            v = entryFound->second->updateTimestamp();
            prop["UpdateTimeStamp"] = v;

            obj.insert(
                obj.begin(),
                std::make_pair("xyz.openbmc_project.Logging.Entry", prop));

            ret_obj[sdbusplus::message::object_path(
                std::string(OBJ_ENTRY) + '/' +
                std::to_string(entryFound->second->id()))] = obj;
        }
    }

    return ret_obj;
}

std::tuple<uint32_t, uint64_t> Manager::getStats(const std::string& nspace)
{
    if (nspace == "all")
    {
        return (std::make_tuple(Manager::lastEntryID(),
                                Manager::lastEntryTimestamp()));
    }

    if (binNameMap.find(nspace) == binNameMap.end())
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::
            ResourceNotFound();
    }
    else
    {
        Bin* thisBin = &(binNameMap[nspace]);

        uint32_t maxErr = 0;
        uint32_t maxInfo = 0;

        if (!thisBin->errorEntries.empty())
        {
            maxErr = *(std::max_element(thisBin->errorEntries.begin(),
                                        thisBin->errorEntries.end()));
        }

        if (!thisBin->infoEntries.empty())
        {
            maxInfo = *(std::max_element(thisBin->infoEntries.begin(),
                                         thisBin->infoEntries.end()));
        }

        uint32_t maxEntry = maxErr > maxInfo ? maxErr : maxInfo;

        if (maxEntry == 0)
        {
            return (std::make_tuple(0, 0));
        }

        return (std::make_tuple(maxEntry,
                                entries.find(maxEntry)->second->timestamp()));
    }
}

void Manager::create(const std::string& message, Entry::Level severity,
                     const std::map<std::string, std::string>& additionalData,
                     const FFDCEntries& ffdc)
{
    // Convert the map into a vector of "key=value" strings
    std::vector<std::string> ad;
    metadata::associations::combine(additionalData, ad);

    createEntry(message, severity, ad, ffdc);
}

size_t Manager::getInfoLogCapacity()
{
    Bin* entryBin = &(binNameMap["SEL"]);
    return entryBin->errorInfoCap;
}

size_t Manager::setInfoLogCapacity(size_t infoLogCapacity)
{
    Bin* entryBin = &(binNameMap["SEL"]);

    if (infoLogCapacity > ERROR_INFO_CAP)
    {
        throw sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument();
    }
    try
    {
        this->updateConfigJsonWithSelCapacity(entryBin->jsonPath,
                                              infoLogCapacity);
    }
    catch (const std::exception& e)
    {
        lg2::error(
            "Can not update the config file to update the SEL capacity.");
        throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
    }
    entryBin->errorInfoCap = infoLogCapacity;
    if (infoLogCapacity < entries.size())
    {
        size_t toDelete = entries.size() - infoLogCapacity;
        this->cancelPendingLogDeletion();
        auto iter = entries.begin();
        while (toDelete-- > 0)
        {
            auto e = iter->first;
            ++iter;
            erase(e);
        }
    }
    return infoLogCapacity;
}

void Manager::rfSendEvent(std::string rfMessage, Entry::Level rfSeverity,
                          std::map<std::string, std::string> rfAdditionalData)
{
    std::vector<std::string> ad;
    if (rfAdditionalData.find("REDFISH_MESSAGE_ID") == rfAdditionalData.end() ||
        rfAdditionalData.find("REDFISH_ORIGIN_OF_CONDITION") ==
            rfAdditionalData.end())
    {
        lg2::error("Redfish Commit Error: Missing required metadata");
        return;
    }

    if ((rfAdditionalData.size() == 3 &&
         rfAdditionalData.find("REDFISH_MESSAGE_ARGS") ==
             rfAdditionalData.end()))
    {
        lg2::error("Redfish Commit Error: Missing required metadata");
        return;
    }

    if (rfAdditionalData.size() > 3)
    {
        lg2::error("Redfish Commit Error: unsupported metadata");
        return;
    }

    metadata::associations::combine(rfAdditionalData, ad);
    createEntry(rfMessage, rfSeverity, ad);
}

} // namespace internal
} // namespace logging
} // namespace phosphor
