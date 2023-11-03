#pragma once

#include "bin.hpp"
#include "elog_block.hpp"
#include "elog_entry.hpp"
#include "xyz/openbmc_project/Collection/DeleteAll/server.hpp"
#include "xyz/openbmc_project/Logging/Create/server.hpp"
#include "xyz/openbmc_project/Logging/Entry/server.hpp"
#include "xyz/openbmc_project/Logging/Capacity/server.hpp"
#include "xyz/openbmc_project/Logging/Namespace/server.hpp"
#include "xyz/openbmc_project/Logging/Internal/Manager/server.hpp"

#include <nlohmann/json.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdeventplus/source/time.hpp>
#include <xyz/openbmc_project/Common/File/error.hpp>

#include <fstream>
#include <list>
#include <vector>

namespace phosphor
{
namespace logging
{

namespace fs = std::filesystem;

extern const std::map<std::string, std::vector<std::string>> g_errMetaMap;
extern const std::map<std::string, level> g_errLevelMap;

using CreateIface = sdbusplus::server::xyz::openbmc_project::logging::Create;
using DeleteAllIface =
    sdbusplus::server::xyz::openbmc_project::collection::DeleteAll;
using NamespaceIface =
    sdbusplus::xyz::openbmc_project::Logging::server::Namespace;
using CapacityIface = sdbusplus::xyz::openbmc_project::Logging::server::Capacity;

namespace details
{
template <typename... T>
using ServerObject = typename sdbusplus::server::object_t<T...>;

using ManagerIface =
    sdbusplus::server::xyz::openbmc_project::logging::internal::Manager;

} // namespace details

constexpr size_t ffdcFormatPos = 0;
constexpr size_t ffdcSubtypePos = 1;
constexpr size_t ffdcVersionPos = 2;
constexpr size_t ffdcFDPos = 3;

using FFDCEntry = std::tuple<CreateIface::FFDCFormat, uint8_t, uint8_t,
                             sdbusplus::message::unix_fd>;

using FFDCEntries = std::vector<FFDCEntry>;

typedef std::variant<bool, uint32_t, int64_t, std::string,
                                 std::vector<uint8_t>, std::vector<std::string>,
                                 uint64_t>
                varType;

typedef std::map<std::string, varType> propMap;

typedef std::map<std::string, propMap> objMap;

using ManagedObject =
    std::map<sdbusplus::message::object_path, objMap>;


namespace internal
{
/** @class Manager
 *  @brief OpenBMC logging manager implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.Logging.Internal.Manager DBus API.
 */
class Manager : public details::ServerObject<details::ManagerIface>
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    virtual ~Manager()
    {
    }

    /** @brief Constructor to put object onto bus at a dbus path.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     */
    Manager(sdbusplus::bus_t& bus, const std::string& objPath);

    /**
     * @fn parseJson
     * @brief Method to parse input json config
     *
     * @param jsonPath
     * @return true
     * @return false
     */
    uint32_t parseJson(const std::string& jsonPath)
    {
        std::ifstream jsonStream;
        nlohmann::json data;
        bool validJsonConfig = false;
        try
        {
            jsonStream.open(jsonPath);
            if (jsonStream.is_open())
            {
                data = nlohmann::json::parse(jsonStream, nullptr, false);
                validJsonConfig = true;
                jsonStream.close();
            }
            else
            {
                lg2::error("Couldn't open argument file passed in. Using only "
                           "default namespaces.");
                return 1;
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to open/parse JSON file: {ERROR}", "ERROR",
                       e.what());
            return 2;
        }

        std::vector<std::string> dirsToPreserve{};

        if (validJsonConfig && !data.is_discarded())
        {
            for (auto& item : data["Namespaces"].items())
            {
                if (item.value()["ID"].is_string())
                {
                    auto id =
                        item.value()["ID"].get_ptr<nlohmann::json::string_t*>();

                    dirsToPreserve.push_back(item.value()["ID"]);

                    auto errorCap =
                        item.value()["ErrorCapacity"]
                            .get_ptr<nlohmann::json::number_unsigned_t*>();

                    auto errorInfoCap =
                        item.value()["InfoErrorCapacity"]
                            .get_ptr<nlohmann::json::number_unsigned_t*>();

                    bool persistInfoLog =
                        true; // by default persist all info logs
                    if (item.value().contains("PersistInfoLog"))
                    {
                        persistInfoLog = item.value()["PersistInfoLog"];
                    }
                    auto bin = phosphor::logging::internal::Bin(
                        std::string(*id), *errorCap, *errorInfoCap,
                        std::string(ERRLOG_PERSIST_PATH) + "/" +
                            std::string(*id),
                        persistInfoLog);

                    if (std::string(*id) == "SEL")
                    {
                        bin.jsonPath = jsonPath;
                    }
                    this->addBin(bin);
                }
            }
        }
        else
        {
            lg2::error("Invalid JSON file passed.");
            return 3;
        }

        std::filesystem::path logDir(std::string{ERRLOG_PERSIST_PATH});

        // clear errlog path, skip configured dirnames, skip non-dirs
        for (const auto& p : std::filesystem::directory_iterator(logDir))
        {
            auto dirName = p.path().filename().string();

            if (std::find(dirsToPreserve.begin(), dirsToPreserve.end(),
                          dirName) != dirsToPreserve.end())
            {
                continue;
            }

            std::error_code ec{};
            if (!std::filesystem::is_directory(p.path(), ec))
            {
                continue;
            }

            ec.clear();
            std::filesystem::remove_all(p.path(), ec);
            if (ec.value() != 0)
            {
                lg2::error("Failed to delete directory: {PATH}", "PATH",
                           p.path().string());
            }
        }

        return 0;
    }

    uint32_t parseRWConfigJson(const std::string& jsonPath)
    {
        lg2::info("parseRWConfigJson {PATH}", "PATH", jsonPath);
        this->rwConfigJsonPath = jsonPath;

        std::ifstream jsonStream;
        nlohmann::json data;
        try
        {
            jsonStream.open(jsonPath);
            if (jsonStream.is_open())
            {
                data = nlohmann::json::parse(jsonStream, nullptr);
                jsonStream.close();
                if (!data.is_object())
                {
                    throw std::invalid_argument("R/W config parse result is "
                                                "not an object");
                }
            }
            else
            {
                lg2::info("Persistent R/W config file {FILE} doesn't exist. "
                          "Using default values.", "FILE", jsonPath);
                return 0;  // It's not an error for this file to not exist
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to open/parse JSON file: {ERROR}", "ERROR",
                       e.what());
            std::error_code ec{};
            fs::remove(jsonPath, ec);
            if (ec.value() != 0)
            {
                lg2::error("Also failed to delete malformed JSON file!");
            }
            throw;  // rethrow to parseErrHandler
        }
        bool logPurgePolicy = data.value("LogPurgePolicy", false);
        lg2::info("Set log purge policy enabled state from R/W config to {STATE}",
                  "STATE", logPurgePolicy);
        this->_autoPurgeResolved = logPurgePolicy;
        return 0;
    }

    uint32_t updateRWConfigJson()
    {
        nlohmann::json data({
            {"LogPurgePolicy", this->_autoPurgeResolved}
        });
        std::ofstream jsonStream;
        try
        {
            jsonStream.open(this->rwConfigJsonPath);
            if (jsonStream.is_open())
            {
                jsonStream << data;
                jsonStream.close();
            }
            else
            {
                lg2::error("Persistent R/W config file {FILE} could not be"
                           "opened for writing.", "FILE", this->rwConfigJsonPath);
                return 1;
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to open/write JSON file: {ERROR}", "ERROR",
                       e.what());
            return 2;
        }
        return 0;
    }

    void updateConfigJsonWithSelCapacity(const std::string& jsonPath,
                                         size_t errorInfoCapacity)
    {
        std::ifstream jsonInputStream;
        std::ofstream jsonOutputStream;
        nlohmann::json data;
        try
        {
            jsonInputStream.open(jsonPath);
            if (jsonInputStream.is_open())
            {
                data = nlohmann::json::parse(jsonInputStream, nullptr, false);
                jsonInputStream.close();
            }
            else
            {
                lg2::error("Couldn't open argument file passed in.");
                throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to update JSON file: {ERROR}", "ERROR", e.what());
            throw;
        }

        for (auto& item : data["Namespaces"].items())
        {
            if (item.value()["ID"].is_string())
            {
                auto id =
                    item.value()["ID"].get_ptr<nlohmann::json::string_t*>();

                if (std::string(*id) == "SEL")
                {
                    auto errorInfoCap =
                        item.value()["InfoErrorCapacity"]
                            .get_ptr<nlohmann::json::number_unsigned_t*>();
                    *errorInfoCap = errorInfoCapacity;
                }
            }
        }

        try
        {
            jsonOutputStream.open(jsonPath);
            if (jsonOutputStream.is_open())
            {
                jsonOutputStream << data;
                jsonOutputStream.close();
            }
            else
            {
                lg2::error("Config file {FILE} could not be opened for writing.",
                        "FILE", jsonPath);
                throw sdbusplus::xyz::openbmc_project::Common::File::Error::Open();;
            }
        }
        catch (const std::exception& e)
        {
            lg2::error("Failed to open/write JSON file: {ERROR}", "ERROR",
                       e.what());
            throw;
        }
    }

    /* @fn getSelPolicy()
     * @brief retrive current sel policy from Settingsd.
     */
    virtual std::string getSelPolicy();

    /*
     * @fn commit()
     * @brief sd_bus Commit method implementation callback.
     * @details Create an error/event log based on transaction id and
     *          error message.
     * @param[in] transactionId - Unique identifier of the journal entries
     *                            to be committed.
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     */
    uint32_t commit(uint64_t transactionId, std::string errMsg) override;

    /*
     * @fn commit()
     * @brief sd_bus CommitWithLvl method implementation callback.
     * @details Create an error/event log based on transaction id and
     *          error message.
     * @param[in] transactionId - Unique identifier of the journal entries
     *                            to be committed.
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] errLvl - level of the error
     */
    uint32_t commitWithLvl(uint64_t transactionId, std::string errMsg,
                           uint32_t errLvl) override;

    /** @brief Erase specified entry d-bus object
     *
     * @param[in] entryId - unique identifier of the entry
     */
    void erase(uint32_t entryId);

    /** @brief Construct error d-bus objects from their persisted
     *         representations.
     */
    void restore();

    /** @brief  Erase all error log entries
     *
     */
    void eraseAll()
    {
        this->cancelPendingLogDeletion();
        auto iter = entries.begin();
        while (iter != entries.end())
        {
            auto e = iter->first;
            ++iter;
            erase(e);
        }
        entryId = 0;
        lastCreatedTimeStamp = 0;
    }

    /** @brief Returns the count of high severity errors
     *
     *  @return int - count of real errors
     */
    int getRealErrSize(const std::string& binName = DEFAULT_BIN_NAME);

    /** @brief Returns the count of Info errors
     *
     *  @return int - count of info errors
     */
    int getInfoErrSize(const std::string& binName = DEFAULT_BIN_NAME);

    /** @brief Returns the number of blocking errors
     *
     *  @return int - count of blocking errors
     */
    int getBlockingErrSize()
    {
        return blockingErrors.size();
    }

    /** @brief Returns the number of property change callback objects
     *
     *  @return int - count of property callback entries
     */
    int getEntryCallbackSize()
    {
        return propChangedEntryCallback.size();
    }

    /**
     * @brief Returns the sdbusplus bus object
     *
     * @return sdbusplus::bus_t&
     */
    sdbusplus::bus_t& getBus()
    {
        return busLog;
    }

    /**
     * @brief Returns the ID of the last created entry
     *
     * @return uint32_t - The ID
     */
    uint32_t lastEntryID() const
    {
        return entryId;
    }

    /**
     * @brief Returns the timestamp of the last created entry
     *
     * @return uint64_t - The Timestamp
     */
    uint64_t lastEntryTimestamp() const
    {
        return lastCreatedTimeStamp;
    }

    void addBin(Bin& bin)
    {
        // Create a directory to persist errors for default path
        std::filesystem::create_directories(bin.persistLocation);
        // Insert into internal DS to keep track
        binNameMap.insert(std::make_pair(bin.name, bin));
    }

    auto getBin(const std::string& binName)
    {
        return binNameMap[binName];
    }


    /** @brief Delete logs per namespace
     *
     * Some description
     *
     * @param[in] nspace - Namespace String
     */
    bool deleteAll(const std::string& nspace, sdbusplus::xyz::openbmc_project::Logging::server::Entry::Level severity);

    /** @brief Get logs per namespace
     *
     * Some description
     *
     * @param[in] nspace - Namespace String
     */
    ManagedObject getAll(const std::string& nspaces, NamespaceIface::ResolvedFilterType rfilter);

    ManagedObject getAll(NamespaceIface::ResolvedFilterType rfilter);
    /** @brief Get logs per namespace
     *
     * Gets Stats about Phosphor Logging Entries
     *
     * Currently returns lastEntryId, lastCreatedEntryTimeStamp
     *
     */
    std::tuple<uint32_t, uint64_t> getStats(const std::string& nspace);

    /**
     * @brief Gets the configuration about purging Resolved Logs
     * @return true if Resolved Logs are currently purged, false otherwise
     */
    bool getAutoPurgeResolved();

    /**
     * @brief Sets a new configuration for purging or not Resolved Logs
     * @param [in] confPurgeResolvedLogs, if true Resolved Logs will be purged
     *             otherwise kept
     */
    void setAutoPurgeResolved(bool confPurgeResolvedLogs);

    /**
     * @brief Adds a entry ID to the list of logs to be deleted asynchronously
     *
     * @param [in] entryId - entry ID of log to delete
    */
    void addPendingLogDelete(uint32_t entryId);

    /**
     * @brief Get the number of log entries pending deletion (for unit tests)
    */
    size_t getPendingLogDeleteCount()
    {
        return _pendingPurgeEvents.size();
    }

    /**
     * @brief called from event loop to delete pending logs (one log per call)
    */
    void pendingLogDeleteCallback();

    /**
     * @brief called when pending deletions should be cancelled
     *
     * This occurs in the following situations:
     * - Log purge policy setting is disabled
     * - eraseAll is called
    */
    void cancelPendingLogDeletion();

    /** @brief Creates an event log
     *
     *  This is an alternative to the _commit() API.  It doesn't use
     *  the journal to look up event log metadata like _commit does.
     *
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] severity - level of the error
     * @param[in] additionalData - The AdditionalData property for the error
     */
    void create(
        const std::string& message,
        sdbusplus::server::xyz::openbmc_project::logging::Entry::Level severity,
        const std::map<std::string, std::string>& additionalData);

    /** @brief Configure the error info capacity.
     *
     * @param[in] infoLogCapacity - capacity of error info event
     * @return the error info capacity
     */
    size_t setInfoLogCapacity(size_t infoLogCapacity);

    /** @brief Get the error info capacity.
     *
     * @return the error info capacity
     */
    size_t getInfoLogCapacity();

    /** @brief Creates an event log, and accepts FFDC files
     *
     * This is the same as create(), but also takes an FFDC argument.
     *
     * The FFDC argument is a vector of tuples that allows one to pass in file
     * descriptors for files that contain FFDC (First Failure Data Capture).
     * These will be passed to any event logging extensions.
     *
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] severity - level of the error
     * @param[in] additionalData - The AdditionalData property for the error
     * @param[in] ffdc - A vector of FFDC file info
     */
    void createWithFFDC(
        const std::string& message,
        sdbusplus::server::xyz::openbmc_project::logging::Entry::Level severity,
        const std::map<std::string, std::string>& additionalData,
        const FFDCEntries& ffdc);

    /** @brief Common wrapper for creating an Entry object
     *
     * @return true if quiesce on error setting is enabled, false otherwise
     */
    bool isQuiesceOnErrorEnabled();

    /** @brief Create boot block association and quiesce host if running
     *
     * @param[in] entryId - The ID of the phosphor logging error
     */
    void quiesceOnError(const uint32_t entryId);

    /** @brief Check if inventory callout present in input entry
     *
     * @param[in] entry - The error to check for callouts
     *
     * @return true if inventory item in associations, false otherwise
     */
    bool isCalloutPresent(const Entry& entry);

    /** @brief Check (and remove) entry being erased from blocking errors
     *
     * @param[in] entryId - The entry that is being erased
     */
    void checkAndRemoveBlockingError(uint32_t entryId);

    /** @brief Persistent map of Entry dbus objects and their ID */
    std::map<uint32_t, std::unique_ptr<Entry>> entries;

    /** @brief Persistent map of entry id to bin Name */
    std::map<uint32_t, std::string> binEntryMap;

  private:
    /** @brief Persistent map of namespaces structure and their strings */
    std::map<std::string, Bin> binNameMap;

    /*
     * @fn _commit()
     * @brief commit() helper
     * @param[in] transactionId - Unique identifier of the journal entries
     *                            to be committed.
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] errLvl - level of the error
     */
    void _commit(uint64_t transactionId, std::string&& errMsg,
                 Entry::Level errLvl);

    /** @brief Call metadata handler(s), if any. Handlers may create
     *         associations.
     *  @param[in] errorName - name of the error
     *  @param[in] additionalData - list of metadata (in key=value format)
     *  @param[out] objects - list of error's association objects
     */
    std::vector<std::string> processMetadata(
        const std::string& errorName, std::vector<std::string>& additionalData,
        const std::map<std::string,
                       const std::function<std::string(Entry&, std::string&)>>&
            fnMap,
        AssociationList& objects) const;

    /** @brief Reads the BMC code level
     *
     *  @return std::string - the version string
     */
    static std::string readFWVersion();

    /** @brief Call any create() functions provided by any extensions.
     *  This is called right after an event log is created to allow
     *  extensions to create their own log based on this one.
     *
     *  @param[in] entry - the new event log entry
     *  @param[in] ffdc - A vector of FFDC file info
     */
    void doExtensionLogCreate(const Entry& entry, const FFDCEntries& ffdc);

    /** @brief Common wrapper for creating an Entry object
     *
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] errLvl - level of the error
     * @param[in] additionalData - The AdditionalData property for the error
     * @param[in] ffdc - A vector of FFDC file info. Defaults to an empty
     * vector.
     */
    void createEntry(std::string errMsg, Entry::Level errLvl,
                     std::vector<std::string> additionalData,
                     const FFDCEntries& ffdc = FFDCEntries{});

    /** @brief Notified on entry property changes
     *
     * If an entry is blocking, this callback will be registered to monitor for
     * the entry having it's Resolved field set to true. If it is then remove
     * the blocking object.
     *
     * @param[in] msg - sdbusplus dbusmessage
     */
    void onEntryResolve(sdbusplus::message_t& msg);

    /** @brief Remove block objects for any resolved entries  */
    void findAndRemoveResolvedBlocks();

    /** @brief Quiesce host if it is running
     *
     * This is called when the user has requested the system be quiesced
     * if a log with a callout is created
     */
    void checkAndQuiesceHost();

    /** @brief Persistent sdbusplus DBus bus connection. */
    sdbusplus::bus_t& busLog;

    /** @brief Id of last error log entry */
    uint32_t entryId;

    /** @brief Timestamp of the last created log entry */
    uint64_t lastCreatedTimeStamp;

    /** @brief The BMC firmware version */
    const std::string fwVersion;

    phosphor::logging::internal::Bin defaultBin;

    /** @brief Array of blocking errors */
    std::vector<std::unique_ptr<Block>> blockingErrors;

    /** @brief Map of entry id to call back object on properties changed */
    std::map<uint32_t, std::unique_ptr<sdbusplus::bus::match_t>>
        propChangedEntryCallback;

    /** @brief Path to persistent R/W config (for log purge policy setting) */
    std::string rwConfigJsonPath;

    /** @brief Current value of the log purge policy setting */
    bool _autoPurgeResolved;

    /** @brief Stack containing resolved log entry IDs awaiting deletion */
    std::vector<uint32_t> _pendingPurgeEvents;

    /** @brief Event source used to trigger log deletion
     *
     * Time is used instead of Defer so it can round-robin with D-Bus
     * (Defer is always prioritized ahead of epoll-based sources)
    */
    sdeventplus::source::Time<sdeventplus::ClockId::Monotonic> _autoPurgeEventSource;
};

} // namespace internal

/** @class Manager
 *  @brief Implementation for deleting all error log entries and
 *         creating new logs.
 *  @details A concrete implementation for the
 *           xyz.openbmc_project.Collection.DeleteAll,
 *           xyz.openbmc_project.Logging.Create and
 *           xyz.openbmc_project.Logging.Capacity and
 *           xyz.openbmc_project.Logging.Namespace interfaces.
 */
class Manager : public details::ServerObject<DeleteAllIface, CreateIface, NamespaceIface, CapacityIface>
{
  public:
    Manager() = delete;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;
    Manager(Manager&&) = delete;
    Manager& operator=(Manager&&) = delete;
    virtual ~Manager() = default;

    /** @brief Constructor to put object onto bus at a dbus path.
     *         Defer signal registration (pass true for deferSignal to the
     *         base class) until after the properties are set.
     *  @param[in] bus - Bus to attach to.
     *  @param[in] path - Path to attach at.
     *  @param[in] manager - Reference to internal manager object.
     */
    Manager(sdbusplus::bus_t& bus, const std::string& path,
            internal::Manager& manager) :
        details::ServerObject<DeleteAllIface, CreateIface, NamespaceIface, CapacityIface>(
            bus, path.c_str(),
            details::ServerObject<DeleteAllIface, CreateIface,
                                  NamespaceIface, CapacityIface>::action::defer_emit),
        manager(manager){};

    /** @brief Delete all d-bus objects.
     */
    void deleteAll() override
    {
        log<level::INFO>("Deleting all log entries");
        manager.eraseAll();
    }

    /** @brief getAll method call implementation to get event logs
     *
     */
    ManagedObject getAll(std::string nspace, NamespaceIface::ResolvedFilterType rfilter) override
    {
        if (nspace.compare("Namespace.All") == 0)
        {
            return manager.getAll(rfilter);
        }

        return manager.getAll(nspace, rfilter);
    }

    bool autoClearResolvedLogEnabled() const
    {
        return manager.getAutoPurgeResolved();
    }

    bool autoClearResolvedLogEnabled(bool purgeResolvedLogs)
    {
        manager.setAutoPurgeResolved(purgeResolvedLogs);
        return purgeResolvedLogs;
    }

    /** @brief getStats method call implementation to get Phosphor Logging Stats
     *
     */
    std::tuple<uint32_t, uint64_t> getStats(std::string nspace) override
    {
        return manager.getStats(nspace);
    }

    /** @brief deleteAll method call implementation to delete all logs per namespace
     *
     */
    bool deleteAll(std::string nspace, sdbusplus::xyz::openbmc_project::Logging::server::Entry::Level severity) override
    {
        return manager.deleteAll(nspace, severity);
    }

    /** @brief D-Bus method call implementation to create an event log.
     *
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] severity - Level of the error
     * @param[in] additionalData - The AdditionalData property for the error
     */
    void create(
        std::string message,
        sdbusplus::server::xyz::openbmc_project::logging::Entry::Level severity,
        std::map<std::string, std::string> additionalData) override
    {
        manager.create(message, severity, additionalData);
    }

    /** @brief D-Bus method call implementation to configure the info capacity.
     *
     * @param[in] infoLogCapacity - capacity of info event
     */
    size_t infoLogCapacity(size_t infoLogCapacity) override
    {
        return manager.setInfoLogCapacity(infoLogCapacity);
    }

    /** @brief D-Bus method call implementation to get the info capacity.
     *
     * @return the info capacity
     */
    size_t infoLogCapacity() const override
    {
        return manager.getInfoLogCapacity();
    }

    /** @brief D-Bus method call implementation to create an event log with FFDC
     *
     * The same as create(), but takes an extra FFDC argument.
     *
     * @param[in] errMsg - The error exception message associated with the
     *                     error log to be committed.
     * @param[in] severity - Level of the error
     * @param[in] additionalData - The AdditionalData property for the error
     * @param[in] ffdc - A vector of FFDC file info
     */
    void createWithFFDCFiles(
        std::string message,
        sdbusplus::server::xyz::openbmc_project::logging::Entry::Level severity,
        std::map<std::string, std::string> additionalData,
        std::vector<std::tuple<CreateIface::FFDCFormat, uint8_t, uint8_t,
                               sdbusplus::message::unix_fd>>
            ffdc) override
    {
        manager.createWithFFDC(message, severity, additionalData, ffdc);
    }

  private:
    /** @brief This is a reference to manager object */
    internal::Manager& manager;
};

} // namespace logging
} // namespace phosphor

