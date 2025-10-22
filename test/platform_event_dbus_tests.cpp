#include "config.h"

#include "extensions.hpp"
#include "log_manager.hpp"
#include "paths.hpp"
#include "topology_test_helper.hpp"

#include <systemd/sd-event.h>

#include <phosphor-logging/asio_connection.hpp>
#include <phosphor-logging/commit.hpp>
#include <phosphor-logging/device_error_log.hpp>
#include <sdbusplus/async.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>

#include <set>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor::logging::test
{

// Reuse the same fixture pattern as log_manager_dbus_tests.cpp
class TestPlatformEventDbus : public ::testing::Test
{
  protected:
    // Create the daemon and sdbusplus::async::contexts.
    void SetUp() override
    {
        // The daemon requires directories to be created first.
        std::filesystem::create_directories(phosphor::logging::paths::error());

        data = std::make_unique<fixture_data>();

        // Setup test topology AFTER fixture is created
        // (fixture initialization calls Manager constructor which tries to
        // query EM) Build topology with test data (4 devices: BMC→Bridge→GPU,
        // BMC→CPU)
        auto testDevices = getTestTopologyData();
        buildTestTopology(testDevices);
    }

    // Stop the daemon, etc.
    void TearDown() override
    {
        // Clean up topology and interfaces (before destroying bus contexts)
        phosphor::logging::test::cleanupTestTopology();

        // Flush any pending asio operations from CommitDeviceError calls
        // The static io_context in AsioConnection accumulates async_method_call
        // operations that need to be processed to avoid memory leaks
        auto& connObject =
            phosphor::logging::AsioConnection::getAsioConnection();
        if (connObject)
        {
            // Poll the io_context to process any queued handlers
            // This ensures async_method_call lambdas are executed and cleaned
            // up
            connObject->get_io_context().poll();
            connObject->get_io_context().restart();
        }

        // Then destroy bus contexts and daemon
        data.reset();
    }

    // Structure to hold complete error details from D-Bus
    struct DeviceError
    {
        int64_t errorCode;
        std::string errorClass;
        std::map<std::string, std::string> additionalData;
    };

    struct DeviceStatusResult
    {
        int status; // 0=Healthy, 1=Degraded, -1=Error
        std::vector<DeviceError> errors;
    };

    // Helper: Query device status via D-Bus (coroutine-safe synchronous call)
    // Uses property-based interface: reads DeviceStatus property
    DeviceStatusResult queryDeviceStatus(uint8_t eid)
    {
        try
        {
            // Build object path: /com/nvidia/state/device_status/<EID>
            std::string objectPath =
                "/com/nvidia/state/device_status/" +
                std::to_string(static_cast<unsigned int>(eid));

            // Read DeviceStatus property via D-Bus Properties interface
            auto method = data->client_ctx.get_bus().new_method_call(
                "xyz.openbmc_project.Logging", objectPath.c_str(),
                "org.freedesktop.DBus.Properties", "Get");
            method.append("com.nvidia.State.DeviceState", "DeviceStatus");

            auto reply = data->client_ctx.get_bus().call(method);

            // Property returns: variant<map<StatusType, tuple<DeviceHealth,
            // vector<tuple<errorCode, ErrorClass, additionalData>>>>>
            std::variant<
                std::map<std::string,
                         std::tuple<std::string,
                                    std::vector<std::tuple<
                                        int64_t, std::string,
                                        std::map<std::string, std::string>>>>>>
                propertyValue;
            reply.read(propertyValue);

            auto statusMap = std::get<
                std::map<std::string,
                         std::tuple<std::string,
                                    std::vector<std::tuple<
                                        int64_t, std::string,
                                        std::map<std::string, std::string>>>>>>(
                propertyValue);

            // Extract Communication entry
            auto commIt = statusMap.find(
                "com.nvidia.State.DeviceState.StatusType.Communication");
            if (commIt == statusMap.end())
            {
                return {0, {}}; // No Communication entry = Healthy
            }

            auto [healthStr, rawErrors] = commIt->second;

            // Convert health string to int (0=Healthy, 1=Degraded)
            int deviceStatus =
                (healthStr.find("Healthy") != std::string::npos) ? 0 : 1;

            // Convert raw errors to our structure
            DeviceStatusResult result;
            result.status = deviceStatus;
            for (const auto& [errorCode, errorClass, additionalData] :
                 rawErrors)
            {
                result.errors.push_back(
                    {errorCode, errorClass, additionalData});
            }

            return result;
        }
        catch (const sdbusplus::exception_t& e)
        {
            // "Unknown object" means no errors have been logged yet for this
            // device This is expected behavior - return Healthy
            std::string error_msg(e.what());
            if (error_msg.find("Unknown object") != std::string::npos)
            {
                return {0, {}}; // No D-Bus object = No errors = Healthy
            }
            return {-1, {}};    // Other D-Bus error
        }
        catch (const std::exception&)
        {
            return {-1, {}}; // Other error occurred
        }
    }

    // Helper: Clear device errors via D-Bus (coroutine-safe synchronous call)
    // Uses property-based interface: writes DeviceStatus property with Healthy
    // status
    void clearDeviceErrors(uint8_t eid)
    {
        try
        {
            // Build object path: /com/nvidia/state/device_status/<EID>
            std::string objectPath =
                "/com/nvidia/state/device_status/" +
                std::to_string(static_cast<unsigned int>(eid));

            // To clear errors, write: {Communication: (Healthy, [])}
            std::map<std::string,
                     std::tuple<std::string,
                                std::vector<std::tuple<
                                    int64_t, std::string,
                                    std::map<std::string, std::string>>>>>
                clearValue;
            clearValue
                ["com.nvidia.State.DeviceState.StatusType.Communication"] =
                    std::make_tuple(
                        "com.nvidia.State.DeviceState.DeviceHealth.Healthy",
                        std::vector<
                            std::tuple<int64_t, std::string,
                                       std::map<std::string, std::string>>>());

            // Write DeviceStatus property via D-Bus Properties interface
            auto method = data->client_ctx.get_bus().new_method_call(
                "xyz.openbmc_project.Logging", objectPath.c_str(),
                "org.freedesktop.DBus.Properties", "Set");
            method.append(
                "com.nvidia.State.DeviceState", "DeviceStatus",
                std::variant<std::map<
                    std::string,
                    std::tuple<std::string,
                               std::vector<std::tuple<
                                   int64_t, std::string,
                                   std::map<std::string, std::string>>>>>>(
                    clearValue));

            data->client_ctx.get_bus().call(method);
        }
        catch (const std::exception&)
        {
            // Ignore errors during cleanup
        }
    }

    /** Run a client task, wait for it to complete, and stop daemon. */
    template <typename T>
    void run(T&& t)
    {
        data->client_ctx.spawn(std::move(t) | stdexec::then([this]() {
                                   data->stop(data->client_ctx);
                               }));
        data->client_ctx.run();
    }

    // Data for the fixture.
    struct fixture_data
    {
        fixture_data() :
            client_ctx(), server_ctx(),
            event(sdeventplus::Event::get_default()),
            objManager(server_ctx, OBJ_LOGGING), iMgr(server_ctx, OBJ_INTERNAL),
            mgr(server_ctx, OBJ_LOGGING, iMgr)
        {
            // Attach event loop to server bus
            server_ctx.get_bus().attach_event(event.get(),
                                              SD_EVENT_PRIORITY_NORMAL);

            // Call extension startup functions (this registers D-Bus
            // interfaces)
            for (auto& startup : Extensions::getStartupFunctions())
            {
                startup(iMgr);
            }

            // Create a thread for the daemon.
            // This will automatically load the nvidia-platform-event extension
            task = std::thread([this]() {
                server_ctx.request_name(BUSNAME_LOGGING);
                server_ctx.run();
            });

            // Give the server time to initialize
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ~fixture_data()
        {
            // Stop the server and wait for the thread to exit.
            stop(server_ctx);
            task.join();
        }

        // Spawn a task to gracefully shutdown an sdbusplus::async::context
        static void stop(sdbusplus::async::context& ctx)
        {
            ctx.spawn(stdexec::just() |
                      stdexec::then([&ctx]() { ctx.request_stop(); }));
        }

        sdbusplus::async::context client_ctx;
        sdbusplus::async::context server_ctx;
        sdeventplus::Event event;
        sdbusplus::server::manager_t objManager;
        internal::Manager iMgr;
        Manager mgr;
        std::thread task;

        // Topology manager for testing (owns device nodes)
    };

    std::unique_ptr<fixture_data> data;
};

// ============================================================================
// Test Case 1: Basic Error Creation via CommitDeviceError
// ============================================================================
TEST_F(TestPlatformEventDbus, BasicDeviceErrorCreation)
{
    using namespace nv::lg2;

    uint8_t deviceAddress = 17; // Use GPU (EID 17) from topology
    int64_t errorCode = 02;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Create device error using CommitDeviceError API
        // This triggers: CommitDeviceError -> D-Bus Create -> Extension Hook ->
        // Error Database
        auto info = phosphor::logging::test::getTestRedfishErrorInfo(
            errorCode, ErrorClass::MCTP);
        std::map<std::string, std::string> additionalData = {
            {"REDFISH_MESSAGE_ID", info.redfishMessageId},
            {"REDFISH_MESSAGE_ARGS", "Device_17, " + info.errorMessage}};

        nv::lg2::CommitDeviceError(deviceAddress, errorCode, ErrorClass::MCTP,
                                   additionalData);

        // Give extension time to process the async log creation
        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify error was created with all expected fields
        auto result = queryDeviceStatus(deviceAddress);
        EXPECT_EQ(result.status, 1); // 1 = Degraded
        EXPECT_EQ(result.errors.size(), 1);

        // Verify error details
        const auto& error = result.errors[0];
        EXPECT_EQ(error.errorCode, errorCode);
        EXPECT_EQ(error.errorClass,
                  "com.nvidia.State.DeviceState.ErrorClass.MCTP");

        // Verify D-Bus data matches GetRedfishErrorInfo() for same error
        // code/class
        auto expectedInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            error.errorCode, ErrorClass::MCTP);
        EXPECT_EQ(error.additionalData.at("ERROR_NUMBER"),
                  std::to_string(errorCode));
        EXPECT_EQ(error.additionalData.at("REDFISH_MESSAGE_ID"),
                  expectedInfo.redfishMessageId);
        // Verify REDFISH_MESSAGE_ARGS contains the error message from
        // GetRedfishErrorInfo
        EXPECT_TRUE(
            error.additionalData.at("REDFISH_MESSAGE_ARGS").find("Device_17") !=
            std::string::npos);
        EXPECT_TRUE(error.additionalData.at("REDFISH_MESSAGE_ARGS")
                        .find(expectedInfo.errorMessage) != std::string::npos);

        // Clean up: Clear the error
        clearDeviceErrors(deviceAddress);

        // Give time for clear to process
        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Verify error was cleared
        auto resultAfter = queryDeviceStatus(deviceAddress);
        EXPECT_EQ(resultAfter.status, 0); // 0 = Healthy
        EXPECT_EQ(resultAfter.errors.size(), 0);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// Test Case 2: FIFO Queue Test (Max Errors Per Class)
// ============================================================================
TEST_F(TestPlatformEventDbus, FIFOQueueTest)
{
    using namespace nv::lg2;

    uint8_t deviceAddress = 17; // Use GPU (EID 17) from topology

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Create 12 errors for same device/class (max is 10)
        // Oldest 2 should be dropped
        for (int i = 0; i < 12; i++)
        {
            auto info = phosphor::logging::test::getTestRedfishErrorInfo(
                i, ErrorClass::MCTP);
            nv::lg2::CommitDeviceError(
                deviceAddress, i, ErrorClass::MCTP,
                {{"REDFISH_MESSAGE_ID", info.redfishMessageId},
                 {"REDFISH_MESSAGE_ARGS", "GPU, " + info.errorMessage}});
        }

        // Give extension time to process
        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Verify: Should only have 10 most recent errors (FIFO dropped 2
        // oldest)
        auto result = queryDeviceStatus(deviceAddress);
        EXPECT_EQ(result.status, 1);         // Degraded
        EXPECT_EQ(result.errors.size(), 10); // Max 10 errors per class

        // Verify FIFO: Should have errors 2-11 (dropped 0 and 1)
        std::set<int64_t> errorCodes;
        for (const auto& err : result.errors)
        {
            errorCodes.insert(err.errorCode);
        }
        EXPECT_EQ(errorCodes.count(0), 0);  // Error 0 should be dropped
        EXPECT_EQ(errorCodes.count(1), 0);  // Error 1 should be dropped
        EXPECT_EQ(errorCodes.count(11), 1); // Error 11 should be present

        // Clean up
        clearDeviceErrors(deviceAddress);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// Test Case 3: All Error Code Types
// ============================================================================
TEST_F(TestPlatformEventDbus, AllErrorCodeTypes)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Test error codes using topology devices (BMC=1, Bridge=16, GPU=17,
        // CPU=32) Use the same device for multiple error classes to cover all
        // error types

        // Power Status codes on BMC (EID 1)
        auto info1 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_ON, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_ON, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", info1.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, " + info1.errorMessage}});

        auto info2 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", info2.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "Bridge, " + info2.errorMessage}});

        // Recovery codes on GPU (EID 17)
        auto info3 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::Recovery::IN_RECOVERY, ErrorClass::Recovery);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::Recovery::IN_RECOVERY, ErrorClass::Recovery,
            {{"REDFISH_MESSAGE_ID", info3.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, " + info3.errorMessage}});

        auto info4 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::Recovery::NOT_IN_RECOVERY, ErrorClass::Recovery);
        nv::lg2::CommitDeviceError(
            32, ErrorCode::Recovery::NOT_IN_RECOVERY, ErrorClass::Recovery,
            {{"REDFISH_MESSAGE_ID", info4.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "CPU, " + info4.errorMessage}});

        // Physical Interface codes on BMC and Bridge (reusing devices)
        auto info5 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PhysicalInterface::PRESENT,
            ErrorClass::PhysicalInterface);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PhysicalInterface::PRESENT,
            ErrorClass::PhysicalInterface,
            {{"REDFISH_MESSAGE_ID", info5.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, " + info5.errorMessage}});

        auto info6 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PhysicalInterface::ABSENT,
            ErrorClass::PhysicalInterface);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::PhysicalInterface::ABSENT,
            ErrorClass::PhysicalInterface,
            {{"REDFISH_MESSAGE_ID", info6.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "Bridge, " + info6.errorMessage}});

        // MCTP codes on GPU and CPU (reusing devices)
        auto info7 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::PING_SUCCESS, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::PING_SUCCESS, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info7.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, " + info7.errorMessage}});

        auto info8 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            32, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info8.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "CPU, " + info8.errorMessage}});

        auto info9 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info9.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, " + info9.errorMessage}});

        auto info10 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::USB_TX_MEMORY_ALLOC_FAILURE, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::USB_TX_MEMORY_ALLOC_FAILURE, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info10.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "Bridge, " + info10.errorMessage}});

        // Give extension time to process all errors
        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(500));

        // Verify: Each device has errors and Redfish info is preserved
        // Note: Devices now have multiple errors from different classes

        // BMC (EID 1): Should have Power, Physical, and MCTP errors
        auto resultBMC = queryDeviceStatus(1);
        EXPECT_GE(resultBMC.errors.size(),
                  1); // At least one error (highest priority shown)
        // Verify at least one error has proper Redfish info
        EXPECT_TRUE(!resultBMC.errors[0]
                         .additionalData.at("REDFISH_MESSAGE_ID")
                         .empty());

        // Bridge (EID 16): Should have Power, Physical, and MCTP errors
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_GE(resultBridge.errors.size(), 1);
        EXPECT_TRUE(!resultBridge.errors[0]
                         .additionalData.at("REDFISH_MESSAGE_ID")
                         .empty());

        // GPU (EID 17): Should have Recovery and MCTP errors
        auto resultGPU = queryDeviceStatus(17);
        EXPECT_GE(resultGPU.errors.size(), 1);
        EXPECT_TRUE(!resultGPU.errors[0]
                         .additionalData.at("REDFISH_MESSAGE_ID")
                         .empty());

        // CPU (EID 32): Should have Recovery and MCTP errors
        auto resultCPU = queryDeviceStatus(32);
        EXPECT_GE(resultCPU.errors.size(), 1);
        EXPECT_TRUE(!resultCPU.errors[0]
                         .additionalData.at("REDFISH_MESSAGE_ID")
                         .empty());

        // Clean up all test devices
        clearDeviceErrors(1);
        clearDeviceErrors(16);
        clearDeviceErrors(17);
        clearDeviceErrors(32);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// Negative Test Cases
// ============================================================================

// ============================================================================
// Negative Test 1: Missing REDFISH_MESSAGE_ID is Rejected
// ============================================================================
TEST_F(TestPlatformEventDbus, MissingRedfishFields)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // CommitDeviceError without REDFISH_MESSAGE_ID should be rejected
        // This validates that we don't create logs with mismatched Redfish
        // messages
        nv::lg2::CommitDeviceError(17, 02, ErrorClass::MCTP, {});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Should NOT create any error (early return due to validation failure)
        // Function logs error to journal and returns without creating D-Bus log
        // entry
        auto result = queryDeviceStatus(17);
        EXPECT_EQ(result.status, 0);        // Healthy (no error created)
        EXPECT_EQ(result.errors.size(), 0); // No errors

        co_return;
    };

    run(test_task());
}

// ============================================================================
// Negative Test 2: Empty REDFISH_MESSAGE_ID is Rejected
// ============================================================================
TEST_F(TestPlatformEventDbus, EmptyRedfishFields)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // CommitDeviceError with empty REDFISH_MESSAGE_ID should be rejected
        // This validates that empty strings are also caught by validation
        nv::lg2::CommitDeviceError(
            16, 02, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", ""}, {"REDFISH_MESSAGE_ARGS", ""}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Should NOT create any error (empty string is also invalid)
        auto result = queryDeviceStatus(16);
        EXPECT_EQ(result.status, 0);        // Healthy (no error created)
        EXPECT_EQ(result.errors.size(), 0); // No errors

        co_return;
    };

    run(test_task());
}

// ============================================================================
// Negative Test 3: Duplicate Error Insertion
// ============================================================================
TEST_F(TestPlatformEventDbus, DuplicateErrors)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Insert same error multiple times
        auto info = phosphor::logging::test::getTestRedfishErrorInfo(
            02, ErrorClass::MCTP);
        for (int i = 0; i < 5; i++)
        {
            nv::lg2::CommitDeviceError(
                1, 02, ErrorClass::MCTP,
                {{"REDFISH_MESSAGE_ID", info.redfishMessageId},
                 {"REDFISH_MESSAGE_ARGS", "Device_1, " + info.errorMessage}});
        }

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Should have 5 instances of same error
        auto result = queryDeviceStatus(1);
        EXPECT_EQ(result.status, 1);
        EXPECT_EQ(result.errors.size(), 5);

        // All should have same error code
        for (const auto& err : result.errors)
        {
            EXPECT_EQ(err.errorCode, 02);
        }

        clearDeviceErrors(1);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_01: Bridge MCTP Failure - GPU Reports Healthy When It Has No Errors
// SCENARIO: Bridge experiences FIFO overflow causing MCTP failure, but GPU
// has no errors. With the new parent precedence logic, GPU correctly reports
// healthy (status=0, errors=0) because parent precedence only applies when
// the child device itself has errors.
// Reference: Bug 5367880, 5367595
// ============================================================================
TEST_F(TestPlatformEventDbus, BridgeMctpFailureBlocksGpuCommunication)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: Bridge (10) → GPU (11)
        // Bridge experiences MCTP communication failure (FIFO overflow)

        // Verify all devices initially healthy
        auto resultBridgeBefore = queryDeviceStatus(16);
        EXPECT_EQ(resultBridgeBefore.status, 0); // Healthy

        auto resultGpuBefore = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuBefore.status, 0); // Healthy

        // Inject Bridge MCTP failure (simulating FIFO overflow)
        auto bridgeInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", bridgeInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU - GPU has no errors, so returns healthy (parent precedence
        // only applies when child has errors)
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 0); // Healthy (GPU itself has no errors)
        EXPECT_EQ(resultGpu.errors.size(), 0);

        // Query Bridge directly - should show its own MCTP error
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_EQ(resultBridge.status, 1); // Degraded
        EXPECT_GE(resultBridge.errors.size(), 1);
        EXPECT_EQ(resultBridge.errors[0].errorCode,
                  ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT);

        // Cleanup
        clearDeviceErrors(16);
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_02: Bridge Failure Hides GPU's Own MCTP Error
// SCENARIO: GPU has MCTP timeout, then Bridge also fails with MCTP error.
// Even with same priority, parent error takes precedence. Validates
// administrators fix Bridge first before investigating GPU. Reference: Bug
// 5285443
// ============================================================================
TEST_F(TestPlatformEventDbus, BridgeFailureHidesGpuOwnMctpError)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: Bridge (10) → GPU (11)

        // Inject GPU's own MCTP timeout (Priority 1)
        auto gpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify GPU shows its own MCTP error
        auto resultGpu1 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu1.status, 1); // Degraded
        EXPECT_GE(resultGpu1.errors.size(), 1);
        EXPECT_EQ(resultGpu1.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT);

        // Inject Bridge MCTP failure (same Priority 1 as GPU)
        auto bridgeInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", bridgeInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU - should now show Bridge's error (parent precedence)
        auto resultGpu2 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu2.status, 1); // Degraded
        EXPECT_GE(resultGpu2.errors.size(), 1);
        EXPECT_EQ(
            resultGpu2.errors[0].errorCode,
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT); // Bridge's
                                                                // error

        // Clear Bridge error - GPU's own error should now be visible
        clearDeviceErrors(16);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Query GPU again - should show its own error (error code 03)
        auto resultGpu3 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu3.status, 1); // Degraded
        EXPECT_GE(resultGpu3.errors.size(), 1);
        EXPECT_EQ(resultGpu3.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT); // GPU's error

        // Cleanup
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_03: Bridge Recovery Restores GPU Visibility
// SCENARIO: After Bridge GPIO reset recovery, Bridge comes back online.
// Validates complete recovery workflow: clearing Bridge errors makes GPU's
// true status visible again.
// Reference: Bug 5230677, 5137049
// ============================================================================
TEST_F(TestPlatformEventDbus, BridgeRecoveryRestoresGpuVisibility)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: Bridge (10) → GPU (11)

        // Create Bridge MCTP failure and GPU's own error
        auto bridgeInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", bridgeInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        auto gpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify GPU shows Bridge error (parent precedence)
        auto resultGpu1 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu1.status, 1); // Degraded
        EXPECT_GE(resultGpu1.errors.size(), 1);
        EXPECT_EQ(
            resultGpu1.errors[0].errorCode,
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT); // Bridge's
                                                                // error

        // Simulate Bridge recovery - clear Bridge errors (GPIO reset +
        // recovery)
        clearDeviceErrors(16);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Query GPU - should now show GPU's own error (Bridge healthy)
        auto resultGpu2 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu2.status, 1); // Degraded
        EXPECT_GE(resultGpu2.errors.size(), 1);
        EXPECT_EQ(resultGpu2.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT); // GPU's error

        // Cleanup GPU error
        clearDeviceErrors(17);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Verify GPU is now fully healthy
        auto resultGpu3 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu3.status, 0); // Healthy
        EXPECT_EQ(resultGpu3.errors.size(), 0);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_04: Multiple Children Under Same Parent - BMC Error Propagates
// SCENARIO: BMC has power status error affecting all direct children (Bridge
// and CPU). Validates that when parent fails, all child devices correctly
// report parent's error.
// ============================================================================
TEST_F(TestPlatformEventDbus, MultipleChildrenUnderSameParent)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10) and CPU (20)

        // Create errors on both children
        auto bridgeInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", bridgeInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        auto cpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            32, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", cpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "CPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify each child shows its own error (parent BMC is healthy)
        auto resultBridge1 = queryDeviceStatus(16);
        EXPECT_GE(resultBridge1.errors.size(), 1);
        EXPECT_EQ(resultBridge1.errors[0].errorCode,
                  ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT);

        auto resultCPU1 = queryDeviceStatus(32);
        EXPECT_GE(resultCPU1.errors.size(), 1);
        EXPECT_EQ(resultCPU1.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT);

        // Inject BMC power error (Priority 0, higher than children's Priority
        // 1)
        auto bmcInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", bmcInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Both children should now show BMC's power error (parent precedence +
        // higher priority)
        auto resultBridge2 = queryDeviceStatus(16);
        EXPECT_GE(resultBridge2.errors.size(), 1);
        EXPECT_EQ(resultBridge2.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF); // BMC's error
        EXPECT_TRUE(resultBridge2.errors[0].errorClass.find("Power") !=
                    std::string::npos);

        auto resultCPU2 = queryDeviceStatus(32);
        EXPECT_GE(resultCPU2.errors.size(), 1);
        EXPECT_EQ(resultCPU2.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF); // BMC's error
        EXPECT_TRUE(resultCPU2.errors[0].errorClass.find("Power") !=
                    std::string::npos);

        // Cleanup
        clearDeviceErrors(1);
        clearDeviceErrors(16);
        clearDeviceErrors(32);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_05: Three-Level Hierarchy - Immediate Parent Only
// SCENARIO: In BMC→Bridge→GPU, GPU only checks immediate parent (Bridge), not
// grandparent (BMC). If BMC has error but Bridge is healthy, GPU shows its own
// status. Validates single-level parent checking per design.
// ============================================================================
TEST_F(TestPlatformEventDbus, ThreeLevelHierarchyImmediateParentOnly)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10) → GPU (11)

        // Create BMC error (grandparent of GPU)
        auto bmcInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", bmcInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        // Create GPU error (no Bridge error - Bridge is healthy)
        auto gpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // GPU should show BMC's propagated power error (Priority 0), not its
        // own MCTP error (Priority 1) Even though GPU only checks immediate
        // parent Bridge for parent precedence, the power error was propagated
        // recursively from BMC to all power-dependent descendants
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 1); // Degraded
        EXPECT_GE(resultGpu.errors.size(), 1);
        EXPECT_EQ(
            resultGpu.errors[0].errorCode,
            ErrorCode::PowerStatus::POWER_OFF); // BMC's propagated power error
        EXPECT_TRUE(resultGpu.errors[0].errorClass.find("Power") !=
                    std::string::npos);

        // Bridge has no errors, so reports healthy (parent precedence only
        // applies when child has errors)
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_EQ(resultBridge.status,
                  0); // Healthy (Bridge itself has no errors)
        EXPECT_EQ(resultBridge.errors.size(), 0);

        // BMC should show its own power error
        auto resultBMC = queryDeviceStatus(1);
        EXPECT_GE(resultBMC.errors.size(), 1);
        EXPECT_EQ(resultBMC.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);

        // Cleanup
        clearDeviceErrors(1);
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_06: Power Error Overrides GPU MCTP Error - Priority 0 vs Priority 1
// SCENARIO: GPU has MCTP timeout (Priority 1), then system enters standby
// (POWER_OFF, Priority 0). Higher priority power errors override lower priority
// communication errors. Reference: Bug 5335608
// ============================================================================
TEST_F(TestPlatformEventDbus, PowerErrorOverridesGpuMctpError)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → GPU (11)

        // Inject GPU MCTP timeout (Priority 1)
        auto gpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device communication failed due to device ping timeout"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify GPU shows MCTP error
        auto resultGpu1 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu1.status, 1); // Degraded
        EXPECT_GE(resultGpu1.errors.size(), 1);
        EXPECT_EQ(resultGpu1.errors[0].errorCode,
                  ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT);

        // System enters standby power - inject BMC POWER_OFF (Priority 0)
        // This will auto-propagate to GPU (poweredInStandby: true)
        auto bmcInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", bmcInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Query GPU - should now show ONLY power error (Priority 0), hiding
        // MCTP error (Priority 1)
        auto resultGpu2 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu2.status, 1); // Degraded
        EXPECT_GE(resultGpu2.errors.size(), 1);
        EXPECT_EQ(resultGpu2.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);
        EXPECT_TRUE(resultGpu2.errors[0].errorClass.find("Power") !=
                    std::string::npos);

        // Cleanup
        clearDeviceErrors(1);
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_07: Physical Interface Absent Overrides Bridge MCTP Error
// SCENARIO: Bridge USB cable disconnected causes Physical Interface ABSENT
// (Priority 1) and MCTP failure (Priority 1 symptom). Physical layer errors
// reported first.
// ============================================================================
TEST_F(TestPlatformEventDbus, PhysicalInterfaceAbsentOverridesBridgeMctpError)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10) → GPU (11)

        // Inject Bridge MCTP error first (Priority 1)
        auto mctpInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", mctpInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        // Inject Bridge Physical Interface ABSENT (Priority 1, same as MCTP)
        auto physInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PhysicalInterface::ABSENT,
            ErrorClass::PhysicalInterface);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::PhysicalInterface::ABSENT,
            ErrorClass::PhysicalInterface,
            {{"REDFISH_MESSAGE_ID", physInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, Device not detected or removed"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query Bridge - should show both errors (same priority), physical
        // layer should be present
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_EQ(resultBridge.status, 1); // Degraded
        EXPECT_GE(resultBridge.errors.size(), 1);

        // At least one error should be Physical Interface
        bool hasPhysical = false;
        for (const auto& err : resultBridge.errors)
        {
            if (err.errorClass.find("PhysicalInterface") != std::string::npos)
            {
                hasPhysical = true;
                break;
            }
        }
        EXPECT_TRUE(hasPhysical);

        // Query GPU - GPU has no errors, so reports healthy (parent precedence
        // only applies when child has errors)
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 0); // Healthy (GPU itself has no errors)
        EXPECT_EQ(resultGpu.errors.size(), 0);

        // Cleanup
        clearDeviceErrors(16);
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_08: GPU In Recovery Mode Blocks Firmware Update
// SCENARIO: GPU enters recovery mode (Priority 0) while having MCTP errors
// (Priority 1). Recovery Status takes precedence, blocking FW updates during
// unstable state. Reference: Bug 5066653, 5071945
// ============================================================================
TEST_F(TestPlatformEventDbus, GpuInRecoveryModeBlocksFirmwareUpdate)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → GPU (11)

        // Inject GPU MCTP error (Priority 1, lower priority)
        auto mctpInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", mctpInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device communication failed due to device ping timeout"}});

        // Inject GPU Recovery Status (Priority 0, higher priority)
        auto recoveryInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::Recovery::IN_RECOVERY, ErrorClass::Recovery);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::Recovery::IN_RECOVERY, ErrorClass::Recovery,
            {{"REDFISH_MESSAGE_ID", recoveryInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, Device entered recovery mode"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU - should show ONLY Recovery Status (Priority 0), hiding
        // MCTP (Priority 1)
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 1); // Degraded
        EXPECT_GE(resultGpu.errors.size(), 1);
        EXPECT_EQ(resultGpu.errors[0].errorCode,
                  ErrorCode::Recovery::IN_RECOVERY);
        EXPECT_TRUE(resultGpu.errors[0].errorClass.find("Recovery") !=
                    std::string::npos);

        // Cleanup
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_09: BMC Power Off Overrides CPU MCTP Error - Cross-Device Priority
// SCENARIO: CPU has MCTP timeout (Priority 1), then BMC power supply fails
// (Priority 0). CPU query shows BMC's power error (from parent) instead of its
// own MCTP error. Reference: Bug 5335608
// ============================================================================
TEST_F(TestPlatformEventDbus, BmcPowerOffOverridesCpuMctpError)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → CPU (20)

        // Inject CPU MCTP timeout (Priority 1)
        auto cpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            32, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", cpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "CPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify CPU shows its own MCTP error
        auto resultCpu1 = queryDeviceStatus(32);
        EXPECT_EQ(resultCpu1.status, 1); // Degraded
        EXPECT_GE(resultCpu1.errors.size(), 1);
        EXPECT_EQ(resultCpu1.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT);

        // Inject BMC POWER_OFF (Priority 0, higher than CPU's Priority 1)
        auto bmcInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", bmcInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Query CPU - should show BMC's power error (Priority 0 from parent),
        // not CPU's MCTP (Priority 1)
        auto resultCpu2 = queryDeviceStatus(32);
        EXPECT_EQ(resultCpu2.status, 1); // Degraded
        EXPECT_GE(resultCpu2.errors.size(), 1);
        EXPECT_EQ(resultCpu2.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);
        EXPECT_TRUE(resultCpu2.errors[0].errorClass.find("Power") !=
                    std::string::npos);

        // Cleanup
        clearDeviceErrors(1);
        clearDeviceErrors(32);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_10: Multiple Priority 0 Errors Both Reported - No Filtering Within Same
// Priority SCENARIO: GPU has both power issue (POWER_OFF, Priority 0) and
// recovery issue (IN_RECOVERY, Priority 0). Both errors should be reported
// without arbitrary filtering.
// ============================================================================
TEST_F(TestPlatformEventDbus, MultiplePriority0ErrorsBothReported)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → GPU (11)

        // Inject GPU Power Status error (Priority 0)
        auto powerInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", powerInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, Device powered off"}});

        // Inject GPU Recovery Status error (Priority 0, same as Power)
        auto recoveryInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::Recovery::IN_RECOVERY, ErrorClass::Recovery);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::Recovery::IN_RECOVERY, ErrorClass::Recovery,
            {{"REDFISH_MESSAGE_ID", recoveryInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, Device entered recovery mode"}});

        // Inject lower priority MCTP error (Priority 1) - should be hidden
        auto mctpInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", mctpInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device communication failed due to device ping timeout"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU - should show BOTH Priority 0 errors, hide Priority 1
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 1); // Degraded
        EXPECT_GE(resultGpu.errors.size(),
                  2);                   // At least 2 errors (both Priority 0)

        // Verify both error classes are present
        bool hasPower = false, hasRecovery = false, hasMctp = false;
        for (const auto& err : resultGpu.errors)
        {
            if (err.errorClass.find("Power") != std::string::npos)
                hasPower = true;
            if (err.errorClass.find("Recovery") != std::string::npos)
                hasRecovery = true;
            if (err.errorClass.find("MCTP") != std::string::npos)
                hasMctp = true;
        }
        EXPECT_TRUE(hasPower);
        EXPECT_TRUE(hasRecovery);
        EXPECT_FALSE(hasMctp); // Priority 1 should be hidden

        // Cleanup
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_11: Power Off Propagates To Power-Dependent Devices - Selective
// Propagation SCENARIO: System enters standby (BMC logs POWER_OFF). Only
// power-dependent devices (GPU, CPU with poweredInStandby: true) receive
// propagated errors. Infrastructure devices (Bridge with poweredInStandby:
// false) don't get propagated errors. Reference: Bug 5335608
// ============================================================================
TEST_F(TestPlatformEventDbus, PowerOffPropagatesToPowerDependentDevices)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10, poweredInStandby: false) → GPU
        // (11, poweredInStandby: true)
        //           BMC → CPU (20, poweredInStandby: true)

        // Verify all devices healthy initially
        auto resultGpuBefore = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuBefore.status, 0); // Healthy

        auto resultCpuBefore = queryDeviceStatus(32);
        EXPECT_EQ(resultCpuBefore.status, 0); // Healthy

        // BMC logs POWER_OFF (Priority 0) - triggers selective propagation
        auto bmcInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", bmcInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Query GPU - should have propagated power error (poweredInStandby:
        // true)
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 1); // Degraded
        EXPECT_GE(resultGpu.errors.size(), 1);
        EXPECT_EQ(resultGpu.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);

        // Query CPU - should have propagated power error (poweredInStandby:
        // true)
        auto resultCpu = queryDeviceStatus(32);
        EXPECT_EQ(resultCpu.status, 1); // Degraded
        EXPECT_GE(resultCpu.errors.size(), 1);
        EXPECT_EQ(resultCpu.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);

        // Query Bridge - healthy because it has no errors (parent precedence
        // only applies when child has errors)
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_EQ(resultBridge.status,
                  0); // Healthy (Bridge itself has no errors)
        EXPECT_EQ(resultBridge.errors.size(), 0);

        // Clear BMC error, verify GPU and CPU still have propagated errors
        clearDeviceErrors(1);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // GPU should still have propagated error (has its own copy)
        auto resultGpuAfter = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuAfter.status, 1); // Still Degraded
        EXPECT_GE(resultGpuAfter.errors.size(), 1);

        // Bridge should now be healthy (had no propagated copy, only showed
        // parent error)
        auto resultBridgeAfter = queryDeviceStatus(16);
        EXPECT_EQ(resultBridgeAfter.status, 0); // Healthy

        // Cleanup
        clearDeviceErrors(17);
        clearDeviceErrors(32);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_12: Power On Auto-Clears Propagated Errors From Power-Dependent Devices
// SCENARIO: After system exits standby (BMC logs POWER_ON), all propagated
// power errors on power-dependent devices (GPU, CPU) should be automatically
// cleared.
// ============================================================================
TEST_F(TestPlatformEventDbus, PowerOnAutoClearsPropagatedErrors)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → GPU (11, poweredInStandby: true), BMC → CPU
        // (20, poweredInStandby: true)

        // BMC logs POWER_OFF - propagates to GPU and CPU
        auto powerOffInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", powerOffInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Verify GPU has propagated power error
        auto resultGpuBefore = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuBefore.status, 1); // Degraded
        EXPECT_GE(resultGpuBefore.errors.size(), 1);

        // Verify CPU has propagated power error
        auto resultCpuBefore = queryDeviceStatus(32);
        EXPECT_EQ(resultCpuBefore.status, 1); // Degraded
        EXPECT_GE(resultCpuBefore.errors.size(), 1);

        // System powers on - BMC logs POWER_ON (triggers auto-clear)
        auto powerOnInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_ON, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_ON, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", powerOnInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered on successfully"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Clear BMC errors (to remove both POWER_OFF and POWER_ON from BMC)
        clearDeviceErrors(1);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU - should be healthy (propagated error auto-cleared by
        // POWER_ON)
        auto resultGpuAfter = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuAfter.status, 0); // Healthy
        EXPECT_EQ(resultGpuAfter.errors.size(), 0);

        // Query CPU - should be healthy (propagated error auto-cleared by
        // POWER_ON)
        auto resultCpuAfter = queryDeviceStatus(32);
        EXPECT_EQ(resultCpuAfter.status, 0); // Healthy
        EXPECT_EQ(resultCpuAfter.errors.size(), 0);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_12B: Power Clear Reveals Original MCTP Error
// SCENARIO: GPU has its own MCTP error (Priority 1), then BMC logs POWER_OFF
// (Priority 0) which propagates to GPU and hides the MCTP error. When BMC logs
// POWER_ON, the propagated power error is cleared, revealing GPU's original
// MCTP error again.
// This validates that clearPropagatedPowerErrorsFromDescendants() only clears
// propagated power errors, not the device's own errors.
// ============================================================================
TEST_F(TestPlatformEventDbus, PowerClearRevealsOriginalMctpError)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → GPU (11, poweredInStandby: true)

        // STEP 1: Create GPU's own MCTP error (Priority 1)
        auto gpuMctpInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuMctpInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify GPU shows its own MCTP error
        auto resultGpu1 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu1.status, 1); // Degraded
        EXPECT_GE(resultGpu1.errors.size(), 1);
        EXPECT_EQ(resultGpu1.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT);
        EXPECT_TRUE(resultGpu1.errors[0].errorClass.find("MCTP") !=
                    std::string::npos);

        // STEP 2: BMC logs POWER_OFF (Priority 0) - propagates to GPU
        // This should hide GPU's MCTP error because Priority 0 > Priority 1
        auto powerOffInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", powerOffInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Verify GPU now shows POWER_OFF (propagated), hiding MCTP error
        auto resultGpu2 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu2.status, 1); // Degraded
        EXPECT_GE(resultGpu2.errors.size(), 1);
        EXPECT_EQ(resultGpu2.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);
        EXPECT_TRUE(resultGpu2.errors[0].errorClass.find("Power") !=
                    std::string::npos);

        // STEP 3: BMC logs POWER_ON - triggers
        // clearPropagatedPowerErrorsFromDescendants() This should clear ONLY
        // the propagated power error from GPU, NOT the GPU's own MCTP error
        auto powerOnInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_ON, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_ON, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", powerOnInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered on successfully"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Clear BMC errors (to remove both POWER_OFF and POWER_ON from BMC)
        clearDeviceErrors(1);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // STEP 4: Verify GPU now shows its ORIGINAL MCTP error again
        // The propagated power error was cleared, but GPU's own MCTP error
        // remains
        auto resultGpu3 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu3.status, 1); // Still Degraded (has MCTP error)
        EXPECT_GE(resultGpu3.errors.size(), 1);
        EXPECT_EQ(
            resultGpu3.errors[0].errorCode,
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT); // Original MCTP error
        EXPECT_TRUE(resultGpu3.errors[0].errorClass.find("MCTP") !=
                    std::string::npos);

        // Cleanup
        clearDeviceErrors(17);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Verify GPU is now fully healthy
        auto resultGpu4 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu4.status, 0); // Healthy
        EXPECT_EQ(resultGpu4.errors.size(), 0);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_13: Power Propagation Selective By Device Property
// SCENARIO: BMC logs POWER_OFF. GPU (poweredInStandby: true) receives
// propagated error. Bridge (poweredInStandby: false) does NOT have propagated
// error, only shows parent error.
// ============================================================================
TEST_F(TestPlatformEventDbus, PowerPropagationSelectiveByDeviceProperty)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10, poweredInStandby: false) → GPU
        // (11, poweredInStandby: true)

        // Create GPU's own MCTP error (to distinguish from propagated power
        // error)
        auto gpuMctpInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuMctpInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify GPU has its MCTP error
        auto resultGpuBefore = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuBefore.status, 1); // Degraded
        EXPECT_GE(resultGpuBefore.errors.size(), 1);

        // BMC logs POWER_OFF (triggers selective propagation)
        auto bmcPowerInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", bmcPowerInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // Verify GPU now has power error (propagated), MCTP hidden by priority
        auto resultGpuAfter = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuAfter.status, 1); // Degraded
        EXPECT_GE(resultGpuAfter.errors.size(), 1);
        EXPECT_EQ(resultGpuAfter.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);

        // Verify Bridge is healthy (has no errors - parent precedence only
        // applies when child has errors)
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_EQ(resultBridge.status,
                  0); // Healthy (Bridge itself has no errors)
        EXPECT_EQ(resultBridge.errors.size(), 0);

        // Clear BMC error - verify GPU still has propagated copy, Bridge now
        // healthy
        clearDeviceErrors(1);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // GPU still Degraded (has propagated copy in its database)
        auto resultGpuFinal = queryDeviceStatus(17);
        EXPECT_EQ(resultGpuFinal.status, 1); // Still Degraded
        EXPECT_GE(resultGpuFinal.errors.size(), 1);

        // Bridge now Healthy (had no propagated copy)
        auto resultBridgeFinal = queryDeviceStatus(16);
        EXPECT_EQ(resultBridgeFinal.status, 0); // Healthy

        // Cleanup
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_14: Child Error Visible After Parent Recovery - Two-Step Recovery
// Workflow SCENARIO: Bridge has MCTP failure, GPU has its own MCTP error.
// Initially GPU shows Bridge error. After Bridge recovery, GPU's own error
// becomes visible. Reference: Bug 5137049
// ============================================================================
TEST_F(TestPlatformEventDbus, ChildErrorVisibleAfterParentRecovery)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10) → GPU (11)

        // Create both Bridge and GPU MCTP errors (same priority)
        auto bridgeInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", bridgeInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        auto gpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Verify GPU shows Bridge error (parent precedence)
        auto resultGpu1 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu1.status, 1); // Degraded
        EXPECT_GE(resultGpu1.errors.size(), 1);
        EXPECT_EQ(
            resultGpu1.errors[0].errorCode,
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT); // Bridge's
                                                                // error

        // Recover Bridge - clear Bridge errors (GPIO reset recovery)
        clearDeviceErrors(16);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Query GPU - should now show its own error (Bridge recovered)
        auto resultGpu2 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu2.status, 1); // Degraded
        EXPECT_GE(resultGpu2.errors.size(), 1);
        EXPECT_EQ(resultGpu2.errors[0].errorCode,
                  ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT); // GPU's error

        // Recover GPU - clear GPU errors
        clearDeviceErrors(17);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Verify GPU fully healthy
        auto resultGpu3 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu3.status, 0); // Healthy
        EXPECT_EQ(resultGpu3.errors.size(), 0);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_15: Same Priority Same Class Different Codes - Parent Error Shown
// SCENARIO: GPU and Bridge both have MCTP errors with different error codes,
// same error class, same priority. Parent error takes precedence.
// ============================================================================
TEST_F(TestPlatformEventDbus, SamePrioritySameClassDifferentCodes)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01) → Bridge (10) → GPU (11)

        // Inject GPU MCTP error (error code 03, Priority 1)
        auto gpuInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", gpuInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, MCTP device discovery failed due to timeout error to obtain UUID"}});

        // Inject Bridge MCTP error (error code 02, Priority 1, same
        // class/priority as GPU)
        auto bridgeInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            16, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", bridgeInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Bridge1, MCTP device communication failed due to device ping timeout"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU - should show Bridge error code 02 (NOT GPU's own 03)
        auto resultGpu = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu.status, 1); // Degraded
        EXPECT_GE(resultGpu.errors.size(), 1);
        EXPECT_EQ(
            resultGpu.errors[0].errorCode,
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT); // Bridge's
                                                                // error
        EXPECT_TRUE(resultGpu.errors[0].errorClass.find("MCTP") !=
                    std::string::npos);

        // Query Bridge - should show its own error code 02
        auto resultBridge = queryDeviceStatus(16);
        EXPECT_GE(resultBridge.errors.size(), 1);
        EXPECT_EQ(resultBridge.errors[0].errorCode,
                  ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT);

        // Cleanup
        clearDeviceErrors(16);
        clearDeviceErrors(17);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_16: Device Without Parent Shows Own Errors - Root Device Behavior
// SCENARIO: BMC is the root device with no parent. It should always show its
// own errors without checking any parent device.
// ============================================================================
TEST_F(TestPlatformEventDbus, DeviceWithoutParentShowsOwnErrors)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Topology: BMC (01, no parent)

        // Inject BMC Physical Interface error (Priority 1)
        auto physInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PhysicalInterface::ABSENT,
            ErrorClass::PhysicalInterface);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PhysicalInterface::ABSENT,
            ErrorClass::PhysicalInterface,
            {{"REDFISH_MESSAGE_ID", physInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device not detected or removed"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query BMC - should show its own error (no parent to check)
        auto resultBMC1 = queryDeviceStatus(1);
        EXPECT_EQ(resultBMC1.status, 1); // Degraded
        EXPECT_GE(resultBMC1.errors.size(), 1);
        EXPECT_EQ(resultBMC1.errors[0].errorCode,
                  ErrorCode::PhysicalInterface::ABSENT);

        // Inject BMC Power error (Priority 0, higher priority)
        auto powerInfo = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            1, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", powerInfo.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "BMC, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query BMC - should show only Power error (Priority 0), Physical
        // Interface hidden (Priority 1)
        auto resultBMC2 = queryDeviceStatus(1);
        EXPECT_EQ(resultBMC2.status, 1); // Degraded
        EXPECT_GE(resultBMC2.errors.size(), 1);
        EXPECT_EQ(resultBMC2.errors[0].errorCode,
                  ErrorCode::PowerStatus::POWER_OFF);

        // Cleanup
        clearDeviceErrors(1);
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_17: Device Not In Topology Fallback Behavior - Graceful Degradation
// SCENARIO: Devices not registered in topology (EID 80, 81) should
// gracefully fall back to showing their own errors without parent checking.
// ============================================================================
// ============================================================================
// Test: Errors from devices NOT in topology are REJECTED
// SCENARIO: Devices 80, 81 are NOT in the topology configuration from
// EntityManager. Errors logged for these devices should be rejected with a
// warning message. D-Bus objects should NOT be created for them.
// This ensures only known devices from topology can have status.
// ============================================================================
TEST_F(TestPlatformEventDbus, DeviceNotInTopologyFallbackBehavior)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Devices 80, 81 NOT in topology configuration
        // Errors for these devices should be REJECTED

        // Inject error on device 80 (not in topology) - should be rejected
        auto dev80Info = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            128, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", dev80Info.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "Device_80, Device powered off"}});

        // Inject error on device 81 (not in topology) - should be rejected
        auto dev81Info = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            129, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", dev81Info.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "Device_81, MCTP device communication failed due to device ping timeout"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query device 80 - should return Healthy (error was rejected, no
        // D-Bus object)
        auto result80 = queryDeviceStatus(80);
        EXPECT_EQ(result80.status,
                  0); // Healthy (no D-Bus object means no errors)
        EXPECT_EQ(result80.errors.size(), 0); // No errors stored

        // Query device 81 - should return Healthy (error was rejected, no
        // D-Bus object)
        auto result81 = queryDeviceStatus(81);
        EXPECT_EQ(result81.status,
                  0); // Healthy (no D-Bus object means no errors)
        EXPECT_EQ(result81.errors.size(), 0); // No errors stored

        // No cleanup needed - errors were never stored
        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_18: Query Non-Existent Device - D-Bus Object Path Not Created
// SCENARIO: Querying a device that has never logged any errors means the D-Bus
// object path doesn't exist yet (dynamically created on first error).
// Properties.Get should gracefully fail, helper returns -1 (error indicator).
// ============================================================================
TEST_F(TestPlatformEventDbus, QueryNonExistentDeviceReturnsHealthy)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Query CPU (EID 32 = 20) that has never had errors logged
        // With topology-driven interface creation, D-Bus object exists but is
        // Healthy D-Bus object path /com/nvidia/state/device_status/32 exists
        // (created during topology init)
        auto result = queryDeviceStatus(32);

        // Expected: Object exists and returns Healthy status
        // D-Bus interfaces are now created during topology initialization,
        // so all topology devices can be queried even before logging errors
        EXPECT_EQ(result.status, 0);        // Healthy
        EXPECT_EQ(result.errors.size(), 0); // No errors

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_19: Clear Non-Existent Device - D-Bus Object Path Not Created
// SCENARIO: Clearing errors on a device that has never had errors means the
// D-Bus object path doesn't exist yet. Properties.Set should be gracefully
// caught. Also tests idempotent clearing (clear twice should be safe).
// ============================================================================
TEST_F(TestPlatformEventDbus, ClearNonExistentDeviceSafeOperation)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Clear device that never had errors (EID FE)
        // D-Bus object path /com/nvidia/state/device_status/254 doesn't exist
        // Properties.Set will throw UnknownObject exception
        // Helper should catch exception and silently succeed (safe no-op)
        clearDeviceErrors(0xFE); // Should NOT crash or throw to caller

        // Create error on device 20
        auto info = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power);
        nv::lg2::CommitDeviceError(
            32, ErrorCode::PowerStatus::POWER_OFF, ErrorClass::Power,
            {{"REDFISH_MESSAGE_ID", info.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "CPU, Device powered off"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Clear device 20 first time
        clearDeviceErrors(32);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // Query device 20 - should be healthy
        auto result = queryDeviceStatus(32);
        if (result.status != -1)
        {
            EXPECT_EQ(result.status, 0); // Healthy
            EXPECT_EQ(result.errors.size(), 0);
        }

        // Clear device 20 second time (idempotent - should not error)
        clearDeviceErrors(32);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_20: D-Bus Object Lifecycle - Path Created On First Error, Reused After
// SCENARIO: Explicitly test the D-Bus object lifecycle and idempotent object
// creation:
// 1. Query before any error → object doesn't exist → returns -1
// 2. Log first error → object gets created dynamically
// 3. Query after first error → object exists → returns error data
// 4. Log SECOND error on same EID → object already exists, just adds error
// 5. Query after second error → shows both errors
// 6. Clear errors → object still exists → returns healthy
// 7. Log third error → object still exists, reuses existing object
// This validates dynamic interface creation and idempotent behavior.
// ============================================================================
TEST_F(TestPlatformEventDbus, DBusObjectLifecycle)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Use GPU (EID 17) from topology
        uint8_t testEid = 17;

        // STEP 1: Query BEFORE any error is logged
        // D-Bus object path doesn't exist yet
        auto resultBefore = queryDeviceStatus(testEid);

        // Expected: Returns 0 (Healthy) because D-Bus object doesn't exist
        // Design decision: No D-Bus object = No errors = Healthy
        EXPECT_EQ(resultBefore.status, 0); // Healthy (no errors logged yet)

        // STEP 2: Log FIRST error for this device
        // D-Bus object already exists (created during topology initialization)
        // Object path: /com/nvidia/state/device_status/17
        auto info1 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            testEid, ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT,
            ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info1.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, First error logged for device"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // STEP 3: Query AFTER first error
        // D-Bus object path now exists
        auto resultAfterFirst = queryDeviceStatus(testEid);

        // Expected: Returns error data (status=1, Degraded)
        EXPECT_EQ(resultAfterFirst.status, 1);        // Degraded
        EXPECT_EQ(resultAfterFirst.errors.size(), 1); // One error
        EXPECT_EQ(resultAfterFirst.errors[0].errorCode,
                  ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT);

        // STEP 4: Log SECOND error on SAME EID
        // D-Bus object path already exists, should NOT try to create again
        // createDeviceStatusInterface() should detect existing object and skip
        // creation
        auto info2 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            testEid, ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info2.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, Second error on existing object"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(300));

        // STEP 5: Query AFTER second error
        // Should show BOTH errors now
        auto resultAfterSecond = queryDeviceStatus(testEid);

        // Expected: Returns both errors (status=1, Degraded)
        EXPECT_EQ(resultAfterSecond.status, 1);        // Degraded
        EXPECT_EQ(resultAfterSecond.errors.size(), 2); // TWO errors now

        // Verify both error codes are present
        bool hasFirstError = false, hasSecondError = false;
        for (const auto& err : resultAfterSecond.errors)
        {
            if (err.errorCode ==
                ErrorCode::MCTP::MCTP_TRANSPORT_FAIL_PING_TIMEOUT)
            {
                hasFirstError = true;
            }
            if (err.errorCode == ErrorCode::MCTP::UUID_DISCOVERY_TIMEOUT)
            {
                hasSecondError = true;
            }
        }
        EXPECT_TRUE(hasFirstError);  // First error still present
        EXPECT_TRUE(hasSecondError); // Second error added successfully

        // STEP 6: Clear all errors
        // D-Bus object still exists, just clears the errors
        clearDeviceErrors(testEid);

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(100));

        // STEP 7: Query AFTER clear
        // D-Bus object still exists, but now returns healthy status
        auto resultCleared = queryDeviceStatus(testEid);

        // Expected: Returns healthy (status=0) because object exists but no
        // errors
        EXPECT_EQ(resultCleared.status, 0);        // Healthy
        EXPECT_EQ(resultCleared.errors.size(), 0); // All errors cleared

        // STEP 8: Log THIRD error (after clear)
        // D-Bus object still exists from before, should reuse it
        auto info3 = phosphor::logging::test::getTestRedfishErrorInfo(
            ErrorCode::MCTP::PING_SUCCESS, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            testEid, ErrorCode::MCTP::PING_SUCCESS, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", info3.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS",
              "GPU, Third error reuses existing object"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // STEP 9: Query AFTER third error
        // Should show the new error
        auto resultAfterThird = queryDeviceStatus(testEid);

        // Expected: Returns new error (status=1, Degraded)
        EXPECT_EQ(resultAfterThird.status, 1);        // Degraded
        EXPECT_EQ(resultAfterThird.errors.size(), 1); // One new error
        EXPECT_EQ(resultAfterThird.errors[0].errorCode,
                  ErrorCode::MCTP::PING_SUCCESS);

        // Final cleanup
        clearDeviceErrors(testEid);

        co_return;
    };

    run(test_task());
}

// ============================================================================
// TOPO_21: Topology-Driven Interface Creation - Reject Unknown EIDs
// SCENARIO: With topology-driven D-Bus interface creation, only devices in
// topology can have errors. Errors from unknown EIDs should be rejected.
// Also verify that large error code values (int64_t range) work correctly.
// ============================================================================
TEST_F(TestPlatformEventDbus, EidBoundaryValues)
{
    using namespace nv::lg2;

    auto test_task = [&, this]() -> sdbusplus::async::task<> {
        // Test 1: Valid topology EID with large error code - should work
        auto infoLarge = phosphor::logging::test::getTestRedfishErrorInfo(
            0x7FFFFFFFFFFFFFFF, ErrorClass::MCTP);
        nv::lg2::CommitDeviceError(
            17, 0x7FFFFFFFFFFFFFFF, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", infoLarge.redfishMessageId},
             {"REDFISH_MESSAGE_ARGS", "GPU, Large error code test"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query GPU (EID 17) - should have the large error code
        auto resultGpu = queryDeviceStatus(0x11);
        EXPECT_EQ(resultGpu.status, 1); // Degraded
        EXPECT_GE(resultGpu.errors.size(), 1);
        EXPECT_EQ(resultGpu.errors[0].errorCode, 0x7FFFFFFFFFFFFFFF);

        // Test 2: Try to log error to EID not in topology (FF) - should be
        // REJECTED
        nv::lg2::CommitDeviceError(
            255, 02, ErrorClass::MCTP,
            {{"REDFISH_MESSAGE_ID", "ResourceEvent.1.2.ResourceErrorsDetected"},
             {"REDFISH_MESSAGE_ARGS", "Invalid EID test"}});

        co_await sdbusplus::async::sleep_for(data->client_ctx,
                                             std::chrono::milliseconds(200));

        // Query EID 0xFF - should return Healthy (no D-Bus object created for
        // invalid EID)
        auto resultInvalid = queryDeviceStatus(0xFF);
        EXPECT_EQ(resultInvalid.status,
                  0); // Healthy (no errors, no D-Bus object)
        EXPECT_EQ(resultInvalid.errors.size(), 0);

        // Test 3: Verify topology devices still work correctly after invalid
        // EID attempt
        auto resultGpu2 = queryDeviceStatus(17);
        EXPECT_EQ(resultGpu2.status, 1); // Still Degraded
        EXPECT_GE(resultGpu2.errors.size(), 1);

        // Cleanup
        clearDeviceErrors(17);

        co_return;
    };

    run(test_task());
}

} // namespace phosphor::logging::test
