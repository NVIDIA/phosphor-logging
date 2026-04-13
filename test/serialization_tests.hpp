#include "config.h"

#include "log_manager.hpp"

#include <stdlib.h>

#include <sdbusplus/bus.hpp>
#include <sdbusplus/test/sdbus_mock.hpp>

#include <filesystem>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace phosphor
{
namespace logging
{
namespace test
{

namespace fs = std::filesystem;

class TestSerialization : public testing::Test
{
  public:
    testing::NiceMock<sdbusplus::SdBusMock> sdbusMock;
    sdbusplus::bus_t bus = sdbusplus::get_mocked_new(&sdbusMock);
    phosphor::logging::internal::Manager manager;

    TestSerialization() : manager(bus, OBJ_INTERNAL)
    {
        char tmplt[] = "/tmp/logging_test.XXXXXX";
        dir = fs::path(mkdtemp(tmplt));
    }

    ~TestSerialization()
    {
        fs::remove_all(dir);
    }

    fs::path dir;
};

} // namespace test
} // namespace logging
} // namespace phosphor
