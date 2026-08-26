#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <sdbusplus/exception.hpp>

#include <iostream>

using namespace phosphor::logging;

int main(int argc, char** argv)
try
{
    if (2 != argc)
    {
        std::cerr << "usage: callout-test <sysfs path>" << std::endl;
        return -1;
    }

    using namespace example::xyz::openbmc_project::example::elog;
    try
    {
        elog<TestCallout>(TestCallout::DEV_ADDR(0xDEADEAD),
                          TestCallout::CALLOUT_ERRNO_TEST(0),
                          TestCallout::CALLOUT_DEVICE_PATH_TEST(argv[1]));
    }
    catch (const TestCallout& e)
    {
        commit(e.name());
    }

    return 0;
}
catch (const std::exception& e)
{
    std::cerr << "callout-test: unhandled exception: " << e.what() << std::endl;
    return EXIT_FAILURE;
}
catch (...)
{
    std::cerr << "callout-test: unknown unhandled exception" << std::endl;
    return EXIT_FAILURE;
}
