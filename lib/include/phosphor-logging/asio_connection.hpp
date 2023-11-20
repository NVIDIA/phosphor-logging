#pragma once
#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>

namespace phosphor
{
namespace logging
{
    class AsioConnection
    {
        public:
            AsioConnection() = delete;
            AsioConnection(const AsioConnection&) = delete;
            AsioConnection& operator=(const AsioConnection&) = delete;
            AsioConnection(AsioConnection&&) = delete;
            AsioConnection& operator=(AsioConnection&&) = delete;
            ~AsioConnection() = delete;

            /** @brief Get the asio connection. */
            static auto& getAsioConnection()
            {
                static boost::asio::io_context io;
                static auto conn = std::make_shared<sdbusplus::asio::connection>(io);
                return conn;
            }
    };
} // namespace user
} // namespace phosphor
