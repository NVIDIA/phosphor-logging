#pragma once

#include "config.h"

#include <set>
#include <string>

namespace phosphor::logging::internal
{

class Bin
{
  public:
    ~Bin() = default;
    Bin() :
        name(DEFAULT_BIN_NAME), errorCap(ERROR_CAP),
        errorInfoCap(ERROR_INFO_CAP), persistLocation(ERRLOG_PERSIST_PATH),
        errorEntries({}), infoEntries({}){};

    Bin(const std::string& str, uint32_t errCap, uint32_t errInfCap,
        const std::string& loc) :
        name(str),
        errorCap(errCap), errorInfoCap(errInfCap), persistLocation(loc),
        errorEntries({}), infoEntries({}){};

    std::string name;
    uint32_t errorCap;
    uint32_t errorInfoCap;
    std::string persistLocation;
    std::set<uint32_t> errorEntries;
    std::set<uint32_t> infoEntries;
};

} // namespace phosphor::logging::internal