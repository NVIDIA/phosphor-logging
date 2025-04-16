#include "extensions.hpp"

namespace phosphor
{
namespace logging
{

StartupFunctions& Extensions::getStartupFunctions()
{
    static StartupFunctions startupFunctions{};
    return startupFunctions;
}

PrepareFunctions& Extensions::getPrepareFunctions()
{
    static PrepareFunctions prepareFunctions{};
    return prepareFunctions;
}

CreateFunctions& Extensions::getCreateFunctions()
{
    static CreateFunctions createFunctions{};
    return createFunctions;
}

DeleteFunctions& Extensions::getDeleteFunctions()
{
    static DeleteFunctions deleteFunctions{};
    return deleteFunctions;
}

DeleteProhibitedFunctions& Extensions::getDeleteProhibitedFunctions()
{
    static DeleteProhibitedFunctions deleteProhibitedFunctions{};
    return deleteProhibitedFunctions;
}

DeleteAllFunctions& Extensions::getDeleteAllFunctions()
{
    static DeleteAllFunctions deleteAllFunctions{};
    return deleteAllFunctions;
}

Extensions::DefaultErrorCaps& Extensions::getDefaultErrorCaps()
{
    static DefaultErrorCaps defaultErrorCaps = DefaultErrorCaps::enable;
    return defaultErrorCaps;
}

} // namespace logging
} // namespace phosphor
