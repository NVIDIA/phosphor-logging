# NVIDIA Platform Event Extension
#
# Extension for device-specific error aggregation, priority-based
# classification, and recovery tracking for platform resiliency
# firmware upgrade workflows.

# Core library sources (excluding entry_points which goes directly to main binary)
nvidia_platform_event_lib_sources = files(
    'device_error_database.cpp',
    'device_status_interface.cpp',
    'device_topology.cpp',
    'manager.cpp',
)

nvidia_platform_event_headers = files(
    'device_error_database.hpp',
    'entry_points.hpp',
    'manager.hpp',
)

# Build helper library
nvidia_platform_event_lib = static_library(
    'nvidia_platform_event',
    nvidia_platform_event_lib_sources,
    include_directories: include_directories(
        '../..',
        '../../gen',
        '../../lib',
        '../../lib/topology',
    ),
    dependencies: [
        conf_h_dep,
        phosphor_logging_dep,
        sdbusplus_dep,
        sdeventplus_dep,
        pdi_dep,
        topology_dep,
    ],
)

# Create dependency for the library
nvidia_platform_event_lib_dep = declare_dependency(
    link_with: nvidia_platform_event_lib,
    include_directories: include_directories('.'),
)

# Add library dependency to log manager
log_manager_ext_deps += [nvidia_platform_event_lib_dep]

# Add entry points directly to main binary
# This is required for REGISTER_EXTENSION_FUNCTION macros to work
log_manager_ext_sources += files('entry_points.cpp')
