# EntityManager interface library sources (minimal EM D-Bus wrapper)
em_interface_sources = files('em_interface.cpp')

# Find dependencies locally (since they may not be defined yet in parent scope)
topology_sdbusplus_dep = dependency('sdbusplus')

# EntityManager interface library dependencies
em_interface_deps = [topology_sdbusplus_dep, phosphor_logging_dep]

# EntityManager interface library (minimal - just EM query + signals)
topology_lib = static_library(
    'topology',
    em_interface_sources,
    include_directories: include_directories('.'),
    dependencies: em_interface_deps,
    implicit_include_directories: false,
)

topology_dep = declare_dependency(
    link_with: topology_lib,
    include_directories: include_directories('.'),
    dependencies: [topology_sdbusplus_dep],
)

