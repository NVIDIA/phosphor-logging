gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
gmock_dep = dependency('gmock', disabler: true, required: false)
if not gtest_dep.found() or not gmock_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: false)
    if gtest_proj.found()
        gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ],
        )
        gmock_dep = gtest_proj.dependency('gmock')
    else
        assert(
            not get_option('tests').enabled(),
            'Googletest is required if tests are enabled',
        )
    endif
endif

if get_option('openpower-pel-extension').allowed()
    subdir('openpower-pels')
endif

tests = [
    'bmc_pos_mgr_test',
    'extensions_test',
    'namespace_logging_test',
    'log_manager_dbus_tests',
    'remote_logging_test_address',
    'remote_logging_test_config',
    'remote_logging_test_port',
    'sdtest',
    'serialization_test_path',
    'serialization_test_properties',
    'serialization_test_additional',
    'linear_policy_test',
    'log_purge_policy_test',
]
foreach t : tests
    test(
        'test_' + t.underscorify(),
        executable(
            'test-' + t.underscorify(),
            t + '.cpp',
            'common.cpp',
            '../phosphor-rsyslog-config/server-conf.cpp',
            dependencies: [
                conf_h_dep,
                gmock_dep,
                gtest_dep,
                log_manager_deps,
                pdi_dep,
                phosphor_logging_dep,
            ],
            include_directories: include_directories('..', '../gen'),
            link_with: log_manager_lib,
        ),
    )
endforeach

tests_non_parallel = [
    'elog_quiesce_test',
    'elog_update_ts_test',
    'elog_errorwrap_test',
]

foreach t : tests_non_parallel
    test(
        'test_' + t.underscorify(),
        executable(
            'test-' + t.underscorify(),
            t + '.cpp',
            'common.cpp',
            '../phosphor-rsyslog-config/server-conf.cpp',
            dependencies: [
                conf_h_dep,
                gmock_dep,
                gtest_dep,
                log_manager_deps,
                phosphor_logging_dep,
            ],
            include_directories: include_directories('..', '../gen'),
            link_with: log_manager_lib,
        ),
        is_parallel: false,
    )
endforeach

#Platform Event D - Bus integration tests
#Tests the complete flow : CommitDeviceError->Extension->Error Database
test(
    'test_platform_event_dbus_tests',
    executable(
        'test-platform-event-dbus-tests',
        'platform_event_dbus_tests.cpp',
        'common.cpp',
        log_manager_sources,
        '../extensions/nvidia-platform-event/entry_points.cpp',
        '../extensions/nvidia-platform-event/manager.cpp',
        '../extensions/nvidia-platform-event/device_error_database.cpp',
        '../extensions/nvidia-platform-event/device_status_interface.cpp',
        '../extensions/nvidia-platform-event/device_topology.cpp',
        dependencies: [
            gmock_dep,
            gtest_dep,
            log_manager_deps,
            pdi_dep,
            phosphor_logging_dep,
            sdeventplus_dep,
            topology_dep,
        ],
        include_directories: include_directories(
            '..',
            '../gen',
            '../lib/topology',
        ),
    ),
    is_parallel: false,
)

test(
    'test_mctp_error_registry_test',
    executable(
        'test-mctp-error-registry-test',
        'mctp_error_registry_test.cpp',
        dependencies: [phosphor_logging_dep],
        include_directories: include_directories('..'),
    ),
)

#Test for util.cpp utility functions
test(
    'test_util',
    executable(
        'test-util',
        'test_util.cpp',
        '../util.cpp',
        dependencies: [
            conf_h_dep,
            gmock_dep,
            gtest_dep,
            phosphor_logging_dep,
            sdbusplus_dep,
        ],
        include_directories: include_directories('..', '../gen'),
    ),
)

#Test for redfish_event_log.cpp
test(
    'test_redfish_event_log',
    executable(
        'test-redfish-event-log',
        'test_redfish_event_log.cpp',
        '../lib/redfish_event_log.cpp',
        dependencies: [
            conf_h_dep,
            gmock_dep,
            gtest_dep,
            phosphor_logging_dep,
            sdbusplus_dep,
        ],
        include_directories: include_directories('..', '../gen', '../lib'),
    ),
)

#Test for sdjournal.cpp
test(
    'test_sdjournal',
    executable(
        'test-sdjournal',
        'test_sdjournal.cpp',
        '../lib/sdjournal.cpp',
        dependencies: [gmock_dep, gtest_dep, phosphor_logging_dep],
        include_directories: include_directories('..', '../gen', '../lib'),
    ),
)

#Test for paths.cpp
test(
    'test_paths',
    executable(
        'test-paths',
        'test_paths.cpp',
        'common.cpp',
        '../paths.cpp',
        dependencies: [conf_h_dep, gtest_dep],
        include_directories: include_directories('..'),
    ),
)

#Test for bin.hpp(Bin class) - gcovr.cfg coverage target
test(
    'test_bin',
    executable(
        'test-bin',
        'test_bin.cpp',
        'common.cpp',
        '../paths.cpp',
        dependencies: [conf_h_dep, gtest_dep],
        include_directories: include_directories('..'),
    ),
)

#Extended tests for phosphor - rsyslog - config / server - conf.cpp
#Tests additional code paths not covered by remote_logging_test_ *.cpp
test(
    'test_rsyslog_server_conf_extended',
    executable(
        'test-rsyslog-server-conf-extended',
        'test_rsyslog_server_conf_extended.cpp',
        '../phosphor-rsyslog-config/server-conf.cpp',
        '../util.cpp',
        '../elog_meta.cpp',
        dependencies: [
            conf_h_dep,
            gmock_dep,
            gtest_dep,
            phosphor_logging_dep,
            pdi_dep,
            sdbusplus_dep,
            sdeventplus_dep,
        ],
        include_directories: include_directories(
            '..',
            '../gen',
            '../phosphor-rsyslog-config',
        ),
    ),
)
