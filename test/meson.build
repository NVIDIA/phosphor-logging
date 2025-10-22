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
    'extensions_test',
    'namespace_logging_test',
    'log_manager_dbus_tests',
    'remote_logging_test_address',
    'remote_logging_test_config',
    'remote_logging_test_port',
    'sdtest',
    'serialization_test_path',
    'serialization_test_properties',
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
            log_manager_sources,
            '../phosphor-rsyslog-config/server-conf.cpp',
            dependencies: [
                gmock_dep,
                gtest_dep,
                log_manager_deps,
                pdi_dep,
                phosphor_logging_dep,
            ],
            include_directories: include_directories('..', '../gen'),
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
            log_manager_sources,
            '../phosphor-rsyslog-config/server-conf.cpp',
            dependencies: [
                gmock_dep,
                gtest_dep,
                log_manager_deps,
                phosphor_logging_dep,
            ],
            include_directories: include_directories('..', '../gen'),
        ),
        is_parallel: false,
    )
endforeach


# Platform Event D-Bus integration tests
# Tests the complete flow: CommitDeviceError -> Extension -> Error Database
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
