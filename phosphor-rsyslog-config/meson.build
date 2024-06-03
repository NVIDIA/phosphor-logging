# List of source files
sources = [
    'main.cpp',
    'server-conf.cpp',
    '../elog_meta.cpp',
    elog_process_gen,
]

# Conditionally add source files
if enable_rsyslog_fwd_actions_conf
    sources += [
        'conf.cpp',
        'fwd-actions.cpp',
    ]
endif

# Define the executable
executable('phosphor-rsyslog-conf',
    sources,
    include_directories: include_directories('..'),
    dependencies: [
        conf_h_dep,
        phosphor_logging_dep,
        pdi_dep,
        sdbusplus_dep,
        sdeventplus_dep,
    ],
    install: true,
)
