# List of source files
sources = [
    'conf.cpp',
    'fwd-actions.cpp',
    'main.cpp',
    'server-conf.cpp',
    '../elog_meta.cpp',
    '../util.cpp',
    elog_process_gen,
    callouts_gen,
]

# Define the executable
executable(
    'phosphor-rsyslog-conf',
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
    install_dir: get_option('libexecdir') / 'phosphor-logging',
)
