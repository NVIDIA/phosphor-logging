sources = [
    'main.cpp',
    'conf.cpp',
    'journal.cpp',
]

executable(
    'phosphor-journal-conf',
    sources,
    include_directories: include_directories('..'),
    dependencies: [
        conf_h_dep,
        phosphor_logging_dep,
        pdi_dep,
        sdbusplus_dep,
    ],
    install: true,
)
