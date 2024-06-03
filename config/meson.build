# Create config.h with constants that use to come from autoconf.
conf_data = configuration_data()
conf_data.set('error_cap', get_option('error_cap'))
conf_data.set('error_info_cap', get_option('error_info_cap'))
conf_data.set('rsyslog_server_conf', get_option('rsyslog_server_conf'))
conf_data.set('rsyslog_fwd_actions_conf_dir_path', get_option('rsyslog_fwd_actions_conf_dir_path'))
conf_data.set('rw_config_file_path', get_option('rw_config_file_path'))
conf_data.set('log_purge_policy_default',
    get_option('log_purge_policy_default').to_string())
conf_h_dep = declare_dependency(
    include_directories: include_directories('.'),
    sources: configure_file(
        input: 'config.h.meson',
        output: 'config.h',
        configuration: conf_data,
    )
)
