<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\SpbctWP\Variables\Cookie;

class Deactivator
{
    /**
     * @var array
     */
    private static $log = array();
    /**
     * @var bool
     */
    private static $deactivation_result = true;
    /**
     * @var bool
     */
    private static $is_complete_deactivation = false;
    /**
     * Perform deactivator actions depending on this config.
     * @var array[]
     */
    private static $deactivator_configs = array(
        'single_site' => array(
            'on_simple' => array(
                'mu_uninstall',
                'unregister_plugin_settings_page',
                'remove_admin_bar',
                'reset_admin_cookies',
            ),
            'on_complete' => array(
                'mu_uninstall',
                'unregister_plugin_settings_page',
                'remove_admin_bar',
                'reset_admin_cookies',
                'reset_common_cookies',
                'delete_common_tables',
                //
                'delete_blog_tables',
                'delete_blog_options',
                'delete_blog_meta',
                //
                'delete_backups',
                'delete_fw_dir',
                'delete_frontend_meta',
                //
                'delete_fs_watcher_journals'
            )
        ),
        'network_wide' => array(
            'on_simple' => array(
                'mu_uninstall',
                'unregister_plugin_settings_page',
                'remove_admin_bar',
                'reset_admin_cookies',
            ),
            'on_complete' => array(
                'mu_uninstall',
                'unregister_plugin_settings_page',
                'reset_admin_cookies',
                'reset_common_cookies',
                'remove_admin_bar',
                //
                'delete_network_wide_options',
                'delete_each_blog_data',
                'delete_backups',
                'delete_fs_watcher_journals'
            )
        ),
        'network_main_site' => array(
            'on_simple' => array(
                'reset_admin_cookies',
                'remove_admin_bar',
            ),
            'on_complete' => array(
                'reset_admin_cookies',
                'delete_blog_tables',
                'delete_blog_options',
                'delete_blog_meta',
                'delete_fw_dir',
                'delete_frontend_meta',
                'delete_fs_watcher_journals'
            )
        ),
    );

    /**
     * @var
     */
    private static $initial_blog;

    /**
     * Perform all required deactivation logic depending on config provided.
     * @param array $call_instance_config
     * @return void
     */
    private static function runActions($call_instance_config)
    {
        global $wpdb;
        $deactivation_type = self::$is_complete_deactivation ? $call_instance_config['on_complete'] : $call_instance_config['on_simple'];
        foreach ($deactivation_type as $action) {
            switch ($action) {
                case 'mu_uninstall':
                    self::muPluginUninstall();
                    break;
                case 'delete_blog_tables':
                    self::deleteBlogTables();
                    break;
                case 'delete_common_tables':
                    self::deleteCommonTables();
                    break;
                case 'delete_blog_options':
                    self::deleteBlogOptions();
                    break;
                case 'delete_backups':
                    \CleantalkSP\SpbctWP\Helpers\Data::removeDirectoryRecursively(SPBC_PLUGIN_DIR . 'backups');
                    break;
                case 'delete_fw_dir':
                    self::deleteSecFWUpdateFolder();
                    break;
                case 'delete_frontend_meta':
                    self::deleteFrontendMeta();
                    break;
                case 'delete_each_blog_data':
                    $blogs = array_keys($wpdb->get_results('SELECT blog_id FROM ' . $wpdb->blogs, OBJECT_K));

                    // Deleting data from each blog
                    foreach ($blogs as $target_blog) {
                        switch_to_blog($target_blog);
                        self::runActions(self::$deactivator_configs['single_site']);
                        self::logThis('actions for blog ' . $target_blog . ' ok');
                    }
                    switch_to_blog(self::$initial_blog);
                    break;
                case 'delete_network_wide_options':
                    delete_site_option(SPBC_NETWORK_SETTINGS);
                    delete_site_option(SPBC_PLUGINS);
                    delete_site_option(SPBC_THEMES);
                    break;
                case 'reset_common_cookies':
                    Cookie::set('spbc_cookies_test', '0', time() - 30, '/');
                    Cookie::set('spbc_log_id', '0', time() - 30, '/');
                    Cookie::set('spbc_secfw_ip_wl', '0', time() - 30, '/');
                    Cookie::set('spbc_timer', '0', time() - 30, '/');
                    break;
                case 'reset_admin_cookies':
                    Cookie::set('spbc_is_logged_in', '0', time() - 30, '/');
                    Cookie::set('spbc_admin_logged_in', '0', time() - 30, '/');
                    break;
                case 'unregister_plugin_settings_page':
                    unregister_setting(SPBC_SETTINGS, SPBC_SETTINGS);
                    break;
                case 'remove_admin_bar':
                    if (
                        /** @psalm-suppress UndefinedFunction */
                    !has_action('admin_bar_menu', 'spbc_admin__admin_bar__add_structure')
                    ) {
                        remove_action('admin_bar_menu', 'spbc_admin__admin_bar__add_structure', 999);
                    }
                    break;
                case 'delete_fs_watcher_journals':
                    $journals_path = \CleantalkSP\SpbctWP\FSWatcher\Storage\SpbctWpFSWFileStorage::getJournalsPath();
                    $journals_path = str_replace('data' . DIRECTORY_SEPARATOR, '', $journals_path);
                    if (is_dir($journals_path) && is_writable($journals_path)) {
                        \CleantalkSP\SpbctWP\Helpers\Data::removeDirectoryRecursively($journals_path);
                    }
            }
            self::logThis($action . ' ok');
        }
    }

    /**
     * Run plugin deactivation logic.
     * @param bool $network Is network wide
     * @param bool $do_log_on_errors Write php error log on deactivation process errors
     * @return bool Result. True if all actions is completed and checked, false otherwise
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function deactivation($network, $do_log_on_errors = false)
    {
        global $spbc;
        self::$is_complete_deactivation = !empty($spbc->settings['misc__complete_deactivation']);

        if (
            /** @psalm-suppress UndefinedFunction */
        !has_action('admin_bar_menu', 'spbc_admin__admin_bar__add_structure')
        ) {
            remove_action('admin_bar_menu', 'spbc_admin__admin_bar__add_structure', 999);
        }

        self::$initial_blog = get_current_blog_id();

        // Deactivation on standalone blog
        if ( !is_multisite() ) {
            self::runActions(
                self::$deactivator_configs['single_site']
            );
            self::checkDeactivationResult('single_site');

            //Network wide deactivation
        } elseif ( $network ) {
            //switch network processing to on
            update_option('spbc_deactivation_in_process', true, false);

            self::runActions(
                self::$deactivator_configs['network_wide']
            );
            //switch network processing to off
            delete_option('spbc_deactivation_in_process');
            self::checkDeactivationResult('network_wide');

            // Deactivation for one blog in the network
        } else {
            self::runActions(
                self::$deactivator_configs['network_main_site']
            );
            self::checkDeactivationResult('network_main_site');
        }

        if ( $do_log_on_errors && !self::$deactivation_result ) {
            error_log("Security by CleanTalk deactivation log: \r\n" . var_export(self::getLog(), true));
        }

        return self::$deactivation_result;
    }

    /**
     * Deletes frontend scan meta results
     * @return void
     */
    private static function deleteFrontendMeta()
    {
        global $wpdb;
        // Deleting scan links results
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->postmeta}
					WHERE meta_key = %s OR meta_key = %s",
                '_spbc_links_checked',
                'spbc_links_checked'
            )
        );

        // Deleting scan frontend results
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->postmeta}
                        WHERE meta_key = %s OR meta_key = %s OR meta_key = %s OR meta_key = %s",
                '_spbc_frontend__last_checked',
                '_spbc_frontend__approved',
                'spbc_frontend__last_checked',
                'spbc_frontend__approved'
            )
        );
    }

    /**
     * Deletes current blog individual tables.
     * @return void
     */
    public static function deleteBlogTables() //ok
    {
        global $wpdb;
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_auth_logs');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_monitoring_users');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall__personal_ips_v4');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall__personal_ips_v6');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall__personal_countries');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall__personal_ips_v4_temp');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall__personal_ips_v6_temp');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall__personal_countries_temp');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_firewall_logs');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_traffic_control_logs');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_traffic_control_logs');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_bfp_blocked');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'spbc_sessions');
    }

    /**
     * Deletes common tables such a spbc_scan_results
     * @return void
     */
    public static function deleteCommonTables() //ok
    {
        global $wpdb;
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_scan_results');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_firewall_data_v4');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_firewall_data_v6');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_firewall_data_v4_temp');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_firewall_data_v6_temp');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_scan_links_logs');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_scan_signatures');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_scan_frontend');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_backups');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_backuped_files');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_scan_results_log');
        $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->base_prefix . 'spbc_cure_log');
    }

    /**
     * Deletes must-used instance of the plugin.
     * @return bool
     */
    public static function muPluginUninstall()
    {
        if ( file_exists(WPMU_PLUGIN_DIR . '/0security-malware-firewall-mu.php') ) {
            return unlink(WPMU_PLUGIN_DIR . '/0security-malware-firewall-mu.php');
        }

        return false;
    }

    /**
     * Deletes current individual blog options.
     */
    public static function deleteBlogOptions() //APBCT
    {
        global $wpdb;
        // Deleting all data from wp_options
        $wpdb->query(
            'DELETE FROM ' . $wpdb->options
            . ' WHERE'
            . ' option_name LIKE "spbc_%" AND'
            . ' option_name <> "spbc_deactivation_in_process"'
        );
    }

    /**
     * Deletes update folders
     * @return void
     */
    private static function deleteSecFWUpdateFolder() //APBCT
    {
        $current_blog_id = get_current_blog_id();
        $wp_upload_dir = wp_upload_dir();
        $update_folder = $wp_upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'fw_files_for_blog_' . $current_blog_id . DIRECTORY_SEPARATOR;
        \CleantalkSP\SpbctWP\Helpers\Data::removeDirectoryRecursively($update_folder);
    }

    /**
     * Do collect log for the instance. Static!
     * @param $message
     * @return void
     */
    private static function logThis($message)
    {
        if ( !is_string($message) ) {
            return;
        }
        self::$log[] = current_datetime()->format('Y-m-d H:i:s') . ' ' . $message;
    }

    /**
     * Return static logs of Deactivation process.
     * @return string
     */
    public static function getLog()
    {
        if ( !empty(self::$log) ) {
            return implode("\r\n", self::$log);
        } else {
            return 'No logs collected yet.';
        }
    }

    /**
     * Check if deactivation is success and all required data has been removed.
     * @param string $type Type of the WordPress instance ('single_site' or other can be found in the static::$deactivator_configs.
     * @return void
     */
    public static function checkDeactivationResult($type)
    {
        global $wpdb;
        if ( !is_string($type) || !in_array($type, array_keys(self::$deactivator_configs)) ) {
            self::logThis('checkDeactivationResult: no such config found');
            return;
        }

        //for single site and complete deactivation
        if ( $type === 'single_site' && self::$is_complete_deactivation ) {
            $options_table_name = $wpdb->prefix . 'options';
            $postmeta_table_name = $wpdb->prefix . 'postmeta';
            $tables_query = 'SHOW TABLES LIKE "%spbc%"';
            $tables_query_result = $wpdb->get_col($tables_query);
            $options_query = 'SELECT * FROM ' . $options_table_name . ' WHERE option_name LIKE "%spbc%"';
            $options_query_result = $wpdb->get_col($options_query);
            $meta_query = 'SELECT * FROM ' . $postmeta_table_name . ' WHERE meta_key LIKE "%spbc%"';
            $meta_query_result = $wpdb->get_col($meta_query);
            if ( count($tables_query_result) || count($options_query_result) || count($meta_query_result) ) {
                self::logThis('checkDeactivationResult: FAILED');
                if ( count($tables_query_result) ) {
                    self::logThis('tables_query_result: ' . implode(',', $tables_query_result));
                }
                if ( count($options_query_result) ) {
                    self::logThis('options_query_result: ' . implode(',', $options_query_result));
                }
                if ( count($meta_query_result) ) {
                    self::logThis('meta_query_result: ' . implode(',', $meta_query_result));
                }
                self::$deactivation_result = false;
                return;
            }
        }
        //todo: for the further actions or unit tests this need to be refactored or updated
        self::logThis('checkDeactivationResult: ' . 'OK');
    }
}
