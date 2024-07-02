<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\SpbctWP\AdjustToEnvironmentModule\AdjustToEnvironmentHandler;
use CleantalkSP\SpbctWP\Cron as SpbcCron;
use CleantalkSP\SpbctWP\HTTP\CDNHeadersChecker;

class Activator
{
    /**
     * Run the plugin activation.
     * @param bool $network Is network wide
     * @param bool $redirect If do need redirect after activation, default is true.
     * @return void
     * @throws \Exception
     */
    public static function activation($network, $redirect = true)
    {
        global $wpdb, $spbc;

        CDNHeadersChecker::sendCDNCheckerRequest();

        if ( current_action() !== 'wp_insert_site' ) {
            delete_option('spbc_deactivation_in_process');
        }

        $tables_analyzer = new \CleantalkSP\SpbctWP\DB\TablesAnalyzer();
        foreach ( $tables_analyzer->getNotExistingTables() as $not_existing_table ) {
            $db_tables_creator = new \CleantalkSP\SpbctWP\DB\TablesCreator();
            $db_tables_creator->createTable($not_existing_table);
        }

        // Activation for network
        if ( is_multisite() && $network ) {
            // For all blogs
            SpbcCron::addTask('scanner_update_signatures', 'spbc_scanner__signatures_update', 86400, time() + 100);
            SpbcCron::updateTask('check_vulnerabilities', 'spbc_security_check_vulnerabilities', 86400, time() + 100);
            SpbcCron::addTask('send_php_logs', 'spbc_PHP_logs__send', 3600, time() + 300);

            if ( empty($spbc->errors['configuration']) ) {
                $scanner_launch_data = spbc_get_custom_scanner_launch_data(true);
                SpbcCron::addTask(
                    'scanner__launch',
                    'spbc_scanner__launch',
                    $scanner_launch_data['period'],
                    $scanner_launch_data['start_time']
                );
            }

            // MU-Plugin
            if ( ! spbc_mu_plugin__install() ) {
                spbc_log('Couldn\'t install Must-Use Plugin. This\'s not critical but it could help plugin to work faster.');
            }

            // For each blog
            $initial_blog = get_current_blog_id();
            $blogs        = array_keys($wpdb->get_results('SELECT blog_id FROM ' . $wpdb->blogs, OBJECT_K));
            foreach ( $blogs as $blog ) {
                switch_to_blog($blog);
                SpbcCron::addTask('send_logs', 'spbc_send_logs', 3600, time() + 1800);
                SpbcCron::addTask('send_report', 'spbc_send_daily_report', 86400, time() + 43200);
                SpbcCron::addTask('firewall_update', 'spbc_security_firewall_update__init', 86400);
                SpbcCron::addTask('send_firewall_logs', 'spbc_send_firewall_logs', 3600, time() + 1800);
                SpbcCron::addTask('access_key_notices', 'spbc_access_key_notices', 3600, time() + 3500);
                SpbcCron::addTask('service_get', 'spbct_perform_service_get', 86400, time() + 3500);
            }
            switch_to_blog($initial_blog);

            // Activation for blog
        } elseif ( is_multisite() ) {
            //Cron jobs
            SpbcCron::addTask('send_logs', 'spbc_send_logs', 3600, time() + 1800);
            SpbcCron::addTask('send_report', 'spbc_send_daily_report', 86400, time() + 43200);
            SpbcCron::addTask('firewall_update', 'spbc_security_firewall_update__init', 86400);
            SpbcCron::addTask('send_firewall_logs', 'spbc_send_firewall_logs', 3600, time() + 1800);
            SpbcCron::addTask('access_key_notices', 'spbc_access_key_notices', 3600, time() + 3500);
            SpbcCron::addTask('service_get', 'spbct_perform_service_get', 86400, time() + 3500);
            SpbcCron::addTask('security_log_clear', 'spbc_security_log_clear', 86400, time() + 43200);
            SpbcCron::addTask('get_brief_data', 'spbc_set_brief_data', 86400, time() + 1800);
        } elseif ( ! is_multisite() ) {
            // Cron
            SpbcCron::addTask('send_logs', 'spbc_send_logs', 3600, time() + 1800);
            SpbcCron::addTask('send_report', 'spbc_send_daily_report', 86400, time() + 43200);
            SpbcCron::addTask('firewall_update', 'spbc_security_firewall_update__init', 86400);
            SpbcCron::addTask('send_firewall_logs', 'spbc_send_firewall_logs', 3600, time() + 1800);
            SpbcCron::addTask('access_key_notices', 'spbc_access_key_notices', 3600, time() + 3500);
            SpbcCron::addTask('scanner_update_signatures', 'spbc_scanner__signatures_update', 86400, time() + 100);
            SpbcCron::addTask('send_php_logs', 'spbc_PHP_logs__send', 3600, time() + 300);
            SpbcCron::addTask('service_get', 'spbct_perform_service_get', 86400, time() + 3500);
            SpbcCron::addTask('security_log_clear', 'spbc_security_log_clear', 86400, time() + 43200);
            SpbcCron::addTask('get_brief_data', 'spbc_set_brief_data', 86400, time() + 1800);
            SpbcCron::updateTask('check_vulnerabilities', 'spbc_security_check_vulnerabilities', 86400, time() + 100);
            SpbcCron::addTask('cdn_check', 'spbc_cdn_checker__send_request', 86400, time() + 86400);

            if ( empty($spbc->errors['configuration']) ) {
                $scanner_launch_data = spbc_get_custom_scanner_launch_data(true);
                SpbcCron::addTask(
                    'scanner__launch',
                    'spbc_scanner__launch',
                    $scanner_launch_data['period'],
                    $scanner_launch_data['start_time']
                );
            }

            // MU-Plugin
            if ( ! spbc_mu_plugin__install() ) {
                spbc_log('Couldn\'t install Must-Use Plugin. This\'s not critical but it could help plugin to work faster.');
            }
        }

        // Redirect
        if ( $redirect ) {
            add_option('spbc_activation__redirect', $spbc->settings_link);
        }

        if ( $spbc->api_key || ( ! is_main_site() && $spbc->network_settings['ms__work_mode'] != 2 ) ) {
            return;
        }
        /**
         * Filters a getting API key flag
         *
         * @param bool Set true if you want to get key automatically after activation the plugin
         */
        if ( apply_filters('spbc_is_get_api_key', false) ) {
            spbc_get_key_auto(true);
        }

        // Try to adjust to environment
        $adjust = new AdjustToEnvironmentHandler();
        $adjust->handle();
    }

    /**
     * Add action for new blog adding depending on current WP version
     * @param string $wp_version Use this for example get_bloginfo('version')
     * @return void
     */
    public static function addActionForNetworkBlogLegacy($wp_version)
    {
        // Hook for newly added blog
        if ( version_compare($wp_version, '5.1.0', '<') ) {
            add_action('wpmu_new_blog', array('self', 'actionNewBlogLegacyMode'), 10, 6);
        } else {
            add_action('wp_insert_site', array('self', 'actionNewBlog'), 10, 1);
        }
    }

    /**
     * @param $blog_id
     * @param $_user_id
     * @param $_domain
     * @param $_path
     * @param $_site_id
     * @param $_meta
     * @return void
     * @throws \Exception
     */
    private static function actionNewBlogLegacyMode($blog_id, $_user_id, $_domain, $_path, $_site_id, $_meta)
    {
        global $spbc;

        if ( spbc_is_plugin_active_for_network('security-malware-firewall/security-malware-firewall.php') ) {
            $spbc = State::resetState();
            switch_to_blog($blog_id);

            spbc_activation(false, false);

            if ( ! $spbc->is_mainsite && ! $spbc->ms__work_mode == 1 ) {
                spbc_set_api_key();
            }

            restore_current_blog();
            State::restoreState();
        }
    }

    /**
     * Wrapper for spbc_activation__new_blog()
     *
     * @param $new_site
     * @psalm-suppress UnusedMethod - this method called via hook wp_insert_site/wpmu_new_blog
     */
    private static function actionNewBlog($new_site)
    {
        self::actionNewBlogLegacyMode($new_site->blog_id, null, null, null, null, null);
    }

    /**
     * Function for redirect to settings
     *
     * @return void
     */
    public static function redirectAfterActivation()
    {
        $settings_redirect = get_option('spbc_activation__redirect', false);

        if ( $settings_redirect && ! isset($_GET['activate-multi']) ) {
            delete_option('spbc_activation__redirect');
            wp_redirect($settings_redirect);
        }
    }
}
