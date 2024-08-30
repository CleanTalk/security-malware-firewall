<?php

namespace CleantalkSP\SpbctWP;

/*
 *
 * CleanTalk Security State class
 *
 * @package Security Plugin by CleanTalk
 * @subpackage State
 * @Version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

use CleantalkSP\SpbctWP\FeatureRestriction\FeatureRestrictionService;

/**
 * @property mixed data
 * @property mixed settings
 * @property mixed network_settings
 * @property mixed network_data
 * @property mixed errors
 * @property mixed fw_stats
 * @psalm-suppress PossiblyUnusedProperty
 */
class State extends \CleantalkSP\Common\State
{
    public $settings__elements = array();

    public $default_settings = array(

       // Key
       'spbc_key'                          => '',

      // Authentication
        '2fa__enable'                       => 0,
        '2fa__roles'                        => array('administrator'),
        'bfp__allowed_wrong_auths'          => 5,
        'bfp__delay__1_fails'               => 3,    // Delay to sleep after 1 wrong auth
        'bfp__delay__5_fails'               => 10,   // Delay to sleep after 5 wrong auths
        'bfp__block_period__5_fails'        => 3600, // By default ban IP for brute force for one hour
        'bfp__count_interval'               => 900,  // Counting login attempts in this interval
        'edit_tech_support_url__enabled'    => 0,
        'edit_tech_support_url__link_default'     => 'https://wordpress.org/support/plugin/security-malware-firewall',
        'edit_tech_support_url__link'       => '',
        'edit_tech_support_url__remove'     => 0,
        'login_page_rename__enabled'        => 0,
        'login_page_rename__name'           => 'custom-login-url',
        'login_page_rename__redirect'       => '',
        'login_page_rename__send_email_notification' => 1,
        'there_was_signature_treatment'     => 0,

        // Firewall
        'fw__custom_message'          => '',   // Hidden

        // Traffic Control
        'traffic_control__enabled'          => 1,
        'traffic_control__autoblock_timeframe' => 300,
        'traffic_control__autoblock_amount' => 1000,
        'traffic_control__autoblock_period' => 60,
        'traffic_control__exclude_authorised_users' => 0,

        // Scanner
        'scanner__auto_start'              => 1,
        'scanner__auto_start_manual'       => 0,
        'scanner__auto_start_manual_time'  => '09:00',
        'scanner__auto_start_manual_tz'    => 0, // In hours
        'scanner__outbound_links'          => 0,
        'scanner__outbound_links_mirrors'  => '',
        'scanner__important_files_listing' => 1,
        'scanner__heuristic_analysis'      => 1,
        'scanner__schedule_send_heuristic_suspicious_files' => 2, //0 - OFF, 1 - ON, 2 - AUTO
        'scanner__signature_analysis'      => 1,
        'scanner__auto_cure'               => 1,
        'scanner__dir_exclusions'          => '',
        'scanner__dir_exclusions_view'     => '',
        'scanner__list_unknown'            => 1,
        'scanner__list_unknown__older_than' => 10, // day
        'scanner__list_approved_by_cleantalk' => 0,
        'scanner__auto_start__set_period'  => 86400,
        'scanner__fs_watcher'  => 1,
        'scanner__fs_watcher__snapshots_period'  => 43200,

        // Frontend scanner
        'scanner__frontend_analysis'       => 1,
        'scanner__frontend_analysis__csrf' => 0,
        'scanner__frontend_analysis__domains_exclusions_view' => "twitter.com\nyoutube.com\nyoutube-nocookie.com\nimg.youtube.com\nmail.ru\nok.ru\nvk.com\nrutube.ru\ndailymotion.com\nyandex.ru\nflikr.com\nfacebook.com\nvimeo.com\nmetacafe.com\nyahoo.com\nmailchimp.com\ngoogletagmanager.com\ngoogle.com\n",
        'scanner__frontend_analysis__domains_exclusions' => "twitter.com\nyoutube.com\nyoutube-nocookie.com\nimg.youtube.com\nmail.ru\nok.ru\nvk.com\nrutube.ru\ndailymotion.com\nyandex.ru\nflikr.com\nfacebook.com\nvimeo.com\nmetacafe.com\nyahoo.com\nmailchimp.com\ngoogletagmanager.com\ngoogle.com\n",

        // Web Application Firewall
        'secfw__enabled'                    => 1,
        'waf__enabled'                      => 1,
        'waf__xss_check'                    => 1,
        'waf__sql_check'                    => 1,
        'waf__exploit_check'                => 1,
        'waf_blocker__enabled'              => 0,
        'upload_checker__file_check'        => 1,
        'upload_checker__do_check_wordpress_modules' => 0,
        'secfw__get_ip'                     => 1,
        'secfw__get_ip__enable_cdn_auto_self_check'     => 1,

        // Data processing
        'data__set_cookies'                 => 1,
        'data__set_cookies__alt_sessions_type' => 1,
        'data__additional_headers'          => 1,

        // Misc
        'misc__prevent_logins_collecting'   => 0,
        'misc__backend_logs_enable'         => 1,
        'misc__forbid_to_show_in_iframes'   => 1,
        'misc__show_link_in_login_form'     => 1,
        'misc__complete_deactivation'       => 0,

        //Vulnerability
        'vulnerability_check__enable_cron'   => 1,
        'vulnerability_check__test_before_install'   => 1,
        'vulnerability_check__warn_on_modules_pages' => 1,

        // Monitoring
        'monitoring__users' => 1,

        // WP
        'wp__use_builtin_http_api'          => 1,
        'wp__disable_xmlrpc'                => 0,
        'wp__disable_rest_api_for_non_authenticated' => 0,
        'wp__disable_rest_api_route_users' => 0,

        // Admin bar
        'admin_bar__show' => 1,
        'admin_bar__admins_online_counter' => 1,
        'admin_bar__brute_force_counter' => 1,
        'admin_bar__firewall_counter' => 1,
        'admin_bar__fs_watcher' => 1,

        // Trusted and affiliate settings
        'spbc_trusted_and_affiliate__shortcode'         => 0,
        'spbc_trusted_and_affiliate__shortcode_tag'     => '',
        'spbc_trusted_and_affiliate__footer'            => 0,
        'spbc_trusted_and_affiliate__add_id'            => 0,

        // Widget show
        'wp__dashboard_widget__show' => 1

    );
    public $default_data = array(

        'key_changed'              => false,
        'plugin_version'           => SPBC_VERSION,
        'user_token'               => '',
        'key_is_ok'                => false,
        'moderate'                 => false,
        'logs_last_sent'           => null,
        'last_sent_events_count'   => null,
        'notice_show'              => null,
        'notice_renew'             => false,
        'notice_trial'             => false,
        'notice_review'            => false,
        'service_id'               => '',
        'account_email'            => '',
        'license_trial'            => 0,
        'account_name_ob'          => '',
        'salt'                     => '',
        'extra_package'            => [
            'backend_logs' => 0,
        ],
        'scanner'                   => array(
            'last_signature_update' => null,
            'last_wp_version'       => null,
            'cron'                  => array(
                'state'         => 'get_hashes',
                'total_scanned' => 0,
                'offset'        => 0,
            ),
            'cured' => array(),
            'last_backup' => 0,
            'last_scan' => 0,
            'first_scan__front_end' => 1,
            'scanner_start_local_date' => null,
            'scanned_total' => 0,
            'signatures_found' => array(),
            'last_signatures_file_url' => '',
        ),
        'errors' => array(
            'cron' => array(),
        ),
        'last_php_log_sent' => 0,
        '2fa_keys'          => array(),
        'current_settings_template_id'   => null,  // Loaded settings template id
        'current_settings_template_name' => null,  // Loaded settings template name
        'ms__key_tries' => 0,
        'unsafe_permissions' => array(),
        'secfw_data_files_info' => array(),
        'display_scanner_warnings' => array(
            'critical' => false,
            'signatures' => false,
            'frontend' => false,
            'analysis' => false,
            'warn_on_admin_bar' => false
        ),
        'site_utc_offset_in_seconds' => 0,

        // White label data
        'wl_mode_enabled'    => false,
        'wl_company_name'    => 'CleanTalk',
        'wl_brandname'       => 'Security by CleanTalk', // Security by CleanTalk || CleanTalk Security || SPBC_NAME
        'wl_url'             => 'https://cleantalk.org/',
        'wl_support_faq'     => 'https://wordpress.org/plugins/security-malware-firewall/faq/',
        'wl_support_url'     => 'https://wordpress.org/support/plugin/security-malware-firewall',
        'wl_support_email'   => 'support@cleantalk.org',

        // default brief data
        'brief_data' => array(
            'bfp_data' => array(),
            'fw_data' => array(),
            'last_actions' => array(),
            'brief_last_updated' => 0,
            'total_count' => 0,
            'logs_scanned_ts' => array(
                'fw' => 0,
                'bfp' => 0,
            ),
        ),
    );

    public $default_network_settings = array(
        'spbc_key'           => '',
        'ms__hoster_api_key' => '',
        'ms__work_mode'       => 1,
    );

    public $default_network_data = array(
        'key_is_ok'  => false,
        'user_token' => '',
        'service_id' => '',
        'moderate'   => 0,
    );

    public $default_remote_calls = array(

    // Common
        'check_website'            => array( 'last_call' => 0, 'cooldown' => 0 ),
        'close_renew_banner'       => array( 'last_call' => 0, ),
        'update_plugin'            => array( 'last_call' => 0, ),
        'drop_security_firewall'   => array( 'last_call' => 0, ),
        'update_settings'          => array( 'last_call' => 0, ),
        'cron_update_task'         => array( 'last_call' => 0, ),
        'perform_service_get'      => array( 'last_call' => 0, ),
        'run_service_template_get' => array( 'last_call' => 0, 'cooldown' => 60 ),

    // Firewall
        'update_security_firewall'         => array( 'last_call' => 0, 'cooldown' => 300 ),
        'update_security_firewall__worker' => array( 'last_call' => 0, 'cooldown' => 0 ),
        'secfw_send_logs'                  => array( 'last_call' => 0),
        'private_record_add'                  => array( 'last_call' => 0, 'cooldown' => 0),
        'private_record_delete'                  => array( 'last_call' => 0, 'cooldown' => 0),
        'update_pscan_statuses'             => array('last_call' => 0, 'cooldown' => 0),

    // Inner
        'download__quarantine_file' => array('last_call' => 0, 'cooldown' => 3),

    // Backups
        'backup_signatures_files' => array('last_call' => 0,),
        'rollback_repair'         => array('last_call' => 0,),

    // Scanner
        'scanner__controller'              => array('last_call' => 0, 'cooldown' => 1),
        'scanner__check_dir'              => array('last_call' => 0, 'cooldown' => 0),
        'launch_background_scan'              => array('last_call' => 0, 'cooldown' => 0),

    // Debug
        'debug' => array('last_call' => 0,),

        // Insert api key (RC without token)
        'post_api_key' => array('last_call' => 0,),
        // CDN check
        'cdn_check' => array('last_call' => 0,),

    );

    public $default_errors = array();

    public $default_fw_stats = array( // phpcs:ignore PSR1.Methods
        'entries'            => 0,
        'last_send_count'    => null,
        'firewall_last_send' => null,

        'updating'             => false,
        'updating_folder'      => 'fw_files',
        'update_percent'       => 0,
        'updating_id'          => null,
        'updating_last_start' => 0,

        'is_on_maintenance' => false,
        'last_update_log' => null,
    );

    public $default_scanner_listing = array(
        'accessible_urls' => array(),
    );

    public $default_scan_plugins_info = array(
        'plugins_found_with_known_vulnerabilities' => 0,
        'plugins_info_requested'       => 0,
        'total_site_plugins_count'     => 0,
        'names_vulnerable_plugins'     => array(),
    );

    public $default_scan_themes_info = array(
        'themes_found_with_known_vulnerabilities' => 0,
        'themes_info_requested'       => 0,
        'total_site_themes_count'     => 0,
        'names_vulnerable_themes'     => array(),
    );

    /**
     * @var FeatureRestrictionService
     */
    public $feature_restrictions;

    /**
     * Additional action with options
     * Set something depending on something
     *
     * Adding some dynamic properties
     *
     * Read code for details
     *
     * @return void
     */
    protected function init()
    {

        /* Changes in settings depending on different circumstances */

        // Data
        // Set salt if it's empty
        $this->data['salt'] = empty($this->data['salt'])
            ? str_pad((string)mt_rand(0, mt_getrandmax()), 6, '0') . str_pad((string)mt_rand(0, mt_getrandmax()), 6, '0')
            : $this->data['salt'];

        // @todo why?
        $this->data['last_php_log_sent'] = empty($this->data['last_php_log_sent'])
            ? time()
            : $this->data['last_php_log_sent'];

        // @todo why?
        /*
         * It's all about first start
         * Looks like we saving it because we need it somewhere in the DB
         */
        if ( $this->getOption('spbc_data') ) {
            $this->save('data');
        }

        /* Adding some dynamic properties */

        // Standalone or main site
        $this->api_key          = $this->settings['spbc_key'];
        $this->settings_link    = is_network_admin() ? 'settings.php?page=spbc' : 'options-general.php?page=spbc';
        $this->dashboard_link   = 'https://cleantalk.org/my/' . ($this->user_token ? '?user_token=' . $this->user_token : '');
        $this->notice_show      = $this->notice_show || $this->isHaveErrors();
        $this->is_windows       = $this->is_windows();


        $this->scaner_enabled = true;

        // Network
        if ( !$this->is_mainsite ) {
            // Custom key allowed
            if ( $this->ms__work_mode != 2 ) {
                $this->scaner_enabled = false;

                // Mutual key
            } elseif ( $this->ms__work_mode == 2 ) {
                $this->api_key          = $this->network_settings['spbc_key'];
                $this->key_is_ok        = $this->network_data['key_is_ok'];
                $this->user_token       = $this->network_data['user_token'];
                $this->service_id       = $this->network_data['service_id'];
                $this->moderate         = $this->network_data['moderate'];
                $this->notice_show      = false;
                $this->scaner_enabled   = false;
            }
        }

        $this->data['site_utc_offset_in_seconds'] = (current_time('timestamp') - time());

        $this->data['wl_company_name'] = $this->data["wl_mode_enabled"] ? $this->data["wl_brandname"] : $this->default_data['wl_company_name'];

        $this->feature_restrictions = new FeatureRestriction\FeatureRestrictionService();
    }

    /**
     * Wrapper for CMS
     * Getting the option from the database
     *
     * @param $option_name
     *
     * @return bool|mixed|void
     */
    protected function getOption($option_name)
    {
        return strpos($option_name, 'network') !== false
            ? get_site_option($this->option_prefix . '_' . $option_name)
            : get_option($this->option_prefix . '_' . $option_name);
    }

    /**
     * @param string $option_name
     * @param bool $use_perfix
     * @param bool $autoload
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function save($option_name, $use_perfix = true, $autoload = true)
    {
        if ( strpos($option_name, 'network') !== false ) {
            return update_site_option(
                $this->option_prefix . '_' . $option_name,
                (array)$this->$option_name
            );
        }

        return update_option(
            $use_perfix ? $this->option_prefix . '_' . $option_name : $option_name,
            (array)$this->$option_name,
            $autoload
        );
    }

    /**
     * @param $option_name
     * @param bool $use_prefix
     * @psalm-suppress PossiblyUnusedMethod
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function deleteOption($option_name, $use_prefix = false)
    {
        if ( $this->__isset($option_name) ) {
            $this->__unset($option_name);
            delete_option(($use_prefix ? $this->option_prefix . '_' : '') . $option_name);
        }
    }

    /**
     * Generates new State when switching to a new blog
     * Useful for Multisite builds
     *
     * @using add_action( 'switch_blog', array( '\CleantalkSP\SpbctWP\State', 'resetState'), 2, 10 );
     */
    public static function resetState()
    {

        global $spbc, $spbc_old;

        $spbc_old = $spbc;

        $spbc = new self(
            'spbc',
            array(
                'settings',
                'data',
                'remote_calls',
                'debug',
                'installing',
                'errors',
                'fw_stats'
            ),
            is_multisite(),
            is_main_site()
        );

        return $spbc;
    }

    public static function restoreState()
    {

        global $spbc, $spbc_old;

        $spbc = $spbc_old;

        unset($spbc_old);
    }

    /**
     * Checking if errors are in the setting, and they are not empty.
     *
     * @return bool
     */
    public function isHaveErrors()
    {
        if ( count((array)$this->errors) ) {
            foreach ( (array)$this->errors as $error ) {
                if ( is_array($error) ) {
                    return (bool)count($error);
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Check if the system is Windows.
     * @return bool false if not windows. Return false on error if  php_uname and PHP_OS are unavailable,
     * also generate spbc configuration error.
     */
    protected function is_windows() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        if ( !function_exists('php_uname') ) {
            if ( defined('PHP_OS') ) {
                $this->error_delete('configuration');
                $result = strpos(strtolower(PHP_OS), 'win') !== false ? true : false;
            } else {
                $error = 'Can not detect operating system type, please check if php_uname() is available '
                    . 'in PHP configuration or PHP_OS are defined. Malware Scanner has been disabled.';
                $this->error_add('configuration', $error);
                $result = false;
            }
        } else {
            $this->error_delete('configuration');
            $result = strpos(strtolower(php_uname('s')), 'windows') !== false ? true : false;
        }
        return $result;
    }

    /**
     * Extends parent error_add adding current_time as custom error timestamp
     * @param $type
     * @param $error
     * @param null $major_type
     * @param bool $set_time
     * @param null $custom_timestamp
     */
    public function error_add($type, $error, $major_type = null, $set_time = true, $custom_timestamp = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        parent::error_add($type, $error, $major_type, $set_time, current_time('timestamp'));
    }
}
