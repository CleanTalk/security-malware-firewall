<?php

use CleantalkSP\SpbctWP\Cron as SpbcCron;
use CleantalkSP\SpbctWP\HTTP\CDNHeadersChecker;
use CleantalkSP\SpbctWP\Scanner\ScanningLog\ScanningLogFacade;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\ListTable;
use CleantalkSP\SpbctWP\Scanner;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\SpbctWP\Helpers\Arr;
use CleantalkSP\SpbctWP\Helpers\CSV;
use CleantalkSP\SpbctWP\Escape;
use CleantalkSP\SpbctWP\Views\Settings;

// Scanner AJAX actions
require_once(SPBC_PLUGIN_DIR . 'inc/spbc-scanner.php');

/*
 * Contactins setting page functions
 * Included from /security-malware-firewall.php -> /inc/spbc-admin.php
 */

/**
 * Action 'admin_menu' - Add the admin options page
 *
 * @global \CleantalkSP\SpbctWP\State $spbc
 */
function spbc_admin_add_page()
{
    global $spbc;

    // Adding setting page
    if (is_network_admin()) {
        add_submenu_page("settings.php", __($spbc->data["wl_brandname"] . ' Settings', 'security-malware-firewall'), $spbc->data["wl_brandname"], 'manage_options', 'spbc', 'spbc_settings_page');
    } else {
        add_options_page(__($spbc->data["wl_brandname"] . ' Settings', 'security-malware-firewall'), $spbc->data["wl_brandname"], 'manage_options', 'spbc', 'spbc_settings_page');
        // add_options_page(__($spbc->data["wl_brandname"] . ' Settings', 'security-malware-firewall'), $spbc->data["wl_brandname"], 'manage_options', 'spbc', [Settings::class, 'page']);
    }

    // Register setting
    register_setting(SPBC_SETTINGS, SPBC_SETTINGS, array(
        'sanitize_callback' => 'spbc_sanitize_settings'
    ));

    spbc_settings__register();
}

/**
 * @return void
 * @psalm-suppress ComplexFunction
 * @ToDo The function need to be refactored and `psalm-suppress` removed
 */
function spbc_settings__register()
{
    global $spbc, $wp_version;

    // Show debug if CONNECTION_ERROR exists
    if ( ! empty($spbc->errors)) {
        $errors = $spbc->errors;
        foreach ($errors as $_type => $error) {
            if ( ! empty($error)) {
                if (is_array(current($error))) {
                    foreach ($error as $_sub_type => $sub_error) {
                        if (strpos($sub_error['error'], 'CONNECTION') !== false) {
                            $spbc->show_debug = true;
                        }
                    }
                } elseif (
                    isset($error['error']) &&
                    is_string($error['error']) && strpos($error['error'], 'CONNECTION') !== false
                ) {
                    $spbc->show_debug = true;
                }
            }
        }
    }

    $spbc->settings__elements = spbc_settings__register_sections_and_fields(
        array(
            // TABS
            // Firewall
            'traffic_control'  => array(
                'type'         => 'tab',
                'display'      => $spbc->settings['secfw__enabled'],
                'title'        => __('Firewall', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-exchange',
                'class_prefix' => 'spbc',
                'active'       => true,
                'ajax'         => true,
                'js_after'     => 'settings_tab--traffic_control.min.js',
                'sections'     => array(
                    'tc_log' => array(
                        'type'   => 'section',
                        'fields' => array(
                            'tc_log' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_traffic_control_log'
                            ),
                        ),
                    ),
                ),
            ),
            // Scanner
            'scanner'          => array(
                'type'         => 'tab',
                'display'      => $spbc->scaner_enabled,
                'title'        => __('Malware Scanner', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-search',
                'class_prefix' => 'spbc',
                'ajax'         => true,
                'js_after'     => 'settings_tab--scanner.min.js',
                'sections'     => array(
                    'scanner' => array(
                        'type'   => 'section',
                        'fields' => array(
                            'scanner' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_scanner'
                            ),
                        ),
                    ),
                ),
            ),
            // Backups
            'backups'          => array(
                'type'         => 'tab',
                'display'      => $spbc->scaner_enabled,
                'title'        => __('Backups', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-download',
                'class_prefix' => 'spbc',
                'active'       => false,
                'ajax'         => true,
                'js_after'     => 'settings_tab--backups.min.js',
                'sections'     => array(
                    'scanner' => array(
                        'type'   => 'section',
                        'fields' => array(
                            'scanner' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_backups'
                            ),
                        ),
                    ),
                ),
            ),
            // Security log
            'security_log'     => array(
                'type'         => 'tab',
                'title'        => __('Security Log', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-user-secret',
                'class_prefix' => 'spbc',
                'ajax'         => true,
                'js_after'     => 'settings_tab--security_log.min.js',
                'sections'     => array(
                    'security_log' => array(
                        'type'   => 'section',
                        'fields' => array(
                            'security_log' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_security_logs'
                            ),
                        ),
                    ),
                ),
            ),
            // Settings
            'settings_general' => array(
                'type'         => 'tab',
                'title'        => __('General Settings', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-sliders',
                'class_prefix' => 'spbc',
                'ajax'         => true,
                'js_after'     => 'settings_tab--settings_general.min.js',
                'after'        => 'submit_button',
                'sections'     => array(
                    'apikey'          => array(
                        'type'   => 'section',
                        'title'  => __('Access Key', 'security-malware-firewall'),
                        'anchor'      => 'apikey',
                        'fields' => array(
                            'apikey'                  => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_key'
                            ),
                            'ms__work_mode'           => array(
                                'type'             => 'field',
                                'input_type'       => 'select',
                                'options'          => array(
                                    array(
                                        'val'             => 1,
                                        'label'           => __('Mutual Account, Individual Access Keys', 'security-malware-firewall'),
                                        'children_enable' => 1,
                                    ),
                                    array(
                                        'val'             => 2,
                                        'label'           => __('Mutual Account, Mutual Access Key', 'security-malware-firewall'),
                                        'children_enable' => 0,
                                    ),
                                    array(
                                        'val'             => 3,
                                        'label'           => __('Individual accounts, individual Access keys', 'security-malware-firewall'),
                                        'children_enable' => 0,
                                    ),
                                ),
                                'title'            => __('WordPress Multisite Work Mode', 'security-malware-firewall'),
                                'description'      => __('You can choose the work mode here for the child blogs and how they will operate with the CleanTalk Cloud. Press "?" for the detailed description.', 'security-malware-firewall'),
                                'long_description' => true,
                                'display'          => $spbc->is_network && $spbc->is_mainsite,
                                'children'         => array('ms__hoster_api_key'),
                                'value_source'     => 'network_settings',
                            ),
                            'ms__hoster_api_key'      => array(
                                'type'                => 'field',
                                'input_type'          => 'text',
                                'title'               => __('Hoster access key', 'security-malware-firewall'),
                                'description'         => __('Another API allowing you to hold multiple blogs on on account.', 'security-malware-firewall'),
                                'class'               => 'spbc_middle_text_field',
                                'title_first'         => true,
                                'long_description'    => true,
                                'display'             => $spbc->is_network && $spbc->is_mainsite,
                                'disabled'            => ! isset($spbc->network_settings['ms__work_mode']) || $spbc->network_settings['ms__work_mode'] != 1,
                                'value_source'        => 'network_settings',
                                'parent_value_source' => 'network_settings',
                                'parent'              => 'ms__work_mode',
                            ),
                            'ms__service_utilization' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_service_utilization',
                                'display'  => $spbc->is_network && $spbc->is_mainsite && $spbc->ms__work_mode == 1,
                            ),
                        ),
                    ),
                    'auth'            => array(
                        'type'   => 'section',
                        'title'  => __('Authentication and Logging In', 'security-malware-firewall'),
                        'anchor' => 'auth',
                        'fields' => array(

                            'bfp__heading' => [
                                'type' => 'plain',
                                'callback' => 'spbc_field_bfp__heading',
                            ],
                            // Hidden BFP fields
                            'bfp__delay__1_fails'      => array('type' => 'field', 'input_type' => 'hidden'),
                            'bfp__delay__5_fails'      => array('type' => 'field', 'input_type' => 'hidden'),

                            'bfp__allowed_wrong_auths' => array(
                                'title' => esc_html__('Maximum authorization tries', 'security-malware-firewall'),
                                'title_first' => true,
                                'type' => 'field',
                                'input_type' => 'number',
                                'min' => 3,
                                'max' => 20,
                                'class' => 'spbc_middle_text_field spbc_sub_setting'
                            ),

                            'bfp__count_interval' => array(
                                'title' => esc_html__('Time frame to measure login attempts', 'security-malware-firewall'),
                                'title_first' => true,
                                'type' => 'field',
                                'input_type' => 'select',
                                'options'    => array(
                                    array('val' => 300, 'label' => __('5 minutes', 'security-malware-firewall'),),
                                    array('val' => 600, 'label' => __('10 minutes', 'security-malware-firewall'),),
                                    array('val' => 900, 'label' => __('15 minutes', 'security-malware-firewall'),),
                                ),
                                'class' => 'spbc_middle_text_field spbc_sub_setting'
                            ),

                            'bfp__block_period__5_fails'  => array(
                                'title' => esc_html__('Blocking for', 'security-malware-firewall'),
                                'title_first' => true,
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options'    => array(
                                    array('val' => 120, 'label' => __('2 minutes', 'security-malware-firewall'),),
                                    array('val' => 300, 'label' => __('5 minutes', 'security-malware-firewall'),),
                                    array('val' => 600, 'label' => __('10 minutes', 'security-malware-firewall'),),
                                    array('val' => 1800, 'label' => __('30 minutes', 'security-malware-firewall'),),
                                    array('val' => 3600, 'label' => __('1 hour', 'security-malware-firewall'),),
                                    array('val' => 10800, 'label' => __('3 hours', 'security-malware-firewall'),),
                                    array('val' => 21600, 'label' => __('6 hours', 'security-malware-firewall'),),
                                    array('val' => 43200, 'label' => __('12 hours', 'security-malware-firewall'),),
                                    array('val' => 86400, 'label' => __('24 hours', 'security-malware-firewall'),),
                                ),
                                'class' => 'spbc_middle_text_field spbc_sub_setting'
                            ),
                            '2fa__enable'                 => array(
                                'type'             => 'field',
                                'input_type'       => 'radio',
                                'options'          => array(
                                    array(
                                        'val'             => 1,
                                        'label'           => __('On', 'security-malware-firewall'),
                                        'children_enable' => 1,
                                    ),
                                    array(
                                        'val'             => 0,
                                        'label'           => __('Off', 'security-malware-firewall'),
                                        'children_enable' => 0,
                                    ),
                                    array(
                                        'val'             => - 1,
                                        'label'           => __('Only for new devices', 'security-malware-firewall'),
                                        'children_enable' => 1,
                                    ),
                                ),
                                'title'            => __('Two-factor authentication (2FA)', 'security-malware-firewall'),
                                'description'      => 'spbc_settings_2fa_description_callback',
                                'children'         => array('2fa__roles]['),
                                'long_description' => true,
                            ),
                            '2fa__roles'                  => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_2fa__roles',
                            ),
                            'login_page_rename__enabled'  => array(
                                'display'     => version_compare($wp_version, '4.0-RC1-src', '>='),
                                'type'        => 'field',
                                'title'       => __('Change address to login script', 'security-malware-firewall'),
                                'description' => __('Please note that this will not hide the links to your registration page on your website.', 'security-malware-firewall'),
                                'children'    => array('login_page_rename__name', 'login_page_rename__redirect', 'login_page_rename__send_email_notification'),
                            ),
                            'login_page_rename__name'     => array(
                                'display'     => version_compare($wp_version, '4.0-RC1-src', '>='),
                                'input_type'  => 'text',
                                'type'        => 'field',
                                'title_first' => true,
                                'title'       => __('Login URL: ', 'security-malware-firewall')
                                                 . get_home_url()
                                                 . '/'
                                                 . (get_option('permalink_structure', false) ? '' : '?'),
                                'class'       => 'spbc_middle_text_field',
                                'parent'      => 'login_page_rename__enabled',
                            ),
                            'login_page_rename__redirect' => array(
                                'display'     => version_compare($wp_version, '4.0-RC1-src', '>='),
                                'input_type'  => 'text',
                                'type'        => 'field',
                                'title_first' => true,
                                'title'       => __('Redirect URL: ', 'security-malware-firewall')
                                                 . get_home_url()
                                                 . '/'
                                                 . (get_option('permalink_structure', false) ? '' : '?'),
                                'description' => __('If someone tries to access the default login page they will be redirected to the URL above.', 'security-malware-firewall'),
                                'class'       => 'spbc_middle_text_field',
                                'parent'      => 'login_page_rename__enabled',
                            ),
                            'login_page_rename__send_email_notification' => array(
                                'display'     => version_compare($wp_version, '4.0-RC1-src', '>='),
                                'input_type'  => 'checkbox',
                                'type'        => 'field',
                                'title_first' => true,
                                'title'       => __('Send the notification with the new login page URL to the admin email address', 'security-malware-firewall'),
                                'description' => __('The email will be send to', 'security-malware-firewall')
                                    . ' (' . spbc_get_admin_email() . ')',
                                'long_description' => true,
                                'parent'      => 'login_page_rename__enabled',
                                'disabled' => !current_user_can('activate_plugins')
                            ),
                            'action_shuffle_salts'        => array(
                                'type'     => 'field',
                                'callback' => 'spbc_settings_field__action_shuffle_salts',
                            ),
                        ),
                    ),
                    'firewall'        => array(
                        'type'        => 'section',
                        'title'       => __('Firewall', 'security-malware-firewall'),
                        'anchor'      => 'firewall',
                        'description' => __('Any IP addresses of the logged in administrators will be automatically added to your Personal Lists and will be approved all the time.', 'security-malware-firewall'),
                        'fields'      => array(
                            'fw__custom_message'                => array(
                                'type'       => 'field',
                                'input_type' => 'hidden',
                            ),
                            'secfw__enabled'                      => array(
                                'type'        => 'field',
                                'title'       => __('Security FireWall', 'security-malware-firewall'),
                                'description' => __('This option allows to filter bots before they access website. Also reduces CPU usage on hosting server and accelerates pages load time.', 'security-malware-firewall'),
                                'long_description' => true,
                            ),
                            'waf__enabled'                      => array(
                                'type'        => 'field',
                                'title'       => __('Web Application Firewall', 'security-malware-firewall'),
                                'description' => __('Catches dangerous stuff like: XSS, MySQL-injections and uploaded malicious files.', 'security-malware-firewall'),
                                'children'    => array(
                                    'waf__xss_check',
                                    'waf__sql_check',
                                    'waf__exploit_check',
                                    'waf_blocker__enabled'
                                ),
                            ),
                            'waf__xss_check'                    => array(
                                'type'             => 'field',
                                'title'            => __('XSS check', 'security-malware-firewall'),
                                'description'      => __('Cross-Site Scripting test.', 'security-malware-firewall'),
                                'long_description' => true,
                                'parent'           => 'waf__enabled',
                            ),
                            'waf__sql_check'                    => array(
                                'type'             => 'field',
                                'title'            => __('SQL-injection check', 'security-malware-firewall'),
                                'description'      => __('SQL-injection test.', 'security-malware-firewall'),
                                'long_description' => true,
                                'parent'           => 'waf__enabled',
                            ),
                            'waf__exploit_check'                => array(
                                'type'        => 'field',
                                'title'       => __('Check for exploits', 'security-malware-firewall'),
                                'description' => __('Check traffic for known exploits.', 'security-malware-firewall'),
                                'parent'      => 'waf__enabled',
                            ),
                            'waf_blocker__enabled'                => array(
                                'type'        => 'field',
                                'title'       => __('WAF Blocker', 'security-malware-firewall'),
                                'description' => __('Blocking a visitor for 24 hours after several WAF detected brute force attempts.', 'security-malware-firewall'),
                                'parent'      => 'waf__enabled',
                            ),
                            'upload_checker__file_check'                   => array(
                                'type'             => 'field',
                                'title'            => __('Run the Upload Checker module for uploaded files', 'security-malware-firewall'),
                                'description'      => __('The plugin will scan files uploaded to the WordPress media library for known malicious code with heuristic and signature analysis. If malware found, upload will stop.', 'security-malware-firewall'),
                                'long_description' => true,
                                'children'         => array('upload_checker__do_check_wordpress_modules')
                            ),
                            'upload_checker__do_check_wordpress_modules' => array(
                                'type'        => 'field',
                                'title'       => __('Check plugins and themes archives before install', 'security-malware-firewall'),
                                'description' => __('Check the plugins and themes uploaded via WordPress built in interface with signature analysis.', 'security-malware-firewall'),
                                'parent'      => 'upload_checker__file_check',
                                'class'       => 'spbc_sub2_setting',
                            ),
                            'traffic_control__enabled'          => array(
                                'type'             => 'field',
                                'title'            => __('Traffic Control', 'security-malware-firewall'),
                                'description'      => __('This feature shows a list of visits and hits of everyone who tried to go to your website. Allows you to ban any visitor, a whole country or a network.', 'security-malware-firewall'),
                                'long_description' => true,
                                'children'         => array(
                                    'traffic_control__autoblock_timeframe',
                                    'traffic_control__autoblock_amount',
                                    'traffic_control__autoblock_period',
                                    'traffic_control__exclude_authorised_users'
                                ),
                            ),
                            'traffic_control__autoblock_timeframe' => array(
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options'    => array(
                                    array('val' => 60, 'label' => __('1 minute', 'security-malware-firewall'),),
                                    array('val' => 180, 'label' => __('3 minutes', 'security-malware-firewall'),),
                                    array('val' => 300, 'label' => __('5 minutes', 'security-malware-firewall'),),
                                    array('val' => 600, 'label' => __('10 minutes', 'security-malware-firewall'),),
                                    array('val' => 900, 'label' => __('15 minutes', 'security-malware-firewall'),),
                                    array('val' => 1800, 'label' => __('30 minutes', 'security-malware-firewall'),),
                                    array('val' => 3600, 'label' => __('60 minutes', 'security-malware-firewall'),),
                                ),
                                'title_first' => true,
                                'title'       => __('Time frame to measure page hits', 'security-malware-firewall'),
                                'class'       => 'spbc_short_text_field',
                                'parent'      => 'traffic_control__enabled',
                            ),
                            'traffic_control__autoblock_amount' => array(
                                'input_type'  => 'text',
                                'type'        => 'field',
                                'title_first' => true,
                                'title'       => __('Block a visitor if count of the opened pages in the Time frame more than', 'security-malware-firewall'),
                                'class'       => 'spbc_short_text_field',
                                'parent'      => 'traffic_control__enabled',
                            ),
                            'traffic_control__autoblock_period' => array(
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options'    => array(
                                    array('val' => 60, 'label' => __('1 minute', 'security-malware-firewall'),),
                                    array('val' => 300, 'label' => __('5 minutes', 'security-malware-firewall'),),
                                    array('val' => 900, 'label' => __('15 minutes', 'security-malware-firewall'),),
                                    array('val' => 3600, 'label' => __('1 hour', 'security-malware-firewall'),),
                                    array('val' => 43200, 'label' => __('12 hours', 'security-malware-firewall'),),
                                    array('val' => 86400, 'label' => __('24 hours', 'security-malware-firewall'),),
                                    array('val' => 259200, 'label' => __('3 days', 'security-malware-firewall'),),
                                ),
                                'title'      => __('Block a visitor if they exceeded the limit of opened pages for', 'security-malware-firewall'),
                                'parent'     => 'traffic_control__enabled',
                            ),
                            'traffic_control__exclude_authorised_users' => array(
                                'type'       => 'field',
                                'title'      => esc_html__('Ignore logged in users', 'security-malware-firewall'),
                                'description' => esc_html__('Enable this option for Traffic Control to stop watching logged in users and keep watching website guests only.', 'security-malware-firewall'),
                                'parent'     => 'traffic_control__enabled',
                            ),
                            'secfw__get_ip' => array(
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options'    => spbc_settings_field__secfw__get_ip__get_labels(),
                                'title'      => __('Get visitors IP from additional headers', 'security-malware-firewall'),
                                'description' => spbc_settings_field__secfw__get_ip__get_description(),
                                'long_description' => true,
                            ),
                            'secfw__get_ip__enable_cdn_auto_self_check' => array(
                                'type'       => 'field',
                                'title'      => __('Enable automatic CDN headers checker', 'security-malware-firewall'),
                                'description' => CDNHeadersChecker::getOptionDescriptionText(),
                            ),
                        ),
                    ),
                    'scanner_setting' => array(
                        'type'    => 'section',
                        'title'   => __('Malware Scanner', 'security-malware-firewall'),
                        'anchor'  => 'scanner_setting',
                        'display' => $spbc->scaner_enabled,
                        'fields'  => array(
                            'scanner__auto_start'                            => array(
                                'type'        => 'field',
                                'title'       => __('Enable autoscanning', 'security-malware-firewall'),
                                'children'    => array('scanner__auto_start_manual','scanner__auto_start__select_period'),
                            ),
                            'scanner__auto_start__set_period'  => array(
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options'    => array(
                                    array('val' => 86400, 'label' => __('24 hours', 'security-malware-firewall'),),
                                    array('val' => 43200, 'label' => __('12 hours', 'security-malware-firewall'),),
                                    array('val' => 259200, 'label' => __('3 days', 'security-malware-firewall'),),
                                    array('val' => 604800, 'label' => __('7 days', 'security-malware-firewall'),),
                                    array('val' => 1209600, 'label' => __('14 days', 'security-malware-firewall'),),
                                    array('val' => 2592000, 'label' => __('30 days', 'security-malware-firewall'),),
                                ),
                                'title'      => __('Scans your website files automatically each:', 'security-malware-firewall'),
                                'description' => spbc_get_next_scan_launch_time_text(),
                                'parent'      => 'scanner__auto_start',
                            ),
                            'scanner__auto_start_manual'                     => array(
                                'type'        => 'field',
                                'title'       => __('Set the time when the autoscanning starts', 'security-malware-firewall'),
                                'description' => __('Scans your website files automatically at the specified time. Uses your browser timezone.', 'security-malware-firewall'),
                                'children'    => array('scanner__auto_start_manual_time'),
                                'parent'      => 'scanner__auto_start',
                            ),
                            'scanner__auto_start_manual_time'                => array(
                                'type'       => 'field',
                                'input_type' => 'time',
                                'parent'     => 'scanner__auto_start_manual',
                                'required'   => true,
                            ),
                            'scanner__auto_start_manual_tz'                => array(
                                'type'       => 'field',
                                'input_type' => 'hidden',
                                'value'      => get_option('gmt_offset'),
                            ),
                            'scanner__outbound_links'                        => array(
                                'type'             => 'field',
                                'title'            => __('Scan for outbound links', 'security-malware-firewall'),
                                'description'      => __('Turning this option on may increase scanning time for websites with a lot of pages.', 'security-malware-firewall'),
                                'long_description' => true,
                                'children'         => array('scanner__outbound_links_mirrors'),
                            ),
                            'scanner__outbound_links_mirrors'                => array(
                                'type'        => 'field',
                                'input_type'  => 'text',
                                'parent'      => 'scanner__outbound_links',
                                'title'       => __('Exclusions', 'security-malware-firewall'),
                                'description' => __('Here you can specify the links that will not be checked by the scanner. Separate them with a comma and omit protocols (examples: "some.com, example.net, my.org").', 'security-malware-firewall'),
                                'class'       => 'spbc_long_text_field',
                            ),
                            'scanner__important_files_listing'               => array(
                                'type'        => 'field',
                                'title'       => __('Scan if listing is enabled for important directory', 'security-malware-firewall'),
                                'description' => __('The scanner will check if important files and directories are publicly accessible such as "ROOT/.svn", "ROOT/.git", "debug.log" and others.', 'security-malware-firewall'),
                                'class'       => 'spbc_long_text_field',
                            ),
                            'scanner__heuristic_analysis'                    => array(
                                'type'             => 'field',
                                'title'            => __('Heuristic analysis', 'security-malware-firewall'),
                                'description'      => __('Will search for dangerous code in modified files. Unknown files will be shown in the results only if both options heuristic analysis and signature analysis are enabled.', 'security-malware-firewall'),
                                'long_description' => true,
                                'children'    => array('scanner__schedule_send_heuristic_suspicious_files'),
                            ),
                            'scanner__schedule_send_heuristic_suspicious_files'                    => array(
                                'type'             => 'field',
                                'title'            => __('Automatically send suspicious files for Cloud analysis', 'security-malware-firewall'),
                                'description'      => __('Will send every file that marked as "Suspicious" by Heuristic check.', 'security-malware-firewall'),
                                'long_description' => true,
                                'input_type'       => 'radio',
                                'options'          => array(
                                    array('val' => 0, 'label' => __('Off', 'security-malware-firewall'),),
                                    array('val' => 2, 'label' => __('Auto', 'security-malware-firewall'), 'default'),
                                    array('val' => 1, 'label' => __('On', 'security-malware-firewall'),),
                                ),
                                'parent'           => 'scanner__heuristic_analysis',
                            ),
                            'scanner__signature_analysis'                    => array(
                                'type'             => 'field',
                                'title'            => __('Signature analysis', 'security-malware-firewall'),
                                'description'      => __('Will search for known malicious signatures in files. Unknown files will be shown in the results only if both options heuristic analysis and signature analysis are enabled.', 'security-malware-firewall'),
                                'long_description' => true,
                            ),
                            'scanner__dir_exclusions'                        => array(
                                'type'        => 'field',
                                'input_type'  => 'textarea',
                                'title'       => __('Directory exclusions for the malware scanner:', 'security-malware-firewall'),
                                'title_first' => true,
                                'description' => __('Input relative directories (WordPress folder is ROOT). Separate each directory path by a new line.', 'security-malware-firewall'),
                                'long_description' => true
                            ),
                            'scanner__auto_cure'                             => array(
                                'type'             => 'field',
                                'title'            => __('Cure malware', 'security-malware-firewall'),
                                'description'      => __('Will cure know malware.', 'security-malware-firewall'),
                                'long_description' => true,
                            ),
                            'scanner__frontend_analysis'                     => array(
                                'type'        => 'field',
                                'title'       => __('Scan HTML code', 'security-malware-firewall'),
                                'description' => __('Will scan HTML code on the website pages for known bad constructions.', 'security-malware-firewall'),
                            ),
                            'scanner__frontend_analysis__csrf'               => array(
                                'type'        => 'field',
                                'title'       => __('Cross-Site Request Forgery Detection', 'security-malware-firewall'),
                                'description' => __('Detects SCRF attack types in the public HTML on your website.', 'security-malware-firewall'),
                                'parent'      => 'scanner__frontend_analysis',
                            ),
                            'scanner__frontend_analysis__domains_exclusions' => array(
                                'type'        => 'field',
                                'input_type'  => 'textarea',
                                'title'       => __('Allowed domains:', 'security-malware-firewall'),
                                'title_first' => true,
                                'description' => __('The scanner will not consider these domains as malware. Separate each domain by a new line.', 'security-malware-firewall'),
                            ),
                            'scanner__list_unknown'                          => array(
                                'type'        => 'field',
                                'title'       => __('List unknown files', 'security-malware-firewall'),
                                'description' => __('Shows the list of found unknown files in the malware scanner report. Unknown files do not have known virus signatures and do not have suspicious code. Meanwhile, unknown files do not belong to the public plugins and themes at wordpress.org.', 'security-malware-firewall'),
                                'children'    => array('scanner__list_unknown__older_than'),
                            ),
                            'scanner__list_unknown__older_than'              => array(
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options'    => array(
                                    array('val' => 1, 'label' => __('1 day', 'security-malware-firewall'),),
                                    array('val' => 3, 'label' => __('3 days', 'security-malware-firewall'), 'default'),
                                    array('val' => 5, 'label' => __('5 days', 'security-malware-firewall'),),
                                    array('val' => 10, 'label' => __('10 days', 'security-malware-firewall'),),
                                ),
                                'title'      => __('Do not show unknown files older than', 'security-malware-firewall'),
                                'parent'     => 'scanner__list_unknown',
                            ),
                            'scanner__list_approved_by_cleantalk' => array(
                                'type'        => 'field',
                                'title'       => __('Show approved by CleanTalk Cloud', 'security-malware-firewall'),
                                'description' => __('Enable this option to enable list of Approve by CleanTalk Cloud files', 'security-malware-firewall'),
                            ),
                            'scanner__file_monitoring'                             => array(
                                'type'             => 'field',
                                'title'            => __('Important File Monitoring', 'security-malware-firewall'),
                                'description'      => __('Monitoring of the individual most important files of the site.', 'security-malware-firewall'),
                            ),
                            'scanner__fs_watcher'                             => array(
                                'type'             => 'field',
                                'title'            => __('File System Watcher', 'security-malware-firewall'),
                                'description'      => \CleantalkSP\SpbctWP\FSWatcher\View\View::getFSWatcherDescription(new \CleantalkSP\SpbctWP\FSWatcher\View\Phrases()),
                                'children' => array('scanner__fs_watcher__snapshots_period')
                            ),
                            'scanner__fs_watcher__snapshots_period'                             => array(
                                'type'             => 'field',
                                'input_type'  => 'select',
                                'options'    => array(
                                    array('val' => 3600, 'label' => __('1 hour', 'security-malware-firewall'),),
                                    array('val' => 10800, 'label' => __('3 hours', 'security-malware-firewall'),),
                                    array('val' => 21600, 'label' => __('6 hours', 'security-malware-firewall'),),
                                    array('val' => 43200, 'label' => __('12 hours', 'security-malware-firewall'),),
                                    array('val' => 86400, 'label' => __('1 day', 'security-malware-firewall'),),
                                ),
                                'title'            => __('Snapshots period', 'security-malware-firewall'),
                                'description'      => \CleantalkSP\SpbctWP\FSWatcher\View\View::getFSWatcherSnapshotsPeriodDescription(new \CleantalkSP\SpbctWP\FSWatcher\View\Phrases()),
                                'parent' => 'scanner__fs_watcher'
                            ),
                        ),
                    ),

                    // Modules vulnerability detection
                    'vulnerability_check'       => array(
                        'type'    => 'section',
                        'title'   => __('Modules vulnerability detection', 'security-malware-firewall'),
                        'anchor'  => 'vulnerability_check',
                        'display' => current_user_can('activate_plugins'),
                        'fields'  => array(
                            'vulnerability_check__test_before_install'            => array(
                                'type'        => 'field',
                                'title'       => __('Test plugins for known vulnerabilities before install them', 'security-malware-firewall'),
                                'description' => __('Request the research.cleantalk.org about the plugin status to let you know about vulnerability status on the page [Plugins->Add new]', 'security-malware-firewall'),
                                'long_description' => true,
                            ),
                            'vulnerability_check__enable_cron'            => array(
                                'type'        => 'field',
                                'title'       => __('Test already installed plugins for known vulnerabilities', 'security-malware-firewall'),
                                'long_description' => true,
                                'description' => __('Every 24 hours the plugin checks all the installed plugins over database research.cleantalk.org. ', 'security-malware-firewall'),
                                'children' => array('vulnerability_check__warn_on_modules_pages'),
                            ),
                            'vulnerability_check__warn_on_modules_pages'            => array(
                                'type'        => 'field',
                                'title'       => __('Warn me about known vulnerabilities of already installed plugins', 'security-malware-firewall'),
                                'description' => __('Modify the page of installed plugins to let you know about vulnerabilities found', 'security-malware-firewall'),
                                'parent' => 'vulnerability_check__enable_cron'
                            ),
                        ),
                    ),

                    // Admin bar
                    'admin_bar'       => array(
                        'type'    => 'section',
                        'title'   => __('Admin Bar', 'security-malware-firewall'),
                        'anchor'  => 'admin_bar',
                        'display' => current_user_can('activate_plugins'),
                        'fields'  => array(
                            'admin_bar__show'                 => array(
                                'type'        => 'field',
                                'title'       => __('Show statistics in admin bar', 'security-malware-firewall'),
                                'description' => __('Show/hide the ' . $spbc->data["wl_company_name"] . ' drop-down menu at the top bar of the WordPress backend.', 'security-malware-firewall'),
                                'children'    => array(
                                    'admin_bar__admins_online_counter',
                                    'admin_bar__brute_force_counter',
                                    'admin_bar__firewall_counter'
                                ),
                            ),
                            'admin_bar__admins_online_counter' => array(
                                'type'        => 'field',
                                'title'       => __('Administrators online counter', 'security-malware-firewall'),
                                'description' => __('Shows the number of administrators online in the admin bar.', 'security-malware-firewall'),
                                'parent'      => 'admin_bar__show',
                            ),
                            'admin_bar__brute_force_counter'  => array(
                                'type'        => 'field',
                                'title'       => __('Allowed/Blocked login attempts counter', 'security-malware-firewall'),
                                'description' => __('Shows the number of blocked login attempts in the admin bar. Counts only the local database.', 'security-malware-firewall'),
                                'parent'      => 'admin_bar__show',
                            ),
                            'admin_bar__firewall_counter'     => array(
                                'type'        => 'field',
                                'title'       => __('Security Firewall counter', 'security-malware-firewall'),
                                'description' => __('Shows the firewall counters in the admin bar. Counts only the local database.', 'security-malware-firewall'),
                                'parent'      => 'admin_bar__show',
                            ),
                            'wp__dashboard_widget__show'     => array(
                                'type'        => 'field',
                                'title'       => __('Security brief report widget', 'security-malware-firewall'),
                                'description' => __('Shows the brief widget on the main admin page', 'security-malware-firewall'),
                            ),
                        )
                    ),

                    'misc' => array(
                        'type'   => 'section',
                        'title'  => __('Miscellaneous', 'security-malware-firewall'),
                        'anchor' => 'misc',
                        'fields' => array(
                            'misc__backend_logs_enable'                  => array(
                                'display'          => is_main_site(),
                                'disabled'         => ! $spbc->data['extra_package']['backend_logs'],
                                'type'             => 'field',
                                'title'            => __('Collect and send PHP logs', 'security-malware-firewall'),
                                'description'      => $spbc->data['extra_package']['backend_logs'] || $spbc->data["wl_mode_enabled"]
                                    ? __('Collect and send PHP error logs to your ' . $spbc->data["wl_company_name"] . ' Dashboard where you can list them.', 'security-malware-firewall')
                                    : sprintf(
                                        __(
                                            'To see the collected logs please use the %sBackend PHP log%s. The %sextra package%s is required to start the collection, please click "Synchronize with the Cloud" in the plugin settings after purchasing the Extra package.',
                                            'security-malware-firewall'
                                        ),
                                        '<a href="https://cleantalk.org/my/backend_logs?user_token=' . $spbc->user_token . '" target="_blank">',
                                        '</a>',
                                        '<a href="https://cleantalk.org/my/bill/security?package=1" target="_blank">',
                                        '</a>'
                                    ),
                                'long_description' => true,
                            ),
                            'misc__prevent_logins_collecting'            => array(
                                'type'        => 'field',
                                'title'       => __('Prevent collecting of authors logins', 'security-malware-firewall'),
                                'long_description' => true,
                                'description' => __('Prevent bots from collecting logins of the content authors from the website links (like example.com/?author=1).', 'security-malware-firewall'),
                            ),
                            'misc__show_link_in_login_form'              => array(
                                'type'        => 'field',
                                'title'       => __('Let them know about protection', 'security-malware-firewall'),
                                'description' => __('Place the ' . $spbc->data["wl_company_name"] . ' warning under the website login form: "Brute-force protection by ' . $spbc->data["wl_brandname"] . '. All attempts are being logged."', 'security-malware-firewall'),
                            ),
                            'wp__disable_xmlrpc'                         => array(
                                'type'             => 'field',
                                'title'            => __('Disable XML-RPC', 'security-malware-firewall'),
                                'description'      => __('Turn this on to disable a WordPress out-of-date technology of connecting websites to miscellaneous systems.', 'security-malware-firewall'),
                                'long_description' => true,
                            ),
                            'wp__disable_rest_api_for_non_authenticated' => array(
                                'type'            => 'field',
                                'title'           => __('Disable REST API for non-authenticated users', 'security-malware-firewall'),
                                'description'     => __('Turn this on to deny access to WordPress REST API for non-authenticated users. Denied requests will get a 401 HTTP Code (Unauthorized).', 'security-malware-firewall'),
                                'children_by_ids' => array('_alternative_mechanism'),
                            ),
                            'wp__disable_rest_api_route_users' => array(
                                'type'            => 'field',
                                'title'           => __('Disable the WordPress endpoint "users" REST API', 'security-malware-firewall'),
                                'description'     => __('Disables access to /wp-json/wp/v2/users and /wp-json/wp/v2/users/"id_user"', 'security-malware-firewall'),
                                'children_by_ids' => array('_alternative_mechanism'),
                            ),
                            'data__set_cookies'                          => array(
                                'type'        => 'field',
                                'title'       => __("Set cookies", 'security-malware-firewall'),
                                'description' => __('Turn this option off or use the alternative mechanism for cookies to forbid the plugin generate any cookies on the website\'s front-end.', 'security-malware-firewall')
                                                 . '<br>' . __('Alternative mechanism will store data in the website database and will not set cookies in browsers, so any cache solution will work just fine.', 'security-malware-firewall'),
                                'input_type'  => 'radio',
                                'options'     => array(
                                    array(
                                        'val'             => 1,
                                        'label'           => __('On', 'security-malware-firewall'),
                                        'children_enable' => 0,
                                    ),
                                    array(
                                        'val'             => 0,
                                        'label'           => __('Off', 'security-malware-firewall'),
                                        'children_enable' => 0,
                                    ),
                                    array(
                                        'val'             => 2,
                                        'label'           => __('Alternative mechanism', 'security-malware-firewall'),
                                        'children_enable' => 1,
                                    ),
                                ),
                            ),
                            'misc__forbid_to_show_in_iframes'            => array(
                                'type'        => 'field',
                                'title'       => __('Forbid to show your website in iFrame tags on third-party websites', 'security-malware-firewall'),
                                'description' => __('If this option is enabled, third-party websites can\'t show content of your website in IFrames.', 'security-malware-firewall'),
                            ),
                            'data__additional_headers'                   => array(
                                'display'          => is_main_site(),
                                'type'             => 'field',
                                'title'            => __('Send additional HTTP headers', 'security-malware-firewall'),
                                'description'      => __('Add these headers to the HTTP responses on the public pages: X-Content-Type-Options, X-XSS-Protection to get protection from XSS and drive-by download attacks.', 'security-malware-firewall'),
                                'long_description' => true,
                            ),
                            'wp__use_builtin_http_api'                   => array(
                                'display'     => is_main_site(),
                                'type'        => 'field',
                                'title'       => __('Use WordPress HTTP API', 'security-malware-firewall'),
                                'description' => __('Alternative way of connection to the ' . $spbc->data["wl_company_name"] . ' Cloud. Enable it if you have connection issues.', 'security-malware-firewall'),
                            ),
                            'misc__complete_deactivation'                => array(
                                'display'     => is_main_site(),
                                'type'        => 'field',
                                'title'       => __('Complete deactivation', 'security-malware-firewall'),
                                'description' =>
                                    sprintf(
                                        __(
                                            'The plugin will leave no traces in WordPress after deactivation. It could help if you have problems with the plugin. All files backed up by Malware scanner will be removed from %s directory.',
                                            'security-malware-firewall'
                                        ),
                                        SPBC_PLUGIN_DIR . 'backups' . DIRECTORY_SEPARATOR
                                    )
                            ),
                            'monitoring__users'                          => array(
                                'type'       => 'field',
                                'input_type' => 'hidden',
                            ),
                        ),
                    ),
                    // Trust text, affiliate settings
                    'spbc_trusted_and_affiliate'                    => array(
                        'type'   => 'section',
                        'display' => ! $spbc->data["wl_mode_enabled"],
                        'title'  => __('Trust text, affiliate settings', 'security-malware-firewall'),
                        //'section' => 'hidden_section',
                        'anchor'      => 'spbc_trusted_and_affiliate',
                        'fields' => array(
                            'spbc_trusted_and_affiliate__shortcode'       => array(
                                'title'           => __('Shortcode', 'security-malware-firewall'),
                                'description' => __(
                                    'You can place this shortcode anywhere on your website. Adds trust text stating that the website is protected from malware by ' . $spbc->data["wl_brandname"] . ' protection',
                                    'security-malware-firewall'
                                ),
                                'type' => 'field',
                                'children' => array ('spbc_trusted_and_affiliate__shortcode_tag')
                            ),
                            'spbc_trusted_and_affiliate__shortcode_tag'                    => array(
                                'type'        => 'field',
                                'input_type'        => 'text',
                                'title'       => __('<- Copy this text and place shortcode wherever you need.', 'security-malware-firewall'),
                                'parent'      => 'spbc_trusted_and_affiliate__shortcode',
                                'class'       => 'spbc_affiliate_shortcode',
                                'disabled' => false,
                            ),
                            'spbc_trusted_and_affiliate__footer' => array(
                                'title'           => __('Add to the footer', 'security-malware-firewall'),
                                'description'     => __(
                                    'Adds trust text stating that the website is protected from malware by ' . $spbc->data["wl_brandname"] . ' protection to the footer of your website.',
                                    'security-malware-firewall'
                                ),
                                'type' => 'field'
                            ),
                            'spbc_trusted_and_affiliate__add_id'         => array(
                                'title'           => __(
                                    'Append your affiliate ID',
                                    'security-malware-firewall'
                                ),
                                'description'     => __(
                                    'Enable this option to append your specific affiliate ID to the trust text created by the options above ("Shortcode" or "Add to the footer"). Terms and your affiliate ID of the {CT_AFFILIATE_TERMS}.',
                                    'security-malware-firewall'
                                ),
                                'type' => 'field'
                            )
                        ),
                    ),
                ),
            ),
            // Summary
            'summary'          => array(
                'type'         => 'tab',
                'title'        => __('Summary', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-info',
                'class_prefix' => 'spbc',
                'ajax'         => false,
                'callback'     => 'spbc_tab__summary',
            ),
            // FSWatcher
            'fswatcher'          => array(
                'type'         => 'tab',
                'title'        => __('File System Watcher', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-info',
                'class_prefix' => 'spbc',
                'ajax'         => true,
                'sections'     => array(
                    'fsw' => array(
                        'type'   => 'section',
                        'fields' => array(
                            'scanner' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_tab__fswatcher'
                            ),
                        ),
                    ),
                ),
                'display'      => $spbc->settings['scanner__fs_watcher']
            ),
            // Debug
            'debug'            => array(
                'type'         => 'tab',
                'display'      => in_array(Server::getDomain(), array(
                        'lc',
                        'loc',
                        'lh',
                        'wordpress'
                    )) || $spbc->debug || $spbc->show_debug,
                'title'        => __('Debug', 'security-malware-firewall'),
                'class_prefix' => 'spbc',
                'ajax'         => true,
                'sections'     => array(
                    'debug' => array(
                        'type'   => 'section',
                        'fields' => array(
                            'drop_debug'               => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_debug_drop'
                            ),
                            'debug_check_connection'   => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_debug__check_connection'
                            ),
                            'debug_set_fw_update_cron' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_debug__set_fw_update_cron'
                            ),
                            'debug_set_scan_cron'      => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_debug__set_scan_cron'
                            ),
                            'debug_set__check_vulnerabilities_cron'      => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_debug__set_check_vulnerabilities_cron'
                            ),
                            'debug_data'               => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_debug'
                            ),
                        ),
                    ),
                ),
            ),
        )
    );
}

/**
 * Preprocess the elements. Registering sections and fields and other stuff
 *
 * @param array $elems Array of elements
 * @param string $section_name Section name to register
 *
 * @return array Processed elements
 */
function spbc_settings__register_sections_and_fields($elems, $_section_name = '')
{
    global $spbc;

    $elems_original = $elems;

    $_plain_default_params = array(
        'title'   => '',
        'html'    => '',
        'display' => true,
    );

    $_tab_default_params = array(
        'name'        => '',
        'title'       => '',
        'description' => '',
        'active'      => false,
        'icon'        => '',
        'display'     => true,
        'preloader'   => '<img class="spbc_spinner_big" src="' . SPBC_PATH . '/images/preloader2.gif" />',
        'ajax'        => true,
        'js_before'   => null,
        'js_after'    => null,
    );

    $_section_default_params = array(
        'title'       => '',
        'description' => '',
        'html_before' => '',
        'html_after'  => '',
        'display'     => true,
    );

    $_field_default_params = array(
        'callback'            => 'spbc_settings__field__draw',
        'input_type'          => 'checkbox',
        'def_class'           => 'spbc_wrapper_field',
        'title_first'         => false,
        'class'               => null,
        'parent'              => null,
        'children'            => null,
        'children_by_ids'     => null,
        'display'             => true, // Draw element or not
        'disabled'            => false,
        'required'            => false,
        'value_source'        => 'settings',
        'parent_value_source' => 'settings',
    );

    foreach ($elems as $elem_name => &$elem) {
        // Merging with default params
        $elem = array_merge(${'_' . $elem['type'] . '_default_params'}, $elem);

        switch ($elem['type']) {
            case 'plain':
                break;
            case 'tab':
                if (isset($elem['sections'])) {
                    $elem['sections'] = spbc_settings__register_sections_and_fields($elem['sections']);
                }
                // Creating new elements with tabs headings (before tabs)
                if ($elem['display']) {
                    // Hiding a tab 'Backups' except for a direct link
                    if ($elem_name === 'backups' && ! (isset($_GET['spbc_tab']) && $_GET['spbc_tab'] === 'backups')) {
                        break;
                    }

                    $tab_head = '<h2 class="spbc_tab_nav spbc_tab_nav-' . $elem_name . ' ' . (! empty($elem['active']) ? 'spbc_tab_nav--active' : '') . '">'
                                . '<i class="' . (isset($elem['icon']) ? $elem['icon'] : 'spbc-icon-search') . '"></i>'
                                . $elem['title']
                                . '</h2>';
                    if (empty($elems_original['tab_headings'])) {
                        Arr::insert(
                            $elems_original,
                            $elem_name,
                            array(
                                'tab_headings' => array(
                                    'type'    => 'tab_headings',
                                    'html'    => $tab_head,
                                    'display' => true,
                                )
                            )
                        );
                    } else {
                        $elems_original['tab_headings']['html'] .= $tab_head;
                    }
                }
                break;
            case 'section':
                if ( ! $elem['display']) {
                    break;
                }
                // add_settings_section('spbc_section__'.$elem_name, '', 'spbc_section__'.$elem_name, 'spbc');
                if (isset($elem['fields'])) {
                    $elem['fields'] = spbc_settings__register_sections_and_fields($elem['fields'], $elem_name);
                }
                break;
            case 'field':
                $elem['name'] = $elem_name;

                if ( ! isset($elem['value']) ) {
                    $elem['value'] = isset($spbc->{$elem['value_source']}[ $elem_name ])
                        ? $spbc->{$elem['value_source']}[ $elem_name ]
                        : 0;
                }

                if (isset($elem['parent'])) {
                    $elem['parent_value'] = isset($spbc->{$elem['parent_value_source']}[ $elem['parent'] ])
                        ? $spbc->{$elem['parent_value_source']}[ $elem['parent'] ]
                        : 0;
                }

                // add_settings_field('spbc_field__'.$elem_name, '', $elem['callback'], 'spbc', 'spbc_section__'.$elem_name, $section_name);
                break;
        }

        $elems_original[ $elem_name ] = $elem;
    }

    return $elems_original;
}

/**
 * Outputs elements and tabs
 *
 * @global \CleantalkSP\SpbctWP\State $spbc
 */
function spbc_settings__draw_elements($elems_to_draw = null, $direct_call = false)
{
    global $spbc;

    if ( ! $direct_call && Post::get('security')) {
        spbc_settings__register();
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
        if (Post::get('tab_name')) {
            /** @psalm-suppress InvalidArrayOffset */
            $elems_to_draw = array($_POST['tab_name'] => $spbc->settings__elements[ Post::get('tab_name') ]);
        }
    }

    foreach ($elems_to_draw as $elem_name => &$elem) {
        if ( ! $elem['display']) {
            continue;
        }

        switch ($elem['type']) {
            case 'plain':
                if (isset($elem['callback']) && function_exists($elem['callback'])) {
                    call_user_func($elem['callback']);
                } else {
                    echo $elem['html'];
                }
                break;
            // case 'tab_headings':
                // echo '<div class="spbc_tabs_nav_wrapper">'
                    //  . $elem['html']
                    //  . '</div>';
                // break;
            case 'tab':
                echo '<div id="spbc_tab-' . $elem_name . '" class="spbc_tab spbc_tab-' . $elem_name . ' ' . (! empty($elem['active']) ? 'spbc_tab--active' : '') . '">';

                if ( ! $elem['ajax'] || ! $direct_call) {
                    // JS before
                    if (isset($elem['js_before'])) {
                        foreach (explode(' ', $elem['js_before']) as $script) {
                            $src = SPBC_PATH . '/js/spbc-' . $script . '?ver=' . SPBC_VERSION;
                            $target = 'spbc_tab-' . $elem_name;
                            echo "<script>
                                let spbct_js_before = document.createElement('script');
                                spbct_js_before.setAttribute('src', '$src');
                                document.getElementById('$target').prepend(spbct_js_before);
                            </script>"; // JS before tab
                        }
                    }

                    // Output
                    if ( ! empty($elem['callback'])) {
                        call_user_func($elem['callback']);
                    } else {
                        spbc_settings__draw_elements($elem['sections'], true);
                    }

                    // Custom elements on tab
                    if (isset($elem['after'])) {
                        if (function_exists($elem['after'])) {
                            echo '<div style="margin-left: 10px;">';
                            call_user_func($elem['after']);
                            echo '</div>';
                        } else {
                            echo $elem['after'];
                        }
                    }

                    // JS after
                    if (isset($elem['js_after'])) {
                        foreach (explode(' ', $elem['js_after']) as $script) {
                            if ( strpos($script, '.min') === false ) {
                                $src = SPBC_PATH . '/js/src/spbc-' . $script . '?ver=' . SPBC_VERSION;
                            } else {
                                $src = SPBC_PATH . '/js/spbc-' . $script . '?ver=' . SPBC_VERSION;
                            }
                            $target = 'spbc_tab-' . $elem_name;
                            echo "<script>
                                if (typeof spbct_js_after === 'undefined') {
                                    let spbct_js_after;
                                }
                                spbct_js_after = document.createElement('script')
                                spbct_js_after.setAttribute('src', '$src');
                                document.getElementById('$target').append(spbct_js_after);
                            </script>"; // JS after tab
                        }
                    }
                } else {
                    echo $elem['preloader'];
                }
                echo '</div>';
                break;
            case 'section':
                $anchor = isset($elem['anchor']) ? 'id="' . $elem['anchor'] . '"' : '';
                $hide_settings = '';
                if (!$spbc->key_is_ok && isset($elem['anchor']) && $elem['anchor'] !== 'apikey') {
                    $hide_settings = '--hide';
                }
                echo '<div class="spbc_tab_fields_group ' . $hide_settings . '">'
                     . '<div class="spbc_group_header" ' . $anchor . '>'
                     . (! empty($elem['title']) ? '<h3><a href="#' . $elem['anchor'] . '">' . $elem['title'] . '</a></h3>' : '')
                     . (! empty($elem['description']) ? '<div class="spbc_settings_description">' . $elem['description'] . '</div>' : '')
                     . '</div>';
                spbc_settings__draw_elements($elem['fields'], true);
                echo '</div>';
                break;
            case 'field':
                call_user_func($elem['callback'], $elem);
                break;
        }
    }

    if (isset($_POST['security']) && ! $direct_call) {
        die();
    }
}

/**
 * @param $field
 *
 * @return void
 */
function spbc_settings__field__draw($field)
{
    global $spbc;

    if ( $field['name'] === 'spbc_trusted_and_affiliate__add_id' ) {
        $href = '<a href="https://cleantalk.org/my/partners" target="_blank">' . __($spbc->data["wl_company_name"] . ' Affiliate Program are here', 'security-malware-firewall') . '</a>';
        $field['description'] = str_replace('{CT_AFFILIATE_TERMS}', $href, $field['description']);
    }

    echo '<div class="' . $field['def_class'] . (! empty($field['class']) ? ' ' . $field['class'] : '') . (isset($field['parent']) ? ' spbc_sub_setting' : '') . '">';

    try {
        spbc_settings__field__draw_field_template($field['input_type'], $field);
    } catch (\Exception $exception) {
        echo $exception->getMessage();
    }

    echo '</div>';
}

/**
 * @throws Exception
 */
function spbc_settings__field__draw_field_template($type_field, array $data)
{
    $template_part = SPBC_PLUGIN_DIR . '/inc/admin-templates/field-templates/' . $type_field . '.php';

    if (!file_exists($template_part)) {
        throw new \Exception('Not founded template part.');
    }

    include $template_part;
    unset($data);
}

function spbc_human_time_to_seconds($human_time)
{
    $human_time = explode(' ', $human_time);

    switch (true) {
        case strpos($human_time[1], 'second') !== false:
            $seconds = (int)$human_time[0] * 1;
            break;
        case strpos($human_time[1], 'min') !== false:
            $seconds = (int)$human_time[0] * 60;
            break;
        case strpos($human_time[1], 'hour') !== false:
            $seconds = (int)$human_time[0] * 3600;
            break;
        case strpos($human_time[1], 'day') !== false:
            $seconds = (int)$human_time[0] * 86400;
            break;
        case strpos($human_time[1], 'week') !== false:
            $seconds = (int)$human_time[0] * 86400 * 7;
            break;
        case strpos($human_time[1], 'month') !== false:
            $seconds = (int)$human_time[0] * 86400 * 30;
            break;
        case strpos($human_time[1], 'year') !== false:
            $seconds = (int)$human_time[0] * 86400 * 365;
            break;
        default:
            $seconds = (int)$human_time[0];
            break;
    }

    return $seconds;
}

/**
 * Convert seconds to a user-friendly text string of % days/hours/minutes.
 * @param int $seconds seconds to convert.
 * @return string converted string like "2 hours", "5 minutes", "1 day". If seconds can not be rounded, returns "% seconds".
 */
function spbc_seconds_to_human_time($seconds)
{
    if ( $seconds % 60 !== 0 ) {
        return $seconds . ' seconds';
    }

    switch (true) {
        case $seconds / 60 / 60 < 1:
            $output = $seconds / 60;
            if ( $output < 1 ) {
                $output = $seconds == 1 ? $seconds . ' second' : $seconds . ' seconds';
                break;
            }
            $output .= $seconds > 60 ? ' minutes' : ' minute';
            break;
        case $seconds / 60 / 60 / 24 < 1:
            $output = $seconds / 60 / 60;
            $output .= $seconds > 3600 ? ' hours' : ' hour';
            break;
        case $seconds / 60 / 60 / 24 / 30 < 1:
            $output = $seconds / 60 / 60 / 24;
            $output .= $seconds > 86400 ? ' days' : ' day';
            break;
        default:
            $output = $seconds . ' seconds';
            break;
    }

    return $output;
}
/**
 * Admin callback function - Displays plugin options page
 */
function spbc_settings_page()
{
    global $spbc;

    Settings::page();

    if (is_network_admin()) {
        return;
    }

    Settings::tabs();

    echo '<form id="spbc_settings_form" method="post" action="options.php" style="margin-right: 12px; margin-top: -9px;">';

    settings_fields(SPBC_SETTINGS);
    spbc_settings__draw_elements($spbc->settings__elements, 'direct_call');

    echo '</form>'
         . '<form id="debug_drop" method="POST"></form>'
         . '<form id="debug_check_connection" method="POST"></form>'
         . '<form id="debug__cron_set" method="POST"></form>'
         . '</div>';
}

/**
 * Message output error block.
 *
 * @return string
 * @global $spbc
 */
function spbc_settings__error__output()
{
    global $spbc;

    $errors_html = '';

    if ( ! empty($spbc->errors)) {
        $errors = $spbc->errors;

        // Types
        $types = array(
            // Common
            'memory_limit_low'          => __('You have less than 25 Mib free PHP memory. Error could occurs while scanning.', 'security-malware-firewall'),
            'php_version'               => __('PHP version is lower than 5.4.0. You are using 10 years old software. We strongly recommend you to update.', 'security-malware-firewall'),
            // Misc
            'apikey'                    => __('Access key validating: ', 'security-malware-firewall'),
            'get_key'                   => __('Getting access key automatically: ', 'security-malware-firewall'),
            'notice_paid_till'          => __('Checking account status: ', 'security-malware-firewall'),
            'access_key_notices'        => __('Checking account status2: ', 'security-malware-firewall'),
            'login_page_rename'         => __('Renaming login URL: ', 'security-malware-firewall'),
            'service_customize'         => __('Service customization: ', 'security-malware-firewall'),
            // Cron
            'cron_scan'                 => __('Scheduled scanning: ', 'security-malware-firewall'),
            'cron'                      => __('Scheduled: ', 'security-malware-firewall'),
            // Misc
            'resend_files_for_analysis' => __('Resending files for analysis: ', 'security-malware-firewall'),
            'scanner_update_signatures' => __('An error occurred while updating the signature table: ', 'security-malware-firewall'),
            'scanner_update_signatures_bad_signatures' => __('Some signatures were not recorded in the database: ', 'security-malware-firewall'),
            'configuration'              => __('Server configuration error: ', 'security-malware-firewall'),
        );
        if ($spbc->moderate == 1) {
            $types['debug']              = __('Debug: ', 'security-malware-firewall');
            $types['send_logs']          = __('Sending security logs: ', 'security-malware-firewall');
            $types['send_firewall_logs'] = __('Sending firewall logs: ', 'security-malware-firewall');
            $types['firewall_update']    = __('Updating firewall: ', 'security-malware-firewall');
            $types['signatures_update']  = __('Updating signatures: ', 'security-malware-firewall');
            $types['send_php_logs']      = __('PHP error log sending: ', 'security-malware-firewall');

            // Subtypes
            $sub_types = array(
                'get_hashes'      => __('Getting hashes: ', 'security-malware-firewall'),
                'get_hashes_plug' => __('Getting plugins hashes: ', 'security-malware-firewall'),
                'clear_table'     => __('Clearing table: ', 'security-malware-firewall'),
                'surface_scan'    => __('Surface scan: ', 'security-malware-firewall'),
                'signature_scan'  => __('Signature scanning: ', 'security-malware-firewall'),
                'heuristic_scan'  => __('Heuristic scanning: ', 'security-malware-firewall'),
                'cure_backup'     => __('Creating a backup: ', 'security-malware-firewall'),
                'cure'            => __('Curing: ', 'security-malware-firewall'),
                'links_scan'      => __('Links scanning: ', 'security-malware-firewall'),
                'send_results'    => __('Sending result: ', 'security-malware-firewall'),
            );
        }

        $errors_out = array();

        foreach ($errors as $type => $error) {
            if ( ! empty($error) && isset($types[ $type ])) {
                if (is_array(current($error))) {
                    foreach ($error as $sub_type => $sub_error) {
                        $text         = isset($sub_error['error_time']) ? date('Y-m-d H:i:s', $sub_error['error_time']) . ': ' : '';
                        $text         .= $types[ $type ];
                        $text         .= isset($sub_types[ $sub_type ]) ? $sub_types[ $sub_type ] : $sub_type . ': ';
                        $text         .= $sub_error['error'];
                        $errors_out[] = $text;
                    }
                } else {
                    $text         = isset($error['error_time']) ? date('Y-m-d H:i:s', $error['error_time']) . ': ' : '';
                    $text         .= $types[ $type ];
                    $text         .= $error['error'];
                    $errors_out[] = $text;
                }
            }
        }

        if ( ! empty($errors_out)) {
            foreach ($errors_out as $value) {
                $errors_html .= '<h4 style="word-break: break-all">' . spbc_render_links_to_tag($value) . '</h4>';
            }

            $link_to_support = 'https://wordpress.org/support/plugin/security-malware-firewall';
            if (!empty($spbc->data['wl_support_url'])) {
                $link_to_support = esc_url($spbc->data['wl_support_url']);
            }

            $errors_html .= '<h4 style="text-align: right;">' . sprintf(__('You can get support any time here: %s.', 'security-malware-firewall'), '<a target="blank" href="' . $link_to_support . '">' . $link_to_support . '</a>') . '</h4>';
        }
    }
    return str_replace("'", '&rsquo;', $errors_html);
}

function spbc_tab__summary()
{
    global $spbc;

    $support_link = $spbc->data["wl_mode_enabled"] ? '<a target="_blank" href="' . $spbc->data["wl_support_url"] . '">' . $spbc->data["wl_brandname"] . '</a>.'
        : '<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall/">wordpress.org</a>.';

    echo '<div class="spbc_tab_fields_group">'
         . '<h3 class="spbc_group_header">' . __('Statistics', 'security-malware-firewall') . '</h3>';
    spbc_field_statistics();
    echo '</div>';
    echo '<br>';
    echo '<div style="margin-left: 10px;">';
    echo '<span id="spbc_gdpr_open_modal" style="text-decoration: underline;">' . __('GDPR compliance', 'security-malware-firewall') . '</span>';
    echo '<div id="gdpr_dialog" class="spbc_hide" style="padding: 0 15px;">' . spbc_show_GDPR_text() . '</div>';
    echo '<br>';
    echo __('Tech support: ', 'security-malware-firewall') . $support_link;
    echo '<br>';
    printf(__('The plugin home page', 'security-malware-firewall') . ' <a href="' . $spbc->data["wl_url"] . '" target="_blank">%s</a>.', $spbc->data["wl_brandname"]);
    echo '<br>';
    echo $spbc->data["wl_brandname"] . __(' is a registered trademark. All rights reserved.', 'security-malware-firewall');
    echo '<br><br>';
    echo '</div>';
}

/**
 * @throws Exception
 */
function spbc_tab__fswatcher()
{
    global $spbc;

    echo "<div class='spbc_wrapper_field'>";

    /**
     * Check if tab is restricted by license, layout according HTML if so.
     */
    $feature_state = $spbc->feature_restrictions->getState($spbc, 'fswatcher');
    if (false === $feature_state->is_active) {
        echo $feature_state->sanitizedReasonOutput();
        echo '</div>';
        return;
    }

    echo \CleantalkSP\SpbctWP\FSWatcher\View\View::renderSelectors(new \CleantalkSP\SpbctWP\FSWatcher\View\Phrases());
    echo '</div>';
}

/**
 * Admin callback function - Displays current statistics
 */
function spbc_field_statistics()
{
    global $spbc;

    echo "<div class='spbc_wrapper_field'>";

    // Security log statistics
    echo(isset($spbc->data['logs_last_sent'], $spbc->data['last_sent_events_count'])
        ? sprintf(__('%d events have been sent to ' . $spbc->data["wl_brandname"] . ' Cloud on %s.', 'security-malware-firewall'), $spbc->data['last_sent_events_count'], date("M d Y H:i:s", $spbc->data['logs_last_sent']))
        : __('Unknown last logs sending time.', 'security-malware-firewall'));
    echo '<br />';

    // Firewall log statistics
    if (is_main_site()) {
        echo(isset($spbc->fw_stats['last_send'], $spbc->fw_stats['last_send_count'])
            ? sprintf(__('Information about %d blocked entries have been sent to ' . $spbc->data["wl_brandname"] . ' Cloud on %s.', 'security-malware-firewall'), $spbc->fw_stats['last_send_count'], date("M d Y H:i:s", $spbc->fw_stats['last_send']))
            : __('Unknown last firewall logs sending time.', 'security-malware-firewall'));
        echo '<br />';
    }

    // Firewall statistics
    if ( isset($spbc->fw_stats['last_updated'], $spbc->fw_stats['entries']) ) {
        $networks_count_text = sprintf(
            esc_html__('%d Networks', 'security-malware-firewall'),
            $spbc->fw_stats['entries']
        );
        if ( isset($spbc->fw_stats['ips_count']) ) {
            $networks_count_text .= ' ';
            $networks_count_text .= sprintf(
                esc_html__('(%s k IPs)', 'security-malware-firewall'),
                number_format($spbc->fw_stats['ips_count'] / 1000, 0, '', ' ')
            );
        }
        $secfw_statistics_text = sprintf(
            esc_html__('Security FireWall database has %s. Last updated at %s.', 'security-malware-firewall'),
            $networks_count_text,
            date('M d Y H:i:s', $spbc->fw_stats['last_updated'])
        );
    } else {
        $secfw_statistics_text = esc_html__('Unknown last Security FireWall updating time.', 'security-malware-firewall');
    }

    echo $secfw_statistics_text ;
    echo '<br />';

    echo $spbc->fw_stats['updating_id'] ? ' <b>Under updating now: ' . $spbc->fw_stats['update_percent'] . '%</b><br />' : '';

    // Scanner statistics
    if ($spbc->scaner_enabled) {
        $duration = isset($spbc->data['scanner']['scan_start_timestamp'], $spbc->data['scanner']['scan_finish_timestamp'])
            ? ' ' . sprintf(__('(duration %s sec)', 'security-malware-firewall'), $spbc->data['scanner']['scan_finish_timestamp'] - $spbc->data['scanner']['scan_start_timestamp'])
            : '';

        echo(isset($spbc->data['scanner']['last_signature_update']) && isset($spbc->data['scanner']['signature_count'])
            ? sprintf(__('Malware scanner signatures was updated %s. For now it contains %s entries.', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_signature_update']), $spbc->data['scanner']['signature_count'])
            : __('Malware scanner signatures hasn\'t been updated yet.', 'security-malware-firewall'));
        echo '<br />';
        echo(! empty($spbc->data['scanner']['last_scan'])
            ? sprintf(__('The last scan of this website was on %s', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_scan']))
              . $duration
            : __('Website hasn\'t been scanned yet.', 'security-malware-firewall'));
        echo '<br />';
        if (isset($spbc->data['scanner']['last_sent'])) {
            printf(__('Scan results were sent to the cloud at %s', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_sent']));
            echo '<br />';
        }
    }

    // PHP log sending statistics
    if ( is_main_site() ) {
        //Param 'last_php_log_sent' is used in unix time, so we should add an offset
        $date_string = date(
            'M d Y H:i:s',
            $spbc->data['last_php_log_sent'] + $spbc->data['site_utc_offset_in_seconds']
        );
        echo(isset($spbc->data['last_php_log_sent'], $spbc->data['last_php_log_amount'])
            ? sprintf(__('%d errors in PHP log have been sent to CleanTalk Cloud on %s', 'security-malware-firewall'), $spbc->data['last_php_log_amount'], $date_string)
            : __('Unknown last PHP log sending time.', 'security-malware-firewall'));
    }

    echo '<br/>';

    if ( is_main_site() ) {
        /*
         * Collect VA calls ro research.cleantalk.org
         */
        //get next call from Cron
        $cron_task_info = SpbcCron::getTask('check_vulnerabilities');
        $next_call = !empty($cron_task_info['next_call'])
            ? date('M d Y H:i:s', (int)($cron_task_info['next_call'] + $spbc->data['site_utc_offset_in_seconds']))
            : 'unknown';
        $va_next_request = sprintf('%s %s', __('next call on', 'security-malware-firewall'), $next_call);

        //get last call from Data
        $last_call = !empty($spbc->data['spbc_security_check_vulnerabilities_last_call'])
            ? date('M d Y H:i:s', (int)($spbc->data['spbc_security_check_vulnerabilities_last_call'] + $spbc->data['site_utc_offset_in_seconds']))
            : 'unknown';
        $va_last_request = sprintf('%s %s', __('last call on', 'security-malware-firewall'), $last_call);

        $va_text = __('Closest vulnerabilities check requests preformed to', 'security-malware-firewall')
            . ' '
            . '<a href="https://research.cleantalk.org">research.cleantalk.org</a>';

        $va_text = sprintf('%s: %s, %s', $va_text, $va_last_request, $va_next_request);
        echo(Escape::escKsesPreset($va_text, 'spbc_settings__display__notifications'));
    }

    echo '<br/>';

    if ( is_main_site() && $spbc->settings['vulnerability_check__enable_cron'] && $spbc->settings['vulnerability_check__warn_on_modules_pages'] ) {
        $h_checking_vulnerabilities = '%s:';
        $row_checking_vulnerabilities = '%s: %d';
        echo '<br/>';
        echo sprintf($h_checking_vulnerabilities, __('The results of checking plugins for vulnerabilities', 'security-malware-firewall'));
        echo '<br/>';
        echo sprintf($row_checking_vulnerabilities, __('Total site plugins count', 'security-malware-firewall'), $spbc->scan_plugins_info['total_site_plugins_count']);
        echo '<br/>';
        echo sprintf($row_checking_vulnerabilities, __('Plugins info requested', 'security-malware-firewall'), $spbc->scan_plugins_info['plugins_info_requested']);
        echo '<br/>';
        echo sprintf($row_checking_vulnerabilities, __('Plugins found with known vulnerabilities', 'security-malware-firewall'), $spbc->scan_plugins_info['plugins_found_with_known_vulnerabilities']);
        echo '<br/><br/>';

        echo sprintf($h_checking_vulnerabilities, __('The results of checking themes for vulnerabilities', 'security-malware-firewall'));
        echo '<br/>';
        echo sprintf($row_checking_vulnerabilities, __('Total site themes count', 'security-malware-firewall'), $spbc->scan_themes_info['total_site_themes_count']);
        echo '<br/>';
        echo sprintf($row_checking_vulnerabilities, __('Themes info requested', 'security-malware-firewall'), $spbc->scan_themes_info['themes_info_requested']);
        echo '<br/>';
        echo sprintf($row_checking_vulnerabilities, __('Themes found with known vulnerabilities', 'security-malware-firewall'), $spbc->scan_themes_info['themes_found_with_known_vulnerabilities']);
        echo '<br/>';
    }

    echo '<br/>';

    //cdn checker data
    add_filter('safe_style_css', function ($styles) {
        $styles[] = 'display';
        return $styles;
    });
    echo Escape::escKsesPreset(CDNHeadersChecker::getSummaryBlockHTML(), 'spbc_cdn_checker_table');

    echo '<br/>';
    echo 'Plugin version: ' . SPBC_VERSION;
    echo '</div>';
}

function spbc_field_banners()
{
    global $spbc_tpl;
    // Rate banner
    // echo sprintf($spbc_tpl['spbc_rate_plugin_tpl'],
    // SPBC_NAME
    // );
    // Translate banner
    if (substr(get_locale(), 0, 2) != 'en') {
        echo sprintf(
            $spbc_tpl['spbc_translate_banner_tpl'],
            substr(get_locale(), 0, 2)
        );
    }
}

/**
 * Admin callback function - Displays field of Api Key
 */
function spbc_field_key()
{
    global $spbc;

    echo "<div class='spbc_wrapper_field'>";

    if (
        is_main_site() ||
        $spbc->ms__work_mode == 3 ||
        ($spbc->ms__work_mode == 1 && is_super_admin())
    ) {
        // Key is OK
        if ($spbc->key_is_ok) {
            echo '<input
					id="spbc_key"
					name="spbc_settings[spbc_key]"
					size="20"
					type="text"
					value="' . str_repeat('*', strlen($spbc->settings['spbc_key'])) . '" key="' . $spbc->settings['spbc_key'] . '"
					style="font-size: 14pt;"
					placeholder="' . __('Enter the key', 'security-malware-firewall') . '" />';

            // Show account name associated with key
            if ( ! empty($spbc->data['account_name_ob'])) {
                echo '<div class="spbc_hide">'
                     . sprintf(
                         __('Account at cleantalk.org is %s.', 'security-malware-firewall'),
                         '<b>' . $spbc->data['account_name_ob'] . '</b>'
                     )
                     . '</div>';
            }
            echo '<a id="showHideLink" class="spbc-links" style="color:#666;" href="#">' . __('Show Access Key', 'security-malware-firewall') . '</a>';

            $additional_links = apply_filters(
                'spct_key_additional_links',
                array()
            );
            if (count($additional_links) > 0) {
                echo '&nbsp;&nbsp;&nbsp;&nbsp;';
                foreach ($additional_links as $link) {
                    echo $link . '&nbsp;&nbsp;&nbsp;&nbsp;';
                }
            }
            // Key is not OK
        } else {
            echo '<input id="spbc_key" name="spbc_settings[spbc_key]" size="20" type="text" value="' . $spbc->settings['spbc_key'] . '" style=\'font-size: 14pt;\' placeholder="' . __('Enter the key', 'security-malware-firewall') . '" />';
            echo '<br/><br/>';
            echo '<a id="spbc-key-manually-link" target="_blank" href="https://cleantalk.org/register?platform=wordpress&email=' . urlencode(spbc_get_admin_email()) . '&website=' . urlencode(parse_url(get_option('home'), PHP_URL_HOST)) . '&product_name=security" style="display: inline-block;">
						<input style="color:#666;" type="button" class="spbc_auto_link" value="' . __('Get access key manually', 'security-malware-firewall') . '" />
					</a>';
            echo '&nbsp;' . __('or', 'security-malware-firewall') . '&nbsp;';
            echo '<button class="spbc_manual_link" id="spbc_setting_get_key_auto" name="spbc_get_apikey_auto" type="button"  value="get_key_auto">'
                 . __('Get access key automatically', 'security-malware-firewall')
                 . '<img style="margin-left: 10px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                 . '<img style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
                 . '</button>';
            echo '<br/><br/>';

            // admin email
            printf(
                __(
                    'Admin e-mail %s %s will be used for registration.',
                    'security-malware-firewall'
                ),
                '<span id="spbc-account-email">'
                . spbc_get_admin_email()
                . '</span>',
                is_main_site() ? spbc_settings__btn_change_account_email_html() : ''
            );

            echo '<div>';
            echo '<input checked type="checkbox" id="license_agreed" onclick="spbcSettingsDependenciesbyId(\'get_key_auto\');"/>';
            echo '<label for="spbc_license_agreed">';
            printf(
                __('I agree with %sPrivacy Policy%s of %sLicense Agreement%s', 'security-malware-firewall'),
                '<a href="https://cleantalk.org/publicoffer#privacy" target="_blank" style="color:#66b;">',
                '</a>',
                '<a href="https://cleantalk.org/publicoffer"         target="_blank" style="color:#66b;">',
                '</a>'
            );
            echo "</label>";
            echo '</div>';

            echo '<input type="hidden" id="spbc_admin_timezone" name="ct_admin_timezone" value="null" />';
        }
    } else {
        echo '<h3>' . __('Access key is provided by network administrator.', 'security-malware-firewall') . '</h3>';
    }

    echo '</div>';
}

/**
 * Current site admin e-mail
 * @return string Admin e-mail
 */
function spbc_get_admin_email()
{
    global $spbc;

    if ( ! is_multisite() ) {
        $admin_email = get_option('admin_email');
    } else {
        $admin_email = get_blog_option(get_current_blog_id(), 'admin_email');
    }

    if ( $spbc->data['account_email'] ) {
        add_filter('spbc_get_api_key_email', function () {
            global $spbc;
            return $spbc->data['account_email'];
        });
    }

    return $admin_email;
}

/**
 * Show button for changed account email
 */
function spbc_settings__btn_change_account_email_html()
{
    return '(<button type="button"
                id="spbc-change-account-email"
                class="spbc-btn-as-link"
                data-default-text="'
                    . __('change email', 'security-malware-firewall') .
                    '"
                data-save-text="'
                    . __('save', 'security-malware-firewall') .
                    '">'
                . __('change email', 'security-malware-firewall') .
            '</button>)';
}

function spbc_field_service_utilization()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">';

    if ($spbc->services_count && $spbc->services_max && $spbc->services_utilization) {
        echo sprintf(
            __('Hoster account utilization: %s%% ( %s of %s websites ).', 'security-malware-firewall'),
            $spbc->services_utilization * 100,
            $spbc->services_count,
            $spbc->services_max
        );

        // Link to the dashboard, so user could extend your subscription for more sites
        if ($spbc->services_utilization * 100 >= 90) {
            echo '&nbsp';
            echo sprintf(
                __('You could extend your subscription %shere%s.', 'security-malware-firewall'),
                '<a href="' . $spbc->data["wl_mode_enabled"] ? $spbc->data["wl_support_url"] : $spbc->dashboard_link . '" target="_blank">',
                '</a>'
            );
        }
    } else {
        _e('Enter the Hoster access key and synchronize with cloud to find out your hoster account utilization.', 'security-malware-firewall');
    }

    echo '</div>';
}

function spbc_settings_2fa_description_callback()
{
    $user = wp_get_current_user();
    if (isset($user->ID) && $user->ID > 0) {
        $email = $user->user_email;
    } else {
        $email = spbc_get_admin_email();
    }

    echo '<div style="margin-bottom: 10px" class="spbc_settings_description">'
         . sprintf(
             __('Verification code will be sent to the admin email (%s) to enable the feature.', 'security-malware-firewall'),
             $email
         )
         . '<br>';
    echo '</div>';
}

function spbc_field_bfp__heading()
{
    global $spbc;

    $description_pattern = 'If someone fails %s authorizations in a row within %s minutes, plugin blocks the visitor for %s '
        . 'by placing a record with "Blocked by BruteForce protection system" status to FireWall.';

    $description = sprintf(
        __($description_pattern, 'security-malware-firewall'),
        $spbc->settings['bfp__allowed_wrong_auths'],
        $spbc->settings['bfp__count_interval'] / 60,
        spbc_seconds_to_human_time((int)$spbc->settings['bfp__block_period__5_fails'])
    );

    $out = '<div class="spbc_wrapper_field">';
    $out .= '<div class="spbc_settings-field_title">';
    $out .= __('Brute Force Protection options', 'security-malware-firewall');
    $out .= '</div>'; // close class="spbc_settings-field_title"
    $out .= '<div class="spbc_settings_description">';
    $out .= $description;
    $out .= '</div>'; // close class="spbc_settings_description"
    $out .= '</div>'; // close class="spbc_wrapper_field"

    echo $out;
}

function spbc_field_2fa__roles()
{
    global $spbc, $wp_roles;

    $wp_roles = new WP_Roles();
    $roles    = $wp_roles->get_names();

    echo '<div class="spbc_wrapper_field spbc_sub_setting">';

    echo '<span class="spbc_settings-field_title spbc_settings-field_title--field">'
         . __('Roles that use two-factor authentication (2FA)', 'security-malware-firewall')
         . '</span>'
         . '<br>';

    echo '<div style="margin-bottom: 10px" class="spbc_settings_description">'
         . __('Hold CTRL button to select multiple roles. Users with unselected roles keep log in to your website in a standard way with their logins and passwords.', 'security-malware-firewall')
         . '<br><em>' . esc_html__('To disable the Google authentication for an account reset the password of that account. Two-factor authentication method will be switched to Email. Or you can disable it directly on the page of the WordPress site profile.', 'security-malware-firewall') . '</em>'
         . '</div>';

    echo '<select multiple="multiple" id="spbc_setting_2fa__roles" name="spbc_settings[2fa__roles][]"'
         . (! $spbc->settings['2fa__enable'] ? ' disabled="disabled"' : '')
         . ' size="' . (count($roles) - 1 < 6 ? count($roles) - 1 : 5) . '"'
         . '>';

    foreach ($roles as $role) {
        echo '<option'
             . (in_array($role, (array) $spbc->settings['2fa__roles']) ? ' selected="selected"' : '')
             . '>' . $role . '</option>';
    }

    echo '</select>';

    echo '</div>';
}

function spbc_field_security_logs__prepare_data(&$table)
{
    global $wpdb;

    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $ips_c[] = $row->auth_ip;
        }
        unset($row);
        $ips_c = spbc_get_countries_by_ips(implode(',', $ips_c));

        $time_offset = current_time('timestamp') - time();

        foreach ($table->rows as $row) {
            $ip = IP::reduceIPv6($row->auth_ip);
            $allow_layout = '<a href="#" onclick="return spbcSecLogsAllowIp(\''
                . esc_attr($ip)
                . '\')" class="spbcGreen tbl-row_action--allow" data-ip=' . $ip . '>'
                . esc_html__('Allow', 'security-malware-firewall') . '</a>';
            $ban_layout = '<a href="#" onclick="return spbcSecLogsBanIp(\''
                . esc_attr($ip)
                . '\')" class="spbc---red tbl-row_action--ban" data-ip=' . $ip . '>'
                . esc_html__('Ban', 'security-malware-firewall') . '</a>';

            $user      = get_user_by('login', $row->user_login);
            $user_part = sprintf(
                "<a href=\"%s\">%s</a>",
                $user ? (admin_url() . '/user-edit.php?user_id=' . $user->data->ID) : '#',
                $row->user_login
            );
            $user_part .= '<br>' . $allow_layout . ' | ' . $ban_layout;

            $url = $row->page;
            if ($url === null) {
                $page = '-';
            } elseif (strlen($url) >= 60) {
                $page = '<div class="spbcShortText">'
                    . '<a href="' . $url . '" target="_blank">' . substr($url, 0, 60) . '...</a>'
                    . '</div>'
                    . '<div class="spbcFullText spbcFullText-right spbc_hide_table_cell_desc">'
                    . '<a href="' . $url . '" target="_blank">' . $url . '</a>'
                    . '</div>';
            } else {
                $page = "<a href='" . $url . "' target='_blank'>" . $url . "</a>";
            }

            $parse_action = spbc_parse_action_from_admin_page_uri($url);
            $is_add_time = !empty($parse_action['add_time']) ? $parse_action['add_time'] : false;
            $time = $row->page_time === null ? '(Calculating)' : '(' . strval($row->page_time) . ' seconds)';

            switch ($row->event) {
                case 'view':
                    $event = __('Viewing admin page ', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'viewing_posts_list':
                    $event = __('Viewing the posts list', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'viewing_pages_list':
                    $event = __('Viewing the pages list', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'editing_post':
                    $event = __('Editing a post', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'editing_post_id':
                    $event =  sprintf(
                        __('Editing post %s', 'security-malware-firewall'),
                        '"' . get_the_title($parse_action['post_id']) . '"' . $parse_action['page_action']
                    );
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'activate_plugin_name':
                    $event = sprintf(
                        __('Activate plugin %s', 'security-malware-firewall'),
                        '"' . $parse_action['plugin_name'] . '"'
                    );
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'deactivate_plugin_name':
                    $event = sprintf(
                        __('Deactivate plugin %s', 'security-malware-firewall'),
                        '"' . $parse_action['plugin_name'] . '"'
                    );
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'uploading_plugin':
                    $event = __('Uploading a plugin', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'adding_user':
                    $event = __('Adding a user', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'deleting_user':
                    $event = __('Deleting a user', 'security-malware-firewall');
                    $event .= $is_add_time ? $time : '';
                    break;
                case 'auth_failed':
                    $event = __('Failed authentication', 'security-malware-firewall');
                    break;
                case 'auth_failed_2fa':
                    $event = __('Failed two factor authentication', 'security-malware-firewall');
                    break;
                case 'auth_failed_g2fa':
                    $event = __('Failed two factor google authentication', 'security-malware-firewall');
                    break;
                case 'invalid_username':
                    $event = __('Invalid username', 'security-malware-firewall');
                    break;
                case 'invalid_email':
                    $event = __('Invalid e-mail', 'security-malware-firewall');
                    break;
                case 'invalid_password':
                    $event = __('Invalid password', 'security-malware-firewall');
                    break;
                case 'login':
                    $event = __('Login', 'security-malware-firewall');
                    break;
                case 'login_new_device':
                    $event = __('Login from new device', 'security-malware-firewall');
                    break;
                case 'login_2fa':
                    $event = __('Two factor authentication', 'security-malware-firewall');
                    break;
                case 'login_g2fa':
                    $event = __('Two factor google authentication', 'security-malware-firewall');
                    break;
                case 'logout':
                    $event = __('Logout', 'security-malware-firewall');
                    break;

                default:
                    $event = $row->event;
                    break;
            }

            $country_part = spbc_report_country_part($ips_c, $row->auth_ip);
            $ip_part      = sprintf(
                "<a href=\"https://cleantalk.org/blacklists/%s\" target=\"_blank\">%s</a>,&nbsp;%s",
                $row->auth_ip,
                IP::reduceIPv6($row->auth_ip),
                $country_part
            );

            $table->items[] = array(
                'cb' => $row->id,
                'user_login' => $user_part,
                'datetime'   => date("M d Y, H:i:s", strtotime($row->datetime) + $time_offset),
                'event'      => $event,
                'page'       => $page,
                'auth_ip'    => $ip_part,
            );
        }
    }
}

/**
 * Admin callback function - Displays description of 'main' plugin parameters section
 * @throws Exception
 */

function spbc_field_security_logs()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">';

    /**
     * Check if tab is restricted by license, layout according HTML if so.
     */
    $feature_state = $spbc->feature_restrictions->getState($spbc, 'security_log');
    if (false === $feature_state->is_active) {
        echo $feature_state->sanitizedReasonOutput();
        echo '</div>';
        return;
    }

    // HEADER
    $message_about_log = __('This table contains details of all brute-force attacks and security actions made in the past 24 hours.', 'security-malware-firewall');

    if ( ! $spbc->data["wl_mode_enabled"] ) {
        $message_about_log .=  sprintf(
            esc_html__(' Please, use your %sSecurity Control Panel%s to see the full report.', 'security-malware-firewall'),
            '<a target="_blank" href="https://cleantalk.org/my/logs?user_token=' . $spbc->user_token . '">',
            '</a>'
        );
    }

    echo "<p class='spbc_hint spbc_hint-security_logs -display--inline-block'>$message_about_log</p>";

    // OUTPUT
    $table = new ListTable(spbc_list_table__get_args_by_type('security_logs'));

    $table->getData();

    // Send logs button
    if ($table->items_total) {
        echo '<p class="spbc_hint spbc_hint-send_security_log spbc_hint--link spbc_hint--top_right">'
             . __('Send logs', 'security-malware-firewall')
             . '</p>';
    }

    $table->display();

    // SHOW MORE
    if ($table->items_total > SPBC_LAST_ACTIONS_TO_VIEW) {
        echo '<div class="spbc__wrapper--center spbc__wrapper--show_more">';
        if ( ! empty($spbc->user_token)) {
            echo '<div class="spbc__show_more_logs">'
                 . "<h3 class='-display--inline-block'>"
                 . __('Proceed to:', 'security-malware-firewall') . "&nbsp;"
                 . "</h3>"
                 . "<a target='_blank' href='https://cleantalk.org/my/logs?service=" . $spbc->service_id . "&user_token=" . $spbc->user_token . "' class='spbc_manual_link -display--inline-block'>"
                 . __('Security Control Panel', 'security-malware-firewall')
                 . "</a>"
                 . "<h3 class='-display--inline-block'>&nbsp;"
                 . __('to see more.', 'security-malware-firewall')
                 . "</h3>"
                 . '</div>';
        }
        echo "<div id='spbc_show_more_button' class='spbc_manual_link'>"
             . __('Show more', 'security-malware-firewall')
             . "</div>"
             . '<img class="spbc_preloader" src="' . SPBC_PATH . '/images/preloader.gif" />'
             . "</div>";
    }

    echo '</div>';
}

function spbc_field_traffic_control_logs__prepare_data(&$table)
{
    global $spbc;

    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $ip_countries[] = $row->ip_entry;
        }
        $ip_countries = spbc_get_countries_by_ips(implode(',', $ip_countries));

        $time_offset = current_time('timestamp') - time();

        foreach ($table->rows as $row) {
            $ip = IP::reduceIPv6($row->ip_entry);
            $allow_layout = '<a href="#" onclick="return spbcTcAllowIp(\'' . esc_attr($ip) . '\')" class="spbcGreen">' . esc_html__('Allow', 'security-malware-firewall') . '</a>';
            $ban_layout = '<a href="#" onclick="return spbcTcBanIp(\'' . esc_attr($ip) . '\')" class="spbc---red">' . esc_html__('Ban', 'security-malware-firewall') . '</a>';
            $ip = "<a href='https://cleantalk.org/blacklists/{$row->ip_entry}' target='_blank'>" . esc_html($ip) . '</a>'
                  . '<br>'
                  . $allow_layout . ' | ' . $ban_layout;

            $requests = '<b>' . $row->requests . '</b>';

            $page_url = strlen($row->page_url) >= 60
                ? '<div class="spbcShortText">' . substr($row->page_url, 0, 60) . '...</div>'
                  . '<div class="spbcFullText spbc_hide_table_cell_desc">' . $row->page_url . '</div>'
                : $row->page_url;

            $user_agent = strlen($row->http_user_agent) >= 60
                ? '<div class="spbcShortText">' . substr($row->http_user_agent, 0, 60) . '...</div>'
                  . '<div class="spbcFullText spbc_hide_table_cell_desc">' . $row->http_user_agent . '</div>'
                : $row->http_user_agent;

            $is_personal_text = $row->is_personal
                ? esc_html__('by personal lists.', 'security-malware-firewall')
                : esc_html__('by common lists.', 'security-malware-firewall');
            $passed_text = esc_html__('Passed', 'security-malware-firewall') . ' ' . $is_personal_text;
            $blocked_text = esc_html__('Blocked', 'security-malware-firewall') . ' ' . $is_personal_text;

            switch ($row->status) {
                case 'PASS':
                    $status = '<span class="spbcGreen">' . $passed_text . '</span>';
                    break;
                case 'PASS_BY_TRUSTED_NETWORK':
                    $status = '<span class="spbcGreen">' . $passed_text . ' ' . __('Trusted network. Click on IP for details.', 'security-malware-firewall') . '</span>';
                    break;
                case 'PASS_BY_WHITELIST':
                    $status = '<span class="spbcGreen">' . $passed_text . ' ' . __('Whitelisted.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY':
                    $status = '<span class="spbcRed">' . $blocked_text . ' ' . __('Blacklisted.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_NETWORK':
                    $status = '<span class="spbcRed">' . $blocked_text . ' ' . __('Hazardous network.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_DOS':
                    $status = '<span class="spbcRed">' . __('Blocked by Traffic control', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_SEC_FW':
                    $status = '<span class="spbcRed">' . __('Blocked. Hazardous network. Security source.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_SPAM_FW':
                    $status = '<span class="spbcRed">' . __('Blocked. Hazardous network. SFW source', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_BFP':
                    $status = '<span class="spbcRed">' . __('Blocked by BruteForce protection system', 'security-malware-firewall') . '</span>';
                    break;
                // WAF
                case 'DENY_BY_WAF_XSS':
                    $status = '<span class="spbcRed">' . __('Blocked by Web Application Firewall: XSS attack detected.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_WAF_SQL':
                    $status = '<span class="spbcRed">' . __('Blocked by Web Application Firewall: SQL-injection detected.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_WAF_FILE':
                    $status = '<span class="spbcRed">'
                              . __('Blocked by Upload Checker module: ', 'security-malware-firewall')
                              . '<span class="spbc_waf_reason_title">'
                              . __('Malicious files upload.', 'security-malware-firewall')
                              . '</span>'
                              . ' <span class="spbc_waf_reason">'
                              . __('Reason: ', 'security-malware-firewall')
                              // .json_decode($row->pattern, true)
                              . $row->pattern
                              . '</span>'
                              . ''
                              . '</span>';
                    break;
                case 'DENY_BY_WAF_EXPLOIT':
                    $status = '<span class="spbcRed">' . __('Blocked by Web Application Firewall: Exploit detected.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_WAF_BLOCKER':
                    $status = '<span class="spbcRed">' . __('Blocked for 24 hours by Web Application Firewall: several attacks detected in a row', 'security-malware-firewall') . '</span>';
                    break;
                default:
                    $status = __('Unknown', 'security-malware-firewall');
                    break;
            }

            $table->items[] = array(
                'ip_entry'        => $ip,
                'country'         => spbc_report_country_part($ip_countries, $row->ip_entry),
                'entry_timestamp' => date('M d Y, H:i:s', $row->entry_timestamp + $time_offset),
                'requests'        => $requests,
                'requests_per'    => '<b>' . spbc_report_tc_requests_per($row->ip_entry, $row->status) . '</b>',
                'status'          => $status,
                'page_url'        => $page_url,
                'http_user_agent' => $user_agent,
            );
        }
    }
}

/**
 * @throws Exception
 */
function spbc_field_traffic_control_log()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">';

    /**
     * Check if tab is restricted by license, layout according HTML if so.
     */
    $feature_state = $spbc->feature_restrictions->getState($spbc, 'firewall_log');
    if (false === $feature_state->is_active) {
        echo $feature_state->sanitizedReasonOutput();
        echo '</div>';
        return;
    }

    $table = new ListTable(spbc_list_table__get_args_by_type('traffic_control'));

    $table->getData();

    echo '<p class="spbc_hint spbc_hint--left -display--inline-block">';
    printf(
        __('This list contains details of access attempts for the past hour and shows only last %d records.', 'security-malware-firewall'),
        SPBC_LAST_ACTIONS_TO_VIEW
    );
    echo "&nbsp;";
    printf(__('The list updates itself every %d seconds automatically.', 'security-malware-firewall'), 60);
    echo sprintf(
        __('Traffic Control blocks visitors who opened more than %s website pages within %s minutes.', 'security-malware-firewall'),
        '<b>' . (isset($spbc->settings['traffic_control__autoblock_amount']) ? $spbc->settings['traffic_control__autoblock_amount'] : 1000) . '</b>',
        '<b>' . (isset($spbc->settings['traffic_control__autoblock_timeframe']) ? (int)$spbc->settings['traffic_control__autoblock_timeframe'] / 60 : 5) . '</b>'
    )
    . ' ';
    echo sprintf(
        __('You can adjust it %shere%s.', 'security-malware-firewall'),
        '<a href="#" onclick="spbcSwitchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_setting_traffic_control__autoblock_amount\', action: \'highlight\', times: 3});">',
        '</a>'
    );
    echo ' ';
    echo sprintf(
        __('Traffic Control is %s.', 'security-malware-firewall'),
        '<b>' . (
                ! empty($spbc->settings['traffic_control__enabled'])
                    ? __('active', 'security-malware-firewall')
                    : __('inactive', 'security-malware-firewall')
        ) . '</b>'
    ) . (! empty($spbc->settings['traffic_control__enabled'])
            ? ''
            : ' ' . sprintf(
                __('You can activate it %shere%s.', 'security-malware-firewall'),
                '<a href="#" onclick="spbcSwitchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_traffic_control__enabled\', 3);">',
                '</a>'
            ));
    echo ' ';
    echo sprintf(
        __('Web Application Firewall (WAF) is %s.', 'security-malware-firewall'),
        '<b>' . (! empty($spbc->settings['waf__enabled'])
            ? __('active', 'security-malware-firewall')
            : __('inactive', 'security-malware-firewall')
        ) . '</b>'
    )
    . (! empty($spbc->settings['waf__enabled'])
        ? ''
        : ' ' . sprintf(
            __('You can activate it %shere%s.', 'security-malware-firewall'),
            '<a href="#" onclick="spbcSwitchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_waf__enabled\', 3);">',
            '</a>'
        )
    );
    echo ' ';
    if ($table->items_total) {
        echo "<a class='spbc_hint spbc_hint-send_traffic_control spbc_hint--link '>Send logs</a>"; // Send logs button
    }
    echo '</p>';

    $table->display();

    if ($table->items_total > SPBC_LAST_ACTIONS_TO_VIEW) {
        echo "<div class='spbc__wrapper--center spbc__wrapper--show_more'>";
        if ($spbc->user_token) {
            echo '<div class="spbc__show_more_logs">'
                 . '<h3 class="-display--inline-block">'
                 . __('Proceed to:', 'security-malware-firewall') . '&nbsp;'
                 . '</h3>'
                 . '<a target="_blank" href="https://cleantalk.org/my/logs_firewall?service=' . $spbc->service_id . '&user_token=' . $spbc->user_token . '" class="spbc_manual_link -display--inline-block">'
                 . __('Security Control Panel', 'security-malware-firewall')
                 . '</a>'
                 . '<h3 class="-display--inline-block">&nbsp;'
                 . __('to see more.', 'security-malware-firewall')
                 . '</h3>'
                 . '</div>';
        }
        echo "<div id='spbc_show_more_fw_logs_button' class='spbc_manual_link'>"
             . __('Show more', 'security-malware-firewall')
             . "</div>"
             . '<img class="spbc_preloader" src="' . SPBC_PATH . '/images/preloader.gif" />'
             . "</div>";
    }

    echo '</div>';
}

function spbc_field_scanner__prepare_data__files(&$table)
{
    global $wpdb,$spbc;

    if ($table->items_count) {
        $root_path = spbc_get_root_path();

        $signatures = $wpdb->get_results('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES, OBJECT_K);

        foreach ($table->rows as $key => $row) {
            // Filtering row actions
            if ($row->last_sent > $row->mtime || $row->size == 0 || $row->size > 1048570) {
                unset($row->actions['send']);
            }

            if ( !$row->real_full_hash || !$row->source_type ) {
                unset($row->actions['replace']);
                unset($row->actions['compare']);
            }

            if ( ! $row->severity) {
                unset($row->actions['view_bad']);
            }
            if ($row->status === 'quarantined') {
                unset($row->actions['quarantine']);
            }

            if ( $table->type === 'approved' ) {
                 $status = esc_html__('User', 'security-malware-firewall');
            } else {
                $status = __('Not checked by Cloud Analysis or ' . $spbc->data["wl_company_name"] . ' Team yet.', 'security-malware-firewall');
                if ( !empty($row->pscan_status) ) {
                    if ( $row->pscan_status === 'DANGEROUS' ) {
                        $status = '<span class="spbcRed">' . __('File is denied by Cloud analysis', 'security-malware-firewall') . '</span>';
                    }
                }
            }

            if ( $row->status === 'APPROVED_BY_CT' ) {
                $status = esc_html__('CleanTalk Team', 'security-malware-firewall');
            }
            if ( $row->status === 'APPROVED_BY_CLOUD' ) {
                $status = esc_html__('Cloud analysis', 'security-malware-firewall');
            }

            if ( !empty($row->status) ) {
                if ( $row->status === 'DENIED_BY_CT' ) {
                    unset($row->actions['send']);
                    unset($row->actions['view_bad']);
                }
            }

            if ( !empty($row->status) ) {
                if ( $row->status === 'DENIED_BY_CT' ) {
                    unset($row->actions['send']);
                    unset($row->actions['view_bad']);
                }
            }

            if ( $table->type === 'suspicious' && in_array($row->fast_hash, spbc_get_list_of_scheduled_suspicious_files_to_send())) {
                $status = __('File will be automatically send for Cloud analysis within 5 minutes.', 'security-malware-firewall');
                unset($row->actions['send']);
                unset($row->actions['approve']);
                unset($row->actions['quarantine']);
                unset($row->actions['delete']);
                unset($row->actions['compare']);
                unset($row->actions['replace']);
            }

            $table->items[] = array(
                'cb'      => $row->fast_hash,
                'uid'     => $row->fast_hash,
                'size'    => substr(number_format($row->size, 2, ',', ' '), 0, - 3),
                'perms'   => $row->perms,
                'mtime'   => date('M d Y H:i:s', $row->mtime + $spbc->data['site_utc_offset_in_seconds']),
                'path'    => strlen($root_path . $row->path) >= 40
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide_table_cell_desc">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'actions' => $row->actions,
                'status' => $status,
            );

            if (isset($row->weak_spots)) {
                $weak_spots = json_decode($row->weak_spots, true);
                $ws_string = '';

                if ($weak_spots) {
                    if ( ! empty($weak_spots['SIGNATURES']) && $signatures) {
                        foreach ($weak_spots['SIGNATURES'] as $_string => $weak_spot_in_string) {
                            foreach ($weak_spot_in_string as $weak_spot) {
                                $ws_string .= '<span class="spbcRed"><i setting="signatures_' . $signatures[ $weak_spot ]->attack_type . '" class="spbc_long_description__show spbc-icon-help-circled"></i>' . $signatures[ $weak_spot ]->attack_type . ': </span>'
                                             . (strlen($signatures[ $weak_spot ]->name) > 30
                                        ? substr($signatures[ $weak_spot ]->name, 0, 30) . '...'
                                        : $signatures[ $weak_spot ]->name);
                            }
                        }
                    }
                    if ( ! empty($weak_spots['CRITICAL'])) {
                        // collecting all kinds of code
                        $all_unique_weak_spots = array();
                        foreach ($weak_spots['CRITICAL'] as $_string => $weak_spot_in_string) {
                            $all_unique_weak_spots[] = $weak_spot_in_string[0];
                        }
                        $all_unique_weak_spots = array_unique($all_unique_weak_spots);
                        foreach ($all_unique_weak_spots as $weak_spot_in_string) {
                            $ws_string .= '<p style="margin: 0;"><span class="spbcRed"><i setting="heuristic_' . str_replace(' ', '_', $weak_spot_in_string) . '" class="spbc_long_description__show spbc-icon-help-circled"></i> Heuristic: </span>'
                                    . (strlen($weak_spot_in_string) > 30
                                    ? substr($weak_spot_in_string, 0, 30) . '...'
                                    : $weak_spot_in_string);
                            $ws_string .= '</p>';
                        }
                    }
                    if ( ! empty($weak_spots['SUSPICIOUS'])) {
                        // collecting all kinds of code
                        $all_unique_weak_spots = array();
                        foreach ($weak_spots['SUSPICIOUS'] as $_string => $weak_spot_in_string) {
                            $all_unique_weak_spots[] = $weak_spot_in_string[0];
                        }
                        $all_unique_weak_spots = array_unique($all_unique_weak_spots);
                        foreach ($all_unique_weak_spots as $weak_spot_in_string) {
                            $ws_string .= '<p style="margin: 0;"><span class="spbcRed"><i setting="suspicious_' . str_replace(' ', '_', $weak_spot_in_string) . '" class="spbc_long_description__show spbc-icon-help-circled"></i> Suspicious: </span>'
                                . (strlen($weak_spot_in_string) > 30
                                ? substr($weak_spot_in_string, 0, 30) . '...'
                                : $weak_spot_in_string);
                            $ws_string .= '</p>';
                        }
                    }
                    if ( ! empty($weak_spots['DENIED_HASH'])) {
                        // collecting all kinds of code
                        $all_unique_weak_spots = array();
                        foreach ($weak_spots['DENIED_HASH'] as $_string => $weak_spot_in_string) {
                            $all_unique_weak_spots[] = $weak_spot_in_string[0];
                        }
                        $all_unique_weak_spots = array_unique($all_unique_weak_spots);
                        foreach ($all_unique_weak_spots as $weak_spot_in_string) {
                             $ws_string .= '<p style="margin: 0;"><span class="spbcRed"><i setting="hash_' . str_replace(' ', '_', $weak_spot_in_string) . '" class="spbc_long_description__show spbc-icon-help-circled"></i> Hash: </span>'
                                . 'denied';

                            $ws_string .= '</p>';
                            $table->items[ $key ]['status'] = "Delete, cure or quarantine the file immediately!";
                        }
                    }
                }

                $table->items[ $key ]['weak_spots'] = $ws_string;
            }

            //delete send action if file extension is not in list for unknown files
            if ( $table->type === 'unknown' && !empty($row->path) ) {
                $ext = pathinfo($row->path, PATHINFO_EXTENSION);
                if (
                    empty($ext) ||
                    (
                        !empty($ext) &&
                        !in_array($ext, array('php', 'html', 'htm', 'php2', 'php3', 'php4', 'php5', 'php6', 'php7', 'phtml', 'shtml', 'phar', 'odf'))
                    )
                ) {
                    if ( isset($table->items[$key], $table->items[$key]['actions'], $table->items[$key]['actions']['send']) ) {
                        unset($table->items[$key]['actions']['send']);
                    }
                }
            }

            if ($table->type === 'skipped') {
                $parsed_item_error = '';
                if ( !empty($row->error_msg) && is_string($row->error_msg) ) {
                    $errors = json_decode($row->error_msg, true);
                    if (!empty($errors)) {
                        foreach ($errors as $_key => $_val) {
                            $parsed_item_error .= '<p>' . $_key . ': ' . $_val . '</p>';
                        }
                    } else {
                        $parsed_item_error = 'Unknown error';
                    }
                }

                unset($table->items[$key]['actions']['view']);

                $table->items[$key]['error_msg'] = $parsed_item_error;
            }

            if (isset($row->size) && (int)($row->size) > 1024 * 1024 * 8) {
                unset($table->items[$key]['actions']['send']);
            }
        }
    }
}

function spbc_field_scanner__prepare_data__analysis_log(&$table)
{
    if ($table->items_count) {
        $root_path = spbc_get_root_path();
        ////should be offset, because $row->last_sent has offset
        $curr_time = current_time('timestamp');
        $table->columns['analysis_comment']  = array('heading' => 'Comment', 'width_percent' => 20);

        foreach ($table->rows as $key => $row) {
            $pscan_status = '-';
            $analysis_comment = '-';
            switch ($row->pscan_processing_status) {
                case 'NEW':
                    $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                    $analysis_comment = __('Processing: new, preparing to queueing..', 'security-malware-firewall');
                    break;
                case 'ERROR':
                    $pscan_status = '<span class="spbcRed">' . __('Checked', 'security-malware-firewall') . '</span>';
                    $analysis_comment = '<span class="spbcRed">' . __('Files cause errors on execution.', 'security-malware-firewall') . '</span>';
                    break;
                case 'IN_SCANER':
                    $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                    $analysis_comment = __('Processing: on the cloud scanner..', 'security-malware-firewall');
                    break;
                case 'IN_SANDBOX':
                case 'NEW_SANDBOX':
                    $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                    $analysis_comment = __('Processing: on the cloud sandbox..', 'security-malware-firewall');
                    break;
                case 'IN_CLOUD':
                case 'NEW_CLOUD':
                    $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                    $analysis_comment = __('Processing: on the cloud analysis system', 'security-malware-firewall');
                    break;
                case 'UNKNOWN':
                    $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                    $analysis_comment = __('Processing: adding to queue..', 'security-malware-firewall');
                    break;
                case 'DONE':
                    if ($row->pscan_status === 'DANGEROUS') {
                        $pscan_status = '<span class="spbcRed">' . $row->pscan_status . '</span>';
                        $analysis_comment = '<span class="spbcRed">' . __('Cloud: file is dangerous', 'security-malware-firewall')  . '</span>';
                    } elseif ($row->pscan_status === 'SAFE') {
                        $pscan_status = '<span class="spbcGreen">' . $row->pscan_status . '</span>';
                        $analysis_comment = '<span class="spbcGreen">' . __('Cloud: file is safe', 'security-malware-firewall')  . '</span>';
                    }
                    break;
                default:
                    $pscan_status = $row->pscan_processing_status;
                    $analysis_comment = 'Not scanned by Cloud or CleanTalk team.';
            }

            if ( isset($row->status) && $row->status === 'QUARANTINED' ) {
                $pscan_status = $row->pscan_status;
                $analysis_comment = __('Quarantined by user', 'security-malware-firewall');
            }

            if ( isset($row->status) && $row->status === 'APPROVED_BY_USER' ) {
                $pscan_status = 'APPROVED';
                $analysis_comment = __('Approved by user', 'security-malware-firewall');
            }

            if ($row->pscan_pending_queue == '1') {
                $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                $analysis_comment = __('Processing: queue is full. File will be resent in 5 minutes.', 'security-malware-firewall');
            }

            // Filter actions for approved files
            if ( in_array($row->pscan_status, array('SAFE','DANGEROUS')) || $curr_time - $row->last_sent < 500 ) {
                unset($row->actions['check_analysis_status']);
            }

            if ( empty($row->pscan_status) ) {
                unset($row->actions['delete']);
                unset($table->bulk_actions['delete_from_analysis_log']);
            }

            $table->items[ $key ] = array(
                'cb'               => $row->fast_hash,
                'uid'              => $row->fast_hash,
                'path'             => strlen($root_path . $row->path) >= 40
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide_table_cell_desc">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'detected_at'      => is_numeric($row->detected_at) ? date('M j, Y, H:i:s', $row->detected_at) : null,
                'last_sent'        => is_numeric($row->last_sent) ? date('M j, Y, H:i:s', $row->last_sent) : null,
                'pscan_status'  => $pscan_status,
                'analysis_comment' => $analysis_comment,
                'actions'          => $row->actions,
            );
        }
    }
}

function spbc_field_scanner__prepare_data__files_quarantine(&$table)
{
    global $spbc;
    if ($table->items_count) {
        $root_path = spbc_get_root_path();
        foreach ($table->rows as $_key => $row) {
            $table->items[] = array(
                'cb'             => $row->fast_hash,
                'uid'            => $row->fast_hash,
                'actions'        => $row->actions,
                'path'           => strlen($root_path . $row->path) >= 40
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide_table_cell_desc">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'previous_state' => json_decode($row->previous_state)->status,
                'severity'       => $row->severity,
                'perms'   => $row->perms,
                'mtime'   => date('M d Y H:i:s', $row->mtime + $spbc->data['site_utc_offset_in_seconds']),
                'q_time'         => date('M d Y H:i:s', $row->q_time),
                'size'           => substr(number_format($row->size, 2, ',', ' '), 0, - 3),
            );
        }
    }
}

function spbc_field_scanner__prepare_data__domains(&$table)
{
    if ($table->items_count) {
        $num = $table->sql['offset'] + 1;
        foreach ($table->rows as $row) {
            $table->items[] = array(
                'num'         => $num++,
                'uid'         => $row->domain,
                'domain'      => "<a href='{$row->domain}' target='_blank'>{$row->domain}</a>",
                'spam_active' => isset($row->spam_active) ? ($row->spam_active ? 'Yes' : 'No') : 'Unknown',
                'page_url'    => $row->page_url,
                'link_count'  => htmlspecialchars($row->link_count),
                'actions'     => $row->actions,
            );
        }
    }
}

function spbc_field_scanner__prepare_data__links(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $table->items[] = array(
                'link_id'     => $row->link_id,
                'link'        => "<a href='{$row->link}' target='_blank'>{$row->link}</a>",
                'page_url'    => "<a href='{$row->page_url}' target='_blank'>{$row->page_url}</a>",
                'link_text'   => htmlspecialchars($row->link_text),
            );
        }
    }
}

function spbc_field_scanner__prepare_data__frontend(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $table->items[] = array(
                // 'cb' row has no useful matter, but should be kept for checkbox placement
                'cb'             => $row->page_id,
                'url'            => $row->url,
                'uid'            => $row->url,
                'page_id'        => $row->page_id,
                'actions'        => $row->actions,
                'dbd_found'      => $row->dbd_found
                    ? '<span class="spbcRed">' . __('Found', 'security-malware-firewall') . '</span>'
                    : '<span class="spbcGreen">' . __('Not found', 'security-malware-firewall') . '</span>',
                'redirect_found' => $row->redirect_found
                    ? '<span class="spbcRed">' . __('Found', 'security-malware-firewall') . '</span>'
                    : '<span class="spbcGreen">' . __('Not found', 'security-malware-firewall') . '</span>',
                'csrf'           => $row->csrf
                    ? '<span class="spbcRed">' . __('Found', 'security-malware-firewall') . '</span>'
                    : '<span class="spbcGreen">' . __('Not found', 'security-malware-firewall') . '</span>',
                'signature'      => $row->signature
                    ? '<span class="spbcRed">' . __('Found', 'security-malware-firewall') . '</span>'
                    : '<span class="spbcGreen">' . __('Not found', 'security-malware-firewall') . '</span>',
            );
        }
    }
}

/**
 * Get data for frontend scan malware results.
 * @param $offset
 * @param $limit
 * @return array|object|stdClass[]|null
 */
function spbc_field_scanner__get_data__frontend_malware($offset = 1, $limit = 20, $order_direction = "DESC", $order = "page_id")
{
    global $wpdb;
    return $wpdb->get_results(
        'SELECT * FROM ' . SPBC_TBL_SCAN_FRONTEND . '
        WHERE approved IS NULL OR approved <> 1
		ORDER BY ' . $order . ' ' . $order_direction . '
		LIMIT ' . $offset . ',' . $limit . ';'
    );
}

/**
 * Get data for frontend scan approved results.
 * @param $offset
 * @param $limit
 * @return array|object|stdClass[]|null
 */
function spbc_field_scanner__get_data__frontend_approved($offset = 0, $limit = 20)
{
    global $wpdb;
    return $wpdb->get_results(
        'SELECT * FROM ' . SPBC_TBL_SCAN_FRONTEND . '
        WHERE approved = 1
		ORDER BY page_id DESC
		LIMIT ' . $offset . ',' . $limit . ';'
    );
}

/**
 * Counts amount of accessible URL
 *
 * @return int
 */
function spbc_field_scanner__files_listing__get_total()
{
    global $spbc;

    $accessible_urls = is_array($spbc->scanner_listing) && !empty($spbc->scanner_listing['accessible_urls'])
        ? $spbc->scanner_listing['accessible_urls']
        : array();

    if (
        isset($accessible_urls) &&
        (is_array($accessible_urls) || is_object($accessible_urls))
    ) {
        return count($accessible_urls);
    }

    return 0;
}

/**
 * Provides data in the correct format for table
 *
 * @return array of objects
 */
function spbc_field_scanner__files_listing__get_data()
{
    global $spbc;

    $out = array();

    $accessible_urls = is_array($spbc->scanner_listing) && !empty($spbc->scanner_listing['accessible_urls'])
        ? $spbc->scanner_listing['accessible_urls']
        : array();

    if (
        isset($accessible_urls) &&
        (is_array($accessible_urls) || is_object($accessible_urls))
    ) {
        foreach ($accessible_urls as $entry) {
            $out[] = (object) $entry;
        }
    }

    return $out;
}

function spbc_field_scanner__files_listing__data_prepare(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $table->items[] = array(
                'url'  => "<a href='{$row->url}' target='_blank'>" . get_option('home') . "{$row->url}</a>",
                'type' => ucfirst($row->type)
                          . '<i setting="' . $row->type . '" class="spbc_long_description__show spbc-icon-help-circled"></i>'
                          . '<i setting="' . $row->type . '" class="spbc_long_recommendation__show spbc-icon-info-circled" style="cursor: pointer;"></i>',
            );
        }
    }
}

/**
 * Modify data to the Approved section
 *
 * @return void
 */
function spbc_field_scanner__approved__data_prepare(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $table->items[] = array(
                'cb'         => $row->page_id,
                'path'       => $row->path,
                'weak_spots' => $row->weak_spots,
                'size'       => $row->size,
                'perms'      => $row->perms,
                'mtime'      => $row->mtime,
                'status'     => $row->status === 'APPROVED_BY_CT'
                    ? esc_html__('CleanTalk Team', 'security-malware-firewall')
                    : esc_html__('User', 'security-malware-firewall'),
            );
        }
    }
}

function spbc_field_scanner__log()
{
    global $spbc;

    $out = '<h4 class="spbc-scan-log-title spbc---hidden">' . esc_html__('Scan log', 'security-malware-firewall') . '</h4><div class="spbc_log-wrapper spbc---hidden"></div>';

    return $out;
}

/**
 * @throws Exception
 */
function spbc_field_scanner()
{
    global $spbc, $wp_version;

    echo '<div class="spbc_wrapper_field">';

    /**
     * Check if tab is restricted by license, layout according HTML if so.
     */
    $feature_state = $spbc->feature_restrictions->getState($spbc, 'scanner');
    if (false === $feature_state->is_active) {
        echo $feature_state->sanitizedReasonOutput();
        echo '</div>';
        return;
    }

    if (preg_match('/^[\d\.]*$/', $wp_version) !== 1) {
        echo '<p class="spbc_hint" style="text-align: center;">';
        printf(__('Your WordPress version %s is not supported', 'security-malware-firewall'), $wp_version);
        echo '</p>';
        // return;
    }

    echo '<p class="spbc_hint" style="text-align: center;">';
    echo '<span class="spbc_hint__last_scan_title">';
    if (empty($spbc->data['scanner']['last_scan'])) {
        _e('System hasn\'t been scanned yet. Please, perform the scan to secure the website.', 'security-malware-firewall');
        //should be offset because last_scan is offset
    } elseif ($spbc->data['scanner']['last_scan'] < current_time('timestamp') - 86400 * 7) {
        _e('System hasn\'t been scanned for a long time', 'security-malware-firewall');
    } else {
        _e('Look below for scan results.', 'security-malware-firewall');
    }
    echo '</span>';
    echo '</br>';
    if (! $spbc->data["wl_mode_enabled"]) {
        printf(
            __('%sView all scan results for this website%s%s', 'security-malware-firewall'),
            "<a target='blank' href='https://cleantalk.org/my/logs_mscan?service={$spbc->service_id}&user_token={$spbc->user_token}'>",
            '<i class="spbc-icon-link-ext"></i>',
            '</a>, '
        );
    }
    // show save to pdf link
    if ( ! empty($spbc->data['scanner']['last_scan'])) {
        echo ' &nbsp;<a id="spbc_scanner_save_to_pdf" href="" onclick="event.preventDefault()">'
                . __('Export results to PDF', 'security-malware-firewall')
                . '</a>, ';
    }
    //show backups link
    printf(
        __('%sBackups%s', 'security-malware-firewall'),
        '&nbsp;<a href="/wp-admin/options-general.php?page=spbc&spbc_tab=backups">',
        '</a>'
    );
    echo '</p>';
    $scanner_disabled = isset($spbc->errors['configuration']) ? 'disabled="disabled"' : '';
    $scanner_disabled_reason = $scanner_disabled
        ? 'title="' . __('Scanner is disabled. Please, check errors on the top of the settings.', 'security-malware-firewall') . '"'
        : '';
    echo '<div style="text-align: center; margin-top: 1em;">'
         . '<button id="spbc_perform_scan" class="spbc_manual_link_scan" type="button" ' . $scanner_disabled . $scanner_disabled_reason . '>'
         . __('Perform Scan', 'security-malware-firewall')
         . '</button>'
         . '<img  class="spbc_preloader" src="' . SPBC_PATH . '/images/preloader.gif" />'
         . '</div>';

    echo '<p id="spbc_scanner__last_scan_info" class="spbc_hint" style="text-align: center; margin-top: 5px;">';
    echo spbc_scanner__last_scan_info(true);
    echo '</p>';

    // Show link for shuffle salts
    if ($spbc->settings['there_was_signature_treatment']) {
        echo '<div style="text-align: center;" id="spbc_notice_about_shuffle_link">';
        echo '<a href="options-general.php?page=spbc&spbc_tab=settings_general#action-shuffle-salts-wrapper">' . __('We recommend changing your secret authentication keys and salts when curing is done.', 'security-malware-firewall') . '</a>';
        echo '</div>';
    }
    echo '<p class="spbc_hint spbc_hint_warning spbc_hint_warning__long_scan" style="display: none; text-align: center; margin-top: 5px;">';
    _e('A lot of files were found, so it will take time to scan', 'security-malware-firewall');
    echo '</p>';
    echo '<p class="spbc_hint spbc_hint_warning spbc_hint_warning__outdated" style="display: none; text-align: center; margin-top: 5px;">';
    _e('Found outdated plugins or themes. Please, update to latest versions.', 'security-malware-firewall');
    echo '</p>';

    //* Debug Buttons
    // Clear hashes
    if (in_array(Server::getDomain(), array('lc', 'loc', 'lh', 'wordpress'), true)) {
        echo '<button id="spbc_scanner_clear" class="spbc_manual_link" type="button">'
            . __('Clear', 'security-malware-firewall')
            . '</button>'
            . '<img class="spbc_preloader" src="' . SPBC_PATH . '/images/preloader.gif" />'
            . '<br /><br />';
    }
    //*/

    echo
        '<div id="spbc_scaner_progress_overall" class="spbc_hide" style="padding-bottom: 10px; text-align: center;">'
        . '<span class="spbc_overall_scan_status_get_cms_hashes">' . __('Receiving core hashes', 'security-malware-firewall') . '</span> -> '
        . '<span class="spbc_overall_scan_status_get_modules_hashes">' . __('Receiving plugin and theme hashes', 'security-malware-firewall') . '</span> -> '
        . '<span class="spbc_overall_scan_status_clean_results">' . __('Preparing', 'security-malware-firewall') . '</span> -> '
        . '<span class="spbc_overall_scan_status_file_system_analysis">' . __('Scanning for modifications', 'security-malware-firewall') . '</span> -> '
        . '<span class="spbc_overall_scan_status_get_denied_hashes">' . __('Updating statuses for the denied files', 'security-malware-firewall') . '</span> -> '
        . '<span class="spbc_overall_scan_status_get_approved_hashes">' . __('Updating statuses for the approved files', 'security-malware-firewall') . '</span> -> ';

    if ($spbc->settings['scanner__file_monitoring']) {
        echo '<span class="spbc_overall_scan_status_file_monitoring">'
             . __('Important File Monitoring', 'security-malware-firewall')
             . '</span> -> ';
    }

    if ($spbc->settings['scanner__signature_analysis']) {
        echo '<span class="spbc_overall_scan_status_signature_analysis">'
             . __('Signature analysis', 'security-malware-firewall')
             . '</span> -> ';
    }

    if ($spbc->settings['scanner__heuristic_analysis']) {
        echo '<span class="spbc_overall_scan_status_heuristic_analysis">'
             . __('Heuristic analysis', 'security-malware-firewall')
             . '</span> -> ';
    }

    if ($spbc->settings['scanner__schedule_send_heuristic_suspicious_files']) {
        echo '<span class="spbc_overall_scan_status_schedule_send_heuristic_suspicious_files">'
            . __('Schedule suspicious files sending', 'security-malware-firewall')
            . '</span> -> ';
    }

    if ($spbc->settings['scanner__auto_cure']) {
        echo '<span class="spbc_overall_scan_status_auto_cure_backup">' . __('Creating a backup', 'security-malware-firewall') . '</span> -> ';
        echo '<span class="spbc_overall_scan_status_auto_cure">' . __('Curing', 'security-malware-firewall') . '</span> -> ';
    }

    if ($spbc->settings['scanner__outbound_links']) {
        echo '<span class="spbc_overall_scan_status_outbound_links">' . __('Scanning links', 'security-malware-firewall') . '</span> -> ';
    }

    if ($spbc->settings['scanner__frontend_analysis']) {
        echo '<span class="spbc_overall_scan_status_frontend_analysis">' . __('Scanning public pages', 'security-malware-firewall') . '</span> -> ';
    }

    if ($spbc->settings['scanner__important_files_listing']) {
        echo '<span class="spbc_overall_scan_status_important_files_listing">' . __('Scanning for publicly accessible files', 'security-malware-firewall') . '</span> -> ';
    }

    echo '<span class="spbc_overall_scan_status_send_results">' . __('Sending results', 'security-malware-firewall') . '</span>'

         . '</div>';
    echo '<div id="spbc_scaner_progress_bar" class="spbc_hide" style="height: 22px;"><div class="spbc_progressbar_counter"><span></span></div></div>';

    // Log style output for scanned files

    echo '<div id="spbc_dialog" title="File output" style="overflow: initial;"></div>';


    echo '<div id="spbc_scan_accordion">';
    if ( ! empty($spbc->data['scanner']['last_scan'])) {
        spbc_field_scanner__show_accordion(true);
    }
    echo '</div>';

    echo '<br>';
    echo spbc_field_scanner__log();

    // Scan results log
    if ( ! empty($spbc->data['scanner']['last_scan'])) {
        spbc_scan_results_log_module();
    }

    // Clear hashes
    if (! empty($spbc->data['scanner']['last_scan'])) {
        echo '<p id="spbc_scanner_clear" class="spbc_hint spbc_hint-send_security_log spbc_hint--link spbc_hint--top_right">'
             . __('Clear scanner logs', 'security-malware-firewall')
             . '</p>'
             . '<img class="spbc_preloader" src="' . SPBC_PATH . '/images/preloader.gif" />';
    }

    echo '<br>';

    echo spbc_bulk_actions_description();

    echo '</div>';
}

function spbc_field_scanner__show_accordion($direct_call = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc;

    //analysis log description
    $dashboard_link = ! $spbc->data['wl_mode_enabled'] ? sprintf(
        __(' at the %s Security Dashboard %s.', 'security-malware-firewall'),
        '<a href="https://cleantalk.org/my/support/open?subject=Cloud%20Malware%20scanner,%20results%20question" target="_blank">',
        '</a>'
    ) : '';
    $analysis_log_description = '<div>' .
        __('List of files sent for the Cloud analysis, it takes up to 10 minutes to process a file. Refresh the page to have the results.', 'security-malware-firewall') .
        '<div id="spbc_notice_cloud_analysis_feedback" class="notice is-dismissible">' .
        '<p>' .
        '<img src="' . SPBC_PATH . '/images/att_triangle.png" alt="attention" style="margin-bottom:-1px">' .
        ' ' .
        __('If you feel that the Cloud verdict is incorrect, please click the link "Copy file info" near the file name and contact us', 'security-malware-firewall') . ' ' .
        $dashboard_link .
        '</p>' .
        '</div>' .
        '</div>';
    if ($spbc->data['display_scanner_warnings']['analysis'] && !$spbc->data['wl_mode_enabled']) {
        $analysis_log_description .= spbc__get_accordion_tab_info_block_html('analysis');
    }

    //critical description
    $critical_description = __('These files contain known vulnerabilities. Immediately cure, quarantine or delete the files!', 'security-malware-firewall');
    if ($spbc->data['display_scanner_warnings']['critical'] && !$spbc->data['wl_mode_enabled']) {
        $critical_description .= spbc__get_accordion_tab_info_block_html('critical');
    }
    if ($spbc->settings['scanner__schedule_send_heuristic_suspicious_files'] ) {
        $scheduled_count = count(spbc_get_list_of_scheduled_suspicious_files_to_send());
        if ( $scheduled_count > 0 ) {
            $critical_description .= Escape::escKsesPreset(spbct_get_automatic_files_send_notice_html($scheduled_count), 'spbc_settings__notice_autosend');
        }
    }

    $suspicious_description = __('These files may not contain malicious code, but they use very dangerous PHP functions and constructions! Take a look at files code or send it to the cloud for analyzing.', 'security-malware-firewall');

    //unknown files description
    $unknown_files_description = __('These files do not include known malware signatures or dangerous code. In same time these files do not belong to the WordPress core or any plugin, theme which are hosted on wordpress.org.', 'security-malware-firewall')
        . ' '
        . __('To disable this list deactivate the', 'security-malware-firewall')
        . ' <i>'
        . '"' . __('List unknown files', 'security-malware-firewall') . '"'
        . '</i> '
        . __('option', 'security-malware-firewall')
        . ' '
        . '<a href="options-general.php?page=spbc&spbc_tab=settings_general#spbc_setting_scanner__list_unknown">' . __('here', 'security-malware-firewall') . '</a>.';
    $unknown_files_description .= $spbc->data['wl_mode_enabled'] ? '' : spbc__get_accordion_tab_info_block_html('unknown');

    //cure log description
    $cure_log_description = '<div>' .
        __('These files were automatically cured. ', 'security-malware-firewall') .
        __('You can see backups and restore files on the ', 'security-malware-firewall') .
        sprintf(
            __('%sBackups tab:%s', 'security-malware-firewall'),
            '<a href="/wp-admin/options-general.php?page=spbc&spbc_tab=backups">',
            '</a>'
        ) .
        '</div>';

    //set descriptions
    $tables_files = array(
        'critical'     => $critical_description,
        'suspicious'   => $suspicious_description,
        'approved'     => __('Manually approved files list.', 'security-malware-firewall'),
        'quarantined'  => __('Punished files.', 'security-malware-firewall'),
        'analysis_log' => $analysis_log_description,
        'cure_log'     => $cure_log_description,
        'skipped'     => __('List of files that were not checked by the scanner.', 'security-malware-firewall'),
    );

    $tables_files['skipped'] .= spbc__get_accordion_tab_info_block_html('skipped');

    if (!$spbc->data['wl_mode_enabled']) {
        $tables_files['suspicious'] .= spbc__get_accordion_tab_info_block_html('suspicious');
    }

    if ($spbc->settings['scanner__list_unknown']) {
        $tables_files['unknown'] = $unknown_files_description;
    }

    if ($spbc->settings['scanner__list_approved_by_cleantalk']) {
        $tables_files['approved_by_cloud'] = __('Approved by CleanTalk Team or Clout files list. To disable this list view, please disable the `Show approved by CleanTalk Cloud` option.', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__outbound_links']) {
        $tables_files['outbound_links'] = __('Found outgoing links from this website and websites the links are leading to.', 'security-malware-firewall');
        $tables_files['outbound_links'] .= spbc__get_accordion_tab_info_block_html('outbound_links');
    }

    if ($spbc->settings['scanner__frontend_analysis']) {
        $tables_files['frontend_malware'] = __('Malware on public pages found', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__frontend_analysis']) {
        $tables_files['frontend_scan_results_approved'] = __('Public pages that approved by user', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__important_files_listing']) {
        $tables_files['files_listing'] = __('Publicly accessible important files found', 'security-malware-firewall');
    }

    if (!empty($spbc->data['unsafe_permissions']['files']) || !empty($spbc->data['unsafe_permissions']['dirs'])) {
        $tables_files['unsafe_permissions'] = __('Permissions for files and directories from the list are unsafe. We recommend change it to 755 for each directory and 644 for each file from the list.', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__file_monitoring']) {
        $tables_files['file_monitoring'] = __('Monitoring important files.', 'security-malware-firewall');
    }

    $accordions_order = array(
        'files' => array(
            'category_description' => __('Files scan results', 'security-malware-firewall'),
            'types' => array(
                'critical',
                'suspicious',
                'approved',
                'approved_by_cloud',
                'quarantined',
                'cure_log',
                'unknown',
                'skipped',
                'analysis_log',
                'unsafe_permissions',
                'files_listing',
                'file_monitoring',
            ),
        ),
        'pages' => array(
            'category_description' => __('Pages scan results', 'security-malware-firewall'),
            'types' => array(
                'outbound_links',
                'frontend_malware',
                'frontend_scan_results_approved',
            ),
            'display' => (bool) $spbc->settings['scanner__frontend_analysis']
        ),
    );

    foreach ($accordions_order as $_category => $data) {
        if ( isset($data['display']) && ! $data['display'] ) {
            continue;
        }
        echo '<div class="spbc_accordion_category_wrapper">';
        echo '<h4 class="spbc_accordion_category_header">' .  $data['category_description'] . '</h4>';
        foreach ($data['types'] as $type_name) {
            if ( !isset($tables_files[$type_name]) ) {
                continue;
            }
            $description = $tables_files[$type_name];
            $args = spbc_list_table__get_args_by_type($type_name);
            $args['id'] = 'spbc_tbl__scanner_' . $type_name;
            $args['type'] = $type_name;

            $table = new ListTable($args);

            $table->getData();

            $danger_dot = '';
            if (
                ($type_name === 'critical' && $spbc->data['display_scanner_warnings']['critical'])
                || ($type_name === 'frontend_malware' && $spbc->data['display_scanner_warnings']['frontend'])
                || ($type_name === 'analysis_log' && $spbc->data['display_scanner_warnings']['analysis'])
            ) {
                $danger_dot = '<span class="red_dot"></span>';
            }

            // Pass output if empty and said to do so
            if ( $args['if_empty_items'] !== false || $table->items_total !== 0 ) {
                echo '<h3><a href="#">' . ucwords(str_replace('_', ' ', $type_name))
                    . ' (<span class="spbc_bad_type_count '
                    . $type_name . '_counter">' . $table->items_total . '</span>)</a>'
                    . $danger_dot . '</h3>';
                echo '<div id="spbc_scan_accordion_tab_' . $type_name . '">';

                echo '<p class="spbc_hint">'
                    . $description
                    . '</p>';
                $table->display();

                echo "</div>";
            }
        }
        echo '</div>';
    }

    if ($direct_call) {
        return;
    } else {
        die('');
    }
}

/**
 * Return arguments for ListTable::__constructor()
 *
 * @param string $table_type
 *
 * @return array
 */
function spbc_list_table__get_args_by_type($table_type)
{
    global $spbc;

    // Default arguments for file tables
    $accordion_default_args = array(
        'sql'            => array(
            'add_col'   => array('fast_hash', 'last_sent', 'real_full_hash', 'severity', 'difference', 'status', 'source_type'),
            'table'     => SPBC_TBL_SCAN_FILES,
            'offset'    => 0,
            'limit'     => SPBC_LAST_ACTIONS_TO_VIEW,
            'get_array' => false,
        ),
        'if_empty_items' => 'NOPE',
        'columns'        => array(
            'cb'    => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
            'path'  => array('heading' => 'Path', 'primary' => true,),
            'size'  => array('heading' => 'Size, bytes',),
            'perms' => array('heading' => 'Permissions',),
            'mtime' => array('heading' => 'Last Modified',),
        ),
        'actions'        => array(
            'view'   => array('name' => 'View', 'handler' => 'spbcScannerButtonFileViewEvent(this);',),
        ),
        'bulk_actions'   => array(
        ),
        'sortable'       => array('path', 'size', 'perms', 'mtime',),
        'pagination'     => array(
            'page'     => 1,
            'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
        ),
    );

    switch ($table_type) {
        case 'links':
            $args = array(
                'id'                => 'spbc_tbl__scanner__outbound_links',
                'sql'               => array(
                    'table'     => SPBC_TBL_SCAN_LINKS,
                    'get_array' => false,
                    'where'     => ' WHERE domain = "' . Post::get('domain', null, 'word') . '"',
                ),
                'order_by'          => array('domain' => 'asc'),
                'html_before'       =>
                    sprintf(__('Links for <b>%s</b> domain.', 'security-malware-firewall'), Post::get('domain', null, 'word')) . ' '
                    . sprintf(__('%sSee all domains%s', 'security-malware-firewall'), '<a href="javascript://" onclick="spbcScannerSwitchTable(this, \'outbound_links\');">', '</a>')
                    . '<br /><br />',
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__links',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No links found.', 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'link_id'     => array(
                        'heading' => __('Number', 'security-malware-firewall'),
                        'class'   => ' tbl-width--50px'
                    ),
                    'link'        => array('heading' => __('Link', 'security-malware-firewall'), 'primary' => true,),
                    'page_url'    => array('heading' => __('Post Page', 'security-malware-firewall'),),
                    'link_text'   => array('heading' => __('Link Text', 'security-malware-firewall'),),
                ),
                'sortable'        => array('link', 'page_url'),
            );
            break;

        case 'domains':
            $args = array(
                'id'                => 'spbc_tbl__scanner__outbound_links',
                'actions'           => array(
                    'edit_post'  => array(
                        'name'           => 'Edit',
                        'type'           => 'link',
                        'local'          => true,
                        'edit_post_link' => true,
                        'target'         => '_blank',
                    ),
                    'show_links' => array(
                        'name'    => 'Show links',
                        'handler' => 'spbcScannerSwitchTable(this, "links");'
                    ),
                ),
                'order_by'          => array('spam_active' => 'desc'),
                'func_data_total'   => 'spbc_scanner_links_count_found__domains',
                'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No links found.', 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'num'         => array(
                        'heading' => __('Number', 'security-malware-firewall'),
                        'class'   => ' tbl-width--50px'
                    ),
                    'domain'      => array('heading' => __('Domain', 'security-malware-firewall'), 'primary' => true,),
                    'spam_active' => array(
                        'heading' => __('Spam-active', 'security-malware-firewall'),
                        'hint'    => __('Does link spotted in spam?', 'security-malware-firewall'),
                    ),
                    'link_count'  => array(
                        'heading' => __('Links of domain', 'security-malware-firewall'),
                        'hint'    => __('Number of found links to the domain on site.', 'security-malware-firewall'),
                    ),
                ),
                'sortable'          => array('spam_active', 'domain', 'link_count'),
            );
            break;

        case 'cure_backups':
            $args = array(
                'id'              => 'spbc_tbl__scanner_cure_backups',
                'sql'             => array(
                    'table'     => SPBC_TBL_BACKUPS,
                    'offset'    => 0,
                    'limit'     => SPBC_LAST_ACTIONS_TO_VIEW,
                    'get_array' => false,
                    'where'     => ' RIGHT JOIN ' . SPBC_TBL_BACKUPED_FILES . ' ON ' . SPBC_TBL_BACKUPS . '.backup_id = ' . SPBC_TBL_BACKUPED_FILES . '.backup_id',
                ),
                'func_data_total' => 'spbc_backups_count_found',
                'func_data_get'   => 'spbc_field_backups__get_data',
                'if_empty_items'  => '<p class="spbc_hint">' . __('No backups found', 'security-malware-firewall') . '</p>',
                'columns'         => array(
                    'backup_id' => array('heading' => 'Backup ID', 'primary' => true,),
                    'datetime'  => array('heading' => 'Date',),
                    'type'      => array('heading' => 'Type',),
                    'real_path' => array('heading' => 'File',),
                ),
                'actions'         => array(
                    'rollback' => array('name' => 'Rollback', 'handler' => 'spbcActionBackupsRollback(this);',),
                    'delete'   => array('name' => 'Delete', 'handler' => 'spbcActionBackupsDelete(this);',),
                ),
                'sortable'        => array('backup_id', 'datetime',),
                'pagination'      => array(
                    'page'     => 1,
                    'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
                ),
                'order_by'        => array('datetime' => 'desc'),
            );
            break;

        case 'traffic_control':
            $args = array(
                'id'                => 'spbc_tbl__traffic_control_logs',
                'sql'               => array(
                    'except_cols' => array('country', 'entries', 'requests_per'),
                    'add_col'     => array('entry_id', 'pattern', 'is_personal'),
                    'table'       => SPBC_TBL_FIREWALL_LOG,
                    'offset'      => 0,
                    'limit'       => SPBC_LAST_ACTIONS_TO_VIEW,
                    'get_array'   => false,
                ),
                'order_by'          => array('entry_timestamp' => 'desc'),
                'func_data_prepare' => 'spbc_field_traffic_control_logs__prepare_data',
                'if_empty_items'    => '<p class=spbc_hint>' . __("Local log is empty.", 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'ip_entry'        => array(
                        'heading' => 'IP',
                        'primary' => true,
                    ),
                    'country'         => array('heading' => 'Country',),
                    'entry_timestamp' => array('heading' => 'Last Request',),
                    'status'          => array('heading' => 'Status',),
                    'requests'        => array('heading' => 'Requests and attempts', 'class' => ' tbl-width--100px'),
                    'requests_per'    => array(
                        'heading' => 'Requests per '
                        . (isset($spbc->settings['traffic_control__autoblock_timeframe']) ? (int)$spbc->settings['traffic_control__autoblock_timeframe'] / 60 : 5)
                        . ' minutes',
                        'class' => ' tbl-width--100px'
                    ),
                    'page_url'        => array('heading' => 'Page',),
                    'http_user_agent' => array('heading' => 'User Agent',),
                ),
                'sortable'          => array('status', 'entry_timestamp', 'requests', 'page_url', 'http_user_agent', 'ip_entry'),
            );
            break;

        case 'security_logs':
            $args = array(
                'id'                => 'spbc_tbl__secuirty_logs',
                'sql'               => array(
                    'add_col'   => array('id', 'page_time'),
                    'table'     => SPBC_TBL_SECURITY_LOG,
                    'where'     => (SPBC_WPMS ? ' WHERE blog_id = ' . get_current_blog_id() : ''),
                    'offset'    => 0,
                    'limit'     => SPBC_LAST_ACTIONS_TO_VIEW,
                    'get_array' => false,
                ),
                'order_by'          => array('datetime' => 'desc'),
                'func_data_prepare' => 'spbc_field_security_logs__prepare_data',
                'if_empty_items'    => '<p class="spbc_hint">' . __("0 brute-force attacks have been made.", 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
                    'user_login' => array('heading' => 'User', 'primary' => true,),
                    'auth_ip'    => array('heading' => 'IP',),
                    'datetime'   => array('heading' => 'Date',),
                    'event'      => array('heading' => 'Action',),
                    'page'       => array('heading' => 'Page',),
                ),
                'sortable'          => array('user_login', 'datetime'),
                'pagination'        => array(
                    'page'     => 1,
                    'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
                ),
                'bulk_actions'   => array(
                    'allow' => array('name' => 'Allow',),
                    'ban' => array('name' => 'Ban',),
                ),
                'bulk_actions_all' => false,
            );
            break;

        case 'critical':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'columns'           => array(
                        'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                        'path'       => array('heading' => 'Path', 'primary' => true, 'width_percent' => 38),
                        'size'       => array('heading' => 'Size, bytes', 'width_percent' => 7),
                        'perms'      => array('heading' => 'Permissions', 'width_percent' => 7),
                        'weak_spots' => array('heading' => 'Detected', 'width_percent' => 18),
                        'mtime'      => array('heading' => 'Last Modified', 'width_percent' => 10),
                        'status'      => array('heading' => 'Analysis verdict', 'width_percent' => 15),
                    ),
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'if_empty_items'    => '<p class="spbc_hint">' . __('No threats are found or all the files have been sent for analysis', 'security-malware-firewall') . '</p>',
                    'actions'           => array(
                        'send'       => array(
                            'name' => 'Send for Analysis',
                            'tip'  => 'Send file to the CleanTalk Cloud for analysis'
                        ),
                        'approve'    => array('name' => 'Approve', 'tip' => 'Approved file will not be scanned again'),
                        'quarantine' => array('name' => 'Quarantine it', 'tip' => 'Place file to quarantine'),
                        'replace'    => array(
                            'name' => 'Replace with Original',
                            'tip'  => 'Restore the initial state of file'
                        ),
                        'delete'     => array('name' => 'Delete',),
                        'compare'    => array(
                            'name'    => 'Compare',
                            'handler' => 'spbcScannerButtonFileCompareEvent(this);',
                        ),
                        'view'       => array(
                            'name'    => 'View',
                            'handler' => 'spbcScannerButtonFileViewEvent(this);',
                        ),
                        'view_bad'   => array(
                            'name'    => 'View Suspicious Code',
                            'handler' => 'spbcScannerButtonFileViewBadEvent(this);',
                        ),
                    ),
                    'bulk_actions'      => array(
                        'send'       => array('name' => 'Send for Analysis',),
                        'approve'    => array('name' => 'Approve',),
                        'delete'     => array('name' => 'Delete',),
                        'replace'    => array('name' => 'Replace with original',),
                        'quarantine' => array('name' => 'Quarantine it',),
                    ),
                    'sql'               => array(
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('critical'),
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            $args['sql']['add_col'][] = 'pscan_status';
            $args['sql']['add_col'][] = 'pscan_pending_queue';
            $args['sql']['add_col'][] = 'full_hash';
            break;

        case 'suspicious':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'columns'           => array(
                        'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                        'path'       => array('heading' => 'Path', 'primary' => true, 'width_percent' => 38),
                        'size'       => array('heading' => 'Size, bytes', 'width_percent' => 7),
                        'perms'      => array('heading' => 'Permissions', 'width_percent' => 7),
                        'weak_spots' => array('heading' => 'Detected', 'width_percent' => 18),
                        'mtime'      => array('heading' => 'Last Modified', 'width_percent' => 10),
                        'status'      => array('heading' => 'Analysis verdict', 'width_percent' => 15),
                    ),
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'if_empty_items'    => false,
                    'actions'           => array(
                        'send'       => array(
                            'name' => 'Send for Analysis',
                            'tip'  => 'Send file to the CleanTalk Cloud for analysis'
                        ),
                        'approve'    => array('name' => 'Approve', 'tip' => 'Approved file will not be scanned again'),
                        'quarantine' => array('name' => 'Quarantine it', 'tip' => 'Place file to quarantine'),
                        'replace'    => array(
                            'name' => 'Replace with Original',
                            'tip'  => 'Restore the initial state of file'
                        ),
                        'delete'     => array('name' => 'Delete',),
                        'compare'    => array(
                            'name'    => 'Compare',
                            'handler' => 'spbcScannerButtonFileCompareEvent(this);',
                        ),
                        'view'       => array(
                            'name'    => 'View',
                            'handler' => 'spbcScannerButtonFileViewEvent(this);',
                        ),
                        'view_bad'   => array(
                            'name'    => 'View Suspicious Code',
                            'handler' => 'spbcScannerButtonFileViewBadEvent(this);',
                        ),
                    ),
                    'bulk_actions'      => array(
                        'send'       => array('name' => 'Send for Analysis',),
                        'approve'    => array('name' => 'Approve',),
                        'delete'     => array('name' => 'Delete',),
                        'replace'    => array('name' => 'Replace with original',),
                        'quarantine' => array('name' => 'Quarantine it',),
                    ),
                    'sql'               => array(
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('suspicious'),
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            break;

        case 'analysis_log':
            $args                 = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__analysis_log',
                    'if_empty_items'    => false,
                    'sql'               => array(
                        'add_col' => array(
                            'pscan_processing_status',
                            'fast_hash',
                            'pscan_status',
                            'pscan_pending_queue'
                        ),
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('analysis_log'),
                    ),
                    'order_by'          => array('pscan_status' => 'desc'),
                    'sortable'          => array('path', 'last_sent', 'pscan_status'),
                )
            );

            $args['columns']      = array(
                'cb'                => array('heading' => '<input type=checkbox>', 'class' => 'check-column', 'width_percent' => 2),
                'path'              => array('heading' => 'Path', 'primary' => true, 'width_percent' => 38),
                'detected_at'       => array('heading' => 'Detected at', 'width_percent' => 15),
                'last_sent'         => array('heading' => 'Sent for analysis at', 'width_percent' => 15),
                'pscan_status'      => array('heading' => 'Cloud verdict', 'width_percent' => 10),
                //'analysis_comment'  => array('heading' => 'Comment', 'width_percent' => 20),
            );

            $args['actions']      = array(
                'check_analysis_status' => array('name' => 'Refresh the analysis status'),
                'copy_file_info' => array('name' => 'Copy file info'),
                'view'       => array(
                    'name'    => 'View',
                    'handler' => 'spbcScannerButtonFileViewEvent(this);',
                ),
                'delete' => array('name' => 'Delete from log', 'handler' => 'spbcScannerAnalysisLogDeleteFromLog(this);'),
            );
            $args['bulk_actions'] = array(
                'check_analysis_status' => array('name' => 'Refresh the analysis status',),
                'delete_from_analysis_log' => array('name' => 'Delete from log', 'handler' => 'spbcScannerAnalysisLogDeleteFromLog(this);'),
            );
            break;

        case 'unknown':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'columns'           => array(
                        'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                        'path'       => array('heading' => 'Path', 'primary' => true, 'width_percent' => 39),
                        'size'       => array('heading' => 'Size, bytes', 'width_percent' => 13),
                        'perms'      => array('heading' => 'Permissions', 'width_percent' => 13),
                        'mtime'      => array('heading' => 'Last Modified', 'width_percent' => 13),
                    ),
                    'if_empty_items'    => false,
                    'actions'           => array(
                        'delete' => array('name' => 'Delete',),
                        'approve' => array('name' => 'Approve',),
                        'view'    => array('name' => 'View',),
                    ),
                    'bulk_actions'      => array(
                        'delete'  => array('name' => 'Delete',),
                        'approve' => array('name' => 'Approve',),
                    ),
                    'sql'               => array(
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('unknown'),
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            $args['actions']['send'] = array('name' => 'Send for Analysis',);
            break;

        case 'approved':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'columns'           => array(
                        'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                        'path'       => array('heading' => 'Path', 'primary' => true, 'width_percent' => 40),
                        'weak_spots' => array('heading' => 'Detected', 'width_percent' => 20),
                        'size'       => array('heading' => 'Size, bytes', 'width_percent' => 7),
                        'perms'      => array('heading' => 'Permissions', 'width_percent' => 7),
                        'mtime'      => array('heading' => 'Last Modified', 'width_percent' => 7),
                        'status'     => array('heading' => 'Approved by', 'width_percent' => 15),
                    ),
                    'if_empty_items'    => false,
                    'actions'           => array(
                        'disapprove' => array('name' => 'Disapprove',),
                    ),
                    'bulk_actions'      => array(
                        'disapprove' => array('name' => 'Disapprove',),
                    ),
                    'sql'               => array(
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('approved'),
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            break;

        case 'approved_by_cloud':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'columns'           => array(
                        'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                        'path'       => array('heading' => 'Path', 'primary' => true, 'width_percent' => 40),
                        'size'       => array('heading' => 'Size, bytes', 'width_percent' => 7),
                        'perms'      => array('heading' => 'Permissions', 'width_percent' => 7),
                        'mtime'      => array('heading' => 'Last Modified', 'width_percent' => 7),
                        'status'     => array('heading' => 'Approved by', 'width_percent' => 15),
                    ),
                    'if_empty_items' => false,
                    'sql'            => array(
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('approved_by_cloud'),
                    ),
                    'order_by'       => array('path' => 'asc'),
                )
            );
            break;

        case 'quarantined':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files_quarantine',
                    'columns'           => array(
                        'cb'             => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
                        'path'           => array('heading' => 'Path', 'primary' => true,),
                        'previous_state' => array('heading' => 'Status',),
                        'severity'       => array('heading' => 'Severity',),
                        'q_time'         => array('heading' => 'Quarantine time',),
                        'size'           => array('heading' => 'Size',),
                    ),
                    'if_empty_items'    => false,
                    'actions'           => array(
                        'restore'  => array('name' => 'Restore',),
                        'delete'   => array('name' => 'Delete',),
                        'view'     => array(
                            'name'    => 'View',
                            'handler' => 'spbcScannerButtonFileViewEvent(this);',
                        ),
                        'download' => array(
                            'name'   => 'Download',
                            'type'   => 'link',
                            'local'  => true,
                            'uid'    => true,
                            'target' => '_blank',
                            'href'   => '?plugin_name=security&spbc_remote_call_token=' . md5($spbc->settings['spbc_key']) . '&spbc_remote_call_action=download__quarantine_file&file_id=',
                        ),
                    ),
                    'bulk_actions'      => array(
                        'restore' => array('name' => 'Restore',),
                        'delete'  => array('name' => 'Delete',),
                    ),
                    'sql'               => array(
                        'add_col' => array_merge($accordion_default_args['sql']['add_col'], array(
                            'previous_state',
                            'q_path',
                            'q_time',
                        )),
                        'where'   => spbc_get_sql_where_addiction_for_table_of_category('quarantined'),
                    ),
                    'sortable'          => array('path', 'previous_state', 'severity', 'q_time', 'size',),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            break;

        case 'outbound_links':
            $args = array(
                'id'                => 'spbc_tbl__scanner__outbound_links',
                'actions'           => array(
                    'edit_post'  => array(
                        'name'           => 'Edit',
                        'type'           => 'link',
                        'local'          => true,
                        'edit_post_link' => true,
                        'target'         => '_blank',
                    ),
                    'show_links' => array(
                        'name'    => 'Show links',
                        'handler' => 'spbcScannerSwitchTable(this, "links");'
                    ),
                ),
                'order_by'          => array('domain' => 'desc'),
                'func_data_total'   => 'spbc_scanner_links_count_found__domains',
                'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No links found.', 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'num'         => array(
                        'heading' => __('Number', 'security-malware-firewall'),
                        'class'   => ' tbl-width--50px'
                    ),
                    'domain'      => array('heading' => __('Domain', 'security-malware-firewall'), 'primary' => true,),
                    'link_count'  => array(
                        'heading' => __('Links of domain', 'security-malware-firewall'),
                        'hint'    => __('Number of found links to the domain on site.', 'security-malware-firewall'),
                    ),
                ),
                'sortable'          => array('domain', 'link_count'),
                'pagination'        => array(
                    'page'     => 1,
                    'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
                ),
            );
            break;

        case 'frontend_malware':
            $args = array(
                'id'                => 'spbc_tbl__scanner_frontend_malware',
                'actions'           => array(
                    'view'     => array('name' => 'View', 'handler' => 'spbcScannerButtonPageViewEvent(this);',),
                    'view_bad' => array(
                        'name'    => 'View Suspicious Code',
                        'handler' => 'spbcScannerButtonPageViewBadEvent(this);',
                    ),
                    'approve_page'  => array('name' => 'Approve Page'),
                ),
                'bulk_actions'      => array(
                    'approve_page' => array('name' => 'Approve',),
                ),
                'sql'               => array(
                    'table'     => SPBC_TBL_SCAN_FRONTEND,
                    'offset'    => 0,
                    'limit'     => 20,
                    'get_array' => false,
                    'where'     => spbc_get_sql_where_addiction_for_table_of_category('frontend_malware'),
                ),
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__frontend',
                'func_data_get' => 'spbc_field_scanner__get_data__frontend_malware',
                'if_empty_items'    => __('No malware found', 'security-malware-firewall'),
                'columns'           => array(
                    'cb'            => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                    'url'            => array('heading' => 'Page', 'primary' => true,   'width_percent' => 38),
                    'dbd_found'      => array('heading' => '<i setting="dbd_found" class="spbc_long_description__show spbc-icon-help-circled"></i>Drive by Download', 'width_percent' => 15),
                    'redirect_found' => array('heading' => '<i setting="redirect_found" class="spbc_long_description__show spbc-icon-help-circled"></i>Redirects', 'width_percent' => 15),
                    'csrf'           => array('heading' => '<i setting="csrf" class="spbc_long_description__show spbc-icon-help-circled"></i>CSRF', 'width_percent' => 15),
                    'signature'      => array('heading' => '<i setting="signature" class="spbc_long_description__show spbc-icon-help-circled"></i>Signatures', 'width_percent' => 15),
                ),
                'order_by'          => array('url' => 'asc'),
                'sortable'          => array('url', 'dbd_found', 'redirect_found', 'signature', 'csrf'),
                'pagination'        => array(
                    'page'     => 1,
                    'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
                ),
            );
            break;

        case 'frontend_scan_results_approved':
            $args = array(
                'id'                => 'spbc_tbl__scanner_frontend_malware',
                'actions'           => array(
                    'view'     => array('name' => 'View', 'handler' => 'spbcScannerButtonPageViewEvent(this);',),
                    'view_bad' => array(
                        'name'    => 'View Suspicious Code',
                        'handler' => 'spbcScannerButtonPageViewBadEvent(this);',
                    ),
                    'disapprove_page'  => array('name' => 'Disapprove page'),
                ),
                'bulk_actions'      => array(
                    'disapprove_page' => array('name' => 'Disapprove',),
                ),
                'sql'               => array(
                    'table'     => SPBC_TBL_SCAN_FRONTEND,
                    'offset'    => 0,
                    'limit'     => 20,
                    'get_array' => false,
                    'where'     => spbc_get_sql_where_addiction_for_table_of_category('frontend_scan_results_approved'),
                ),
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__frontend',
                'func_data_get' => 'spbc_field_scanner__get_data__frontend_approved',
                'if_empty_items'    => false,
                'columns'           => array(
                    'cb'            => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
                    'url'            => array('heading' => 'Page', 'primary' => true,),
                    'dbd_found'      => array('heading' => '<i setting="dbd_found" class="spbc_long_description__show spbc-icon-help-circled"></i>Drive by Download',),
                    'redirect_found' => array('heading' => '<i setting="redirect_found" class="spbc_long_description__show spbc-icon-help-circled"></i>Redirects',),
                    'csrf'           => array('heading' => '<i setting="csrf" class="spbc_long_description__show spbc-icon-help-circled"></i>CSRF',),
                    'signature'      => array('heading' => '<i setting="signature" class="spbc_long_description__show spbc-icon-help-circled"></i>Signatures',),
                ),
                'order_by'          => array('url' => 'asc'),
                'sortable'          => array('url', 'dbd_found', 'redirect_found', 'signature', 'csrf'),
                'pagination'        => array(
                    'page'     => 1,
                    'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
                ),
            );
            break;

        case 'files_listing':
            $args = array(
                'id'                => 'spbc_tbl__scanner__files_listing',
                'func_data_total'   => 'spbc_field_scanner__files_listing__get_total',
                'func_data_get'     => 'spbc_field_scanner__files_listing__get_data',
                'func_data_prepare' => 'spbc_field_scanner__files_listing__data_prepare',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No threads are found', 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'url'  => array('heading' => __('URL', 'security-malware-firewall'), 'primary' => true,),
                    'type' => array('heading' => __('Type', 'security-malware-firewall'),),
                ),
                'pagination'        => array(
                    'page'     => 1,
                    'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
                ),
                'order_by'          => array('path' => 'asc'),
            );
            break;

        case 'unsafe_permissions':
            $args = array(
                'id' => 'spbc_tbl__scanner_scan_unsafe_permissions',
                'actions' => array (),
                'func_data_total'   => 'spbc_scanner__unsafe_permissions_count',
                'func_data_get'     => 'spbc_scanner_unsafe_permissions_data',
                'if_empty_items' => __('All files and directories have the safe permission levels', 'security-malware-firewall'),
                'columns' => array(
                    'path'           => array('heading' => 'Path','primary' => true,),
                    'perms'     => array('heading' => 'Permission',),
                ),
                'order_by'  => array('path' => 'asc'),
                'pagination' => array(
                    'page'     => 1,
                    'per_page' => 20,
                ),
            );
            break;

        case 'file_monitoring':
            $args = array(
                'id' => 'spbc_tbl__scanner_scan_file_monitoring',
                'actions' => array (
                    'current_snapshot' => array(
                        'name' => 'Snapshots',
                        'handler' => 'spbcScannerFileMonitoringShowCurrentSnapshot(this);',
                    ),
//                    'view_bad' => array(
//                        'name'    => 'View Suspicious Code',
//                        'handler' => 'spbcScannerButtonPageViewBadEvent(this);',
//                    ),
//                    'approve'  => array('name' => 'Approve', 'handler' => 'spbc_scanner_button_page_approve(this);'),
                ),
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__file_monitoring_files',
                'func_data_total'   => 'spbc_scanner__file_monitoring_count',
                'func_data_get'     => 'spbc_scanner_file_monitoring_data',
                'if_empty_items' => __('No important files.', 'security-malware-firewall'),
                'columns' => array(
                    'path'           => array('heading' => 'Path', 'primary' => true,),
                ),
                'order_by'  => array('path' => 'asc'),
                'pagination' => array(
                    'page'     => 1,
                    'per_page' => 20,
                ),
            );
            break;

        case 'cure_log':
            $args = array(
                'id' => 'spbc_tbl__scanner_scan_cure_log',
                'actions' => array (
                    'view'     => array(
                        'name'    => 'View',
                        'handler' => 'spbcScannerButtonFileViewEvent(this);',
                    ),
                    'cure'     => array(
                        'name'    => 'Cure',
                        'handler' => 'spbcScannerButtonCureFileAjaxHandler(this);',
                    ),
                    'restore'     => array(
                        'name'    => 'Restore',
                        'handler' => 'spbcScannerButtonRestoreFromBackupAjaxHandler(this);',
                    ),
                ),
                'bulk_actions'      => array(
                    'cure' => array('name' => 'Cure',),
                ),
                'func_data_total'   => 'spbc_scanner__cure_log_get_count_total',
                'func_data_get'     => 'spbc_scanner__get_cure_log_data',
                'func_data_prepare'     => 'spbc_scanner__cure_log_data_prepare',
                'if_empty_items' => __('There are no automatically cured files.', 'security-malware-firewall'),
                'columns' => array(
                    'cb'             => array('heading' => '<input type=checkbox>', 'class' => 'check-column',  'width_percent' => 2),
                    'real_path'      => array('heading' => 'Path','primary' => true,),
                    'last_cure_date' => array('heading' => 'Cure date',),
                    'cured'          => array('heading' => 'Status',),
                    'cci_cured'      => array('heading' => 'Threats cured count',),
                    'fail_reason'    => array('heading' => 'Reason of fail',),
                ),
                'order_by'  => array('real_path' => 'asc'),
                'pagination' => array(
                    'page'     => 1,
                    'per_page' => 20,
                ),
            );

            $cure_log = new Scanner\CureLog\CureLog();
            if ( !$cure_log->hasFailedCureTries() ) {
                unset($args['columns']['fail_reason']);
            }
            break;
        case 'skipped':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'if_empty_items'    => false,
                    'bulk_actions'      => false,
                    'actions'           => array(),
                    'sql'               => array(
                        'where' => spbc_get_sql_where_addiction_for_table_of_category('skipped'),
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            $args['columns'] = array(
                'path'       => array('heading' => 'Path', 'primary' => true, 'width_percent' => 39),
                'size'       => array('heading' => 'Size, bytes', 'width_percent' => 10),
                'perms'      => array('heading' => 'Permissions', 'width_percent' => 10),
                'mtime'      => array('heading' => 'Last Modified', 'width_percent' => 13),
                'error_msg'  => array('heading' => 'Reason', 'width_percent' => 28),
            );
            $args['sql']['add_col'][] = 'error_msg';
            break;
        default:
            $args = $accordion_default_args;
    }

    $args['type'] = $table_type;

    return $args;
}

function spbc_field_backups__get_data($offset = 0, $limit = 20)
{
    global $wpdb;

    return $wpdb->get_results(
        'SELECT ' . SPBC_TBL_BACKUPS . '.backup_id, ' . SPBC_TBL_BACKUPS . '.datetime, ' . SPBC_TBL_BACKUPS . '.type, ' . SPBC_TBL_BACKUPED_FILES . '.real_path
		FROM ' . SPBC_TBL_BACKUPS . '
		RIGHT JOIN ' . SPBC_TBL_BACKUPED_FILES . ' ON ' . SPBC_TBL_BACKUPS . '.backup_id = ' . SPBC_TBL_BACKUPED_FILES . '.backup_id
		ORDER BY DATETIME DESC
		LIMIT ' . $offset . ',' . $limit . ';'
    );
}

function spbc_field_backups()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">';

    $feature_state = $spbc->feature_restrictions->getState($spbc, 'backups');
    if (false === $feature_state->is_active) {
        echo $feature_state->sanitizedReasonOutput();
        echo '</div>';
        return;
    }
    echo '<div id="spbct-tab-backups--react"></div>';

    echo '<div id="spbc_scan_accordion2">';

    $table = new ListTable(spbc_list_table__get_args_by_type('cure_backups'));
    $table->getData();

    // Pass output if empty and said to do so
    if ($table->items_total !== 0) {
        echo '<h3>'
             . '<a href="#">'
             . ucwords(str_replace('_', ' ', 'cure_backups'))
             . ' <span class="spbc_bad_type_count ' . 'cure_backups' . '_counter">'
             . $table->items_total
             . '</span>'
             . '</a>'
             . '</h3>';
        echo '<div id="spbc_scan_accordion_tab_' . 'cure_backups' . '">';

        echo '<p class="spbc_hint">'
             . __('All backups that were made during the automatic curing procedure', 'security-malware-firewall')
             . '</p>';

        $table->display();

        echo "</div>";
    }

    echo '</div>';

    echo '</div>';
}

function spbc_field_debug_drop()
{
    echo '<div class="spbc_wrapper_field">'
         . '<br>'
         . '<input form="debug_drop" type="submit" name="spbc_debug__drop" value="Drop debug data" />'
         . '<div class="spbc_settings_description">If you don\'t what is this just push the button =)</div>'
         . '</div>';
}

function spbc_field_debug__check_connection()
{
    echo '<div class="spbc_wrapper_field">'
         . '<br>'
         . '<input form="debug_check_connection" type="submit" name="spbc_debug__check_connection" value="Check connection to servers" />'
         . '</div>';
}

function spbc_field_debug__set_fw_update_cron()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">'
        . '<br>'
        . '<form id="debug__cron_set_set_fw_update">'
        . '<input type="hidden" name="plugin_name"             value="security" />'
        . '<input type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
        . '<input type="hidden" name="spbc_remote_call_token"  value="' . md5($spbc->api_key) . '" />'
        . '<input type="hidden" name="task"                    value="firewall_update" />'
        . '<input type="hidden" name="handler"                 value="spbc_security_firewall_update__init" />'
        . '<input type="hidden" name="period"                  value="86400" />'
        . '<input type="hidden" name="first_call"              value="' . (time() + 60) . '" />'
        . '<input type="submit" name="spbc_debug__fw_update_cron_10_seconds" value="Set FW update to 60 seconds from now" />'
        . '</form>'
        . '</div>';
}

function spbc_field_debug__set_scan_cron()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">'
        . '<br>'
        . '<form id="debug__cron_set_set_scan_cron">'
        . '<input type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
        . '<input type="hidden" name="plugin_name"             value="security" />'
        . '<input type="hidden" name="spbc_remote_call_token"  value="' . md5($spbc->api_key) . '" />'
        . '<input type="hidden" name="task"                    value="scanner__launch" />'
        . '<input type="hidden" name="handler"                 value="spbc_scanner__launch" />'
        . '<input type="hidden" name="period"                  value="86400" />'
        . '<input type="hidden" name="first_call"              value="' . (time() + 60) . '" />'
        . '<input type="submit" name="spbc_debug__scan_cron_60_seconds" value="Schedule scan 60 seconds from now" />'
        . '</form>'
        . '</div>';
}

function spbc_field_debug__set_check_vulnerabilities_cron()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">'
        . '<br>'
        . '<form id="debug__cron_set_set_check_vulnerabilities">'
        . '<input type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
        . '<input type="hidden" name="plugin_name"             value="security" />'
        . '<input type="hidden" name="spbc_remote_call_token"  value="' . md5($spbc->api_key) . '" />'
        . '<input type="hidden" name="task"                    value="check_vulnerabilities" />'
        . '<input type="hidden" name="handler"                 value="spbc_security_check_vulnerabilities" />'
        . '<input type="hidden" name="period"                  value="86400" />'
        . '<input type="hidden" name="first_call"              value="' . (time() + 60) . '" />'
        . '<input type="submit"'
        . 'name="spbc_debug__check_vulnerabilities_cron_60_seconds"'
        . 'value="Schedule check vulnerabilities in 60 seconds from now" />'
        . '</form>'
        . '</div>';
}

function spbc_field_debug()
{
    global $spbc;
    if ($spbc->debug) {
        $debug  = get_option(SPBC_DEBUG);
        $output = print_r($debug, true);
        $output = str_replace("\n", "<br>", $output);
        $output = preg_replace("/[^\S]{4}/", "&nbsp;&nbsp;&nbsp;&nbsp;", $output);
        echo "<div class='spbc_wrapper_field'>";
        echo $output
             . "<label for=''>" .

             "</label>" .
             "<div class='spbc_settings_description'>" .

             "</div>";
        echo "</div>";
    }
}

/**
 * Admin callback function - Sanitize settings
 *
 * @param array $settings raw settings array
 *
 * @return array sanitized settings
 */
function spbc_sanitize_settings($settings)
{
    global $spbc;

    // Set missing settings.
    foreach ($spbc->default_settings as $setting => $value) {
        if ( ! isset($settings[ $setting ])) {
            $settings[ $setting ] = null;
            settype($settings[ $setting ], gettype($value));
        }
    }
    unset($setting, $value);

    //Sanitizing traffic_control__autoblock_amount setting
    if (isset($settings['traffic_control__autoblock_amount'])) {
        $settings['traffic_control__autoblock_amount'] = floor(intval($settings['traffic_control__autoblock_amount']));
        $settings['traffic_control__autoblock_amount'] = ($settings['traffic_control__autoblock_amount'] == 0 ? 1000 : $settings['traffic_control__autoblock_amount']);
        $settings['traffic_control__autoblock_amount'] = ($settings['traffic_control__autoblock_amount'] < 20 ? 20 : $settings['traffic_control__autoblock_amount']);
    }

    // XSS: sanitize options
    foreach ($settings as &$setting) {
        if (is_scalar($setting)) {
            $setting = preg_replace('/[<"\'>]/', '', trim((string)$setting));
        }
    }

    // Sanitize URLs for redirect login page
    $settings['login_page_rename__name'] = preg_match('@^[a-zA-Z0-9-/]+$@', (string)$settings['login_page_rename__name']) &&
                                           ! in_array(
                                               $settings['login_page_rename__name'],
                                               \CleantalkSP\SpbctWP\RenameLoginPage::getForbiddenSlugs(),
                                               true
                                           )
        ? $settings['login_page_rename__name']
        : 'login';

    $settings['login_page_rename__redirect'] = preg_match('@^[a-zA-Z0-9-=/]+$@', $settings['login_page_rename__redirect'])
                                               || $settings['login_page_rename__redirect'] === ''
        ? $settings['login_page_rename__redirect']
        : '';
    // Send email notification to admin if about changing login URL
    if (
        empty($spbc->settings['login_page_rename__enabled']) &&
        $settings['login_page_rename__enabled'] &&
        ($settings['login_page_rename__send_email_notification'] && current_user_can('activate_plugins'))
    ) {
        $mail = wp_mail(
            spbc_get_admin_email(),
            $spbc->data["wl_brandname"] . esc_html__(': New login URL', 'security-malware-firewall'),
            sprintf(
                esc_html__('New login URL is: %s', 'security-malware-firewall'),
                \CleantalkSP\SpbctWP\RenameLoginPage::getURL($settings['login_page_rename__name'])
            )
            . "\n\n"
            . esc_html__('Please, make sure that you will not forget the URL!', 'security-malware-firewall')
        );

        // If email is not sent, disabling the feature
        if ( !$mail ) {
            $spbc->error_add(
                'login_page_rename',
                __('Can not send notification email to the admin address. New login URL was not sent. Changes aborted.', 'security-malware-firewall')
            );
            $settings['login_page_rename__enabled'] = '0';
        } else {
            $spbc->error_delete('login_page_rename');
        }
    }

    if (!$settings['login_page_rename__send_email_notification']) {
        $spbc->error_delete('login_page_rename', true);
    }

    // Send logs for 2 previous days
    if ($settings['misc__backend_logs_enable'] && ! $spbc->settings['misc__backend_logs_enable']) {
        //neither we show this in the UI, method spbc_PHP_logs__collect use time() value to collect logs correct
        $spbc->data['last_php_log_sent'] = time() - 86400 * 2;
        $spbc->save('data');
    }

    // Scanner custom start time logic
    if ( empty($spbc->errors['configuration']) && $spbc->settings['scanner__auto_start_manual_time']) {
    //if ( empty($spbc->errors['configuration']) ) {
        $scanner_launch_data = spbc_get_custom_scanner_launch_data(false, $settings);
        \CleantalkSP\SpbctWP\Cron::updateTask(
            'scanner__launch',
            'spbc_scanner__launch',
            $scanner_launch_data['period'],
            $scanner_launch_data['start_time']
        );
    }

    // Sanitizing website mirrors
    if ($settings['scanner__outbound_links_mirrors']) {
        if (preg_match('/^[\sa-zA-Z0-9,_\.\-\~]+$/', $settings['scanner__outbound_links_mirrors'])) {
            $tmp     = explode(',', $settings['scanner__outbound_links_mirrors']);
            $mirrors = array();
            foreach ($tmp as $key => $value) {
                $value = trim($value);
                if ( ! empty($value)) {
                    $mirrors[ $key ] = trim($value);
                }
            }
            unset($key, $value);
            $settings['scanner__outbound_links_mirrors'] = implode(', ', $mirrors);
        }
    }

    // Sanitizing scanner dirs exceptions
    if ( $settings['scanner__dir_exclusions'] ) {
        $dirs = CSV::parseNSV($settings['scanner__dir_exclusions']);
        $settings['scanner__dir_exclusions'] = array();
        foreach ($dirs as $dir) {
            $dir = preg_replace('#\\\\+|\/+#', '/', $dir);
            $dir = trim($dir, "/");
            $instance_dir_separator = $spbc->is_windows ? '\\' : '/';
            $dir = str_replace('/', $instance_dir_separator, $dir);
            $settings['scanner__dir_exclusions'][] = $dir;
        }
        $settings['scanner__dir_exclusions'] = implode("\n", $settings['scanner__dir_exclusions']);
    }

    // Sanitizing frontend scanner URL exclusions
    if ($settings['scanner__frontend_analysis__domains_exclusions']) {
        $urls                                                       = CSV::parseNSV($settings['scanner__frontend_analysis__domains_exclusions']);
        $settings['scanner__frontend_analysis__domains_exclusions'] = array();
        foreach ($urls as $url) {
            if (preg_match('/\S+?\.\S+/', $url)) {
                $settings['scanner__frontend_analysis__domains_exclusions'][] = $url;
            }
        }
        $settings['scanner__frontend_analysis__domains_exclusions'] = implode("\n", $settings['scanner__frontend_analysis__domains_exclusions']);

        // Reset the scanner frontend result if the setting was changed
        if (
            is_main_site() &&
            (
                $settings['scanner__frontend_analysis__domains_exclusions'] !== $spbc->settings['scanner__frontend_analysis__domains_exclusions'] ||
                $settings['scanner__frontend_analysis__csrf'] !== $spbc->settings['scanner__frontend_analysis__csrf']
            )
        ) {
            Scanner\Frontend::resetCheckResult();
        }
    }

    // Sanitizing API key
    $settings['spbc_key']      = trim($settings['spbc_key']);
    $settings['spbc_key']      = preg_match('/^[a-z\d]*$/', $settings['spbc_key']) ? $settings['spbc_key'] : $spbc->settings['spbc_key']; // Check key format a-z\d
    $settings['spbc_key']      = is_main_site() || $spbc->ms__work_mode != 2 ? $settings['spbc_key'] : $spbc->network_settings['spbc_key'];
    $spbc->data['key_changed'] = $settings['spbc_key'] !== $spbc->settings['spbc_key'];
    $spbc->data['key_is_ok']   = spbc_api_key__is_correct($settings['spbc_key']);

    if ($settings['spbc_key'] === '' && $spbc->data['key_changed']) {
        $spbc = spbc_drop_to_defaults_on_key_clearance($spbc);
        \CleantalkSP\SpbctWP\Cron::removeAllTasks();
    }

    $spbc->save('data');

    if ($spbc->is_network && $spbc->is_mainsite) {
        // @todo Should check unset settings because some hook is saving settings twice
        $spbc->network_settings['spbc_key'] = $settings['spbc_key'];

        if (isset($settings['ms__hoster_api_key'])) {
            $spbc->network_settings['ms__hoster_api_key'] = $settings['ms__hoster_api_key'];
            unset($settings['ms__hoster_api_key']);
        }

        if (isset($settings['ms__work_mode'])) {
            $spbc->network_settings['ms__work_mode'] = $settings['ms__work_mode'];
            unset($settings['ms__work_mode']);
        }

        $spbc->save('network_settings');

        $spbc->network_data = array(
            'key_is_ok'  => $spbc->data['key_is_ok'],
            'user_token' => isset($spbc->data['user_token']) ? $spbc->data['user_token'] : '',
            'service_id' => isset($spbc->data['service_id']) ? $spbc->data['service_id'] : '',
            'moderate'   => $spbc->data['moderate'],
        );
        $spbc->save('network_data');
    }

    if (isset($settings['2fa__enable'])) {
        if ($settings['2fa__enable'] == 1 || $settings['2fa__enable'] == -1) {
            $code2fa = get_site_option('spbc_confirmation_code');
            if (isset($code2fa['verified']) && $code2fa['verified'] === false) {
                $settings['2fa__enable'] = 0;
            }
        }

        if ($settings['2fa__enable'] == 0) {
            delete_site_option('spbc_confirmation_code');
        }
    }

    /**
     * Triggered before returning the settings
     */
    do_action('spbc_before_returning_settings', $settings);

    return $settings;
}

//Get auto key button
function spbc_get_key_auto($direct_call = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc;

    $website        = parse_url(get_option('home'), PHP_URL_HOST) . parse_url(get_option('home'), PHP_URL_PATH);
    $platform       = 'wordpress';
    $user_ip        = \CleantalkSP\SpbctWP\Helpers\IP::get();
    $timezone       = Post::get('ct_admin_timezone');
    $language       = \CleantalkSP\Variables\Server::get('HTTP_ACCEPT_LANGUAGE');
    /** @psalm-suppress RedundantCondition */
    $wpms           = SPBC_WPMS && defined('SUBDOMAIN_INSTALL') && ! SUBDOMAIN_INSTALL;
    $white_label    = false;
    $hoster_api_key = $spbc->ms__hoster_api_key;
    $admin_email    = spbc_get_admin_email();

    /**
     * Filters the email to get API key
     *
     * @param string email to get API key
     */
    $filtered_admin_email = apply_filters('spbc_get_api_key_email', $admin_email);

    $result = API::method__get_api_key(
        'security',
        $filtered_admin_email,
        $website,
        $platform,
        $timezone,
        $language,
        $user_ip,
        $wpms,
        $white_label,
        $hoster_api_key
    );

    if ( ! empty($result['error'])) {
        $spbc->data['key_is_ok'] = false;
        $spbc->error_add('get_key', $result);

        $out = array(
            'success' => true,
            'reload'  => false,
            'msg'     => $result['error']
        );
    } elseif ( ! isset($result['auth_key'])) {
        $out = array(
            'success' => true,
            'reload'  => false,
            'msg'     => sprintf(
                __('Please, get the Access Key from %s CleanTalk Control Panel %s and insert it in the Access Key field', 'cleantalk-spam-protect'),
                '<a href="https://cleantalk.org/my/?cp_mode=security" target="_blank">',
                '</a>'
            )
        );
    } else {
        $settings['spbc_key'] = trim($result['auth_key']);
        $settings['spbc_key'] = preg_match('/^[a-z\d]*$/', $settings['spbc_key']) ? $settings['spbc_key'] : $spbc->settings['spbc_key']; // Check key format a-z\d
        $settings['spbc_key'] = is_main_site() || $spbc->ms__work_mode != 2 ? $settings['spbc_key'] : $spbc->network_settings['spbc_key'];

        $spbc->settings['spbc_key'] = $settings['spbc_key'];
        $spbc->save('settings');

        $spbc->data['user_token']  = (! empty($result['user_token']) ? $result['user_token'] : '');
        $spbc->data['key_is_ok']   = spbc_api_key__is_correct($settings['spbc_key']);
        $spbc->data['key_changed'] = true;
        $spbc->save('data');

        $templates = \CleantalkSP\SpbctWP\CleantalkSettingsTemplates::get_options_template($result['auth_key']);

        if ( ! empty($templates)) {
            $templatesObj = new \CleantalkSP\SpbctWP\CleantalkSettingsTemplates($result['auth_key']);
            $out          = array(
                'success'      => true,
                'getTemplates' => $templatesObj->getHtmlContent(true),
            );
        } else {
            $out = array(
                'success' => true,
                'reload'  => true,
            );
        }
    }

    if ($direct_call) {
        return $result;
    }

    die(json_encode($out));
}

function spbc_settings__update_account_email($direct_call = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc;

    $account_email = Post::get('accountEmail');

    // not valid email
    if (!$account_email || !filter_var(Post::get('accountEmail'), FILTER_VALIDATE_EMAIL)) {
        die(
            json_encode(
                array(
                    'error' => 'Please, enter valid email.'
                )
            )
        );
    }

    // email not changed
    if (isset($spbc->data['account_email']) && $account_email === $spbc->data['account_email']) {
        die(
            json_encode(
                array(
                    'success' => 'ok'
                )
            )
        );
    }

    $spbc->data['account_email'] = $account_email;
    $spbc->save('data');

    // Link GET ACCESS KEY MANUALLY
    $manually_link = sprintf(
        'https://cleantalk.org/register?platform=wordpress&email=%s&website=%s',
        urlencode(spbc_get_admin_email()),
        urlencode(get_bloginfo('url'))
    );

    die(
        json_encode(
            array(
                'success' => 'ok',
                'manuallyLink' => $manually_link
            )
        )
    );
}

function spbc_show_more_security_logs_callback()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    // PREPROCESS INPUT
    $args                 = spbc_list_table__get_args_by_type('security_logs');
    $args['sql']['limit_force'] = Post::get('amount', 'int') ?: SPBC_LAST_ACTIONS_TO_VIEW;

    // OUTPUT
    $table = new ListTable($args);
    $table->getData();

    die(
        json_encode(
            array(
                'html' => $table->displayRows(null, 'return'),
                'size' => $table->items_count,
            )
        )
    );
}

function spbc_show_more_security_firewall_logs_callback()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    $args                 = spbc_list_table__get_args_by_type('traffic_control');
    $args['sql']['limit'] = Post::get('amount', 'int') ?: SPBC_LAST_ACTIONS_TO_VIEW;

    // OUTPUT
    $table = new ListTable($args);
    $table->getData();

    if (Post::get('full_refresh')) {
        $table->display();
        die();
    }

    die(
        json_encode(
            array(
                'html' => $table->displayRows(null, 'return'),
                'size' => $table->items_count,
            )
        )
    );
}

function spbc_tc__filter_ip()
{
    global $spbc;

    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    $ip = Post::get('ip');
    $status = Post::get('status');

    if ( IP::validate($ip) === false ) {
        wp_send_json_error('IP is not correct.');
    }

    if ( $status !== 'allow' && $status !== 'deny' ) {
        wp_send_json_error('Status is not correct.');
    }

    // Add to the personal lists to the Cloud
    $res_cloud = API::method__private_list_add($spbc->user_token, $ip, $spbc->data['service_id'], ['status' => $status]);
    if ( isset($res_cloud['records']) && is_array($res_cloud['records']) ) {
        foreach ( $res_cloud['records'] as $record ) {
            if ( $record['operation_status'] === 'FAILED' ) {
                wp_send_json_error('API: adding IP ' . $record['record'] . ' failed: ' . $record['operation_message']);
            }
        }
    } else {
        wp_send_json_error('API wrong answer.');
    }

    // Add to the local database
    $status_for_db = $status === 'allow' ? '1' : '0';
    $version = IP::validate($ip);
    if ( $version === 'v4' ) {
        $data[] = ip2long($ip) . ',' . ip2long('255.255.255.255') . ',' . $status_for_db;
    } elseif ( $version === 'v6' ) {
        $data[] = $ip . ',' . '128' . ',' . $status_for_db;
    } else {
        wp_send_json_error('Local database: adding IP ' . $ip . ' failed: ip does not look like a valid IP address');
    }

    try {
        $res_local = spbct_sfw_private_records_handler('add', json_encode($data, JSON_FORCE_OBJECT));
        wp_send_json_success($res_local);
    } catch (\Exception $e) {
        wp_send_json_error('Local database: adding IP ' . $ip . ' failed: ' . $e->getMessage());
    }
}

/**
 * @return void
 */
function spbc_settings__get_description()
{
    global $spbc;

    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if (!isset($_POST['setting_id'])) {
        return;
    }

    $setting_id = str_replace(' ', '_', $_POST['setting_id']);

    $tc_learn_more_link = ! $spbc->data["wl_mode_enabled"]
        ? '<p><a class="spbc_long_desc__link" href="https://blog.cleantalk.org/wordpress-ddos-protection-how-to-mitigate-ddos-attacks/" target="_blank">'
         . __('Learn more', 'security-malware-firewall')
         . '</a></p>'
        : '';

    $logins_collecting_learn_mode_links = ! $spbc->data["wl_mode_enabled"]
        ? '<p><a class="spbc_long_desc__link" href="https://blog.cleantalk.org/hiding-your-wordpress-username-from-bad-bots/" target="_blank">'
          . __('Learn more', 'security-malware-firewall')
          . '</a></p>'
        : '';

    $two_fa_learn_more_link = ! $spbc->data["wl_mode_enabled"]
        ? '<p><a class="spbc_long_desc__link" href="https://cleantalk.org/help/two-factor-auth" target="_blank">'
          . __('Use this guide', 'security-malware-firewall')
          . '</a>'
          . ' ' . __('to see more details.', 'security-malware-firewall')
          . '</p>'
        : '';

    $descriptions = array(
        'secfw__enabled'              => array(
            'title' => __('Security FireWall', 'security-malware-firewall'),
            'desc'  => __('Security FireWall is a part of the security service and blocks a malicious active before the site pages load.', 'security-malware-firewall')
        ),
        'waf__xss_check'              => array(
            'title' => __('XSS check', 'security-malware-firewall'),
            'desc'  => __('Cross-Site Scripting (XSS) — prevents malicious code to be executed/sent to any user. As a result malicious scripts can not get access to the cookie files, session tokens and any other confidential information browsers use and store. Such scripts can even overwrite content of HTML pages. ' . $spbc->data["wl_company_name"] . ' WAF monitors for patterns of these parameters and block them.', 'security-malware-firewall')
        ),
        'waf__sql_check'              => array(
            'title' => __('SQL-injection check', 'security-malware-firewall'),
            'desc'  => __('SQL Injection — one of the most popular ways to hack websites and programs that work with databases. It is based on injection of a custom SQL code into database queries. It could transmit data through GET, POST requests or cookie files in an SQL code. If a website is vulnerable and execute such injections then it would allow attackers to apply changes to the website\'s MySQL database.', 'security-malware-firewall')
        ),
        'upload_checker__file_check'             => array(
            'title' => __('Check uploaded files', 'security-malware-firewall'),
            'desc'  => __('The option checks each uploaded file to a website for malicious code. If it\'s possible for visitors to upload files to a website, for instance a work resume, then attackers could abuse it and upload an infected file to execute it later and get access to your website.', 'security-malware-firewall')
        ),
        'traffic_control__enabled'    => array(
            'title' => __('Traffic Control', 'security-malware-firewall'),
            'desc'  => __('It analyzes quantity of requests towards website from any IP address for a certain period of time. For example, for an ordinary visitor it\'s impossible to generate 2000 requests within 1 hour. Big amount of requests towards website from the same IP address indicates that there is a high chance of presence of a malicious program.', 'security-malware-firewall')
                . $tc_learn_more_link
        ),
        'scanner__outbound_links'     => array(
            'title' => __('Scan links', 'security-malware-firewall'),
            'desc'  => __('This option allows you to know the number of outgoing links on your website and website addresses they lead to. These websites addresses will be checked with the ' . $spbc->data["wl_company_name"] . ' Database and the results will show if they were used in spam messages. The option\'s purpose is to check your website and find hidden, forgotten and spam links. You should always remember if you have links to other websites which have a bad reputation, it could affect your visitors\' trust and your SEO.', 'security-malware-firewall')
        ),
        'scanner__heuristic_analysis' => array(
            'title' => __('Heuristic analysis', 'security-malware-firewall'),
            'desc'  => __('Often, authors of malicious code disguise their code which makes it difficult to identify it by their signatures. The malicious code itself can be placed anywhere on the site, for example the obfuscated PHP-code in the "logo.png" file, and the code itself is called by one inconspicuous line in "index.php". Therefore, the usage of plugins to search for malicious code is preferable. Heuristic analysis can indicate suspicious PHP constructions in a file that you should pay attention to.', 'security-malware-firewall')
        ),
        'scanner__schedule_send_heuristic_suspicious_files' => array(
            'title' => __('Auto-send suspicious files for analysis', 'security-malware-firewall'),
            'desc'  => __('Automatic schedule suspicious files to send for analysis. Make note, if the file contains a malware signature, the file will not be sent, because this case is definitely a malware.', 'security-malware-firewall')
        ),
        'scanner__signature_analysis' => array(
            'title' => __('Signature analysis', 'security-malware-firewall'),
            'desc'  => __('Code signatures — it\'s a code sequence a malicious program consists of. Signatures are being added to the database after analysis of the infected files. Search for such malicious code sequences is performed in scanning by signatures. If any part of code matches a virus code from the database, such files would be marked as critical.', 'security-malware-firewall')
        ),
        'scanner__auto_cure'          => array(
            'title' => __('Cure malware', 'security-malware-firewall'),
            'desc'  => __('It cures infected files automatically if the scanner knows cure methods for these specific cases. If the option is disabled then when the scanning process ends you will be presented with several actions you can do to the found files: Cure. Malicious code will be removed from the file. Replace. The file will be replaced with the original file. Delete. The file will be put in quarantine. Do nothing. Before any action is chosen, backups of the files will be created and if the cure is unsuccessful it\'s possible to restore each file.', 'security-malware-firewall')
        ),
        'misc__backend_logs_enable'   => array(
            'title' => __('Collect and send PHP logs', 'security-malware-firewall'),
            'desc'  => __('To control appearing errors you have to check log file of your hosting account regularly. It\'s inconvenient and just a few webmasters pay attention to it. Also, errors could appear for a short period of time and only when one specific function is running, they can\'t be spotted in other circumstances so it\'s hard to catch them. PHP errors tell you that some of your website functionality doesn\'t work correctly, furthermore hackers may use these errors to get access to your website. The ' . $spbc->data["wl_company_name"] . ' Scanner will check your website backend once per hour. Statistics of errors is available in your ' . $spbc->data["wl_company_name"] . ' Dashboard.', 'security-malware-firewall')
        ),
        'vulnerability_check__enable_cron'    => array(
            'title' => __('Test installed plugins for known vulnerabilities', 'security-malware-firewall'),
            'desc'  => __('All the data about vulnerability statuses will be saved. If a known vulnerability found plugin informs you in Dashboard about details and gives instructions. Also, if appropriated setting below is enabled, you will be informed about the status on the modules page', 'security-malware-firewall')
        ),
        'vulnerability_check__test_before_install'    => array(
            'title' => __('Test plugins for known vulnerabilities before install them', 'security-malware-firewall'),
            'desc'  => __('The plugin will request the vulnerability check over research.cleantalk.org for all the plugins listed on the installation page. If the appropriated data received, you will be earned about the result.', 'security-malware-firewall')
        ),
        'misc__prevent_logins_collecting'    => array(
            'title' => __('Prevent collecting of authors logins', 'security-malware-firewall'),
            'desc'  => __('The option helps to hide the name of the author of articles on the site pages. This helps protect against login parsing, spam, and brute force.', 'security-malware-firewall')
                . $logins_collecting_learn_mode_links
        ),
        'data__set_cookies'           => array(
            'title' => __('Set cookies', 'security-malware-firewall'),
            'desc'  => __('Part of the CleanTalk FireWall functions depend on cookie files, so disabling this option could lead to deceleration of the firewall work. It will affect user identification who are logged in right now. Traffic Control will not be able to determine authorized users and they could be blocked when the request limit is reached. We do not recommend to disable this option without serious reasons. However, you should disable this option is you\'re using Varnish.', 'security-malware-firewall')
        ),
        '2fa__enable'                 => array(
            'title' => __('Two factor authentication for administrators', 'security-malware-firewall'),
            'desc'  => __('Two-Factor Authentication for WordPress admin accounts will improve your website security and make it safer, if not impossible, for hackers to breach your WordPress account. Two-Factor Authentication works via e-mail. Authentication code will be sent to your admin email. When authorizing, a one-time code will be sent to your email. While entering the code, make sure that it does not contain spaces. With your first authorization, the ' . $spbc->data["wl_company_name"] . ' Security plugin remembers your browser and you won’t have to input your authorization code every time anymore. However, if you started to use a new device or a new browser then you are required to input your authorization code. The plugin will remember your browser for 30 days.', 'security-malware-firewall')
                . $two_fa_learn_more_link
        ),
        'data__additional_headers'    => array(
            'title' => __('Additional Headers', 'security-malware-firewall'),
            'desc'  => __('"X-Content-Type-Options" improves the security of your site (and your users) against some types of drive-by-downloads. <br> "X-XSS-Protection" header improves the security of your site against some types of XSS (cross-site scripting) attacks.', 'security-malware-firewall') .
                       '<br>' . esc_html__('"Strict-Transport-Security" response header (often abbreviated as HSTS) informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it using HTTP should automatically be converted to HTTPS.', 'security-malware-firewall') .
                       '<br>' . esc_html__('"Referrer-Policy" make the `Referer` http-header transferring more strictly.', 'security-malware-firewall')
        ),
        'wp__disable_xmlrpc'          => array(
            'title' => __('Disable XML-RPC', 'security-malware-firewall'),
            'desc'  => __('XML-RPC is an out-of-date technology that can compromise websites. It is still enabled by default in WordPress for the purpose of reverse compatibility for some parts of information systems like old apps on phones and tablets. Please, make sure that you don\'t use such obsolete systems. If you don\'t know anything about it it\'s a good practice to enable this option and disable the XML-RPC.<br><br>Enabled XML-RPC could give hackers a possibility to brute-force your website credentials and access your website.', 'security-malware-firewall')
        ),
        'ms__work_mode'               => array(
            'title' => __('WordPress Multisite Work Mode', 'security-malware-firewall'),
            'desc'  => __(
                '<h4>Mutual Account, Individual Access Keys</h4>'
                . '<span>Each blog uses a separate key from the network administrator account. Each blog has its own separate security log, settings, personal lists. Key will be provided automatically to each blog once it is created or during the plugin activation process. The key could be changed only by the network administrator.</span>'
                . '<h4>Mutual Account, Mutual Access Key</h4>'
                . '<span>All blogs use one mutual key. They also share security logs, settings and personal lists with each other. Network administrator holds the key.</span>'
                . '<h4>Individual accounts, individual Access keys</h4>'
                . '<span>Each blog uses its own account and its own key. Separate security logs, settings, personal lists. Blog administrator can change the key on his own.</span>',
                'security-malware-firewall'
            )
        ),
        'ms__hoster_api_key'          => array(
            'title' => __('Hoster access key', 'security-malware-firewall'),
            'desc'  => __('You could find it here:<br><a href ="https://cleantalk-screenshots.s3.amazonaws.com/help/hosting-antispam/hapi-ru.png"><img src="https://cleantalk-screenshots.s3.amazonaws.com/help/hosting-antispam/hapi-ru.png"></a><br>Press on the screenshot to zoom.', 'security-malware-firewall')
        ),
        'listing'                     => array(
            'title' => __('Directory can be listed from the Internet', 'security-malware-firewall'),
            'desc'  => __('The listing of a directory allows an attacker to see the files inside the folder and the very existence of the folder. So if he sees ".git" folder is open for the listing, he can assume that you are using GIT technology and could exploit the known security issues to hack the website.', 'security-malware-firewall')
        ),
        'accessible'                  => array(
            'title' => __('File is accessible from the Internet', 'security-malware-firewall'),
            'desc'  => __('Anyone who knows the location of the file could download its content. This could sound pretty harmless, but in fact if this file is an error log, the attacker could identify the modules and plugins you are using and get some additional info about his hack attempts.', 'security-malware-firewall')
        ),
        'action_shuffle_salts'        => array(
            'title' => 'Shuffle Salts',
            'desc'  => __('WordPress secret keys and salts are a random set of symbols that are being used in encrypting the 
                    usernames and passwords that are being stored in the browser cookies. If the site has been hacked, 
                    all data on the site can be considered compromised. One of the first important recommendations is 
                    to change all passwords and security keys. If hackers have the security keys, they can regain 
                    access to the site even if the passwords have been changed. It is very important to change each 
                    security key along with the passwords when the malicious code is removed.', 'security-malware-firewall')
        ),
        'dbd_found' => array(
            'title' => 'Drive by Download',
            'desc'  => __('Unintentional loading of data from an external source is possible', 'security-malware-firewall')
        ),
        'redirect_found' => array(
            'title' => 'Redirects',
            'desc'  => __('An unexpected redirect to another resource is possible', 'security-malware-firewall')
        ),
        'csrf' => array(
            'title' => 'CSRF',
            'desc'  => __('Code found that can be used for csrf attacks', 'security-malware-firewall')
        ),
        'signature' => array(
            'title' => 'Signatures',
            'desc'  => __('Search for malicious code using the Cleantalk signature database', 'security-malware-firewall')
        ),
        'signatures_XSS' => array(
            'title' => 'XSS attack',
            'desc'  => __('Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are 
                    injected into otherwise benign and trusted websites.', 'security-malware-firewall')
        ),
        'signatures_SQL_INJECTION' => array(
            'title' => 'SQL injection',
            'desc'  => __('SQL injection is a code injection technique that might destroy your database.', 'security-malware-firewall')
        ),
        'signatures_EXPLOIT' => array(
            'title' => 'Exploit',
            'desc'  => __('An exploit is a piece of software, a chunk of data, or a sequence of commands that takes 
                    advantage of a bug or vulnerability to cause unintended or unanticipated behavior to occur on 
                    computer software, hardware, or something electronic (usually computerized).', 'security-malware-firewall')
        ),
        'signatures_SUSPICIOUS' => array(
            'title' => 'Suspicious',
            'desc'  => __('The code looks suspicious. Make sure it is safe.', 'security-malware-firewall')
        ),
        'signatures_MALWARE' => array(
            'title' => 'Malware',
            'desc'  => __('Malware has been found during the signature analysis.', 'security-malware-firewall')
        ),
        'heuristic_assert' => array(
            'title' => 'assert()',
            'desc'  => __('Using the function in production is not recommended', 'security-malware-firewall')
        ),
        'heuristic_eval' => array(
            'title' => 'eval()',
            'desc'  => __('The eval() language construct is very dangerous because it allows execution of arbitrary PHP code. Its use thus is discouraged.', 'security-malware-firewall')
        ),
        'heuristic_create_function' => array(
            'title' => 'create_function()',
            'desc'  => __('This function internally performs an eval() and as such has the same security issues as eval().', 'security-malware-firewall')
        ),
        'heuristic_system' => array(
            'title' => 'system()',
            'desc'  => __('Execute an external program and display the output', 'security-malware-firewall')
        ),
        'heuristic_passthru' => array(
            'title' => 'passthru()',
            'desc'  => __('Execute an external program and display raw output', 'security-malware-firewall')
        ),
        'heuristic_proc_open' => array(
            'title' => 'proc_open()',
            'desc'  => __('Execute a command and open file pointers for input/output', 'security-malware-firewall')
        ),
        'heuristic_exec' => array(
            'title' => 'exec()',
            'desc'  => __('Execute an external program', 'security-malware-firewall')
        ),
        'heuristic_pcntl_exec' => array(
            'title' => 'pcntl_exec()',
            'desc'  => __('Executes specified program in current process space', 'security-malware-firewall')
        ),
        'heuristic_popen' => array(
            'title' => 'popen()',
            'desc'  => __('Opens process file pointer', 'security-malware-firewall')
        ),
        'heuristic_shell_exec' => array(
            'title' => 'shell_exec()',
            'desc'  => __('Execute command via shell and return the complete output as a string', 'security-malware-firewall')
        ),
        'heuristic_str_rot13' => array(
            'title' => 'str_rot13()',
            'desc'  => __('Perform the rot13 transform on a string', 'security-malware-firewall')
        ),
        'heuristic_syslog' => array(
            'title' => 'syslog()',
            'desc'  => __('Generate a system log message', 'security-malware-firewall')
        ),
        'heuristic_global_variables_in_a_sys_command' => array(
            'title' => 'Super global in system command',
            'desc'  => __('Found direct request to super global variables in the system commands functions.', 'security-malware-firewall')
        ),
        'heuristic_base64_decode' => array(
            'title' => 'base64_decode()',
            'desc'  => __('Suspicious base64_decode usage.', 'security-malware-firewall')
        ),
        'heuristic_the_function_contains_suspicious_arguments' => array(
            'title' => '',
            'desc'  => __('The function contains suspicious arguments', 'security-malware-firewall')
        ),
        'suspicious_str_rot13' => array(
            'title' => 'str_rot13()',
            'desc'  => __('Perform the rot13 transform on a string', 'security-malware-firewall')
        ),
        'login_page_rename__send_email_notification' => array(
            'title' => 'Send email with new login URL',
            'desc'  => __('If enabled, the plugin will necessarily send the notification to the admin email before login URL is changed.
            If email could not be sent, all the changes will be reverted.
            Disable this option if you have mail connection issues or SMTP service is not configured on this WordPress instance.
            Please note that only user that has permissions to activate plugins can disable this option.', 'security-malware-firewall'),
        ),
        'scanner__dir_exclusions' => array(
            'title' => __('Directory exclusions ruleset', 'security-malware-firewall'),
            'desc'  => __('This rules will exclude the directory and all subdirectories matching the specified path. Any type of directory separator is acceptable. Example: wp-content/themes/yourtheme/skipthisdir', 'security-malware-firewall'),
        ),
        'hash_denied_hash' => array(
            'title' => 'denied_hash',
            'desc'  => __('The file hash is in denied list. It means that the Security analysts have marked this file
             as critically dangerous early. We do recommend you to order the Security Audit service.', 'security-malware-firewall')
        ),
        'secfw__get_ip' => array(
            'title' => IP::getOptionLongDescriptionArray()['title'],
            'desc'  => IP::getOptionLongDescriptionArray()['desc'],
        ),
        'no_description' => array(
            'title' => esc_html($setting_id),
            'desc'  => __('No description provided yet for this item. We are sorry about this. Please, contact support@cleantalk.org for further help.', 'security-malware-firewall'),
        ),
    );

    $out = isset($descriptions[ $setting_id ]) ? $descriptions[ $setting_id ] : $descriptions['no_description'];

    wp_send_json($out);
}

/**
 * @return void
 */
function spbc_settings__get_recommendation()
{
    global $spbc;

    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if (!isset($_POST['setting_id'])) {
        return;
    }

    $setting_id = str_replace(' ', '_', $_POST['setting_id']);

    $recomendations = array(
        'listing' => array(
            'title' => __('Directory can be listed from the Internet', 'security-malware-firewall'),
            'desc'  => __('The listing of a directory allows an attacker to see the files inside the folder and the very existence of the folder. So if he sees ".git" folder is open for the listing, he can assume that you are using GIT technology and could exploit the known security issues to hack the website.', 'security-malware-firewall')
        ),
        'accessible' => array(
            'title' => __('File is accessible from the Internet', 'security-malware-firewall'),
            'desc'  => __('To solve this issue rename or move the debug.log')
                . '<br><br>'
                . '<a href="https://wordpress.org/support/article/debugging-in-wordpress/#wp_debug_log" target="_blank" class="spbc_manual_link">'
                . __('More info', 'security-malware-firewall')
                . '</a>'
        ),
        'unsafe_permissions' => array(
            'title' => __('You likely do need to modify file permissions', 'security-malware-firewall'),
            'desc'  => __('Do it via FTP or hosting control panel. Set 644 for files and 755 for folders. If you are not sure, contact your hosting provider.', 'security-malware-firewall')
                . '<br><br>'
                . '<a href="https://wordpress.org/documentation/article/changing-file-permissions/" target="_blank" class="spbc_manual_link">'
                . __('More info', 'security-malware-firewall')
                . '</a>'
        ),
    );

    if (!isset($recomendations[ $setting_id ])) {
        return;
    }

    wp_send_json($recomendations[ $setting_id ]);
}

function spbc_show_GDPR_text()
{
    return wpautop('The notice requirements remain and are expanded. They must include the retention time for personal data, and contact information for data controller and data protection officer has to be provided.
	Automated individual decision-making, including profiling (Article 22) is contestable, similarly to the Data Protection Directive (Article 15). Citizens have rights to question and fight significant decisions that affect them that have been made on a solely-algorithmic basis. Many media outlets have commented on the introduction of a "right to explanation" of algorithmic decisions, but legal scholars have since argued that the existence of such a right is highly unclear without judicial tests and is limited at best.
	To be able to demonstrate compliance with the GDPR, the data controller should implement measures, which meet the principles of data protection by design and data protection by default. Privacy by design and by default (Article 25) require data protection measures to be designed into the development of business processes for products and services. Such measures include pseudonymising personal data, by the controller, as soon as possible (Recital 78).
	It is the responsibility and the liability of the data controller to implement effective measures and be able to demonstrate the compliance of processing activities even if the processing is carried out by a data processor on behalf of the controller (Recital 74).
	Data Protection Impact Assessments (Article 35) have to be conducted when specific risks occur to the rights and freedoms of data subjects. Risk assessment and mitigation is required and prior approval of the national data protection authorities (DPAs) is required for high risks. Data protection officers (Articles 37–39) are required to ensure compliance within organisations.
	They have to be appointed:')
           . '<ul style="padding: 0px 25px; list-style: disc;">'
           . '<li>for all public authorities, except for courts acting in their judicial capacity</li>'
           . '<li>if the core activities of the controller or the processor are:</li>'
           . '<ul style="padding: 0px 25px; list-style: disc;">'
           . '<li>processing operations, which, by virtue of their nature, their scope and/or their purposes, require regular and systematic monitoring of data subjects on a large scale</li>'
           . '<li>processing on a large scale of special categories of data pursuant to Article 9 and personal data relating to criminal convictions and offences referred to in Article 10;</li>'
           . '</ul>'
           . '</li>'
           . '</ul>';
}

// Ajax handler of spbctGenerateConfirmationCode() from js
function spbctGenerateAndSendConfirmationCode()
{
    global $spbc;

    $user = wp_get_current_user();
    if (isset($user->ID) && $user->ID > 0) {
        $email = $user->user_email;
    } else {
        $email = spbc_get_admin_email();
    }

    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    $confirmation_code = get_site_option('spbc_confirmation_code', false);
    $save_code         = true;

    // Code is outdated. Generate a new code
    if ( ! isset($confirmation_code['generate_time']) || $confirmation_code['generate_time'] + 10 * 60 < time()) {
        $confirmation_code = array(
            'code'          => rand(10000000, 99999999),
            'generate_time' => time(),
            'verified'      => false,
        );

        $save_code = update_site_option('spbc_confirmation_code', $confirmation_code);
    }

    if (isset($confirmation_code['code'])) {
        if ($save_code === true) {
            $mail_result = wp_mail(
                $email,
                $spbc->data["wl_brandname"] . esc_html__(' confirmation code ', 'security-malware-firewall') . get_home_url(),
                sprintf(
                    $spbc->data["wl_brandname"] . esc_html__('. Two-Factor Authentication Code on %s - %s', 'security-malware-firewall'),
                    get_home_url(),
                    $confirmation_code['code']
                )
            );

            if ($mail_result) {
                wp_send_json_success();
            } else {
                wp_send_json_error(__('Confirmation code not send!', 'security-malware-firewall'));
            }
        } else {
            wp_send_json_error(__('Confirmation code not saved!', 'security-malware-firewall'));
        }
    } else {
        wp_send_json_error(__('Confirmation code generation error!', 'security-malware-firewall'));
    }
}

// Ajax handler of spbctCheckConfirmationCode() from js
function spbctCheckConfirmationCode()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    if ( ! isset($_POST['code'])) {
        wp_send_json_error('Confirmation code not provided!');
    }

    $code = filter_input(INPUT_POST, 'code', FILTER_SANITIZE_NUMBER_INT);

    $get_code = get_site_option('spbc_confirmation_code');

    if ($get_code && array_key_exists('code', $get_code) && array_key_exists('generate_time', $get_code)) {
        if ($get_code['code'] == $code && $get_code['generate_time'] + 10 * 60 > time()) { //Code is live for 10 minutes
            if (isset($get_code['verified']) && $get_code['verified'] === false) {
                $get_code['verified'] = true;
                update_site_option('spbc_confirmation_code', $get_code);
            }
            wp_send_json_success($get_code);
        } else {
            wp_send_json_error('Confirmation code is wrong or outdated!');
        }
    } else {
        wp_send_json_error('Could not check confirmation code!');
    }
}

/**
 * Ajax handler for checking renew banner
 */
function spbc_settings__check_renew_banner()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    global $spbc;
    wp_send_json(array(
        'close_renew_banner' => $spbc->data['notice_show'] == 0
            ? true
            : false
    ));
}

/**
 * Descriptions for scanner results actions.
 * @return string
 */
function spbc_bulk_actions_description()
{
    global $spbc;

    $actions = array(
        'delete'     => array(
            'title' => esc_html__('Delete', 'security-malware-firewall'),
            'tip'   => esc_html__('Delete the chosen file from your website file system in a safe way. You should be careful with this action as there is no turing back.', 'security-malware-firewall')
        ),
        'view'       => array(
            'title' => esc_html__('View', 'security-malware-firewall'),
            'tip'   => esc_html__('View the chosen file.', 'security-malware-firewall')
        ),
        'send'       => array(
            'title' => esc_html__('Send for Analysis', 'security-malware-firewall'),
            'tip'   => esc_html__('Send the chosen file to the ' . $spbc->data["wl_brandname"] . ' Cloud for analysis.', 'security-malware-firewall'),
        ),
        'approve'    => array(
            'title' => esc_html__('Approve', 'security-malware-firewall'),
            'tip'   => esc_html__('Approve the chosen file so it will not be scanned again. You can always disapprove it in the "Approved" category.', 'security-malware-firewall')
        ),
        'quarantine' => array(
            'title' => esc_html__('Quarantine', 'security-malware-firewall'),
            'tip'   => esc_html__('Put the chosen file to quarantine where it can not harm the website.', 'security-malware-firewall')
        ),
        'replace'    => array(
            'title' => esc_html__('Replace', 'security-malware-firewall'),
            'tip'   => esc_html__('Restore the initial state of the chosen file if the file is accessible. It applies only to the WordPress core files.', 'security-malware-firewall')
        ),
        'compare'    => array(
            'title' => esc_html__('Compare', 'security-malware-firewall'),
            'tip'   => esc_html__('View the difference between the original WordPress core file and the one you have in your website.', 'security-malware-firewall')
        ),
        'view_bad'   => array(
            'title' => esc_html__('View Malicious Code', 'security-malware-firewall'),
            'tip'   => esc_html__('View malicious code that was found by the scanner, so you can inspect it more clearly.', 'security-malware-firewall')
        ),
    );

    $description = '<div id="spbcscan-scanner-caption">';
    $description .= '<div class="column">';
    $description .= '<ul>';
    $description .= '<h4>' . esc_html__('Available actions on the found files:', 'security-malware-firewall') . '</h4>';

    $action_description = array();
    foreach ($actions as $action) {
        // @todo description with tooltips
        // $action_description[] =
        // ' <u>' . $action['title'] . '</u>'
        // . ' <i class="spbc_popup_tip--spbc-icon---show spbc-icon-help-circled" spbc_tip_title="' . ucfirst( $action['title'] ) . '" spbc_tip_text="' . $action['tip'] . '"></i>';
        $action_description[] =
            '<li><strong>' . ucfirst($action['title']) . ':</strong> ' . $action['tip'] . '</li>';
    }

    $description .= implode('', $action_description);
    $description .= '</u>';
    $description .= __('The actions are available only after scanning your website.', 'security-malware-firewall');

    $description .= '</div>';
    $description .= '<div class="column">';
    $description .= '<div id="spbcscan-results-log-caption">';
    $description .= '<h4>' . esc_html__('File Scan Results:', 'security-malware-firewall') . '</h4>';
    $description .= '<p><b>OK</b> - ' . esc_html__('file is fine.', 'security-malware-firewall') . '</p>';
    $description .= '<p><b>APPROVED</b> - ' . esc_html__('file is approved by the user.', 'security-malware-firewall') . '</p>';
    $description .= '<p><b>APPROVED_BY_CT</b> - ' . esc_html__('file is approved by ' . $spbc->data["wl_brandname"] . '.', 'security-malware-firewall') . '</p>';
    $description .= '<p><b>MODIFIED</b> - ' . esc_html__('file is different from the original one.', 'security-malware-firewall') . '</p>';
    $description .= '<p><b>INFECTED</b> - ' . esc_html__('file is infected.', 'security-malware-firewall') . '</p>';
    $description .= '<p><b>QUARANTINED</b> - ' . esc_html__('file has been quarantined.', 'security-malware-firewall') . '</p>';
    $description .= '<p><b>UNKNOWN</b> - ' . esc_html__('file of unknown origin.', 'security-malware-firewall') . '</p>';
    $description .= '</div>';
    $description .= '</div>';
    $description .= '</div>';

    $description .= '<br><br>';
    $description .= '*<br>';
    $description .= esc_html__('Website total files - only executable files (*.php, *.html, *.htm, *.phtml, *.shtml, *.phar, *.odf) except for the quarantined files, files of zero size and files larger than the acceptable size (2 MB).', 'security-malware-firewall');
    $description .= '<br>';
    $description .= esc_html__('Files scanned - files have been checked. Some files will be added to the scan if the scanner deems it necessary.', 'security-malware-firewall');

    return $description;
}

/**
 * We draw a module with the scan results for all files,
 * with pagination and filtering
 */
function spbc_scan_results_log_module()
{
    ScanningLogFacade::render();
}

/**
 * Implementation of service_update_local_settings functionality
 */
add_action('spbc_before_returning_settings', 'spbc__send_local_settings_to_api');

function spbc__send_local_settings_to_api($settings)
{
    $api_key  = $settings['spbc_key'] ?: '';
    $settings = json_encode($settings);
    $hostname = preg_replace('/^(https?:)?(\/\/)?(www\.)?/', '', get_site_url());

    API::methodSendLocalSettings($api_key, $hostname, $settings);
}

add_action('spbc_before_returning_settings', 'spbc_cdn_checker__run_check_on_settings_change');

function spbc_cdn_checker__run_check_on_settings_change($settings)
{
    if ( isset($settings['secfw__get_ip__enable_cdn_auto_self_check']) && $settings['secfw__get_ip__enable_cdn_auto_self_check'] != 0) {
        //CDNHeadersChecker::sendCDNCheckerRequest();
        SpbcCron::updateTask('cdn_check', 'spbc_cdn_checker__send_request', 86400, time() + 60);
    }
}


/**
 *
 */
function spbc_settings_field__action_shuffle_salts()
{
    global $spbc;

    $button_disabled = 'disabled';

    if ($spbc->settings['there_was_signature_treatment']) {
        $button_disabled = '';
    }

    ?>
    <div class="spbc_wrapper_field" id="action-shuffle-salts-wrapper">
        <span class="spbc_setting-field_title--field" style="margin: 10px 0 5px;">
            <?= __('Change unique and secret authentication keys and salts', 'security-malware-firewall'); ?>
            <i setting="action_shuffle_salts" class="spbc_long_description__show spbc-icon-help-circled"></i>
        </span>
        <div class="spbc_settings_description">
            <?= __('The function updates the secret keys and salts. All users will need to log in again.', 'security-malware-firewall'); ?>
        </div>
        <button type="button" id="action-shuffle-salts" class="button button-primary <?= $button_disabled; ?>"
                style="margin: 5px 0 0 10px;">
            <?= __('Shuffle salts', 'security-malware-firewall'); ?>
        </button>
    </div>
    <?php
}

function spbc_settings_field__secfw__get_ip__get_description()
{
    $ip = IP::get();

    return sprintf(
        'Your detected IP address is %s',
        '<a href="https://cleantalk.org/my-ip/' . $ip . '" target="_blank">' . $ip . '</a>'
    );
}

function spbc_settings_field__secfw__get_ip__get_labels()
{
    $options          = array();
    $options[]        = array('val' => 1, 'label' => __('Auto', 'security-malware-firewall'),);

    foreach (IP::$known_headers_collection as $key => $header ) {
        IP::get($header['slug'], [], true);
        $option_value = $header['name'];
        $option_value .= isset(IP::getInstance()->ips_stored[$header['slug']])
            ? ' (' . IP::getInstance()->ips_stored[$header['slug']] . ')'
            : ' (not provided)';
        $options[]    = array('val' => $key, 'label' => $option_value);
    }

    return $options;
}

/**
 * @return int|void
 */
function spbc_scanner__unsafe_permissions_count()
{
    global $spbc;
    $unsafe_permission = new Scanner\UnsafePermissionsModule\UnsafePermissionFunctions($spbc);

    return $unsafe_permission->getCountData();
}

/**
 * @return array
 */
function spbc_scanner_unsafe_permissions_data()
{
    global $spbc;
    $unsafe_permission = new Scanner\UnsafePermissionsModule\UnsafePermissionFunctions($spbc);

    return $unsafe_permission->getDataToAccordion();
}

/**
 * Wrapper for Cure log files counter.
 * @return int
 */
function spbc_scanner__cure_log_get_count_total()
{
    $cure_log = new Scanner\CureLog\CureLog();
    return $cure_log->getCountData();
}

/**
 * @return array|object
 */
function spbc_scanner__get_cure_log_data()
{
    $offset = 0;
    $amount = 20;
    if (isset($_POST['page'])) {
        $offset = ((int)$_POST['page'] - 1) * $amount;
    }
    $cure_log = new Scanner\CureLog\CureLog();
    return $cure_log->getDataToAccordion($offset, $amount);
}

/**
 * Prepare cure log table
 * @param $table
 * @return void
 */
function spbc_scanner__cure_log_data_prepare(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $_key => $row) {
            // Add Cure action if file was not cure
            if ($row->cured !== 'FAILED') {
                unset($row->actions['cure']);
            }

            $cure_status_string = $row->cured === 'CURED'
                ? '<span class="spbcGreen">' . $row->cured . '</span>'
                : '<span class="spbcRed">' . $row->cured . '</span>';

            $table->items[] = array(
                'cb'             => $row->fast_hash,
                'uid'            => $row->fast_hash,
                'actions'        => $row->actions,
                'real_path' => $row->real_path,
                'last_cure_date'       => $row->last_cure_date,
                'cured'   => $cure_status_string,
                'cci_cured'   => $row->cci_cured,
                'fail_reason'         => $row->fail_reason,
            );
        }
    }
}

function spbc_render_links_to_tag($value)
{
    $pattern = "/(https?:\/\/[^\s]+)/";
    $value = preg_replace($pattern, '<a target="_blank" href="$1">$1</a>', $value);
    return Escape::escKsesPreset($value, 'spbc_settings__display__notifications');
}

function spbc_scanner__last_scan_info($direct_call = false)
{
    global $spbc;

    if ( ! $direct_call ) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    if ( ! empty($spbc->data['scanner']['last_scan'])) {
        $output = sprintf(
            __('The last scan of this website was on %s, website total files*: %d, files scanned*: %d.', 'security-malware-firewall'),
            date('M d Y H:i:s', $spbc->data['scanner']['last_scan']),
            isset($spbc->data['scanner']['files_total']) ? $spbc->data['scanner']['files_total'] : $spbc->data['scanner']['last_scan_amount'],
            isset($spbc->data['scanner']['scanned_total']) ? $spbc->data['scanner']['scanned_total'] : null
        );
        if ($spbc->settings['scanner__outbound_links']) {
            $count_outbound_links = (string)spbc__get_count_outbound_links();
            $output .= sprintf(' ' . __('Outbound links found: %s.', 'security-malware-firewall'), $count_outbound_links);
        }
    } else {
        $output = __('Website hasn\'t been scanned yet.', 'security-malware-firewall');
    }

    if ( ! $direct_call ) {
        wp_send_json_success($output . spbc_get_next_scan_launch_time_text());
    }

    return $output . spbc_get_next_scan_launch_time_text();
}

/**
 * Get the string with next scan time description.
 * - "The next automatic scan is scheduled on %s."
 * @return string
 */
function spbc_get_next_scan_launch_time_text()
{
    global $spbc;

    $task = \CleantalkSP\SpbctWP\Cron::getTask('scanner__launch');
    if ($spbc->settings['scanner__auto_start']
        && isset($task['next_call'])
    ) {
        return sprintf(
            ' ' . __('The next automatic scan is scheduled on %s %s.', 'security-malware-firewall'),
            date('M d Y H:i:s', $task['next_call']),
            spbc_wp_timezone_string()
        );
    }
    return '';
}

/**
 * Generate HTML code for accordions to suggest user manual audit services.
 * @param $for string destination accordion name
 * @return string html
 */
function spbc__get_accordion_tab_info_block_html($for)
{
    global $spbc;

    $button_div = '';
    $show_exclaim_triangle = false;
    $email = spbc_get_admin_email();
    $website = get_home_url();

    switch ($for) {
        case 'critical':
            //critical files accordion
            $info_block_out = __('With a high degree of probability, your site has been infected. If you need professional help 
        from security specialists, feel free to order', 'security-malware-firewall');

            $classes = 'notice notice-warning';
            $show_exclaim_triangle = true;

            //generate button
            $landing_page_link = 'https://l.cleantalk.org/website-malware-removal?email=' . esc_attr($email) . '&website=' . esc_attr($website);
            $button_text = __('Request Malware removal', 'security-malware-firewall');
            $button_div = '<div style="text-align: center; padding: 10px">';
            $button_div .= '
                <a class="spbc_manual_link" target="_blank" href="' . $landing_page_link . '">'
                . '<i class="spbc-icon-link-ext"></i>&nbsp;&nbsp;'
                . $button_text
                . '</a>
                ';
            $button_div .= '</div>';
            break;
        case 'suspicious':
            $info_block_out = '<p>' . __('If you are not sure of the results and cannot assess for yourself whether these files are dangerous or not, then we recommend sending these files to the cloud for analysis. Select suspicious files and click "Send for Analysis".', 'security-malware-firewall') . '</p>';
            $info_block_out .= '<p>' . __('Please, note, the size of file to send is restricted with 1024 Kb.', 'security-malware-firewall') . '</p>';
            if ( (int) $spbc->settings['scanner__schedule_send_heuristic_suspicious_files'] === 2 ) {
                $info_block_out .= '<p>'
                    . sprintf(
                        'Suspicious files are sent to the CleanTalk cloud to be analyzed by Cloud Malware scanner. If you do not want to send it to the cloud, turn this option off in the plugin %s settings %s',
                        '<a href="options-general.php?page=spbc&spbc_tab=settings_general#spbc_setting_scanner__heuristic_analysis">',
                        '</a>'
                    )
                    . '</p>';
            }
            $classes = 'notice notice-info';
            break;
        case 'analysis':
            // todo this was the same output as suspicious - removed for now
            return '';
        case 'unknown':
            $template = '
            <div>
                %MAIN_TEXT%
                <ul style="list-style-type: circle; padding-left: 2%">
                    <li>%OPTION_1%</li>
                    <li>%OPTION_2%</li>
                </ul>
            </div>
            ';
            $landing_page_link = 'https://l.cleantalk.org/website-security-audit?email=' . esc_attr($email) . '&website=' . esc_attr($website);
            $main_text = __('If you are not sure about these files, you have two options,', 'security-malware-firewall');
            $option1 = __('Send it to the cloud where files will be passed through additional tests (Send for Analysis).', 'security-malware-firewall');
            $option2 = sprintf(
                __('Request the %sSecurity Audit%s of your website by our Research team. A researcher checks the site among most common security threats, as well as all Unknown files and gives you detailed report. As a promotion, you have annual Security license for one website for free.', 'security-malware-firewall'),
                "<a href='{$landing_page_link}' target='_blank'>",
                "</a>"
            );
            $template = str_replace('%MAIN_TEXT%', $main_text, $template);
            $template = str_replace('%OPTION_1%', $option1, $template);
            $template = str_replace('%OPTION_2%', $option2, $template);
            $info_block_out = $template;
            $classes = 'notice notice-info';
            break;
        case 'skipped':
            $template = '
                <div>
                    <p>%HEADER_P%:</p>
                    <ul style="list-style-type: circle; padding-left: 2%">
                        <li>%NOT_EMPTY%</li>
                        <li>%SIGN_RESTRICT%</li>
                        <li>%HEUR_RESTRICT%</li>
                    </ul>
                    <p>%SUGGEST_FM%</p>
                    <p>%SUGGEST_CONTACT% <a href="%LINK%">%LINK%</a></p>
                </div>
            ';
            $header_p = __('Please, note the restrictions', 'security-malware-firewall');
            $empty_info = __('Scanner does not check and report about empty files (file size is 0).', 'security-malware-firewall');
            $signatures_restrict = __('Signatures module does not check files with size larger then %d Kb.', 'security-malware-firewall');
            $value = \CleantalkSP\Common\Scanner\SignaturesAnalyser\Controller::SIGNATURES_SCAN_MAX_FILE_SIZE / 1024;
            $signatures_restrict = sprintf($signatures_restrict, $value);
            $heuristic_restrict = __('Heuristic module does not check files with size larger then %d Kb. ', 'security-malware-firewall');
            $value = \CleantalkSP\Common\Scanner\HeuristicAnalyser\HeuristicAnalyser::HEURISTIC_SCAN_MAX_FILE_SIZE / 1024;
            $heuristic_restrict = sprintf($heuristic_restrict, $value);

            $suggest_file_manger = __('You can use a file manager to manage files in the list.', 'security-malware-firewall');
            $suggest_contact = __('If you are sure that a file should be checked please let us know', 'security-malware-firewall');
            $link = 'https://wordpress.org/support/plugin/security-malware-firewall/';
            $template = str_replace('%HEADER_P%', $header_p, $template);
            $template = str_replace('%SIGN_RESTRICT%', $signatures_restrict, $template);
            $template = str_replace('%HEUR_RESTRICT%', $heuristic_restrict, $template);
            $template = str_replace('%NOT_EMPTY%', $empty_info, $template);
            $template = str_replace('%SUGGEST_FM%', $suggest_file_manger, $template);
            $template = str_replace('%SUGGEST_CONTACT%', $suggest_contact, $template);
            $template = str_replace('%LINK%', $link, $template);
            $info_block_out = $template;
            $classes = 'notice notice-info';
            break;
        case 'outbound_links':
            $info_block_out = '<p>'
                . __('Viruses post links to lead site visitors to compromised and fishing sites. It is a good idea to check links that you have not seen before. To manage the option go to the', 'security-malware-firewall')
                . ' '
                . '<a href="options-general.php?page=spbc&spbc_tab=settings_general#scanner_setting">'
                . __('scanner settings', 'security-malware-firewall')
                . '</a></p>';
            $classes = 'notice notice-info';
            break;
        default:
            return '';
    }

    $out = '<div id="spbc_notice_cloud_analysis_feedback" class="' . $classes . '" style="margin-left: 0px; margin-right: 0px;">';
    $out .= '<p>';
    // show triangle
    $out .= $show_exclaim_triangle
        ? '<img src="' . SPBC_PATH . '/images/att_triangle.png" alt="attention" style="margin-bottom:-1px">&nbsp'
        : '';
    // complete the suggestion text
    $out .= $info_block_out;
    $out .= '</p>';
    // add button if needs
    $out .= $button_div;

    $out .= '</div>';

    return $out;
}

/**
 * Returns notice HTML about automatic sending is enabled.
 * @param int $scheduled_count count of files scheduled to send
 * @return string HTML
 */
function spbct_get_automatic_files_send_notice_html($scheduled_count)
{
    $html = '<div class="notice notice-info">';
    $html .= '<p>';
    $html .= '<img src="' . SPBC_PATH . '/images/att_triangle.png" alt="attention" style="margin-bottom:-1px"> ';
    $html .= "The automatic sending files for Cloud analysis is enabled in the plugin settings. Files count: $scheduled_count";
    $html .= '</p>';
    $html .= '</div>';
    return $html;
}

/**
 * Returns list of files scheduled to send for analysis due scan process.
 * Uses state->data if available, wpdb query if not.
 * @return array Array of fast_hash
 */
function spbc_get_list_of_scheduled_suspicious_files_to_send()
{
    global $wpdb, $spbc;

    if ( !isset($spbc->data['scheduled_suspicious_files_to_send']) ) {
        $query = 'SELECT fast_hash FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE pscan_pending_queue = 1';
        $result = array_keys($wpdb->get_results($query, OBJECT_K));
        $spbc->data['scheduled_suspicious_files_to_send'] = $result;
    }

    return (array)$spbc->data['scheduled_suspicious_files_to_send'];
}

/**
 * @return int|void
 */
function spbc_scanner__file_monitoring_count()
{
    return Scanner\FileMonitoringModule\FileMonitoringRepository::getCountFilesInDb();
}

/**
 * @return array
 */
function spbc_scanner_file_monitoring_data()
{
    return Scanner\FileMonitoringModule\FileMonitoringTabData::getDataToAccordion();
}

function spbc_field_scanner__prepare_data__file_monitoring_files(&$table)
{
    $table = Scanner\FileMonitoringModule\FileMonitoringTabData::prepareDataToAccordion($table);
}

function spbc__get_count_outbound_links()
{
    global $wpdb;

    return $wpdb->get_var(
        "SELECT COUNT(*) FROM " . SPBC_TBL_SCAN_LINKS . ";"
    );
}

/**
 * Drop current data to defaults from state->default_data.
 * On exceptions roll back to old current state.
 * Attention! This function does not save the state to options,
 * only the current state object will be handled.
 * @param \CleantalkSP\SpbctWP\State $spbc current state
 * @return \CleantalkSP\SpbctWP\State state dropped
 */
function spbc_drop_to_defaults_on_key_clearance(\CleantalkSP\SpbctWP\State $spbc)
{
    $old_data = $spbc->data;
    try {
        $keep_data_keys = array(
            'scanner',
            'display_scanner_warnings',
            'errors'
        );
        $spbc->error_delete_all(true);
        foreach ( $spbc->default_data as $key => $value) {
            if (!in_array($key, $keep_data_keys)) {
                $spbc->data[$key] = $value;
            }
        }
    } catch (Exception $e) {
        $spbc->data = $old_data;
    }

    return $spbc;
}
