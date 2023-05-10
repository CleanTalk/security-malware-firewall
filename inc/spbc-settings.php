<?php

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
    }

    // Register setting
    register_setting(SPBC_SETTINGS, SPBC_SETTINGS, array(
        'sanitize_callback' => 'spbc_sanitize_settings'
    ));

    spbc_settings__register();
}

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
            // STATUS. Security status.
            'status'           => array(
                'type'     => 'plain',
                'callback' => 'spbc_field_security_status',
            ),
            // BUTTONS
            // Dashboard
            'cp_button'        => array(
                'type'    => 'plain',
                'display' => $spbc->key_is_ok && !$spbc->data["wl_mode_enabled"],
                'html'    => '<div id="goToCleanTalk" class="spbc-div-2" style="display: inline-block; position: relative; top: -2px; margin-right: 7px;">'
                             . '<a id="goToCleanTalkLink" class="spbc_manual_link" target="_blank" href="https://cleantalk.org/my?user_token=' . $spbc->user_token . '&cp_mode=security">'
                             . '<i class="spbc-icon-link-ext"></i>&nbsp;&nbsp;'
                             . __('Security Dashboard', 'security-malware-firewall')
                             . '</a>'
                             . '</div>',
            ),
            // Support
            'support_button'   => array(
                'type'    => 'plain',
                'html'    => '<a target="_blank" href="' . $spbc->data["wl_support_url"] . '" style="display: inline-block; position: relative; top: -2px;">'
                             . '<button type="button" class="spbc_auto_link">'
                             . '<i class="spbc-icon-link-ext"></i>&nbsp;&nbsp;'
                             . __('Support', 'security-malware-firewall')
                             . '</button>'
                             . '</a>',
                'display' => $spbc->key_is_ok && !$spbc->data["wl_mode_enabled"],
            ),
            // Synchronize button
            'sync_button'      => array(
                'type'    => 'plain',
                'display' => spbc_api_key__is_correct(),
                'html'    => '&nbsp;&nbsp;<button type="button" class="spbc_auto_link" id="spbc_button__sync" style="display: inline-block; position: relative; top: -2px; margin-right: 7px;">'
                             . '<i class="spbc-icon-upload-cloud"></i>&nbsp;&nbsp;'
                             . __('Synchronize with Cloud', 'security-malware-firewall')
                             . '<img style="margin-left: 10px; margin-top: 1px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                             . '<img style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
                             . '</button>',
            ),

            // TABS
            // Scanner
            'scanner'          => array(
                'type'         => 'tab',
                'display'      => $spbc->scaner_enabled,
                'title'        => __('Malware Scanner', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-search',
                'class_prefix' => 'spbc',
                'active'       => true,
                'ajax'         => true,
                'js_before'    => 'scanner-plugin.min.js',
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
            // Firewall
            'traffic_control'  => array(
                'type'         => 'tab',
                'display'      => $spbc->fw_enabled,
                'title'        => __('Firewall', 'security-malware-firewall'),
                'icon'         => 'spbc-icon-exchange',
                'class_prefix' => 'spbc',
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
                                'children'    => array('login_page_rename__name', 'login_page_rename__redirect',),
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
                        'display'     => $spbc->fw_enabled,
                        'description' => __('Any IP addresses of the logged in administrators will be automatically added to your Personal Lists and will be approved all the time.', 'security-malware-firewall'),
                        'fields'      => array(
                            'fw__custom_message'                => array(
                                'type'       => 'field',
                                'input_type' => 'hidden',
                            ),
                            'waf__enabled'                      => array(
                                'type'        => 'field',
                                'title'       => __('Web Application Firewall', 'security-malware-firewall'),
                                'description' => __('Catches dangerous stuff like: XSS, MySQL-injections and uploaded malicious files.', 'security-malware-firewall'),
                                'children'    => array(
                                    'waf__xss_check',
                                    'waf__sql_check',
                                    'waf__file_check',
                                    'waf__exploit_check'
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
                            'waf__file_check'                   => array(
                                'type'             => 'field',
                                'title'            => __('Check uploaded files', 'security-malware-firewall'),
                                'description'      => __('Check uploaded files for malicious code.', 'security-malware-firewall'),
                                'long_description' => true,
                                'parent'           => 'waf__enabled',
                                'children'         => array('waf__file_check__uploaded_plugins')
                            ),
                            'waf__file_check__uploaded_plugins' => array(
                                'type'        => 'field',
                                'title'       => __('Check plugins and themes while uploading', 'security-malware-firewall'),
                                'description' => __('Check the plugins and themes uploaded via WordPress built in interface with heuristic and signature analysis.', 'security-malware-firewall'),
                                'parent'      => 'waf__file_check',
                                'class'       => 'spbc_sub2_setting',
                            ),
                            'waf__exploit_check'                => array(
                                'type'        => 'field',
                                'title'       => __('Check for exploits', 'security-malware-firewall'),
                                'description' => __('Check traffic for known exploits.', 'security-malware-firewall'),
                                'parent'      => 'waf__enabled',
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
                            'scanner__outbound_links'                        => array(
                                'type'             => 'field',
                                'title'            => __('Scan links', 'security-malware-firewall'),
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
                                'description' => __('Input relative directories (WordPress folder is ROOT). Separate each directory by a new line and omit the character "\" at the beginning. All subdirectories will be excluded too.', 'security-malware-firewall'),
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
                                //                                'children'   => array( 'data__set_cookies__alt_sessions_type' )
                            ),
                            //                            'data__set_cookies__alt_sessions_type' => array(
                            //                                'type'        => 'field',
                            //                                'title'       => __( 'Alternative cookies handler type', 'security-malware-firewall' ),
                            //                                'description' => __( 'This could be helpful if you are using alternative mechanism for cookies and have REST API disabled. REST works faster.', 'security-malware-firewall' ),
                            //                                'input_type'  => 'radio',
                            //                                'options'     => array(
                            //                                    array( 'val' => 1, 'label' => __( 'REST API', 'security-malware-firewall' ), ),
                            //                                    array( 'val' => 2, 'label' => __( 'AJAX handler', 'security-malware-firewall' ), ),
                            //                                ),
                            //                                'parent' => 'data__set_cookies',
                            //                                'disabled' => $spbc->settings['data__set_cookies'] != 2,
                            //                            ),
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

                $elem['value'] = isset($spbc->{$elem['value_source']}[ $elem_name ])
                    ? $spbc->{$elem['value_source']}[ $elem_name ]
                    : 0;

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
 * @global type $spbc
 */
function spbc_settings__draw_elements($elems_to_draw = null, $direct_call = false)
{
    global $spbc;

    if ( ! $direct_call && Post::get('security')) {
        spbc_settings__register();
        check_ajax_referer('spbc_secret_nonce', 'security');
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
            case 'tab_headings':
                echo '<div class="spbc_tabs_nav_wrapper">'
                     . $elem['html']
                     . '</div>';
                break;
            case 'tab':
                echo '<div class="spbc_tab spbc_tab-' . $elem_name . ' ' . (! empty($elem['active']) ? 'spbc_tab--active' : '') . '">';

                if ( ! $elem['ajax'] || ! $direct_call) {
                    // JS before
                    if (isset($elem['js_before'])) {
                        foreach (explode(' ', $elem['js_before']) as $script) {
                            echo '<script src="' . SPBC_PATH . '/js/spbc-' . $script . '?ver=' . SPBC_VERSION . '"></script>'; // JS before tab
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
                            call_user_func($elem['after']);
                        } else {
                            echo $elem['after'];
                        }
                    }

                    // JS after
                    if (isset($elem['js_after'])) {
                        foreach (explode(' ', $elem['js_after']) as $script) {
                            echo '<script src="' . SPBC_PATH . '/js/spbc-' . $script . '?ver=' . SPBC_VERSION . '"></script>'; // JS after tab
                        }
                    }
                } else {
                    echo $elem['preloader'];
                }
                echo '</div>';
                break;
            case 'section':
                $anchor = isset($elem['anchor']) ? 'id="' . $elem['anchor'] . '"' : '';
                echo '<div class="spbc_tab_fields_group">'
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
 *
 * @psalm-suppress ComplexFunction
 */
function spbc_settings__field__draw($field)
{
    global $spbc;

    if ( $field['name'] === 'spbc_trusted_and_affiliate__add_id' ) {
        $href = '<a href="https://cleantalk.org/my/partners" target="_blank">' . __($spbc->data["wl_company_name"] . ' Affiliate Program are here', 'security-malware-firewall') . '</a>';
        $field['description'] = str_replace('{CT_AFFILIATE_TERMS}', $href, $field['description']);
    }

    echo '<div class="' . $field['def_class'] . (! empty($field['class']) ? ' ' . $field['class'] : '') . (isset($field['parent']) ? ' spbc_sub_setting' : '') . '">';

    switch ($field['input_type']) {
        // Checkbox type
        case 'checkbox':
            echo '<input type="checkbox" id="spbc_setting_' . $field['name'] . '" name="spbc_settings[' . $field['name'] . ']" value="1" '
                 //.(!$spbc->data['moderate'] ? ' disabled="disabled"' : '')
                 . ($field['disabled'] ? ' disabled="disabled"' : '')
                 . ($field['required'] ? ' required="required"' : '')
                 . ($field['value'] == '1' ? ' checked' : '')
                 . ($field['parent'] && ! $spbc->settings[ $field['parent'] ] ? ' disabled="disabled"' : '')
                 . (! $field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"')
                 . (! $field['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",", $field['children']) . '\')"')
                 . (! $field['children_by_ids'] ? '' : ' onchange="spbcSettingsDependenciesbyId([\'' . implode("','", $field['children_by_ids']) . '\'])"')
                 . ' />';
            echo isset($field['title'])
                ? '<label for="spbc_setting_' . $field['name'] . '" class="spbc_setting-field_title--' . $field['type'] . '">' . $field['title'] . '</label>'
                : '';
            echo isset($field['long_description'])
                ? '<i setting="' . $field['name'] . '" class="spbc_long_description__show spbc-icon-help-circled"></i>'
                : '';
            echo isset($field['description'])
                ? '<div class="spbc_settings_description">' . $field['description'] . '</div>'
                : '';
            break;

        // Radio type
        case 'radio':
            echo isset($field['title'])
                ? '<span class="spbc_settings-field_title spbc_settings-field_title--' . $field['type'] . '">' . $field['title'] . '</span>'
                : '';
            echo isset($field['long_description'])
                ? '<i setting="' . $field['name'] . '" class="spbc_long_description__show spbc-icon-help-circled"></i>'
                : '';
            if (isset($field['description']) && function_exists($field['description'])) {
                call_user_func($field['description']);
            } else {
                echo isset($field['description']) && ! function_exists($field['description'])
                    ? '<div style="margin-bottom: 10px" class="spbc_settings_description">' . $field['description'] . '</div>'
                    : '';
            }
            foreach ($field['options'] as $option) {
                echo '<input'
                     . ' type="radio"'
                     . ' class="spbc_setting_' . $field['type'] . '"'
                     . ' id="spbc_setting__' . (strtolower(str_replace(' ', '_', $option['label']))) . '"'
                     . ' name="spbc_settings[' . $field['name'] . ']"'
                     . ' value="' . $option['val'] . '"'
                     . ($field['parent'] ? ' disabled="disabled"' : '')
                     . (! $field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"')
                     . (! $field['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",", $field['children']) . '\')"')
                     . (! $field['children_by_ids'] ? '' : ' onchange="spbcSettingsDependenciesbyId([\'' . implode("','", $field['children_by_ids']) . '\'])"')
                     . ($field['value'] == $option['val'] ? ' checked' : '') . ' />'
                     . '<label for="spbc_setting__' . $option['label'] . '"> ' . $option['label'] . '</label>';
                echo '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;';
            }
            break;

        // Dropdown list type
        case 'select':
            echo isset($field['title'])
                ? '<label for="spbc_setting_' . $field['name'] . '" class="spbc_settings-field_title spbc_settings-field_title--' . $field['type'] . '">' . $field['title'] . '</label>&nbsp;'
                : '';
            echo '<select'
                 . ' class="spbc_setting_' . $field['type'] . '"'
                 . ' id="spbc_setting_' . $field['name'] . '"'
                 . ' name="spbc_settings[' . $field['name'] . ']"'
                 . ($field['disabled'] || ($field['parent'] && ! $field['parent_value']) ? ' disabled="disabled"' : '')
                 . (! $field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"')
                 // .' onchange="console.log( jQuery(this).find(\'option:selected\') ); console.log( jQuery(this).find(\'option:selected\').attr(\'children_enable\') );"'
                 . ($field['children']
                    ? ' onchange="spbcSettingsDependencies(\'' . implode(",", $field['children']) . '\', jQuery(this).find(\'option:selected\').attr(\'children_enable\'))"'
                    : ''
                 )

                 . '>';

            foreach ($field['options'] as $option) {
                echo '<option'
                     . ' value="' . $option['val'] . '"'
                     . ($field['value'] == $option['val'] ? 'selected' : '')
                     . (isset($option['children_enable']) ? ' children_enable=' . $option['children_enable'] : '')
                     . '>'
                     . $option['label']
                     . '</option>';
            }
            echo '</select>';
            echo isset($field['long_description'])
                ? '<i setting="' . $field['name'] . '" class="spbc_long_description__show spbc-icon-help-circled"></i>'
                : '';
            echo isset($field['description'])
                ? '<div style="margin-bottom: 10px" class="spbc_settings_description">' . $field['description'] . '</div>'
                : '';

            break;

        // Text type
        case 'text':
            if ($field['title_first']) {
                echo '<label for="spbc_setting_' . $field['name'] . '" class="spbc_settings-field_title spbc_settings-field_title--' . $field['type'] . '">' . $field['title'] . '</label>&nbsp;';
            }

            $affiliate_short_code = $field['name'] === 'spbc_trusted_and_affiliate__shortcode_tag'
                ? '[cleantalk_security_affiliate_link]'
                : '';
            $readonly = !empty($affiliate_short_code) ? 'readonly' : '';
            echo '<input type="text" id="spbc_setting_' . $field['name'] . '" name="spbc_settings[' . $field['name'] . ']" '
                 //.(!$spbc->data['moderate'] ? ' disabled="disabled"' : '')
                 . ($field['class'] ? ' class="' . $field['class'] . '"' : '')
                 . ($field['required'] ? ' required="required"' : '')
                 . 'value="' . ($field['value'] ?: $affiliate_short_code) . '" '
                 . $readonly
                 . ($field['disabled'] || ($field['parent'] && ! $field['parent_value']) ? ' disabled="disabled"' : '')
                 . (! $field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"')
                 . (! $field['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",", $field['children']) . '\')"')
                 . ' />';

            if ( ! $field['title_first']) {
                echo '&nbsp;<label for="spbc_setting_' . $field['name'] . '" class="spbc_setting-field_title--' . $field['type'] . '">'
                     . $field['title']
                     . '</label>';
            }

            echo isset($field['long_description'])
                ? '<i setting="' . $field['name'] . '" class="spbc_long_description__show icon-help-circled"></i>'
                : '';

            if (isset($field['description'])) {
                echo '<div class="spbc_settings_description">' . $field['description'] . '</div>';
            }
            break;

        // Textarea type
        case 'textarea':
            if ($field['title_first']) {
                echo '<label for="spbc_setting_' . $field['name'] . '" class="spbc_settings-field_title spbc_settings-field_title--' . $field['type'] . '">' . $field['title'] . '</label><br>';
            }

            echo '<textarea'
                 . ' id="spbc_setting_' . $field['name'] . '"'
                 . ' name="spbc_settings[' . $field['name'] . ']" '
                 . ($field['required'] ? ' required="required"' : '')
                 . ($field['parent'] && ! $spbc->settings[ $field['parent'] ] ? ' disabled="disabled"' : '')
                 . ' style="width: 400px; height: 150px;"'
                 . ' >'
                 . ($field['value'] ?: '')
                 . '</textarea>';

            if ( ! $field['title_first']) {
                echo '&nbsp;<label for="spbc_setting_' . $field['name'] . '" class="spbc_setting-field_title--' . $field['type'] . '">'
                     . $field['title']
                     . '</label>';
            }

            if (isset($field['description'])) {
                echo '<div class="spbc_settings_description">' . $field['description'] . '</div>';
            }

            break;

        // Time
        case 'time':
            echo '<input'
                 . ' type="time"'
                 . ' id="spbc_setting_' . $field['name'] . '"'
                 . ' name="spbc_settings[' . $field['name'] . ']" ' . ($field['parent'] && ! $spbc->settings[ $field['parent'] ] ? ' disabled="disabled"' : '')
                 . ' value="' . $field['value'] . '" '
                 . ($field['required'] ? ' required="required"' : '')
                 . '>';
            echo '<input type = "hidden" id = "user_timezone" name = "user_timezone" value = "">';
            break;

        // Number
        case 'number':
            if ($field['title_first']) {
                echo '<label for="spbc_setting_' . $field['name'] . '" class="spbc_settings-field_title spbc_settings-field_title--' . $field['type'] . '">' . $field['title'] . '</label>&nbsp;';
            }
            echo '<input'
                 . ' type="number"'
                 . ' id="spbc_setting_' . $field['name'] . '"'
                 . ' name="spbc_settings[' . $field['name'] . ']" ' . ($field['parent'] && ! $spbc->settings[ $field['parent'] ] ? ' disabled="disabled"' : '')
                 . ' value="' . $field['value'] . '" '
                 . ' min="' . $field['min'] . '" '
                 . ' max="' . $field['max'] . '" '
                 . ($field['required'] ? ' required="required"' : '')
                 . '>';
            if ( ! $field['title_first']) {
                echo '&nbsp;<label for="spbc_setting_' . $field['name'] . '" class="spbc_setting-field_title--' . $field['type'] . '">'
                     . $field['title']
                     . '</label>';
            }

            if (isset($field['description'])) {
                echo '<div class="spbc_settings_description">' . $field['description'] . '</div>';
            }
            break;

        // Hidden
        case 'hidden':
            echo '<input'
                 . ' type="hidden"'
                 . ' name="spbc_settings[' . $field['name'] . ']" '
                 . ' value="' . $field['value'] . '"'
                 . ($field['required'] ? ' required="required"' : '')
                 . '>';
            break;
    }

    echo '</div>';
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

function spbc_seconds_to_human_time($seconds)
{
    switch (true) {
        case $seconds / 60 / 60 < 1:
            $output = $seconds / 60 . ' min';
            break;
        case $seconds / 60 / 60 / 24 < 1:
            $output = $seconds / 60 / 60 . ' hours';
            break;
        case $seconds / 60 / 60 / 24 / 30 < 1:
            $output = $seconds / 60 / 60 / 24 . ' days';
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

    // If it's network admin dashboard
    if (is_network_admin()) {
        $link = get_site_option('siteurl') . 'wp-admin/options-general.php?page=spbc';
        printf("<h2>" . __("Please, enter the %splugin settings%s in main site dashboard.", 'security-malware-firewall') . "</h2>", "<a href='$link'>", "</a>");

        return;
    }

    // Version lower than 5.4.0
    if (is_admin() && version_compare(phpversion(), '5.4.0', '<')) {
        $spbc->error_add('php_version', '');
    } else {
        $spbc->error_delete('php_version');
    }

    // Low memory limit error
    $m_limit = ini_get('memory_limit');

    if (is_string($m_limit) && $m_limit !== "-1") {
        $prefix = strtolower(substr($m_limit, - 1, 1));
        $number = substr($m_limit, 0, - 1);
        switch ($prefix) {
            case 'k':
                $m_limit = (int)$number * 1000;
                break;
            case 'm':
                $m_limit = (int)$number * 1000000;
                break;
            case 'g':
                $m_limit = (int)$number * 1000000000;
                break;
        }

        if ($m_limit - memory_get_usage(true) < 25 * 1024 * 1024) {
            $spbc->error_add('memory_limit_low', '');
        } else {
            $spbc->error_delete('memory_limit_low');
        }
    }

    $user = wp_get_current_user();
    if (isset($user->ID) && $user->ID > 0) {
        $email = $user->user_email;
    } else {
        $email = get_option('admin_email');
    }

    // Outputs errors if exists
    spbc_settings__error__output();

    $feedback_link = $spbc->data["wl_mode_enabled"] ? '' : '<b style="display: inline-block;">'
        . sprintf(
            __('Do you like CleanTalk? %sPost your feedback here%s%s.', 'cleantalk'),
            '<a href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/#new-post" target="_blank">',
            '<i class="spbc-icon-link-ext"></i>',
            '</a>'
        )
        . '</b>'
        . '<br />';

    $support_link = $spbc->data["wl_mode_enabled"] ? '<a target="_blank" href="' . $spbc->data["wl_support_url"] . '">' . $spbc->data["wl_brandname"] . '</a>.'
        : '<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall/">wordpress.org</a>.';

    echo '<div id="gdpr_dialog" class="spbc_hide" style="padding: 0 15px;">'
         . spbc_show_GDPR_text()
         . '</div>'

         . '<div id="confirmation-code" class="spbc_hide" style="padding: 0 15px;">'
         . '<p>' . sprintf(
             esc_html__('Check %s inbox for the confirmation code.', 'cleantalk'),
             $email
         ) . '</p>'
         . '<i>' . esc_html__('The code is valid for 10 minutes. If you want to change the status in this period, the new code won\'t be sent, please, use the code you\'ve already received.', 'cleantalk') . '</i><br><br>'
         . '<input name="spbct-confirmation-code" type="text" />'
         . '&nbsp;&nbsp;<button type="button" id="confirmation-code--resend" class="button button-primary">Resend</button>'
         . '</div>'

         . '<div class="wrap">'
         . '<form id="spbc_settings_form" method="post" action="options.php">'
         . '<h2 style="display: inline-block;">' . $spbc->data["wl_brandname"] . '</h2>'
         . '<div style="float: right; margin : 10px 0 0 0; font-size: 13px;">';
    echo __('Tech support of ' . $spbc->data["wl_brandname"], 'cleantalk')
         . '&nbsp;'
         . $support_link
         // .' <a href="https://community.cleantalk.org/viewforum.php?f=25" target="_blank">'.__("Tech forum", 'cleantalk').'</a>'
         // .($user_token ? ", <a href='https://cleantalk.org/my/support?user_token=$user_token&cp_mode=antispam' target='_blank'>".__("Service support ", 'cleantalk').'</a>' : '').
         . '<br>';
    echo __('Plugin Homepage at', 'cleantalk') . ' <a href="' . $spbc->data["wl_url"] . '" target="_blank">' . $spbc->data["wl_url"] . '</a>.<br/>';
    echo '<span id="spbc_gdpr_open_modal" style="text-decoration: underline;">' . __('GDPR compliance', 'cleantalk') . '</span><br/>';
    echo $spbc->data["wl_brandname"] . __(' is a registered trademark. All rights reserved.', 'cleantalk') . '<br/>'
         . '<br />'
         . $feedback_link
         . spbc_badge__get_premium(false, true)
         . '</div>'
         . '</br>';

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
 * @return void
 * @global $spbc
 */
function spbc_settings__error__output()
{
    global $spbc;

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
            echo '<div id="spbcTopWarning" class="error" style="position: relative;">'
                 . '<h3 style="display: inline-block;">' . __('Errors:', 'security-malware-firewall') . '</h3>';
            foreach ($errors_out as $value) {
                echo '<h4>' . spbc_render_links_to_tag($value) . '</h4>';
            }
            echo '<h4 style="text-align: right;">' . sprintf(__('You can get support any time here: %s.', 'security-malware-firewall'), '<a target="blank" href="https://wordpress.org/support/plugin/security-malware-firewall">https://wordpress.org/support/plugin/security-malware-firewall</a>') . '</h4>';
            echo '</div>';
        }
    }
}

/**
 * Admin callback function - Displays field of security status
 */
function spbc_field_security_status()
{
    global $spbc;

    // Setting img's paths
    $path_to_img = SPBC_PATH . '/images/';
    $img         = $path_to_img . 'yes.png';
    $img_no      = $path_to_img . 'no.png';
    $img_no_gray = $path_to_img . 'no_gray.png';

    // Setting statuses
    $scanner_status =
        $spbc->key_is_ok &&
        $spbc->moderate &&
        (isset($spbc->data['scanner']['last_scan']) && $spbc->data['scanner']['last_scan'] + (86400 * 7) > current_time('timestamp'));
    $ssl_status     = is_ssl();
    $ssl_text       = sprintf(
        '%s' . __('SSL Installed', 'security-malware-firewall') . '%s',
        $ssl_status || ! $spbc->key_is_ok || $spbc->data["wl_mode_enabled"] ? '' : '<a href="https://cleantalk.org/my/?cp_mode=ssl' . ($spbc->user_token ? '&user_token=' . $spbc->user_token : '') . '" target="_blank">',
        $ssl_status || ! $spbc->key_is_ok || $spbc->data["wl_mode_enabled"] ? '' : '</a>'
    );

    // Output statuses
    echo '<h2 style="display: inline-block;">' . __('Status:', 'security-malware-firewall') . '</h2>';

    echo '<div style="display: inline-block; margin: 10px 0 10px;">';

    echo '<img class="spbc_status_icon" src="' . ($spbc->key_is_ok && $spbc->moderate ? $img : $img_no) . '"/>'
         . '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-security_log\')[0])">'
         . __('Brute-Force Protection', 'security-malware-firewall')
         . '</a>';

    echo '<img class="spbc_status_icon" src="' . ($spbc->key_is_ok && $spbc->moderate ? $img : $img_no) . '"/>'
         . '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-traffic_control\')[0])">'
         . __('FireWall', 'security-malware-firewall')
         . '</a>';

    if ($spbc->scaner_enabled) {
        echo '<img class="spbc_status_icon" id="spbc_scanner_status_icon" src="' . ($scanner_status ? $img : $img_no) . '"/>'
             . '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-scanner\')[0])">'
             . __('Malware Scanner', 'security-malware-firewall')
             . '</a>';
    }

    echo '<img class="spbc_status_icon" src="' . ($spbc->key_is_ok && $spbc->moderate ? $img : $img_no) . '"/>' . __('Security Report', 'security-malware-firewall');

    echo '<img class="spbc_status_icon" src="' . ($spbc->key_is_ok && $spbc->moderate ? $img : $img_no) . '"/>'
         . '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-security_log\')[0])">'
         . __('Security Audit Log', 'security-malware-firewall')
         . '</a>';

    echo '<img class="spbc_status_icon" src="' . ($ssl_status && $spbc->moderate ? $img : $img_no) . '"/>' . $ssl_text;

    // Autoupdate status
    if ($spbc->notice_auto_update) {
        echo '<img class="spbc_status_icon" src="' . ($spbc->auto_update == 1 ? $img : ($spbc->auto_update == - 1 ? $img_no : $img_no_gray)) . '"/>'
             . '<a href="https://cleantalk.org/help/cleantalk-auto-update" target="_blank">'
             . __('Auto update', 'security-malware-firewall')
             . '</a>';
    }

    echo '</div>';
    echo '<br>';
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
    echo '<span id="spbc_gdpr_open_modal" style="text-decoration: underline">' . __('GDPR compliance', 'security-malware-firewall') . '</span>';
    echo '<br>';
    echo __('Tech support: ', 'security-malware-firewall') . $support_link;
    echo '<br>';
    printf(__('The plugin home page', 'security-malware-firewall') . ' <a href="' . $spbc->data["wl_url"] . '" target="_blank">%s</a>.', $spbc->data["wl_brandname"]);
    echo '<br>';
    echo $spbc->data["wl_brandname"] . __(' is a registered trademark. All rights reserved.', 'security-malware-firewall');
    echo '<br>';
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
    echo(isset($spbc->fw_stats['last_updated'], $spbc->fw_stats['entries'])
        ? sprintf(__('Security FireWall database has %d IPs. Last updated at %s.', 'security-malware-firewall'), $spbc->fw_stats['entries'], date('M d Y H:i:s', $spbc->fw_stats['last_updated']))
        : __('Unknown last Security FireWall updating time.', 'security-malware-firewall'));
    echo $spbc->fw_stats['updating_id'] ? ' <b>Under updating now: ' . $spbc->fw_stats['update_percent'] . '%</b>' : '';
    echo '<br />';

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
                         __('Account at cleantalk.org is %s.', 'cleantalk'),
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
            echo '<a target="_blank" href="https://cleantalk.org/register?platform=wordpress&email=' . urlencode(get_option('admin_email')) . '&website=' . urlencode(parse_url(get_option('home'), PHP_URL_HOST)) . '&product_name=security" style="display: inline-block;">
						<input style="color:#666;" type="button" class="spbc_auto_link" value="' . __('Get access key manually', 'security-malware-firewall') . '" />
					</a>';
            echo '&nbsp;' . __('or', 'security-malware-firewall') . '&nbsp;';
            echo '<button class="spbc_manual_link" id="spbc_setting_get_key_auto" name="spbc_get_apikey_auto" type="button"  value="get_key_auto">'
                 . __('Get access key automatically', 'security-malware-firewall')
                 . '<img style="margin-left: 10px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
                 . '<img style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
                 . '</button>';
            echo '<br/><br/>';
            echo '<div style="font-size: 10pt; color: #666 !important">'
                 . sprintf(
                     __('Admin e-mail (%s) will be used for registration', 'security-malware-firewall'),
                     get_option('admin_email')
                 )
                 . '</div>';
            echo '<div>';
            echo '<input checked type="checkbox" id="license_agreed" onclick="spbcSettingsDependencies(\'get_key_auto\');"/>';
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
        $email = get_option('admin_email');
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

    $description_pattern = 'If someone fails %s authorizations in a row within %s min they will be blocked for %s';
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
        if ($role == 'Subscriber') {
            continue;
        }
        echo '<option'
             . (in_array($role, (array) $spbc->settings['2fa__roles']) ? ' selected="selected"' : '')
             . '>' . $role . '</option>';
    }

    echo '</select>';

    echo '</div>';
}

function spbc_field_security_logs__prepare_data(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $ips_c[] = $row->auth_ip;
        }
        unset($row);
        $ips_c = spbc_get_countries_by_ips(implode(',', $ips_c));

        $time_offset = current_time('timestamp') - time();

        foreach ($table->rows as $row) {
            $user      = get_user_by('login', $row->user_login);
            $user_part = sprintf(
                "<a href=\"%s\">%s</a>",
                $user ? (admin_url() . '/user-edit.php?user_id=' . $user->data->ID) : '#',
                $row->user_login
            );

            $page = $row->page === null ? '-' : "<a href='" . $row->page . "' target='_blank'>" . $row->page . "</a>";

            switch ($row->event) {
                case 'view':
                    $event = sprintf(
                        __('Viewing admin page (%s)', 'security-malware-firewall'),
                        $row->page_time === null
                            ? 'Calculating'
                            : strval($row->page_time) . ' seconds'
                    );
                    break;
                case 'auth_failed':
                    $event = __('Failed authentication', 'security-malware-firewall');
                    break;
                case 'auth_failed_2fa':
                    $event = __('Failed two factor authentication', 'security-malware-firewall');
                    break;
                case 'invalid_username':
                    $event = __('Invalid username', 'security-malware-firewall');
                    break;
                case 'invalid_email':
                    $event = __('Invalid e-mail', 'security-malware-firewall');
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
 */

function spbc_field_security_logs()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">';

    if ( ! $spbc->key_is_ok) {
        $button = '<input type="button" class="button button-primary" value="' . __('To setting', 'security-malware-firewall') . '"  />';
        $link   = sprintf(
            '<a
					href="#"
					onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_key\', action: \'highlight\', times: 3});">%s</a>',
            $button
        );
        echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">' . __('Please, enter access key.', 'security-malware-firewall') . '</h3>' . $link . '</div>';

        return;
    }

    // HEADER
    $message_about_log = sprintf(
        __('This table contains details of all brute-force attacks and security actions made in the past 24 hours. Number of the last records shown: %d.', 'security-malware-firewall'),
        SPBC_LAST_ACTIONS_TO_VIEW
    );

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
            $allow_layout = '<a href="#" onclick="return spbc_tc__allow_ip(\'' . esc_attr($ip) . '\')" class="spbcGreen">' . esc_html__('Allow', 'security-malware-firewall') . '</a>';
            $ban_layout = '<a href="#" onclick="return spbc_tc__ban_ip(\'' . esc_attr($ip) . '\')" class="spbc---red">' . esc_html__('Ban', 'security-malware-firewall') . '</a>';
            $ip = "<a href='https://cleantalk.org/blacklists/{$row->ip_entry}' target='_blank'>" . esc_html($ip) . '</a>'
                  . '<br>'
                  . $allow_layout . ' | ' . $ban_layout;

            $requests = '<b>' . $row->requests . '</b>';

            $page_url = strlen($row->page_url) >= 60
                ? '<div class="spbcShortText">' . substr($row->page_url, 0, 60) . '...</div>'
                  . '<div class="spbcFullText spbc_hide">' . $row->page_url . '</div>'
                : $row->page_url;

            $user_agent = strlen($row->http_user_agent) >= 60
                ? '<div class="spbcShortText">' . substr($row->http_user_agent, 0, 60) . '...</div>'
                  . '<div class="spbcFullText spbc_hide">' . $row->http_user_agent . '</div>'
                : $row->http_user_agent;

            switch ($row->status) {
                case 'PASS':
                    $status = '<span class="spbcGreen">' . __('Passed', 'security-malware-firewall') . '</span>';
                    break;
                case 'PASS_BY_TRUSTED_NETWORK':
                    $status = '<span class="spbcGreen">' . __('Passed. Trusted network. Click on IP for details.', 'security-malware-firewall') . '</span>';
                    break;
                case 'PASS_BY_WHITELIST':
                    $status = '<span class="spbcGreen">' . __('Passed. Whitelisted.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY':
                    $status = '<span class="spbcRed">' . __('Blocked. Blacklisted.', 'security-malware-firewall') . '</span>';
                    break;
                case 'DENY_BY_NETWORK':
                    $status = '<span class="spbcRed">' . __('Blocked. Hazardous network. Common source.', 'security-malware-firewall') . '</span>';
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
                              . __('Blocked by Web Application Firewall: ', 'security-malware-firewall')
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
                default:
                    $status = __('Unknown', 'security-malware-firewall');
                    break;
            }

            $table->items[] = array(
                'ip_entry'        => $ip,
                'country'         => spbc_report_country_part($ip_countries, $row->ip_entry),
                'entry_timestamp' => date('M d Y, H:i:s', $row->entry_timestamp + $time_offset),
                'requests'        => $requests,
                'requests_per'    => '<b>' . spbc_report_tc_requests_per($row->ip_entry) . '</b>',
                'status'          => $status,
                'page_url'        => $page_url,
                'http_user_agent' => $user_agent,
            );
        }
    }
}

function spbc_field_traffic_control_log()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">';

    // Bad key
    if ( ! $spbc->key_is_ok) {
        $button = '<input type="button" class="button button-primary" value="' . __('To setting', 'security-malware-firewall') . '"  />';
        $link   = sprintf(
            '<a
					href="#"
					onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_key\', action: \'highlight\', times: 3});">%s</a>',
            $button
        );
        echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">' . __('Please, enter access key.', 'security-malware-firewall') . '</h3>' . $link . '</div>';

        // Subscription should be renewed
    } elseif ( ! $spbc->moderate) {
        $button = '<input type="button" class="button button-primary" value="' . __('RENEW', 'security-malware-firewall') . '"  />';
        $link   = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
        echo '<div style="margin-top: 10px;">'
             . '<h3 style="margin: 5px; display: inline-block;">' . __('Please renew your security license.', 'security-malware-firewall') . '</h3>' . $link .
             '</div>';

        // Subscription is ok
    } else {
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
            '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_setting_traffic_control__autoblock_amount\', action: \'highlight\', times: 3});">',
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
                    '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_traffic_control__enabled\', 3);">',
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
                '<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_waf__enabled\', 3);">',
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
            if ( ! $row->real_full_hash) {
                unset($row->actions['compare']);
            }
            if ( ! $row->real_full_hash) {
                unset($row->actions['replace']);
            }
            if ( ! $row->severity) {
                unset($row->actions['view_bad']);
            }
            if ($row->status === 'quarantined') {
                unset($row->actions['quarantine']);
            }

            $cloud_status = __('Not checked by Cloud Analysis or ' . $spbc->data["wl_company_name"] . ' Team yet.', 'security-malware-firewall');
            if ( !empty($row->pscan_status) ) {
                if ( $row->pscan_status === 'DANGEROUS' ) {
                    $cloud_status = '<span class="spbcRed">' . __('File is denied by Cloud analysis', 'security-malware-firewall') . '</span>';
                }
            }

            if ( !empty($row->analysis_status) ) {
                if ( $row->analysis_status === 'DANGEROUS' ) {
                    $cloud_status = '<span class="spbcRed">' . __('File is denied by ' . $spbc->data["wl_company_name"] . ' team', 'security-malware-firewall') . '</span>';
                }
            }

            $table->items[] = array(
                'cb'      => $row->fast_hash,
                'uid'     => $row->fast_hash,
                'size'    => substr(number_format($row->size, 2, ',', ' '), 0, - 3),
                'perms'   => $row->perms,
                'mtime'   => date('M d Y H:i:s', $row->mtime + $spbc->data['site_utc_offset_in_seconds']),
                'path'    => strlen($root_path . $row->path) >= 40
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'actions' => $row->actions,
                'status' => $cloud_status,
            );

            if (isset($row->weak_spots)) {
                $weak_spots = json_decode($row->weak_spots, true);
                if ($weak_spots) {
                    if ( ! empty($weak_spots['SIGNATURES']) && $signatures) {
                        foreach ($weak_spots['SIGNATURES'] as $_string => $weak_spot_in_string) {
                            foreach ($weak_spot_in_string as $weak_spot) {
                                $ws_string = '<span class="spbcRed"><i setting="signatures_' . $signatures[ $weak_spot ]->attack_type . '" class="spbc_long_description__show spbc-icon-help-circled"></i>' . $signatures[ $weak_spot ]->attack_type . ': </span>'
                                             . (strlen($signatures[ $weak_spot ]->name) > 30
                                        ? substr($signatures[ $weak_spot ]->name, 0, 30) . '...'
                                        : $signatures[ $weak_spot ]->name);
                            }
                        }
                    } elseif ( ! empty($weak_spots['CRITICAL'])) {
                        foreach ($weak_spots['CRITICAL'] as $_string => $weak_spot_in_string) {
                            foreach ($weak_spot_in_string as $weak_spot) {
                                $ws_string = '<span class="spbcRed"><i setting="heuristic_' . $weak_spot . '" class="spbc_long_description__show spbc-icon-help-circled"></i> Heuristic: </span>'
                                             . (strlen($weak_spot) > 30
                                        ? substr($weak_spot, 0, 30) . '...'
                                        : $weak_spot);
                            }
                        }
                    } else {
                        $ws_string = '';
                    }
                } else {
                    $ws_string = '';
                }

                $table->items[ $key ]['weak_spots'] = $ws_string;
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

        foreach ($table->rows as $key => $row) {
            $analysis_status = '-';
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

            //old versions compatibility (with manual checking)
            if ( !empty($row->analysis_status) ) {
                if ($row->analysis_status === 'DANGEROUS') {
                    $analysis_status = '<span class="spbcRed">' . $row->analysis_status . '</span>';
                    $analysis_comment = '<span class="spbcRed">' . __('Manual check: file is dangerous', 'security-malware-firewall')  . '</span>';
                } elseif ($row->analysis_status === 'SAFE') {
                    $analysis_status = '<span class="spbcGreen">' . $row->analysis_status . '</span>';
                    $analysis_comment = '<span class="spbcGreen">' . __('Manual check: file is safe', 'security-malware-firewall')  . '</span>';
                }
                unset($row->actions['check_analysis_status']);
            }

            if ( isset($row->status) && $row->status === 'QUARANTINED' ) {
                $pscan_status = $row->pscan_status;
                $analysis_comment = __('Quarantined by user', 'security-malware-firewall');
            }

            if ($row->pscan_pending_queue == '1') {
                $pscan_status = __('Queued for inspection', 'security-malware-firewall');
                $analysis_comment = __('Processing: queue is full. File will be resent in 5 minutes.', 'security-malware-firewall');
            }

            // Filter actions for approved files
            if ( in_array($row->pscan_status, array('SAFE','DANGEROUS')) || $curr_time - $row->last_sent < 500 ) {
                unset($row->actions['check_analysis_status']);
            }

            $table->items[ $key ] = array(
                'cb'               => $row->fast_hash,
                'uid'              => $row->fast_hash,
                'path'             => strlen($root_path . $row->path) >= 40
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'detected_at'      => is_numeric($row->detected_at) ? date('M j, Y, H:i:s', $row->detected_at) : null,
                'last_sent'        => is_numeric($row->last_sent) ? date('M j, Y, H:i:s', $row->last_sent) : null,
                'analysis_status'  => $analysis_status,
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
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'previous_state' => $row->previous_state,
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
                'spam_active' => isset($row->spam_active) ? ($row->spam_active ? 'Yes' : 'No') : 'Unknown',
            );
        }
    }
}

function spbc_field_scanner__prepare_data__frontend(&$table)
{
    if ($table->items_count) {
        foreach ($table->rows as $row) {
            $table->items[] = array(
                'url'            => "<a href='{$row->url}' target='_blank'>{$row->url}</a>",
                'uid'            => $row->url,
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
 * Counts amount of accessible URL
 *
 * @return int
 */
function spbc_field_scanner__files_listing__get_total()
{
    global $spbc;

    $accessible_urls = $spbc->scanner_listing['accessible_urls'];

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

    $accessible_urls = $spbc->scanner_listing['accessible_urls'];

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
                          . '<i setting="' . $row->type . '" class="spbc_long_description__show spbc-icon-help-circled"></i>',
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

function spbc_field_scanner()
{
    global $spbc, $wp_version;

    echo '<div class="spbc_wrapper_field">';

    // Key is bad
    if ( ! $spbc->key_is_ok) {
        $button = '<input type="button" class="button button-primary" value="' . __('To setting', 'security-malware-firewall') . '"  />';
        $link   = sprintf(
            '<a
					href="#"
					onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_key\', action: \'highlight\', times: 3});">%s</a>',
            $button
        );
        echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">' . __('Please, enter access key.', 'security-malware-firewall') . '</h3>' . $link . '</div>';

        // Subscription bad
    } elseif ( ! $spbc->moderate) {
        $button = '<input type="button" class="button button-primary" value="' . __('RENEW', 'security-malware-firewall') . '"  />';
        $link   = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
        echo '<div style="margin-top: 10px;"><h3 style="margin: 5px; display: inline-block;">' . __('Please renew your security license.', 'security-malware-firewall') . '</h3>' . $link . '</div>';
        // All is ok
    } else {
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
        printf(
            __('%sView all scan results for this website%s%s', 'security-malware-firewall'),
            "<a target='blank' href='https://cleantalk.org/my/logs_mscan?service={$spbc->service_id}&user_token={$spbc->user_token}'>",
            '<i class="spbc-icon-link-ext"></i>',
            '</a>'
        );
        // show save to pdf link
        if ( ! empty($spbc->data['scanner']['last_scan'])) {
            echo ', &nbsp;<a id="spbc_scanner_save_to_pdf" href="" onclick="event.preventDefault()">'
                    . __('Export results to PDF', 'security-malware-firewall')
                    . '</a>';
        }
        //show backups link
        printf(
            __(', %sBackups%s', 'security-malware-firewall'),
            '&nbsp;<a href="/wp-admin/options-general.php?page=spbc&spbc_tab=backups">',
            '</a>'
        );
        echo '</p>';
        $scanner_disabled = isset($spbc->errors['configuration']) ? 'disabled="disabled"' : '';
        $scanner_disabled_reason = $scanner_disabled
            ? 'title="' . __('Scanner is disabled. Please, check errors on the top of the settings.', 'security-malware-firewall') . '"'
            : '';
        echo '<div style="text-align: center;">'
             . '<button id="spbc_perform_scan" class="spbc_manual_link" type="button" ' . $scanner_disabled . $scanner_disabled_reason . '>'
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
            echo '<a href="#"
                     onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'action-shuffle-salts-wrapper\', action: \'highlight\', times: 3});">' . __('We recommend changing your secret authentication keys and salts when curing is done.', 'security-malware-firewall') . '</a>';
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
            . '<span class="spbc_overall_scan_status_get_approved_hashes">' . __('Updating statuses for the approved files', 'security-malware-firewall') . '</span> -> ';

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

        echo '<br>';

        echo spbc_bulk_actions_description();
    }
    echo '</div>';
}

function spbc_field_scanner__show_accordion($direct_call = false)
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc;

    $section_description = __('List of files sent for cloud analysis.', 'security-malware-firewall');
    $section_tip_more_details = ! $spbc->data["wl_mode_enabled"]
        ? '<a href="https://cleantalk.org/my/inc_cmws_log">' . __('CleanTalk Security dashboard', 'security-malware-firewall') . '</a>'
        : '';
    $analysis_log_description = '<div>' .
        $section_description .
        $section_tip_more_details .
        '<div id="spbc_notice_cloud_analysis_feedback" class="notice is-dismissible">' .
        '<p>' .
        '<img src="' . SPBC_PATH . '/images/att_triangle.png" alt="attention" style="margin-bottom:-1px">' .
        ' ' .
        __('If you feel that the Cloud verdict is incorrect, 
        please click the link "Copy file info" near the file name and contact us via', 'security-malware-firewall') .
        ' ' .
        '<a href="mailto:' . $spbc->data["wl_support_email"] . '">' . $spbc->data["wl_support_email"] . '</a>' .
        '</p>' .
        '</div>' .
        '</div>';

    $tables_files = array(
        'critical'     => __('These files may not contain malicious code but they use very dangerous PHP functions and constructions! PHP developers don\'t recommend to use it and it looks very suspicious.', 'security-malware-firewall'),
        'suspicious'   => __('Found modified executable files', 'security-malware-firewall'),
        'approved'     => __('Approved files. When an approved file is added to the CleanTalk cloud, it will be removed from this list.', 'security-malware-firewall'),
        'quarantined'  => __('Punished files.', 'security-malware-firewall'),
        'analysis_log' => $analysis_log_description
    );

    if ($spbc->settings['scanner__list_unknown']) {
        $tables_files['unknown'] = __('These files do not include known malware signatures or dangerous code. In same time these files do not belong to the WordPress core or any plugin, theme which are hosted on wordpress.org.', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__outbound_links']) {
        $tables_files['outbound_links'] = __('Found outgoing links from this website and websites the links are leading to', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__frontend_analysis']) {
        $tables_files['frontend_malware'] = __('Malware on public pages found', 'security-malware-firewall');
    }

    if ($spbc->settings['scanner__important_files_listing']) {
        $tables_files['files_listing'] = __('Publicly accessible important files found', 'security-malware-firewall');
    }

    if (!empty($spbc->data['unsafe_permissions']['files']) || !empty($spbc->data['unsafe_permissions']['dirs'])) {
        $tables_files['unsafe_permissions'] = __('Permissions for files and directories from the list are unsafe. We recommend change it to 755 for each directory and 644 for each file from the list.', 'security-malware-firewall');
    }

    foreach ($tables_files as $type_name => $description) {
        $args         = spbc_list_table__get_args_by_type($type_name);
        $args['id']   = 'spbc_tbl__scanner_' . $type_name;
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

        if ($type_name === 'analysis_log' && $spbc->data['display_scanner_warnings']['analysis_all_safe']) {
            $danger_dot = '<span class="green_dot"></span>';
        }

        // Pass output if empty and said to do so
        if ( $args['if_empty_items'] !== false || $table->items_total !== 0 ) {
            echo '<h3><a href="#">' . ucwords(str_replace('_', ' ', $type_name)) . ' (<span class="spbc_bad_type_count ' . $type_name . '_counter">' . $table->items_total . '</span>)</a>' . $danger_dot . '</h3>';
            echo '<div id="spbc_scan_accordion_tab_' . $type_name . '">';

            echo '<p class="spbc_hint">'
                 . $description
                 . '</p>';
            $table->display();

            echo "</div>";
        }
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
            'add_col'   => array('fast_hash', 'last_sent', 'real_full_hash', 'severity', 'difference', 'status',),
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
            'delete' => array('name' => 'Delete',),
            'view'   => array('name' => 'View', 'handler' => 'spbc_scanner_button_file_view_event(this);',),
        ),
        'bulk_actions'   => array(
            'delete' => array('name' => 'Delete',),
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
                'order_by'          => array('spam_active' => 'asc'),
                'html_before'       =>
                    sprintf(__('Links for <b>%s</b> domain.', 'security-malware-firewall'), Post::get('domain', null, 'word')) . ' '
                    . sprintf(__('%sSee all domains%s', 'security-malware-firewall'), '<a href="#" onclick="spbc_scanner__switch_table(this, \'domains\');">', '</a>')
                    . '<br /><br />',
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__links',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No links are found', 'security-malware-firewall') . '</p>',
                'columns'           => array(
                    'link_id'     => array(
                        'heading' => __('Number', 'security-malware-firewall'),
                        'class'   => ' tbl-width--50px'
                    ),
                    'link'        => array('heading' => __('Link', 'security-malware-firewall'), 'primary' => true,),
                    'page_url'    => array('heading' => __('Post Page', 'security-malware-firewall'),),
                    'link_text'   => array('heading' => __('Link Text', 'security-malware-firewall'),),
                    'spam_active' => array(
                        'heading' => __('Spam-active', 'security-malware-firewall'),
                        'hint'    => __('Does link spotted in spam?', 'security-malware-firewall'),
                    ),
                ),
                'sortable'          => array('link', 'page_url', 'spam_active'),
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
                        'handler' => 'spbc_scanner__switch_table(this, "links");'
                    ),
                ),
                'order_by'          => array('spam_active' => 'desc'),
                'func_data_total'   => 'spbc_scanner_links_count_found__domains',
                'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No links are found', 'security-malware-firewall') . '</p>',
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
                    'rollback' => array('name' => 'Rollback', 'handler' => 'spbc_action__backups__rollback(this);',),
                    'delete'   => array('name' => 'Delete', 'handler' => 'spbc_action__backups__delete(this);',),
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
                    'add_col'     => array('entry_id', 'pattern'),
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
                    'requests'        => array('heading' => 'Requests', 'class' => ' tbl-width--100px'),
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
                    'user_login' => array('heading' => 'User', 'primary' => true,),
                    'auth_ip'    => array('heading' => 'IP',),
                    'datetime'   => array('heading' => 'Date',),
                    'event'      => array('heading' => 'Action',),
                    'page'       => array('heading' => 'Page',),
                ),
                'sortable'          => array('user_login', 'datetime'),
            );
            break;

        case 'critical':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'columns'           => array(
                        'cb'         => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
                        'path'       => array('heading' => 'Path', 'primary' => true,),
                        'size'       => array('heading' => 'Size, bytes',),
                        'perms'      => array('heading' => 'Permissions',),
                        'weak_spots' => array('heading' => 'Detected'),
                        'mtime'      => array('heading' => 'Last Modified',),
                        'status'      => array('heading' => 'Analysis verdict',),
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
                            'handler' => 'spbc_scanner_button_file_compare_event(this);',
                        ),
                        'view'       => array(
                            'name'    => 'View',
                            'handler' => 'spbc_scanner_button_file_view_event(this);',
                        ),
                        'view_bad'   => array(
                            'name'    => 'View Suspicious Code',
                            'handler' => 'spbc_scanner_button_file_view_bad_event(this);',
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
                        'where' => ' WHERE severity IN("CRITICAL") AND 
                            (status <> "QUARANTINED" AND 
                                status <> "APROVED" AND 
                                status <> "APPROVED_BY_CT")
                            AND 
                            (last_sent IS NULL OR 
                            pscan_status = "DANGEROUS" OR
                            analysis_status = "DANGEROUS")',
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            $args['sql']['add_col'][] = 'analysis_status';
            $args['sql']['add_col'][] = 'pscan_status';
            break;

        case 'suspicious':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
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
                            'handler' => 'spbc_scanner_button_file_compare_event(this);',
                        ),
                        'view'       => array(
                            'name'    => 'View',
                            'handler' => 'spbc_scanner_button_file_view_event(this);',
                        ),
                        'view_bad'   => array(
                            'name'    => 'View Suspicious Code',
                            'handler' => 'spbc_scanner_button_file_view_bad_event(this);',
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
                        'where' => ' WHERE severity <> "CRITICAL" AND
                        last_sent IS NULL AND
                        (status = "MODIFIED" AND severity IS NOT NULL) OR (status = "INFECTED" AND severity = "SUSPICIOUS")',
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
                            'pscan_pending_queue',
                            'analysis_status'
                        ),
                        'where' => ' WHERE last_sent IS NOT NULL',
                    ),
                    'order_by'          => array('pscan_status' => 'desc'),
                    'sortable'          => array('path', 'last_sent', 'analysis_status', 'pscan_status'),
                )
            );
            $args['columns']      = array(
                'cb'                => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
                'path'              => array('heading' => 'Path', 'primary' => true,),
                'detected_at'       => array('heading' => 'Detected at',),
                'last_sent'         => array('heading' => 'Sent for analysis at',),
                'pscan_status'      => array('heading' => 'Cloud verdict',),
                'analysis_status'   => array('heading' => 'Manual verdict',),
                'analysis_comment'  => array('heading' => 'Comment',),
            );
            $args['actions']      = array(
                'check_analysis_status' => array('name' => 'Check analysis status'),
                'copy_file_info' => array('name' => 'Copy file info'),
                'view'       => array(
                    'name'    => 'View',
                    'handler' => 'spbc_scanner_button_file_view_event(this);',
                ),
            );
            $args['bulk_actions'] = array(
                'check_analysis_status' => array('name' => 'Check analysis status',),
            );
            break;

        case 'unknown':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'if_empty_items'    => false,
                    'actions'           => array(
                        'approve' => array('name' => 'Approve',),
                        'view'    => array('name' => 'View',),
                    ),
                    'bulk_actions'      => array(
                        'approve' => array('name' => 'Approve',),
                    ),
                    'sql'               => array(
                        'where' => ' WHERE
						    status NOT IN ("APROVED","APPROVED_BY_CT","APPROVED_BY_CLOUD") AND
						    detected_at >= ' . (time() - $spbc->settings['scanner__list_unknown__older_than'] * 86400) . ' AND
						    source IS NULL AND
		                    path NOT LIKE "%wp-content%themes%" AND
                            path NOT LIKE "%wp-content%plugins%" AND
                            path NOT LIKE "%wp-content%cache%" AND
                            path NOT LIKE "%wp-config.php" AND
						    (severity IS NULL OR severity NOT IN ("CRITICAL", "DANGER", "SUSPICIOUS"))',
                    ),
                    'order_by'          => array('path' => 'asc'),
                )
            );
            break;

        case 'approved':
            $args = array_replace_recursive(
                $accordion_default_args,
                array(
                    'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
                    'if_empty_items'    => false,
                    'actions'           => array(
                        'disapprove' => array('name' => 'Disapprove',),
                    ),
                    'bulk_actions'      => array(
                        'disapprove' => array('name' => 'Disapprove',),
                    ),
                    'sql'               => array(
                        'where' => ' WHERE status = "APROVED"',
                    ),
                    'order_by'          => array('path' => 'asc'),
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
                            'handler' => 'spbc_scanner_button_file_view_event(this);',
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
                        'where'   => ' WHERE status = "QUARANTINED"',
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
                        'handler' => 'spbc_scanner__switch_table(this, "links");'
                    ),
                ),
                'order_by'          => array('spam_active' => 'desc'),
                'func_data_total'   => 'spbc_scanner_links_count_found__domains',
                'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
                'if_empty_items'    => '<p class="spbc_hint">' . __('No links are found', 'security-malware-firewall') . '</p>',
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
                    'view'     => array('name' => 'View', 'handler' => 'spbc_scanner_button_page_view_event(this);',),
                    'view_bad' => array(
                        'name'    => 'View Suspicious Code',
                        'handler' => 'spbc_scanner_button_page_view_bad_event(this);',
                    ),
                    'approve'  => array('name' => 'Approve', 'handler' => 'spbc_scanner_button_page_approve(this);'),
                ),
                'sql'               => array(
                    'table'     => SPBC_TBL_SCAN_FRONTEND,
                    'offset'    => 0,
                    'limit'     => 20,
                    'get_array' => false,
                    'where'     => '  WHERE approved IS NULL OR approved <> 1',
                ),
                'func_data_prepare' => 'spbc_field_scanner__prepare_data__frontend',
                'if_empty_items'    => __('No malware found', 'security-malware-firewall'),
                'columns'           => array(
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

    if ( ! $spbc->key_is_ok) {
        $button = '<input type="button" class="button button-primary" value="' . __('To setting', 'security-malware-firewall') . '"  />';
        $link   = sprintf('<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_key\', 3);">%s</a>', $button);
        echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">' . __('Please, enter access key.', 'security-malware-firewall') . '</h3>' . $link . '</div>';
    } elseif ( ! $spbc->moderate) {
        $button = '<input type="button" class="button button-primary" value="' . __('RENEW', 'security-malware-firewall') . '"  />';
        $link   = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
        echo '<div style="margin-top: 10px;"><h3 style="margin: 5px; display: inline-block;">' . __('Please renew your security license.', 'security-malware-firewall') . '</h3>' . $link . '</div>';
    } else {
        echo '<p class="spbc_hint" style="text-align: center;">';
        _e('Different types of backups', 'security-malware-firewall');
        echo '</p>';

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
    }

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
         . '<input form="debug__cron_set" type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
         . '<input form="debug__cron_set" type="hidden" name="plugin_name"             value="security" />'
         . '<input form="debug__cron_set" type="hidden" name="spbc_remote_call_token"  value="' . md5($spbc->api_key) . '" />'
         . '<input form="debug__cron_set" type="hidden" name="task"                    value="firewall_update" />'
         . '<input form="debug__cron_set" type="hidden" name="handler"                 value="spbc_security_firewall_update__init" />'
         . '<input form="debug__cron_set" type="hidden" name="period"                  value="86400" />'
         . '<input form="debug__cron_set" type="hidden" name="first_call"              value="' . (time() + 60) . '" />'
         . '<input form="debug__cron_set" type="submit" name="spbc_debug__fw_update_cron_10_seconds" value="Set FW update to 60 seconds from now" />'
         . '</div>';
}

function spbc_field_debug__set_scan_cron()
{
    global $spbc;

    echo '<div class="spbc_wrapper_field">'
         . '<br>'
         . '<input form="debug__cron_set" type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
         . '<input form="debug__cron_set" type="hidden" name="plugin_name"             value="security" />'
         . '<input form="debug__cron_set" type="hidden" name="spbc_remote_call_token"  value="' . md5($spbc->api_key) . '" />'
         . '<input form="debug__cron_set" type="hidden" name="task"                    value="scanner__launch" />'
         . '<input form="debug__cron_set" type="hidden" name="handler"                 value="spbc_scanner__launch" />'
         . '<input form="debug__cron_set" type="hidden" name="period"                  value="86400" />'
         . '<input form="debug__cron_set" type="hidden" name="first_call"              value="' . (time() + 60) . '" />'
         . '<input form="debug__cron_set" type="submit" name="spbc_debug__scan_cron_60_seconds" value="Schedule scan 60 seconds from now" />'
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
    if (empty($spbc->settings['login_page_rename__enabled']) && $settings['login_page_rename__enabled']) {
        $mail = wp_mail(
            get_option('admin_email'),
            $spbc->data["wl_brandname"] . esc_html__(': New login URL', 'security-malware-firewall'),
            sprintf(
                esc_html__('New login URL is: %s', 'security-malware-firewall'),
                \CleantalkSP\SpbctWP\RenameLoginPage::getURL($settings['login_page_rename__name'])
            )
            . "\n\n"
            . esc_html__('Please, make sure that you will not forget the URL!', 'security-malware-firewall')
        );

        // If email is not sent, disabling the feature
        if ( ! $mail) {
            $spbc->error_add(
                'login_page_rename',
                __('New login URL was not sent. Changes aborted.', 'security-malware-firewall')
            );
            $settings['login_page_rename__enabled'] = '0';
        } else {
            $spbc->error_delete('login_page_rename');
        }
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
    if ($settings['scanner__dir_exclusions']) {
        $dirs                                = CSV::parseNSV($settings['scanner__dir_exclusions']);
        $settings['scanner__dir_exclusions'] = array();
        foreach ($dirs as $dir) {
            if (is_dir(ABSPATH . $dir)) {
                $settings['scanner__dir_exclusions'][] = $dir;
            }
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
    $admin_email    = get_option('admin_email');

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

function spbc_show_more_security_logs_callback()
{
    check_ajax_referer('spbc_secret_nonce', 'security');

    // PREPROCESS INPUT
    $args                 = spbc_list_table__get_args_by_type('security_logs');
    $args['sql']['limit'] = Post::get('amount', 'int') ?: SPBC_LAST_ACTIONS_TO_VIEW;

    // OUTPUT
    $table = new ListTable($args);
    $table->getData();

    die(
        json_encode(
            array(
                'html' => $table->displayRows('return'),
                'size' => $table->items_count,
            )
        )
    );
}

function spbc_show_more_security_firewall_logs_callback()
{
    check_ajax_referer('spbc_secret_nonce', 'security');

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
                'html' => $table->displayRows('return'),
                'size' => $table->items_count,
            )
        )
    );
}

function spbc_tc__filter_ip()
{
    global $spbc;

    check_ajax_referer('spbc_secret_nonce', 'security');

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

    check_ajax_referer('spbc_secret_nonce', 'security');

    if (!isset($_POST['setting_id'])) {
        return;
    }

    $setting_id = $_POST['setting_id'];

    $tc_learn_more_link = ! $spbc->data["wl_mode_enabled"]
        ? '<p><a class="spbc_long_desc__link" href="https://blog.cleantalk.org/wordpress-ddos-protection-how-to-mitigate-ddos-attacks/">'
         . __('Learn more', 'security-malware-firewall')
         . '</a></p>'
        : '';

    $logins_collecting_learn_mode_links = ! $spbc->data["wl_mode_enabled"]
        ? '<p><a class="spbc_long_desc__link" href="https://blog.cleantalk.org/hiding-your-wordpress-username-from-bad-bots/">'
          . __('Learn more', 'security-malware-firewall')
          . '</a></p>'
        : '';

    $descriptions = array(
        'waf__xss_check'              => array(
            'title' => __('XSS check', 'security-malware-firewall'),
            'desc'  => __('Cross-Site Scripting (XSS) — prevents malicious code to be executed/sent to any user. As a result malicious scripts can not get access to the cookie files, session tokens and any other confidential information browsers use and store. Such scripts can even overwrite content of HTML pages. ' . $spbc->data["wl_company_name"] . ' WAF monitors for patterns of these parameters and block them.', 'security-malware-firewall')
        ),
        'waf__sql_check'              => array(
            'title' => __('SQL-injection check', 'security-malware-firewall'),
            'desc'  => __('SQL Injection — one of the most popular ways to hack websites and programs that work with databases. It is based on injection of a custom SQL code into database queries. It could transmit data through GET, POST requests or cookie files in an SQL code. If a website is vulnerable and execute such injections then it would allow attackers to apply changes to the website\'s MySQL database.', 'security-malware-firewall')
        ),
        'waf__file_check'             => array(
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
        ),
        'data__additional_headers'    => array(
            'title' => __('Additional Headers', 'security-malware-firewall'),
            'desc'  => __('"X-Content-Type-Options" improves the security of your site (and your users) against some types of drive-by-downloads. <br> "X-XSS-Protection" header improves the security of your site against some types of XSS (cross-site scripting) attacks.', 'security-malware-firewall')
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
    );

    if (!isset($descriptions[ $setting_id ])) {
        return;
    }

    wp_send_json($descriptions[ $setting_id ]);
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
        $email = get_option('admin_email');
    }

    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    $confirmation_code = get_site_option('spbc_confirmation_code', false);
    $save_code         = true;

    // Code is outdated. Generate a new code
    if ( ! isset($confirmation_code['generate_time']) || $confirmation_code['generate_time'] + 10 * 60 < time()) {
        $confirmation_code = array(
            'code'          => rand(10000000, 99999999),
            'generate_time' => time(),
        );

        $save_code = update_site_option('spbc_confirmation_code', $confirmation_code);
    }

    if (isset($confirmation_code['code'])) {
        if ($save_code === true) {
            $mail_result = wp_mail(
                $email,
                $spbc->data["wl_brandname"] . esc_html__(' confirmation code', 'security-malware-firewall'),
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
    $description .= esc_html__('Website total files - only executable files (*.php, *.html, *.htm) except for the quarantined files, files of zero size and files larger than the acceptable size.', 'security-malware-firewall');
    $description .= '<br>';
    $description .= esc_html__('Files scanned - files was checked. Some files will be added to the scan if the scanner deems it necessary.', 'security-malware-firewall');

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
        check_ajax_referer('spbc_secret_nonce', 'security');
    }

    if ( ! empty($spbc->data['scanner']['last_scan'])) {
        $output = sprintf(
            __('The last scan of this website was on %s, website total files*: %d, files scanned*: %d.', 'security-malware-firewall'),
            date('M d Y H:i:s', $spbc->data['scanner']['last_scan']),
            isset($spbc->data['scanner']['files_total']) ? $spbc->data['scanner']['files_total'] : $spbc->data['scanner']['last_scan_amount'],
            isset($spbc->data['scanner']['scanned_total']) ? $spbc->data['scanner']['scanned_total'] : null
        );
        if ($spbc->settings['scanner__outbound_links']) {
            $output .= sprintf(' ' . __('Outbound links found: %s.', 'security-malware-firewall'), isset($spbc->data['scanner']['last_scan_links_amount']) ? $spbc->data['scanner']['last_scan_links_amount'] : 0);
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
        && ! empty($spbc->data['scanner']['last_scan'])
        && isset($task['next_call'])
    ) {
        return sprintf(
            ' ' . __('The next automatic scan is scheduled on %s.', 'security-malware-firewall'),
            date('M d Y H:i:s', $task['next_call'])
        );
    }
    return '';
}
