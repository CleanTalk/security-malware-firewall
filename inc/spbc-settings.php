<?php

use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\ListTable;
use CleantalkSP\SpbctWP\Scanner;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\SpbctWP\Helpers\Arr;
use CleantalkSP\SpbctWP\Helpers\CSV;

// Scanner AJAX actions
require_once(SPBC_PLUGIN_DIR . 'inc/spbc-scanner.php');

/*
 * Contactins setting page functions
 * Included from /security-malware-firewall.php -> /inc/spbc-admin.php
 */

/**
 * Action 'admin_menu' - Add the admin options page
 *
 * @global type $spbc
 */
function spbc_admin_add_page() {
	
	// Adding setting page
	if(is_network_admin())
		add_submenu_page("settings.php", __( SPBC_NAME . ' Settings', 'security-malware-firewall'), SPBC_NAME, 'manage_options', 'spbc', 'spbc_settings_page');
	else
		add_options_page(                __( SPBC_NAME . ' Settings', 'security-malware-firewall'), SPBC_NAME, 'manage_options', 'spbc', 'spbc_settings_page');
	
	// Register setting
    register_setting(SPBC_SETTINGS, SPBC_SETTINGS, 'spbc_sanitize_settings');
		
	spbc_settings__register();
	
}

function spbc_settings__register() {
	
	global $spbc, $wp_version;
	
	// Show debug if CONNECTION_ERROR exists
	if(!empty($spbc->errors)){
		$errors = $spbc->errors;
		foreach($errors as $type => $error){
			if(!empty($error)){
				if(is_array(current($error))){
					foreach($error as $sub_type => $sub_error){
      
						if(strpos($sub_error['error'], 'CONNECTION') !== false){
                            $spbc->show_debug = true;
                        }
					}
				}elseif (
                    isset($error['error']) &&
                    is_string($error['error']) && strpos($error['error'], 'CONNECTION') !== false
                ){
                    $spbc->show_debug = true;
                }
			}
		}
	}
	
    $spbc->settings__elements = spbc_settings__register_sections_and_fields(array(
			
			// STATUS. Security status.
			'status' => array(
				'type'   => 'plain',
				'callback'    => 'spbc_field_security_status',
			),
			// BUTTONS
			// Dashboard
			'cp_button' => array(
				'type' => 'plain',
				'display' => $spbc->key_is_ok,
				'html'    => '<div id="goToCleanTalk" class="spbc-div-2" style="display: inline-block; position: relative; top: -2px; margin-right: 7px;">'
						. '<a id="goToCleanTalkLink" class="spbc_manual_link" target="_blank" href="https://cleantalk.org/my?user_token='.$spbc->user_token.'&cp_mode=security">'
						. __('Security Control Panel', 'security-malware-firewall')
						. '</a>'
					. '</div>',
			),
			// Support
			'support_button' => array(
				'type' => 'plain',
				'html'    => '<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall" style="display: inline-block; position: relative; top: -2px;">'
						. '<input type="button" class="spbc_auto_link" value="'.__('Support', 'security-malware-firewall').'" />'
					. '</a>',
                'display' => $spbc->key_is_ok,
			),
		    // Synchronize button
			'sync_button' => array(
				'type' => 'plain',
				'display' => spbc_api_key__is_correct(),
				'html'    => '&nbsp;&nbsp;<button type="button" class="spbc_auto_link" id="spbc_button__sync" style="display: inline-block; position: relative; top: -2px; margin-right: 7px;">'
			             . '<i class="spbc-icon-upload-cloud"></i>&nbsp;&nbsp;'
			             . __('Synchronize with Cloud', 'security-malware-firewall')
			             .'<img style="margin-left: 10px; margin-top: 1px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
			             .'<img style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
		             .'</button>',
			),
			
			// TABS
			// Scanner
			'scanner' => array(
				'type' => 'tab',
				'display' => $spbc->scaner_enabled,
				'title' => __('Malware Scanner', 'security-malware-firewall'),
				'icon' => 'spbc-icon-search',
				'class_prefix' => 'spbc',
				'active' => true,
				'ajax' => true,
				'js_before' => 'scanner-plugin.js', // @todo minimize with "Tester" software. Because uglify failed to minimized it.
				'js_after' => 'settings_tab--scanner.min.js',
				'sections' => array(
					'scanner' => array(
						'type' => 'section',
						'fields' => array(
							'scanner' => array(
								'type' => 'field',
								'callback' => 'spbc_field_scanner'
							),
						),
					),
				),
			),
			// Backups
			'backups' => array(
				'type' => 'tab',
				'display' => $spbc->scaner_enabled && $spbc->settings['scanner__auto_cure'],
				'title' => __('Backups', 'security-malware-firewall'),
				'icon' => 'spbc-icon-download',
				'class_prefix' => 'spbc',
				'active' => false,
				'ajax' => true,
				'js_after' => 'settings_tab--backups.min.js',
				'sections' => array(
					'scanner' => array(
						'type' => 'section',
						'fields' => array(
							'scanner' => array(
								'type' => 'field',
								'callback' => 'spbc_field_backups'
							),
						),
					),
				),
			),
			// Security log
			'security_log' => array(
				'type' => 'tab',
				'title' => __('Security Log', 'security-malware-firewall'),
				'icon' => 'spbc-icon-user-secret',
				'class_prefix' => 'spbc',
				'ajax' => true,
				'js_after' => 'settings_tab--security_log.min.js',
				'sections' => array(
					'security_log' => array(
						'type' => 'section',
						'fields' => array(
							'security_log' => array(
								'type' => 'field',
								'callback' => 'spbc_field_security_logs'
							),
						),
					),
				),
			),
			// Firewall
			'traffic_control' => array(
				'type' => 'tab',
				'display' => $spbc->fw_enabled,
				'title' => __('Firewall', 'security-malware-firewall'),
				'icon' => 'spbc-icon-exchange',
				'class_prefix' => 'spbc',
				'ajax' => true,
				'js_after' => 'settings_tab--traffic_control.min.js',
				'sections' => array(
					'tc_log' => array(
						'type' => 'section',
						'fields' => array(
							'tc_log' => array(
								'type' => 'field',
								'callback' => 'spbc_field_traffic_control_log'
							),
						),
					),
				),
			),
			// Settings
			'settings_general' => array(
				'type' => 'tab',
				'title' => __('General Settings', 'security-malware-firewall'),
				'icon' => 'spbc-icon-sliders',
				'class_prefix' => 'spbc',
				'ajax' => true,
				'js_after'  => 'settings_tab--settings_general.min.js',
				'after' => 'submit_button',
				'sections' => array(
					'apikey' => array(
						'type' => 'section',
						'title' => __('Access Key', 'security-malware-firewall'),
						'fields' => array(
							'apikey' => array(
								'type' => 'field',
								'callback' => 'spbc_field_key'
							),
                            'ms__work_mode' => array(
                                'type'       => 'field',
                                'input_type' => 'select',
                                'options' => array(
                                    array( 'val' => 1, 'label' => __('Mutual Account, Individual Access Keys', 'security-malware-firewall'), 'children_enable' => 1, ),
                                    array( 'val' => 2, 'label' => __('Mutual Account, Mutual Access Key', 'security-malware-firewall'), 'children_enable' => 0, ),
                                    array( 'val' => 3, 'label' => __('Individual accounts, individual Access keys', 'security-malware-firewall'), 'children_enable' => 0, ),
                                ),
                                'title'            => __( 'WordPress Multisite Work Mode', 'security-malware-firewall' ),
                                'description'      => __( 'You can choose the work mode here for the child blogs and how they will operate with the CleanTalk Cloud. Press "?" for the detailed description.', 'security-malware-firewall' ),
                                'long_description' => true,
                                'display'          => $spbc->is_network && $spbc->is_mainsite,
                                'children'         => array( 'ms__hoster_api_key' ),
                                'value_source'     => 'network_settings',
                            ),
                            'ms__hoster_api_key' => array(
                                'type'             => 'field',
                                'input_type'       => 'text',
                                'title'            => __( 'Hoster access key', 'security-malware-firewall' ),
                                'description'      => __( 'Another API allowing you to hold multiple blogs on on account.', 'security-malware-firewall' ),
                                'class'            => 'spbc_middle_text_field',
                                'title_first'      => true,
                                'long_description' => true,
                                'display'          => $spbc->is_network && $spbc->is_mainsite,
                                'disabled'         => ! isset( $spbc->network_settings['ms__work_mode'] ) || $spbc->network_settings['ms__work_mode'] != 1,
                                'value_source'     => 'network_settings',
                                'parent_value_source' => 'network_settings',
                                'parent' => 'ms__work_mode',
                            ),
                            'ms__service_utilization' => array(
                                'type'     => 'field',
                                'callback' => 'spbc_field_service_utilization',
                                'display'  => $spbc->is_network && $spbc->is_mainsite && $spbc->ms__work_mode == 1,
                            ),
						),
					),
					'auth' => array(
						'type' => 'section',
						'title' => __('Authentication and Logging In', 'security-malware-firewall'),
						'fields' => array(
							
							// Hidden BFP fields
							'bfp__allowed_wrong_auths' => array( 'type' => 'field', 'input_type' => 'hidden' ),
							'bfp__delay__1_fails' => array( 'type' => 'field', 'input_type' => 'hidden' ),
							'bfp__delay__5_fails' => array( 'type' => 'field', 'input_type' => 'hidden' ),
							'bfp__count_interval' => array( 'type' => 'field', 'input_type' => 'hidden' ),
							
							'bfp__block_period__5_fails' => array(
								'type' => 'field',
								'input_type' => 'select',
								'options' => array(
									array('val' => 120,   'label' => __('2 minutes', 'security-malware-firewall'),   ),
									array('val' => 300,   'label' => __('5 minutes', 'security-malware-firewall'),  ),
									array('val' => 600,   'label' => __('10 minutes', 'security-malware-firewall'),  ),
									array('val' => 1800,  'label' => __('30 minutes', 'security-malware-firewall'),  ),
									array('val' => 3600,  'label' => __('1 hour', 'security-malware-firewall'),  ),
									array('val' => 10800, 'label' => __('3 hours', 'security-malware-firewall'), ),
									array('val' => 21600, 'label' => __('6 hours', 'security-malware-firewall'), ),
									array('val' => 43200, 'label' => __('12 hours', 'security-malware-firewall'), ),
									array('val' => 86400, 'label' => __('24 hours', 'security-malware-firewall'), ),
								),
								'title' => __('If someone fails 5 authorizations in a row within 15 min they will be blocked for ', 'security-malware-firewall'),
							),
							'2fa__enable' => array(
								'type' => 'field',
								'input_type' => 'radio',
								'options' => array(
									array('val' => 1, 'label'  => __('On', 'security-malware-firewall'),   'children_enable' => 1,),
									array('val' => 0, 'label'  => __('Off', 'security-malware-firewall'),  'children_enable' => 0,),
									array('val' => -1, 'label' => __('Only for new devices', 'security-malware-firewall'), 'children_enable' => 1,),
								),
								'title' => __('Two-factor authentication (2FA)', 'security-malware-firewall'),
								'description' => 'spbc_settings_2fa_description_callback',
                                'children' => array('2fa__roles]['),
                                'long_description' => true,
                            ),
							'2fa__roles' => array(
								'type' => 'field',
								'callback' => 'spbc_field_2fa__roles',
							),
							'login_page_rename__enabled' => array(
								'display' => version_compare( $wp_version, '4.0-RC1-src', '>=' ),
								'type' => 'field',
								'title' => __('Change address to login script', 'security-malware-firewall'),
                                'description' => __('Please note that this will not hide the links to your registration page on your website.', 'security-malware-firewall'),
								'children' => array('login_page_rename__name','login_page_rename__redirect',),
							),
								'login_page_rename__name' => array(
									'display' => version_compare( $wp_version, '4.0-RC1-src', '>=' ),
									'input_type' => 'text',
									'type' => 'field',
									'title_first' => true,
									'title' => __('Login URL: ', 'security-malware-firewall')
                                               . get_home_url()
                                               . '/'
                                               . ( get_option( 'permalink_structure', false ) ? '' : '?'),
									'class' => 'spbc_middle_text_field',
									'parent' => 'login_page_rename__enabled',
								),
								'login_page_rename__redirect' => array(
									'display' => version_compare( $wp_version, '4.0-RC1-src', '>=' ),
									'input_type' => 'text',
									'type' => 'field',
									'title_first' => true,
									'title' => __('Redirect URL: ', 'security-malware-firewall')
                                               . get_home_url()
                                               . '/'
                                               . ( get_option( 'permalink_structure', false ) ? '' : '?'),
									'description' => __('If someone tries to access the default login page they will be redirected to the URL above.', 'security-malware-firewall'),
									'class' => 'spbc_middle_text_field',
									'parent' => 'login_page_rename__enabled',
								),
                            'action_shuffle_salts' => array(
                                'type' => 'field',
                                'callback' => 'spbc_settings_field__action_shuffle_salts',
                            ),
						),
					),
					'firewall' => array(
						'type' => 'section',
						'title' => __('Firewall', 'security-malware-firewall'),
						'display' => $spbc->fw_enabled,
						'description' => __('Any IP addresses of the logged in administrators will be automatically added to your Personal Lists and will be approved all the time.', 'security-malware-firewall'),
						'fields' => array(
                            'fw__custom_message' => array(
                                'type' => 'field',
                                'input_type' => 'hidden',
                            ),
                            'fw__append_standard_message' => array(
                                'type' => 'field',
                                'input_type' => 'hidden',
                            ),
							'waf__enabled' => array(
								'type' => 'field',
								'title' => __('Web Application Firewall', 'security-malware-firewall'),
								'description' => __('Catches dangerous stuff like: XSS, MySQL-injections and uploaded malicious files.', 'security-malware-firewall'),
								'children' => array('waf__xss_check','waf__sql_check','waf__file_check','waf__exploit_check'),
							),
							'waf__xss_check' => array(
								'type' => 'field',
								'title' => __('XSS check', 'security-malware-firewall'),
								'description' => __('Cross-Site Scripting test.', 'security-malware-firewall'),
								'long_description' => true,
								'parent' => 'waf__enabled',
							),
							'waf__sql_check' => array(
								'type' => 'field',
								'title' => __('SQL-injection check', 'security-malware-firewall'),
								'description' => __('SQL-injection test.', 'security-malware-firewall'),
								'long_description' => true,
								'parent' => 'waf__enabled',
							),
							'waf__file_check' => array(
								'type' => 'field',
								'title' => __('Check uploaded files', 'security-malware-firewall'),
								'description' => __('Check uploaded files for malicious code.', 'security-malware-firewall'),
								'long_description' => true,
								'parent' => 'waf__enabled',
                                'children' => array('waf__file_check__uploaded_plugins')
							),
                            'waf__file_check__uploaded_plugins' => array(
                                'type' => 'field',
                                'title' => __('Check plugins and themes while uploading', 'security-malware-firewall'),
                                'description' => __('Check the plugins and themes uploaded via WordPress built in interface with heuristic and signature analysis.', 'security-malware-firewall'),
                                'parent' => 'waf__file_check',
                                'class' => 'spbc_sub2_setting',
                            ),
							'waf__exploit_check' => array(
								'type' => 'field',
								'title' => __('Check for exploits', 'security-malware-firewall'),
								'description' => __('Check traffic for known exploits.', 'security-malware-firewall'),
								'parent' => 'waf__enabled',
							),
							'traffic_control__enabled' => array(
								'type' => 'field',
								'title' => __('Traffic Control', 'security-malware-firewall'),
								'description' => __('This feature shows a list of visits and hits of everyone who tried to go to your website. Allows you to ban any visitor, a whole country or a network.', 'security-malware-firewall'),
								'long_description' => true,
								'children' => array('traffic_control__autoblock_amount', 'traffic_control__autoblock_period'),
							),
							'traffic_control__autoblock_amount' => array(
								'input_type' => 'text',
								'type' => 'field',
								'title_first' => true,
								'title' => __('Block a visitor if they opened this number of website pages in 1 hour', 'security-malware-firewall'),
								'class' => 'spbc_short_text_field',
								'parent' => 'traffic_control__enabled',
							),
							'traffic_control__autoblock_period' => array(
								'type' => 'field',
								'input_type' => 'select',
								'options' => array(
									array('val' => 1800,   'label' => __('30 minutes', 'security-malware-firewall'),   ),
									array('val' => 3600,   'label' => __('1 hour', 'security-malware-firewall'),   ),
									array('val' => 7200,   'label' => __('2 hours', 'security-malware-firewall'),   ),
									array('val' => 14400,  'label' => __('4 hours', 'security-malware-firewall'),  ),
								),
								'title' => __('Block a visitor if they exceeded the limit of opened pages for', 'security-malware-firewall'),
								'parent' => 'traffic_control__enabled',
							),
						),
					),
					'scanner_setting' => array(
						'type' => 'section',
						'title' => __('Malware Scanner', 'security-malware-firewall'),
						'display' => $spbc->scaner_enabled,
						'fields' => array(
							'scanner__auto_start' => array(
								'type' => 'field',
								'title' => __('Enable autoscanning', 'security-malware-firewall'),
								'description' => __('Scans your website files automatically each 24 hours.', 'security-malware-firewall'),
								'children' => array('scanner__auto_start_manual'),
							),
							'scanner__auto_start_manual' => array(
								'type' => 'field',
								'title' => __('Set the time when the autoscanning starts each day', 'security-malware-firewall'),
								'description' => __('Scans your website files automatically at the specified time. Uses your browser timezone.', 'security-malware-firewall'),
								'children' => array('scanner__auto_start_manual_time'),
								'parent' => 'scanner__auto_start',
							),
							'scanner__auto_start_manual_time' => array(
								'type' => 'field',
								'input_type' => 'time',
								'parent' => 'scanner__auto_start_manual',
                                'required' => true,
							),
							'scanner__outbound_links' => array(
								'type' => 'field',
								'title' => __('Scan links', 'security-malware-firewall'),
								'description' => __('Turning this option on may increase scanning time for websites with a lot of pages.', 'security-malware-firewall'),
								'long_description' => true,
								'children' => array('scanner__outbound_links_mirrors'),
							),
							'scanner__outbound_links_mirrors' => array(
								'type' => 'field',
								'input_type' => 'text',
								'parent' => 'scanner__outbound_links',
								'title' => __('Exclusions', 'security-malware-firewall'),
								'description' => __('Here you can specify the links that will not be checked by the scanner. Separate them with a comma and omit protocols (examples: "some.com, example.net, my.org").', 'security-malware-firewall'),
								'class' => 'spbc_long_text_field',
							),
                            'scanner__important_files_listing' => array(
                                'type' => 'field',
                                'title' => __('Scan if listing is enabled for important directory', 'security-malware-firewall'),
                                'description' => __('The scanner will check if important files and directories are publicly accessible such as "ROOT/.svn", "ROOT/.git", "debug.log" and others.', 'security-malware-firewall'),
                                'class' => 'spbc_long_text_field',
                            ),
							'scanner__heuristic_analysis' => array(
								'type' => 'field',
								'title' => __('Heuristic analysis', 'security-malware-firewall'),
								'description' => __('Will search for dangerous code in modified files. Unknown files will be shown in the results only if both options heuristic analysis and signature analysis are enabled.', 'security-malware-firewall'),
								'long_description' => true,
							),
							'scanner__signature_analysis' => array(
								'type' => 'field',
								'title' => __('Signature analysis', 'security-malware-firewall'),
								'description' => __('Will search for known malicious signatures in files. Unknown files will be shown in the results only if both options heuristic analysis and signature analysis are enabled.', 'security-malware-firewall'),
								'long_description' => true,
							),
                            'scanner__dir_exclusions' => array(
                                'type' => 'field',
                                'input_type' => 'textarea',
                                'title' => __('Directory exclusions for the malware scanner:', 'security-malware-firewall'),
                                'title_first' => true,
                                'description' => __('Input relative directories (WordPress folder is ROOT). Separate each directory by a new line and omit the character "\" at the beginning. All subdirectories will be excluded too.', 'security-malware-firewall'),
                            ),
							'scanner__auto_cure' => array(
								'type' => 'field',
								'title' => __('Cure malware', 'security-malware-firewall'),
								'description' => __('Will cure know malware.', 'security-malware-firewall'),
								'long_description' => true,
							),
							'scanner__frontend_analysis' => array(
								'type' => 'field',
								'title' => __('Scan HTML code', 'security-malware-firewall'),
								'description' => __('Will scan HTML code on the website pages for known bad constructions.', 'security-malware-firewall'),
							),
                            'scanner__frontend_analysis__csrf' => array(
                                'type' => 'field',
                                'title' => __('Cross-Site Request Forgery Detection', 'security-malware-firewall'),
                                'description' => __('Detects SCRF attack types in the public HTML on your website.', 'security-malware-firewall'),
                                'parent' => 'scanner__frontend_analysis',
                            ),
                            'scanner__frontend_analysis__domains_exclusions' => array(
                                'type' => 'field',
                                'input_type' => 'textarea',
                                'title' => __('Allowed domains:', 'security-malware-firewall'),
                                'title_first' => true,
                                'description' => __('The scanner will not consider these domains as malware. Separate each domain by a new line.', 'security-malware-firewall'),
                            ),
                            'scanner__list_unknown' => array(
                                'type' => 'field',
                                'title' => __('List unknown files', 'security-malware-firewall'),
                                'description' => __('Shows the list of found unknown files in the malware scanner report. Unknown files do not have known virus signatures and do not have suspicious code. Meanwhile, unknown files do not belong to the public plugins and themes at wordpress.org.', 'security-malware-firewall'),
                                'children' => array('scanner__list_unknown__older_than'),
                            ),
                            'scanner__list_unknown__older_than' => array(
                                'type' => 'field',
                                'input_type' => 'select',
                                'options' => array(
                                    array('val' => 1,   'label' => __('1 day', 'security-malware-firewall'),   ),
                                    array('val' => 3,   'label' => __('3 days', 'security-malware-firewall'), 'default'),
                                    array('val' => 5,   'label' => __('5 days', 'security-malware-firewall'),   ),
                                    array('val' => 10,  'label' => __('10 days', 'security-malware-firewall'),  ),
                                ),
                                'title' => __('Do not show unknown files older than', 'security-malware-firewall'),
                                'parent' => 'scanner__list_unknown',
                            ),
						),
					),
                    
                    // Admin bar
                    'admin_bar' => array(
                        'type' => 'section',
                        'title' => __('Admin Bar', 'security-malware-firewall'),
                        'display' => current_user_can( 'activate_plugins' ),
                        'fields' => array(
                            'admin_bar__show' => array(
                                'type'        => 'field',
                                'title'       => __('Show statistics in admin bar', 'security-malware-firewall'),
                                'description' => __('Show/hide the CleanTalk drop-down menu at the top bar of the WordPress backend.', 'security-malware-firewall'),
                                'children' => array('admin_bar__users_online_counter', 'admin_bar__brute_force_counter', 'admin_bar__firewall_counter' ),
                            ),
                            'admin_bar__users_online_counter' => array(
                                'type'        => 'field',
                                'title'       => __('Administrators online counter', 'security-malware-firewall'),
                                'description' => __('Shows the number of administrators online in the admin bar.', 'security-malware-firewall'),
                                'parent' => 'admin_bar__show',
                            ),
                            'admin_bar__brute_force_counter' => array(
                                'type'        => 'field',
                                'title'       => __('Allowed/Blocked login attempts counter', 'security-malware-firewall'),
                                'description' => __('Shows the number of blocked login attempts in the admin bar. Counts only the local database.', 'security-malware-firewall'),
                                'parent' => 'admin_bar__show',
                            ),
                            'admin_bar__firewall_counter' => array(
                                'type'        => 'field',
                                'title'       => __('Security Firewall counter', 'security-malware-firewall'),
                                'description' => __('Shows the firewall counters in the admin bar. Counts only the local database.', 'security-malware-firewall'),
                                'parent' => 'admin_bar__show',
                            ),
                        )
                    ),
					
					'misc' => array(
						'type' => 'section',
						'title' => __('Miscellaneous', 'security-malware-firewall'),
						'fields' => array(
							'misc__backend_logs_enable' => array(
								'display' => is_main_site(),
								'disabled' => ! $spbc->data['extra_package']['backend_logs'],
								'type' => 'field',
								'title' => __('Collect and send PHP logs', 'security-malware-firewall'),
								'description' => $spbc->data['extra_package']['backend_logs']
                                    ? __('Collect and send PHP error logs to your CleanTalk Dashboard where you can list them.', 'security-malware-firewall')
								    : sprintf(
                                        __(
                                            'To see the collected logs please use the %sBackend PHP log%s. The %sextra package%s is required to start the collection.',
                                            'security-malware-firewall'
                                        ),
                                        '<a href="https://cleantalk.org/my/backend_logs?user_token=' . $spbc->user_token . '" target="_blank">',
								        '</a>',
								        '<a href="http://cleantalk.org/my/bill/security?package=1">',
								        '</a>'
                                    ),
								'long_description' => true,
							),
                            'misc__prevent_logins_collecting' => array(
                                'type' => 'field',
                                'title' => __('Prevent collecting of authors logins', 'security-malware-firewall'),
                                'description' => __('Prevent bots from collecting logins of the content authors from the website links (like example.com/?author=1).', 'security-malware-firewall'),
                            ),
							'misc__show_link_in_login_form' => array(
								'type' => 'field',
								'title' => __('Let them know about protection', 'security-malware-firewall'),
								'description' => __('Place the CleanTalk warning under the website login form: "Brute-force protection by CleanTalk Security. All attempts are being logged."', 'security-malware-firewall'),
							),
							'wp__disable_xmlrpc' => array(
								'type' => 'field',
								'title' => __('Disable XML-RPC', 'security-malware-firewall'),
								'description' => __('Turn this on to disable a WordPress out-of-date technology of connecting websites to miscellaneous systems.', 'security-malware-firewall'),
								'long_description' => true,
							),
                            'wp__disable_rest_api_for_non_authenticated' => array(
                                'type'            => 'field',
                                'title'           => __( 'Disable REST API for non-authenticated users', 'security-malware-firewall' ),
                                'description'     => __( 'Turn this on to deny access to WordPress REST API for non-authenticated users. Denied requests will get a 401 HTTP Code (Unauthorized).', 'security-malware-firewall' ),
                                'children_by_ids' => array( '_alternative_mechanism' ),
                            ),
                            'data__set_cookies' => array(
                                'type' => 'field',
                                'title'       => __( "Set cookies", 'security-malware-firewall' ),
                                'description' => __( 'Turn this option off or use the alternative mechanism for cookies to forbid the plugin generate any cookies on the website\'s front-end.', 'security-malware-firewall' )
                                     . '<br>' . __( 'Alternative mechanism will store data in the website database and will not set cookies in browsers, so any cache solution will work just fine.', 'security-malware-firewall' ),
                                'input_type'  => 'radio',
                                'options'     => array(
                                    array( 'val' => 1, 'label' => __( 'On', 'security-malware-firewall' ),                  'children_enable' => 0, ),
                                    array( 'val' => 0, 'label' => __( 'Off', 'security-malware-firewall' ),                 'children_enable' => 0, ),
                                    array( 'val' => 2, 'label' => __( 'Alternative mechanism', 'security-malware-firewall' ), 'children_enable' => 1, ),
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
							'misc__forbid_to_show_in_iframes' => array(
								'type' => 'field',
								'title' => __('Forbid to show your website in iFrame tags on third-party websites', 'security-malware-firewall'),
								'description' => __('If this option is enabled, third-party websites can\'t show content of your website in IFrames.', 'security-malware-firewall'),
							),
							'data__additional_headers' => array(
								'display'     => is_main_site(),
								'type'        => 'field',
								'title'       => __('Send additional HTTP headers', 'security-malware-firewall'),
								'description' => __('Add these headers to the HTTP responses on the public pages: X-Content-Type-Options, X-XSS-Protection to get protection from XSS and drive-by download attacks.', 'security-malware-firewall'),
								'long_description' => true,
							),
							'wp__use_builtin_http_api' => array(
								'display'     => is_main_site(),
								'type'        => 'field',
								'title'       => __('Use WordPress HTTP API', 'security-malware-firewall'),
								'description' => __('Alternative way of connection to the CleanTalk Cloud. Enable it if you have connection issues.', 'security-malware-firewall'),
							),
							'misc__complete_deactivation' => array(
								'display' => is_main_site(),
								'type' => 'field',
								'title' => __('Complete deactivation', 'security-malware-firewall'),
								'description' => __('The plugin will leave no traces in WordPress after deactivation. It could help if you have problems with the plugin.', 'security-malware-firewall'),
							),
                            'monitoring__users' => array(
                                'type' => 'field',
                                'input_type' => 'hidden',
                            ),
						),
					),
				),
			),
			// Summary
			'summary' => array(
				'type' => 'tab',
				'title' => __('Summary', 'security-malware-firewall'),
				'icon' => 'spbc-icon-info',
				'class_prefix' => 'spbc',
				'ajax' => false,
				'callback' => 'spbc_tab__summary',
			),
			// Debug
			'debug' => array(
				'type' => 'tab',
				'display' => in_array( Server::get_domain(), array( 'lc', 'loc', 'lh', 'wordpress' ) ) || $spbc->debug || $spbc->show_debug,
				'title' => __('Debug', 'security-malware-firewall'),
				'class_prefix' => 'spbc',
				'ajax' => true,
				'sections' => array(
					'debug' => array(
						'type' => 'section',
						'fields' => array(
							'drop_debug' => array(
								'type' => 'field',
								'callback' => 'spbc_field_debug_drop'
							),
							'debug_check_connection' => array(
								'type' => 'field',
								'callback' => 'spbc_field_debug__check_connection'
							),
                            'debug_set_fw_update_cron' => array(
                                'type' => 'field',
                                'callback' => 'spbc_field_debug__set_fw_update_cron'
                            ),
                            'debug_set_scan_cron' => array(
                                'type' => 'field',
                                'callback' => 'spbc_field_debug__set_scan_cron'
                            ),
							'debug_data' => array(
								'type' => 'field',
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
 * @return array Processed elements
 */
function spbc_settings__register_sections_and_fields($elems, $section_name = '') {
	
    global $spbc;
    
	$elems_original = $elems;
	
	$plain_default_params = array(
		'title'   => '',
		'html'    => '',
		'display' => true,
	);
	
	$tab_default_params = array(
		'name'		  => '',
		'title'		  => '',
		'description' => '',
		'active'	  => false,
		'icon'		  => '',
		'display'	  => true,
		'preloader'	  => '<img class="spbc_spinner_big" src="' . SPBC_PATH . '/images/preloader2.gif" />',
		'ajax'		  => true,
		'js_before'	  => null,
		'js_after'	  => null,
	);
	
	$section_default_params = array(
		'title'          => '',
		'description'    => '',
		'html_before'    => '',
		'html_after'     => '',
		'display' => true,
	);
	
	$field_default_params = array(
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
	
	foreach($elems as $elem_name => &$elem){
		
		// Merging with default params
		$elem = array_merge(${$elem['type'].'_default_params'}, $elem);
		
		switch ($elem['type']) {
			case 'plain':
				
				break;
			case 'tab':
				if(isset($elem['sections']))
					$elem['sections'] = spbc_settings__register_sections_and_fields($elem['sections']);
				// Creating new elements with tabs headings (before tabs)
				if($elem['display']){
					$tab_head = '<h2 class="spbc_tab_nav spbc_tab_nav-'. $elem_name .' '. (!empty($elem['active']) ? 'spbc_tab_nav--active' : '').'">'
							. '<i class="'. (isset($elem['icon']) ? $elem['icon'] : 'spbc-icon-search') .'"></i>'
							. $elem['title']
						. '</h2>';
					if(empty($elems_original['tab_headings'])){
						Arr::insert(
							$elems_original,
							$elem_name,
							array('tab_headings' => array(
								'type' => 'tab_headings',
								'html' => $tab_head,
								'display' => true,
							))
						);
					}else{
						$elems_original['tab_headings']['html'] .= $tab_head;
					}
				}
				break;
			case 'section':
//				add_settings_section('spbc_section__'.$elem_name, '', 'spbc_section__'.$elem_name, 'spbc');
				if(isset($elem['fields']))
					$elem['fields'] = spbc_settings__register_sections_and_fields($elem['fields'], $elem_name);
				break;
			case 'field':
			    
                $elem['name']  = $elem_name;
                
                $elem['value'] = isset( $spbc->{$elem['value_source']}[ $elem_name ] )
                    ? $spbc->{$elem['value_source']}[ $elem_name ]
                    : 0;
                
                if( isset( $elem['parent'] ) ){
                    $elem['parent_value'] = isset( $spbc->{$elem['parent_value_source']}[ $elem['parent'] ] )
                        ? $spbc->{$elem['parent_value_source']}[ $elem['parent'] ]
                        : 0;
                }
                
//				add_settings_field('spbc_field__'.$elem_name, '', $elem['callback'], 'spbc', 'spbc_section__'.$elem_name, $section_name);
				break;
		}
		
		$elems_original[$elem_name] = $elem;
	}
	
	return $elems_original;
	
}

/**
 * Outputs elements and tabs
 *
 * @global type $spbc
 */
function spbc_settings__draw_elements($elems_to_draw = null, $direct_call = false) {
	
	global $spbc;
	
	if( ! $direct_call && Post::get( 'security' ) ){
		spbc_settings__register();
		check_ajax_referer('spbc_secret_nonce', 'security');
		if( Post::get( 'tab_name' ) )
            $elems_to_draw = array( $_POST['tab_name'] => $spbc->settings__elements[ Post::get( 'tab_name' ) ] );
	}
	
	foreach($elems_to_draw as $elem_name => &$elem){
		
		if(!$elem['display'])
			continue;
		
		switch ($elem['type']) {
			
			case 'plain':
				if(isset($elem['callback']) && function_exists($elem['callback']))
					call_user_func($elem['callback']);
				else
					echo $elem['html'];
				break;
				
			case 'tab_headings':
				echo '<div class="spbc_tabs_nav_wrapper">'
					. $elem['html']
				. '</div>';
				break;
			
			case 'tab':
				
				echo '<div class="spbc_tab spbc_tab-'. $elem_name .' '. (!empty($elem['active']) ? 'spbc_tab--active' : '') .'">';
				
					if(!$elem['ajax'] || !$direct_call){
						
						// JS before
						if(isset($elem['js_before'])){
							foreach(explode(' ', $elem['js_before']) as $script){
								echo '<script src="'. SPBC_PATH .'/js/spbc-'. $script .'?ver='. SPBC_VERSION .'"></script>'; // JS before tab
							}
						}
						
						// Output
						if(!empty($elem['callback'])) call_user_func($elem['callback']);
						else                          spbc_settings__draw_elements($elem['sections'], true);
						
						// Custom elements on tab
						if(isset($elem['after'])){
							if(function_exists($elem['after'])) call_user_func($elem['after']);
							else                                echo $elem['after'];
						}
						
						// JS after
						if(isset($elem['js_after'])){
							foreach(explode(' ', $elem['js_after']) as $script){
								echo '<script src="'. SPBC_PATH .'/js/spbc-'. $script .'?ver='. SPBC_VERSION .'"></script>'; // JS after tab
							}
						}
					}else
						echo $elem['preloader'];
				echo '</div>';
				break;
				
			case 'section':
				echo '<div class="spbc_tab_fields_group">'
				     .'<div class="spbc_group_header">'
				     .(!empty($elem['title']) ? '<h3>'. $elem['title'] .'</h3>' : '')
				     .(!empty($elem['description']) ? '<div class="spbc_settings_description">'. $elem['description'] .'</div>' : '')
				     .'</div>';
				spbc_settings__draw_elements($elem['fields'], true);
				echo '</div>';
				break;
			
			case 'field':
				call_user_func($elem['callback'], $elem);
				break;
		}
		
	}
	
	if(isset($_POST['security']) && !$direct_call)
		die();
}

function spbc_settings__field__draw($field){
	
	global $spbc;
	
	echo '<div class="'.$field['def_class'].(!empty($field['class']) ? ' '.$field['class'] : '').(isset($field['parent']) ? ' spbc_sub_setting' : '').'">';
		
		switch($field['input_type']){
			
			// Checkbox type
			case 'checkbox':
				echo '<input type="checkbox" id="spbc_setting_'.$field['name'].'" name="spbc_settings['.$field['name'].']" value="1" '
					//.(!$spbc->data['moderate'] ? ' disabled="disabled"' : '')
					.($field['disabled'] ? ' disabled="disabled"' : '')
                    .($field['required'] ? ' required="required"' : '')
					.($field['value'] == '1' ? ' checked' : '')
					.($field['parent'] && !$spbc->settings[$field['parent']] ? ' disabled="disabled"' : '')
                    .(!$field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"' )
					.(!$field['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",",$field['children']) . '\')"')
					.(!$field['children_by_ids'] ? '' : ' onchange="spbcSettingsDependenciesbyId([\''.implode("','",$field['children_by_ids']).'\'])"')
					.' />';
				echo isset($field['title'])
					? '<label for="spbc_setting_'.$field['name'].'" class="spbc_setting-field_title--'.$field['type'].'">'.$field['title'].'</label>'
					: '';
				echo isset($field['long_description'])
					? '<i setting="'.$field['name'].'" class="spbc_long_description__show spbc-icon-help-circled"></i>'
					: '';
				echo isset($field['description'])
					?'<div class="spbc_settings_description">'. $field['description'] .'</div>'
					: '';
				break;
			
			// Radio type
			case 'radio':
				echo isset($field['title'])
					? '<span class="spbc_settings-field_title spbc_settings-field_title--'.$field['type'].'">'.$field['title'].'</span>'
					: '';
				echo isset($field['long_description'])
					? '<i setting="'.$field['name'].'" class="spbc_long_description__show spbc-icon-help-circled"></i>'
					: '';
                if( isset($field['description'] ) && function_exists( $field['description'] ) ){
                    call_user_func( $field['description'] );
                }else{
                    echo isset( $field['description'] ) && ! function_exists( $field['description'] )
                        ? '<div style="margin-bottom: 10px" class="spbc_settings_description">' . $field['description'] . '</div>'
                        : '';
                }
				foreach($field['options'] as $option){
					echo '<input'
						.' type="radio"'
						.' class="spbc_setting_'.$field['type'].'"'
						.' id="spbc_setting__' . ( strtolower( str_replace( ' ', '_', $option['label'] ) ) ) . '"'
						.' name="spbc_settings['.$field['name'].']"'
						.' value="'.$option['val'].'"'
						.($field['parent'] ? ' disabled="disabled"' : '')
                        .(!$field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"' )
                        .(!$field['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",",$field['children']) . '\')"')
                        .(!$field['children_by_ids'] ? '' : ' onchange="spbcSettingsDependenciesbyId([\''.implode("','",$field['children_by_ids']).'\'])"')
						.($field['value'] == $option['val'] ? ' checked' : '').' />'
						.'<label for="spbc_setting__'.$option['label'].'"> ' . $option['label'] . '</label>';
					echo '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;';
				}
				break;
			
			// Dropdown list type
			case 'select':
				echo isset($field['title'])
					? '<label for="spbc_setting_'.$field['name'].'" class="spbc_settings-field_title spbc_settings-field_title--'.$field['type'].'">'.$field['title'].'</label>&nbsp;'
					: '';
				echo '<select'
					.' class="spbc_setting_'.$field['type'].'"'
					.' id="spbc_setting_'.$field['name'].'"'
					.' name="spbc_settings['.$field['name'].']"'
                    .( $field['disabled'] || ( $field['parent'] && ! $field['parent_value'] ) ? ' disabled="disabled"' : '')
                    .(!$field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"' )
//					.' onchange="console.log( jQuery(this).find(\'option:selected\') ); console.log( jQuery(this).find(\'option:selected\').attr(\'children_enable\') );"'
                    .( $field['children']
                        ? ' onchange="spbcSettingsDependencies(\'' . implode(",",$field['children']) . '\', jQuery(this).find(\'option:selected\').attr(\'children_enable\'))"'
                        : ''
                     )
					
					.'>';
				
				foreach($field['options'] as $option){
					echo '<option'
							. ' value="' . $option['val'] . '"'
							. ($field['value'] == $option['val'] ?  'selected' : '')
                            . (isset( $option['children_enable'] ) ? ' children_enable=' . $option['children_enable'] : '')
                         .'>'
							. $option['label']
						. '</option>';
				}
				echo '</select>';
				echo isset($field['long_description'])
					? '<i setting="'.$field['name'].'" class="spbc_long_description__show spbc-icon-help-circled"></i>'
					: '';
				echo isset($field['description'])
					?'<div style="margin-bottom: 10px" class="spbc_settings_description">'. $field['description'] .'</div>'
					: '';
				
				break;
			
			// Text type
			case 'text':
				
				if($field['title_first'])
					echo '<label for="spbc_setting_'.$field['name'].'" class="spbc_settings-field_title spbc_settings-field_title--'.$field['type'].'">'.$field['title'].'</label>&nbsp;';
				
				echo '<input type="text" id="spbc_setting_'.$field['name'].'" name="spbc_settings['.$field['name'].']" '
					//.(!$spbc->data['moderate'] ? ' disabled="disabled"' : '')
                    .($field['required'] ? ' required="required"' : '')
					.'value="'.($field['value'] ?: '').'" '
					.( $field['disabled'] || ( $field['parent'] && ! $field['parent_value'] ) ? ' disabled="disabled"' : '')
                    .(!$field['children'] ? '' : ' children="' . implode(",", $field['children']) . '"' )
                    .(!$field['children'] ? '' : ' onchange="spbcSettingsDependencies(\'' . implode(",",$field['children']) . '\')"')
					.' />';
				
				if(!$field['title_first'])
					echo '&nbsp;<label for="spbc_setting_'.$field['name'].'" class="spbc_setting-field_title--'.$field['type'].'">'
						.$field['title']
					.'</label>';
				
                echo isset($field['long_description'])
                    ? '<i setting="'.$field['name'].'" class="spbc_long_description__show icon-help-circled"></i>'
                    : '';

				if(isset($field['description']))
					echo '<div class="spbc_settings_description">'.$field['description'].'</div>';
				break;
				
			// Textarea type
			case 'textarea':
				
				if( $field['title_first'] )
					echo '<label for="spbc_setting_' . $field['name'] . '" class="spbc_settings-field_title spbc_settings-field_title--' . $field['type'] . '">' . $field['title'] . '</label><br>';
                
                echo '<textarea'
                     . ' id="spbc_setting_' . $field['name'] . '"'
                     . ' name="spbc_settings[' . $field['name'] . ']" '
                     . ( $field['required'] ? ' required="required"' : '' )
				     . ( $field['parent'] && ! $spbc->settings[ $field['parent'] ] ? ' disabled="disabled"' : '' )
				     . ' style="width: 400px; height: 150px;"'
				     . ' >'
					 . ( $field['value'] ?: '' )
					 . '</textarea>';
				
				if( ! $field['title_first'] ){
					echo '&nbsp;<label for="spbc_setting_' . $field['name'] . '" class="spbc_setting-field_title--' . $field['type'] . '">'
					     . $field['title']
					     . '</label>';
				}
				
				if( isset( $field['description'] ) )
					echo '<div class="spbc_settings_description">' . $field['description'] . '</div>';
				
				break;
			
			// Time
			case 'time':
				echo '<input'
					.' type="time"'
					.' id="spbc_setting_'.$field['name'].'"'
					.' name="spbc_settings['.$field['name'].']" '.($field['parent'] && !$spbc->settings[$field['parent']] ? ' disabled="disabled"' : '')
                     .' value="'. $field['value'] . '" '
                     .($field['required'] ? ' required="required"' : '')
                     .'>';
				echo '<input type = "hidden" id = "user_timezone" name = "user_timezone" value = "">';
				break;
				
			// Hidden
			case 'hidden':
				echo '<input'
				     .' type="hidden"'
				     .' name="spbc_settings['.$field['name'].']" '
                     .' value="'. $field['value'] . '"'
                     .($field['required'] ? ' required="required"' : '')
                     .'>';
				break;
		}
		
	echo '</div>';
}

function spbc_human_time_to_seconds($human_time){
	
	$human_time = explode(' ', $human_time);
	
	switch(true){
		case strpos($human_time[1], 'second') !== false :
			$seconds = $human_time[0] * 1;
			break;
		case strpos($human_time[1], 'min') !== false :
			$seconds = $human_time[0] * 60;
			break;
		case strpos($human_time[1], 'hour') !== false :
			$seconds = $human_time[0] * 3600;
			break;
		case strpos($human_time[1], 'day') !== false :
			$seconds = $human_time[0] * 86400;
			break;
		case strpos($human_time[1], 'week') !== false :
			$seconds = $human_time[0] * 86400 * 7;
			break;
		case strpos($human_time[1], 'month') !== false :
			$seconds = $human_time[0] * 86400 * 30;
			break;
		case strpos($human_time[1], 'year') !== false :
			$seconds = $human_time[0] * 86400 * 365;
			break;
		default:
			$seconds = $human_time[0];
			break;
	}
	
	return $seconds;
}

/**
 * Admin callback function - Displays plugin options page
 */
function spbc_settings_page() {
	
	global $spbc;
	
	// If it's network admin dashboard
	if(is_network_admin()){
		$link = get_site_option('siteurl').'wp-admin/options-general.php?page=spbc';
		printf("<h2>" . __("Please, enter the %splugin settings%s in main site dashboard.", 'security-malware-firewall') . "</h2>", "<a href='$link'>", "</a>");
		return;
	}
	
	// Waringns counter on Summary tab
	$warnings = '';
	$warnings .= !empty($spbc->data['warnings']['black'])  ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--black">%s</span>',  $spbc->data['warnings']['black'])  : '';
	$warnings .= !empty($spbc->data['warnings']['red'])    ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--red">%s</span>',    $spbc->data['warnings']['red'])    : '';
	$warnings .= !empty($spbc->data['warnings']['orange']) ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--orange">%s</span>', $spbc->data['warnings']['orange']) : '';
	$warnings .= !empty($spbc->data['warnings']['green'])  ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--green">%s</span>',  $spbc->data['warnings']['green'])  : '';
	
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--black">%s</span>',  1);
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--red">%s</span>',    2);
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--orange">%s</span>', 3);
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--green">%s</span>',  4);
	
	// Version lower than 5.4.0
	if(is_admin() && version_compare(phpversion(), '5.4.0', '<')){
		$spbc->error_add('php_version', '');
	}else{
		$spbc->error_delete('php_version');
	}
    
    // Low memory limit error
    $m_limit = ini_get('memory_limit');
    
    if(is_string($m_limit) && $m_limit !== "-1"){
        $prefix = strtolower(substr($m_limit, -1, 1));
        $numder = substr($m_limit, 0, -1);
        switch($prefix){
            case 'k': $m_limit = $numder * 1000; break;
            case 'm': $m_limit = $numder * 1000000; break;
            case 'g': $m_limit = $numder * 1000000000; break;
        }
        
        if($m_limit - memory_get_usage(true) < 25 * 1024 * 1024 ){
            $spbc->error_add('memory_limit_low', '');
        }else{
            $spbc->error_delete('memory_limit_low');
        }
    }

	$user = wp_get_current_user();
	if (isset($user->ID) && $user->ID > 0) {
		$email = $user->user_email;
	} else {
		$email = get_option( 'admin_email' );
	}
	
	// Outputs errors if exists
	spbc_settings__error__output();
	
	echo ''
		. '<div id="gdpr_dialog" class="spbc_hide" style="padding: 0 15px;">'
			. spbc_show_GDPR_text()
		. '</div>'

	     . '<div id="confirmation-code" class="spbc_hide" style="padding: 0 15px;">'
	        . '<p>' . sprintf(
					esc_html__('Check %s inbox for the confirmation code.', 'cleantalk' ),
					$email
				) . '</p>'
	        . '<i>' . esc_html__( 'The code is valid for 10 minutes. If you want to change the status in this period, the new code won\'t be sent, please, use the code you\'ve already received.', 'cleantalk' ) . '</i><br><br>'
	        . '<input name="spbct-confirmation-code" type="text" />'
	        . '&nbsp;&nbsp;<button type="button" id="confirmation-code--resend" class="button button-primary">Resend</button>'
	     . '</div>'
		
		. '<div class="wrap">'
			. '<form id="spbc_settings_form" method="post" action="options.php">'
				. '<h2 style="display: inline-block;">'. SPBC_NAME. '</h2>'
				. '<div style="float: right; margin : 10px 0 0 0; font-size: 13px;">';
						echo __('Tech support of CleanTalk:', 'cleantalk')
							.'&nbsp;'
							.'<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall/">wordpress.org</a>.'
						// .' <a href="https://community.cleantalk.org/viewforum.php?f=25" target="_blank">'.__("Tech forum", 'cleantalk').'</a>'
						// .($user_token ? ", <a href='https://cleantalk.org/my/support?user_token=$user_token&cp_mode=antispam' target='_blank'>".__("Service support ", 'cleantalk').'</a>' : '').
							.'<br>';
						echo __('Plugin Homepage at', 'cleantalk').' <a href="http://cleantalk.org" target="_blank">cleantalk.org</a>.<br/>';
						echo '<span id="spbc_gdpr_open_modal" style="text-decoration: underline;">'.__('GDPR compliance', 'cleantalk').'</span><br/>';
						echo __('CleanTalk is a registered trademark. All rights reserved.', 'cleantalk').'<br/>'
						. '<br />'
						. '<b style="display: inline-block;">'
						.sprintf(
							__('Do you like CleanTalk? %sPost your feedback here%s.', 'cleantalk'),
							'<a href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/#new-post" target="_blank">',
							'</a>'
						)
					. '</b>'
					. '<br />'
					.spbc_badge__get_premium(false, true)
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
* @global SpbcState $spbc
* @return void
*/
function spbc_settings__error__output(){
	
	global $spbc;
	
	if(!empty($spbc->errors)){
		
		$errors = $spbc->errors;
		
		// Types
		$types = array(
			// Common
			'memory_limit_low'     => __('You have less than 25 Mib free PHP memory. Error could occurs while scanning.', 'security-malware-firewall'),
			'php_version'          => __('PHP version is lower than 5.4.0. You are using 10 years old software. We strongly recommend you to update.', 'security-malware-firewall'),
			// Misc
			'apikey'             => __('Access key validating: ', 'security-malware-firewall'),
			'get_key'            => __('Getting access key automatically: ', 'security-malware-firewall'),
			'notice_paid_till'   => __('Checking account status: ', 'security-malware-firewall'),
			'access_key_notices' => __('Checking account status2: ', 'security-malware-firewall'),
            'login_page_rename'  => __( 'Renaming login URL: ', 'security-malware-firewall' ),
            'service_customize'  => __( 'Service customization: ', 'security-malware-firewall' ),
			// Cron
			'cron_scan'     => __('Scheduled scanning: ', 'security-malware-firewall'),
			'cron'          => __('Scheduled: ', 'security-malware-firewall'),
		);
		if ($spbc->moderate == 1) {
            
            $types['debug']              = __( 'Debug: ', 'security-malware-firewall' );
            $types['send_logs']          = __( 'Sending security logs: ', 'security-malware-firewall' );
            $types['send_firewall_logs'] = __( 'Sending firewall logs: ', 'security-malware-firewall' );
            $types['firewall_update']    = __( 'Updating firewall: ', 'security-malware-firewall' );
            $types['signatures_update']  = __( 'Updating signatures: ', 'security-malware-firewall' );
            $types['send_php_logs']      = __( 'PHP error log sending: ', 'security-malware-firewall' );

			// Subtypes
			$sub_types = array(
				'get_hashes'      => __('Getting hashs: ', 'security-malware-firewall'),
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
		
		foreach($errors as $type => $error){
			if(!empty($error) && isset($types[$type])) {
				if(is_array(current($error))){
					foreach($error as $sub_type => $error){
						$text = isset($error['error_time']) ? date('Y-m-d H:i:s', $error['error_time']) . ': ' : '';
						$text .= $types[$type];
						$text .= isset($sub_types[$sub_type]) ? $sub_types[$sub_type] : $sub_type.': ';
						$text .= $error['error'];
						$errors_out[] = $text;
					}
				}else{
					$text = isset($error['error_time']) ? date('Y-m-d H:i:s', $error['error_time']) . ': ' : '';
					$text .= $types[$type];
					$text .= $error['error'];
					$errors_out[] = $text;
				}
			}
		}
		
		if(!empty($errors_out)){
			echo '<div id="spbcTopWarning" class="error" style="position: relative;">'
				.'<h3 style="display: inline-block;">'.__('Errors:', 'security-malware-firewall').'</h3>';
				foreach($errors_out as $value){
					echo '<h4>'.$value.'</h4>';
				}
				echo '<h4 style="text-align: right;">'.sprintf(__('You can get support any time here: %s.', 'security-malware-firewall'), '<a target="blank" href="https://wordpress.org/support/plugin/security-malware-firewall">https://wordpress.org/support/plugin/security-malware-firewall</a>').'</h4>';
			echo '</div>';
		}
	}
}

/**
 * Admin callback function - Displays field of security status
 */
function spbc_field_security_status(){
	
	global $spbc;
	
	// Setting img's paths
	$path_to_img = SPBC_PATH . '/images/';
	$img = $path_to_img.'yes.png';
	$img_no = $path_to_img.'no.png';
	$img_no_gray = $path_to_img.'no_gray.png';
	
	// Setting statuses
	$scanner_status =
        $spbc->key_is_ok &&
        $spbc->moderate &&
        ( isset( $spbc->data['scanner']['last_scan'] ) && $spbc->data['scanner']['last_scan'] + ( 86400 * 7) > current_time('timestamp') );
	$ssl_status = is_ssl();
	$ssl_text   = sprintf('%s' . __('SSL Installed', 'security-malware-firewall') . '%s',
		$ssl_status || !$spbc->key_is_ok ? '' : '<a href="https://cleantalk.org/my/?cp_mode=ssl'.($spbc->user_token ? '&user_token='.$spbc->user_token : '').'" target="_blank">',
		$ssl_status || !$spbc->key_is_ok ? '' : '</a>'
	);
	
	// Output statuses
	echo '<h2 style="display: inline-block;">'.__('Status:', 'security-malware-firewall').'</h2>';
	
	echo '<div style="display: inline-block; margin: 10px 0 10px;">';
	
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok && $spbc->moderate ? $img : $img_no).'"/>'
			.'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-security_log\')[0])">'
				.__('Brute-Force Protection', 'security-malware-firewall')
			.'</a>';
			
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok && $spbc->moderate ? $img : $img_no).'"/>'
			.'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-traffic_control\')[0])">'
				.__('FireWall', 'security-malware-firewall')
			.'</a>';
			
		if($spbc->scaner_enabled){
			echo '<img class="spbc_status_icon" id="spbc_scanner_status_icon" src="'.($scanner_status ? $img : $img_no).'"/>'
			.'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-scanner\')[0])">'
				.__('Malware Scanner', 'security-malware-firewall')
			.'</a>';
		}
		
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok && $spbc->moderate ? $img : $img_no).'"/>'.__('Security Report', 'security-malware-firewall');
		
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok && $spbc->moderate ? $img : $img_no).'"/>'
			.'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-security_log\')[0])">'
				.__('Security Audit Log', 'security-malware-firewall')
			.'</a>';
			
		echo '<img class="spbc_status_icon" src="'.($ssl_status && $spbc->moderate ? $img : $img_no).'"/>'.$ssl_text;
		
		// Autoupdate status
        if( $spbc->notice_auto_update ){
			echo '<img class="spbc_status_icon" src="'.($spbc->auto_update == 1 ? $img : ($spbc->auto_update == -1 ? $img_no : $img_no_gray)).'"/>'
				.'<a href="http://cleantalk.org/help/cleantalk-auto-update" target="_blank">'
					.__('Auto update', 'security-malware-firewall')
				.'</a>';
		}
		
	echo '</div>';
	echo '<br>';

}

function spbc_tab__summary(){
	echo '<div class="spbc_tab_fields_group">'
		. '<h3 class="spbc_group_header">'. __('Statistics', 'security-malware-firewall') .'</h3>';
		spbc_field_statistics();
	echo '</div>';
	echo '<br>';
	echo '<span id="spbc_gdpr_open_modal" style="text-decoration: underline">'.__('GDPR compliance', 'security-malware-firewall').'</span>';
	echo '<br>';
	echo __('Tech support:', 'security-malware-firewall') . ' <a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall">wordpress.org</a>';
	echo '<br>';
	printf(__('The plugin home page', 'security-malware-firewall') .' <a href="https://wordpress.org/plugins/security-malware-firewall/" target="_blank">%s</a>.', SPBC_NAME);
	echo '<br>';
	echo __('CleanTalk is a registered trademark. All rights reserved.', 'security-malware-firewall');
	echo '<br>';
}

/**
 * Admin callback function - Displays current statistics
 */
function spbc_field_statistics(){
	
	global $spbc;
	
	echo "<div class='spbc_wrapper_field'>";
	
	// Security log statistics
	echo (isset($spbc->data['logs_last_sent'], $spbc->data['last_sent_events_count'])
		? sprintf(__('%d events have been sent to CleanTalk Cloud on %s.', 'security-malware-firewall'), $spbc->data['last_sent_events_count'], date("M d Y H:i:s", $spbc->data['logs_last_sent']))
		: __('Unknown last logs sending time.', 'security-malware-firewall'));
	echo '<br />';

	// Firewall log statistics
	if( is_main_site() ) {
		echo (isset($spbc->fw_stats['last_send'], $spbc->fw_stats['last_send_count'])
			? sprintf(__('Information about %d blocked entries have been sent to CleanTalk Cloud on %s.', 'security-malware-firewall'), $spbc->fw_stats['last_send_count'], date("M d Y H:i:s", $spbc->fw_stats['last_send']))
			: __('Unknown last firewall logs sending time.', 'security-malware-firewall'));
		echo '<br />';
	}

	// Firewall statistics
	echo (isset($spbc->fw_stats['last_updated'], $spbc->fw_stats['entries'])
		? sprintf(__('Security FireWall database has %d IPs. Last updated at %s.', 'security-malware-firewall'), $spbc->fw_stats['entries'], date('M d Y H:i:s', $spbc->fw_stats['last_updated']))
		: __('Unknown last Security FireWall updating time.', 'security-malware-firewall'));
	echo  $spbc->fw_stats['updating_id'] ? ' <b>Under updating now: ' . $spbc->fw_stats['update_percent'] . '%</b>' : '';
	echo '<br />';

	// Scanner statistics
	if($spbc->scaner_enabled){
		echo (isset($spbc->data['scanner']['last_signature_update']) && isset($spbc->data['scanner']['signature_count'])
			? sprintf(__('Malware scanner signatures was updated %s. For now it contains %s entries.', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_signature_update']), $spbc->data['scanner']['signature_count'])
			: __('Malware scanner signatures hasn\'t been updated yet.', 'security-malware-firewall'));
		echo '<br />';
        echo ( ! empty( $spbc->data['scanner']['last_scan'] )
			? sprintf( __('The last scan of this website was on %s', 'security-malware-firewall'), date( 'M d Y H:i:s', $spbc->data['scanner']['last_scan'] ) )
			: __( 'Website hasn\'t been scanned yet.', 'security-malware-firewall' ) );
		echo '<br />';
		if(isset($spbc->data['scanner']['last_sent'])){
			printf(__('Scan results were sent to the cloud at %s', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_sent']));
			echo '<br />';
		}
	}
	
	// PHP log sending statistics
	if( is_main_site() ) {
		echo (isset($spbc->data['last_php_log_sent'], $spbc->data['last_php_log_amount'])
			? sprintf(__('%d errors in PHP log have been sent to CleanTalk Cloud on %s', 'security-malware-firewall'), $spbc->data['last_php_log_amount'], date('M d Y H:i:s', $spbc->data['last_php_log_sent']))
			: __('Unknown last PHP log sending time.', 'security-malware-firewall'));
	}

	echo '<br/>';
	echo 'Plugin version: ' . SPBC_VERSION;

	echo '</div>';
}

function spbc_field_banners(){
	global $spbc_tpl;
	// Rate banner
	// echo sprintf($spbc_tpl['spbc_rate_plugin_tpl'],
		// SPBC_NAME
	// );
	// Translate banner
	if(substr(get_locale(), 0, 2) != 'en'){
		echo sprintf($spbc_tpl['spbc_translate_banner_tpl'],
			substr(get_locale(), 0, 2)
		);
	}
}

/**
 * Admin callback function - Displays field of Api Key
 */
function spbc_field_key( $values = null ) {

	global $spbc;
	
	echo "<div class='spbc_wrapper_field'>";
		
		if(
            is_main_site() ||
		    $spbc->ms__work_mode == 3 ||
		    ( $spbc->ms__work_mode == 1 && is_super_admin() )
        ){
			// Key is OK
			if($spbc->key_is_ok){
				echo '<input
					id="spbc_key"
					name="spbc_settings[spbc_key]"
					size="20"
					type="text"
					value="'.str_repeat('*', strlen($spbc->settings['spbc_key'])).'" key="'.$spbc->settings['spbc_key'].'"
					style="font-size: 14pt;"
					placeholder="' . __('Enter the key', 'security-malware-firewall') . '" />';
				
				// Show account name associated with key
				if(!empty($spbc->data['account_name_ob'])){
					echo '<div class="spbc_hide">'
						.sprintf(
							__('Account at cleantalk.org is %s.', 'cleantalk'),
							'<b>'.$spbc->data['account_name_ob'].'</b>'
						)
					.'</div>';
				}
				echo '<a id="showHideLink" class="spbc-links" style="color:#666;" href="#">'.__('Show Access Key', 'security-malware-firewall').'</a>';

				$additional_links = apply_filters(
					'spct_key_additional_links',
					array()
				);
				if( count( $additional_links ) > 0 ) {
					echo '&nbsp;&nbsp;&nbsp;&nbsp;';
					foreach( $additional_links as $link ) {
						echo $link . '&nbsp;&nbsp;&nbsp;&nbsp;';
					}
				}
			
			// Key is not OK
			}else{
				
				echo '<input id="spbc_key" name="spbc_settings[spbc_key]" size="20" type="text" value="'.$spbc->settings['spbc_key'].'" style=\'font-size: 14pt;\' placeholder="' . __('Enter the key', 'security-malware-firewall') . '" />';
				echo '<br/><br/>';
				echo '<a target="_blank" href="https://cleantalk.org/register?platform=wordpress&email='.urlencode(get_option('admin_email')).'&website='.urlencode(parse_url(get_option( 'home' ), PHP_URL_HOST)).'&product_name=security" style="display: inline-block;">
						<input style="color:#666;" type="button" class="spbc_auto_link" value="'.__('Get access key manually', 'security-malware-firewall').'" />
					</a>';
				echo '&nbsp;'.__('or', 'security-malware-firewall').'&nbsp;';
				echo '<button class="spbc_manual_link" id="spbc_setting_get_key_auto" name="spbc_get_apikey_auto" type="button"  value="get_key_auto">'
				     . __('Get access key automatically', 'security-malware-firewall')
				     . '<img style="margin-left: 10px;" class="spbc_preloader_button" src="' . SPBC_PATH . '/images/preloader2.gif" />'
				     . '<img style="margin-left: 10px;" class="spbc_success --hide" src="' . SPBC_PATH . '/images/yes.png" />'
				     .'</button>';
				echo '<br/><br/>';
				echo '<div style="font-size: 10pt; color: #666 !important">'
					.sprintf(
						__('Admin e-mail (%s) will be used for registration', 'security-malware-firewall'),
						get_option('admin_email')
					)
				.'</div>';
				echo '<div>';
					echo '<input checked type="checkbox" id="license_agreed" onclick="spbcSettingsDependencies(\'get_key_auto\');"/>';
					echo '<label for="spbc_license_agreed">';
						printf(
							__('I agree with %sPrivacy Policy%s of %sLicense Agreement%s', 'security-malware-firewall'),
							'<a href="https://cleantalk.org/publicoffer#privacy" target="_blank" style="color:#66b;">', '</a>',
							'<a href="https://cleantalk.org/publicoffer"         target="_blank" style="color:#66b;">', '</a>'
						);
					echo "</label>";
				echo '</div>';
				
				echo '<input type="hidden" id="spbc_admin_timezone" name="ct_admin_timezone" value="null" />';
			}
			
		}else{
			echo '<h3>' . __('Access key is provided by network administrator.', 'security-malware-firewall') . '</h3>';
		}
		
	echo '</div>';
	
}

function spbc_field_service_utilization(){
    
    global $spbc;
    
    echo '<div class="spbc_wrapper_field">';
    
    if( $spbc->services_count && $spbc->services_max && $spbc->services_utilization ){
        
        echo sprintf(
            __( 'Hoster account utilization: %s%% ( %s of %s websites ).', 'security-malware-firewall' ),
            $spbc->services_utilization * 100,
            $spbc->services_count,
            $spbc->services_max
        );
        
        // Link to the dashboard, so user could extend your subscription for more sites
        if( $spbc->services_utilization * 100 >= 90 ){
            echo '&nbsp';
            echo sprintf(
                __( 'You could extend your subscription %shere%s.', 'security-malware-firewall' ),
                '<a href="' . $spbc->dashboard_link . '" target="_blank">',
                '</a>'
            );
        }
        
    }else{
        _e( 'Enter the Hoster access key and synchronize with cloud to find out your hoster account utilization.', 'security-malware-firewall' );
    }
    
    echo '</div>';
}

function spbc_settings_2fa_description_callback(){

	$user = wp_get_current_user();
	if (isset($user->ID) && $user->ID > 0) {
		$email = $user->user_email;
	} else {
		$email = get_option( 'admin_email' );
	}

    echo '<div style="margin-bottom: 10px" class="spbc_settings_description">'
         . sprintf(
             __('Verification code will be sent to the admin email (%s) to enable the feature.', 'security-malware-firewall'),
	         $email
         )
        . '<br>';
    echo '</div>';
    
}

function spbc_field_2fa__roles() {
	
	global $spbc, $wp_roles;
	
	$wp_roles = new WP_Roles();
	$roles = $wp_roles->get_names();
	
	echo '<div class="spbc_wrapper_field spbc_sub_setting">';
    
        echo '<span class="spbc_settings-field_title spbc_settings-field_title--field">'
             . __( 'Roles that use two-factor authentication (2FA)', 'security-malware-firewall' )
             . '</span>'
             . '<br>';
	    
        echo '<div style="margin-bottom: 10px" class="spbc_settings_description">'
             . __( 'Hold CTRL button to select multiple roles. Users with unselected roles keep log in to your website in a standard way with their logins and passwords.' , 'security-malware-firewall' )
             .'<br><em>'. esc_html__( 'To disable the Google authentication for an account reset the password of that account. Two-factor authentication method will be switched to Email.', 'security-malware-firewall' ) .'</em>'
             . '</div>';
        
		echo '<select multiple="multiple" id="spbc_setting_2fa__roles" name="spbc_settings[2fa__roles][]"'
			.(!$spbc->settings['2fa__enable'] ? ' disabled="disabled"' : '')
			.' size="'.(count($roles)-1 < 6 ? count($roles)-1 : 5).'"'
			. '>';
		
			foreach ($roles as $role){
				if($role == 'Subscriber')
					continue;
				echo '<option'
					.(in_array($role, (array)$spbc->settings['2fa__roles']) ? ' selected="selected"' : '')
					. '>'.$role.'</option>';
			}
		
		echo '</select>';
	
	echo '</div>';
}

function spbc_field_security_logs__prepare_data(&$table){
	
	if($table->items_count){
		
		foreach($table->rows as $row){
			$ips_c[] = $row->auth_ip;
		} unset($row);
		$ips_c = spbc_get_countries_by_ips(implode(',', $ips_c));
		
		$time_offset = current_time('timestamp') - time();
		
		foreach($table->rows as $row){
			
			$user = get_user_by('login', $row->user_login);
			$user_part = sprintf("<a href=\"%s\">%s</a>",
				$user ? (admin_url() . '/user-edit.php?user_id=' .  $user->data->ID) : '#',
				$row->user_login
			);
			
			$page      = $row->page      === null ? '-'           : "<a href='".$row->page."' target='_blank'>".$row->page."</a>";
			
			
			switch($row->event){
				case 'view':
					$event = sprintf(
						__('Viewing admin page (%s)', 'security-malware-firewall'),
						$row->page_time === null
							? 'Calculating'
							: strval($row->page_time).' secoonds'
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
			$ip_part = sprintf("<a href=\"https://cleantalk.org/blacklists/%s\" target=\"_blank\">%s</a>,&nbsp;%s",
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
 
function spbc_field_security_logs($value = array('id' => 'spbc_option_security_logs', 'class' => 'spbc-settings-section')){
	
	global $spbc, $wpdb;
	
	echo '<div class="spbc_wrapper_field">';
	
		if(!$spbc->key_is_ok){
			$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
			$link = sprintf(
				'<a
					href="#"
					onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_key\', action: \'highlight\', times: 3});">%s</a>',
				$button
			);
			echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter access key.', 'security-malware-firewall').'</h3>'.$link.'</div>';
			return;
		}

		// HEADER
		$message_about_log = sprintf(__('This table contains details of all brute-force attacks and security actions made in the past 24 hours. Number of the last records shown: %d. Please, use your %sSecurity Control Panel%s to see the full report.', 'security-malware-firewall'),
			SPBC_LAST_ACTIONS_TO_VIEW,
			'<a target="_blank" href="https://cleantalk.org/my/logs?user_token='.$spbc->user_token.'">',
			'</a>'
		);
		echo "<p class='spbc_hint spbc_hint-security_logs -display--inline-block'>$message_about_log</p>";

		// OUTPUT
		$table = new ListTable(spbc_list_table__get_args_by_type('security_logs' ) );

		$table->get_data();

		// Send logs button
		if($table->items_total)
			echo '<p class="spbc_hint spbc_hint-send_security_log spbc_hint--link spbc_hint--top_right">'
				.__('Send logs', 'security-malware-firewall')
			.'</p>';

		$table->display();

		// SHOW MORE
		if($table->items_total > SPBC_LAST_ACTIONS_TO_VIEW){
			echo '<div class="spbc__wrapper--center spbc__wrapper--show_more">';
				if(!empty($spbc->user_token)){
					echo '<div class="spbc__show_more_logs">'
						."<h3 class='-display--inline-block'>"
							.__('Proceed to:', 'security-malware-firewall')."&nbsp;"
						."</h3>"
						."<a target='_blank' href='https://cleantalk.org/my/logs?service=".$spbc->service_id."&user_token=".$spbc->user_token."' class='spbc_manual_link -display--inline-block'>"
							.__('Security Control Panel', 'security-malware-firewall')
						."</a>"
						."<h3 class='-display--inline-block'>&nbsp;"
							.__('to see more.', 'security-malware-firewall')
						."</h3>"
					.'</div>';
				}
				echo "<div id='spbc_show_more_button' class='spbc_manual_link'>"
					.__('Show more', 'security-malware-firewall')
				."</div>"
				.'<img class="spbc_preloader" src="'.SPBC_PATH.'/images/preloader.gif" />'
			."</div>";
		}
	
	echo '</div>';
	
}

function spbc_field_traffic_control_logs__prepare_data(&$table){
	
	global $spbc;
	
	if($table->items_count){
		
		foreach($table->rows as $row)
			$ip_countries[] = $row->ip_entry;
		$ip_countries = spbc_get_countries_by_ips(implode(',', $ip_countries));
		
		$time_offset = current_time('timestamp') - time();
		
		foreach($table->rows as $row){
			
			$ip = "<a href='https://cleantalk.org/blacklists/{$row->ip_entry}' target='_blank'>".IP::reduceIPv6($row->ip_entry).'</a>'
				.'&nbsp;<sup>'
					."<a href='https://cleantalk.org/my/show_private?service_id={$spbc->service_id}&add_record={$row->ip_entry}&service_type=securityfirewall' target='_blank' class='spbc---gray'>"
						.__('Manage', 'security-malware-firewall').
					'</a>'
				 .'</sup>';
			
			$requests = '<b>'.$row->requests.'</b>';
			
			$page_url =	strlen($row->page_url) >= 60
					 ? '<div class="spbcShortText">'.substr($row->page_url, 0, 60).'...</div>'
					  .'<div class="spbcFullText spbc_hide">'.$row->page_url.'</div>'
					 : $row->page_url;
					 
			$user_agent = strlen($row->http_user_agent) >= 60
					? '<div class="spbcShortText">'.substr($row->http_user_agent, 0, 60).'...</div>'
					 .'<div class="spbcFullText spbc_hide">'.$row->http_user_agent.'</div>'
					: $row->http_user_agent;
			
			switch($row->status){
				case 'PASS':                    $status = '<span class="spbcGreen">' . __('Passed', 'security-malware-firewall').'</span>';
					break;
				case 'PASS_BY_TRUSTED_NETWORK': $status = '<span class="spbcGreen">' . __('Passed. Trusted network. Click on IP for details.', 'security-malware-firewall').'</span>';
					break;
				case 'PASS_BY_WHITELIST':       $status = '<span class="spbcGreen">' . __('Passed. Whitelisted.', 'security-malware-firewall').'</span>';
					break;
				case 'DENY':                    $status = '<span class="spbcRed">'   . __('Blocked. Blacklisted.', 'security-malware-firewall').'</span>';
					break;
				case 'DENY_BY_NETWORK':	        $status = '<span class="spbcRed">'   . __('Blocked. Hazardous network. Common source.', 'security-malware-firewall').'</span>';
					break;
				case 'DENY_BY_DOS':             $status = '<span class="spbcRed">'   . __('Blocked by DoS prevention system', 'security-malware-firewall').'</span>';
					break;
				case 'DENY_BY_SEC_FW':          $status = '<span class="spbcRed">'   . __('Blocked. Hazardous network. Security source.', 'security-malware-firewall').'</span>';
					break;
				case 'DENY_BY_SPAM_FW':         $status = '<span class="spbcRed">'   . __('Blocked. Hazardous network. SFW source', 'security-malware-firewall').'</span>';
					break;
				case 'DENY_BY_BFP':             $status = '<span class="spbcRed">'   . __('Blocked by BruteForce protection system', 'security-malware-firewall').'</span>';
					break;
					
				// WAF
				case 'DENY_BY_WAF_XSS':
					$status = '<span class="spbcRed">' . __('Blocked by Web Application Firewall: XSS attack detected.', 'security-malware-firewall')    . '</span>';
					break;
				case 'DENY_BY_WAF_SQL':
					$status = '<span class="spbcRed">' . __('Blocked by Web Application Firewall: SQL-injection detected.', 'security-malware-firewall') . '</span>';
					break;
				case 'DENY_BY_WAF_FILE':
					$status = '<span class="spbcRed">'
						.__('Blocked by Web Application Firewall: ', 'security-malware-firewall')
						.'<span class="spbc_waf_reason_title">'
							.__('Malicious files upload.', 'security-malware-firewall')
						.'</span>'
						.' <span class="spbc_waf_reason">'
							.__('Reason: ', 'security-malware-firewall')
							// .json_decode($row->pattern, true)
							.$row->pattern
						.'</span>'
						.''
					.'</span>';
					break;
				case 'DENY_BY_WAF_EXPLOIT':
					$status = '<span class="spbcRed">' . __('Blocked by Web Application Firewall: Exploit detected.', 'security-malware-firewall') . '</span>';
					break;
				default: $status = __('Unknown', 'security-malware-firewall'); break;
			}
			
			$table->items[] = array(
				'ip_entry'        => $ip,
				'country'         => spbc_report_country_part($ip_countries, $row->ip_entry),
				'entry_timestamp' => date('M d Y, H:i:s', $row->entry_timestamp + $time_offset),
				'requests'        => $requests,
				'status'          => $status,
				'page_url'        => $page_url,
				'http_user_agent' => $user_agent,
			);
		}
	}
}

function spbc_field_traffic_control_log( $value = array() ){
	
	global $spbc, $wpdb, $spbc_tpl;
	
	echo '<div class="spbc_wrapper_field">';
	
	// Bad key
    if( ! $spbc->key_is_ok ){
		$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
		$link = sprintf(
			'<a
					href="#"
					onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_key\', action: \'highlight\', times: 3});">%s</a>',
			$button
		);
		echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter access key.', 'security-malware-firewall').'</h3>'.$link.'</div>';
		
    // Subscription should be renewed
    }elseif( ! $spbc->moderate ){
		$button = '<input type="button" class="button button-primary" value="'.__('RENEW', 'security-malware-firewall').'"  />';
		$link = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
		echo '<div style="margin-top: 10px;">'
			.'<h3 style="margin: 5px; display: inline-block;">'.__('Please renew your security license.', 'security-malware-firewall').'</h3>'.$link.
		'</div>';
		
    // Subscription is ok
	}else{
		
		$table = new ListTable(spbc_list_table__get_args_by_type('traffic_control' ) );
		
		$table->get_data();
		
		if($table->items_total){
			echo '<p class="spbc_hint spbc_hint--left -display--inline-block">';
				printf(__('This list contains details of access attempts for the past hour and shows only last %d records.', 'security-malware-firewall'),
						SPBC_LAST_ACTIONS_TO_VIEW
					);
					echo "&nbsp;";
				printf(__('The list updates itself every %d seconds automatically.', 'security-malware-firewall'), 60);
			echo '</p>';
			echo "<p class='spbc_hint spbc_hint-send_traffic_control spbc_hint--link spbc_hint--top_right'>Send logs</p>"; // Send logs button
			
		}
		
		echo '<p class="spbc_hint spbc_hint--left -display--inline-block">&nbsp;'
			.sprintf(
				__('Traffic Control blocks visitors who opened more than %s website pages within 1 hour.', 'security-malware-firewall'),
				'<b>'.(isset($spbc->settings['traffic_control__autoblock_amount']) ? $spbc->settings['traffic_control__autoblock_amount'] : 1000).'</b>'
			)
			.' '
			.sprintf(
				__('You can adjust it %shere%s.', 'security-malware-firewall'),
				'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_traffic_control__autoblock_amount\', 3);">',
				'</a>'
			)
		.'</p>';
		echo '<br>';
		echo '<p class="spbc_hint spbc_hint--left -display--inline-block">&nbsp;'
			.sprintf(
				__('Traffic Control is %s.', 'security-malware-firewall'),
				'<b>'.(!empty($spbc->settings['traffic_control__enabled'])
					? __('active', 'security-malware-firewall')
					: __('inactive', 'security-malware-firewall')
					)
				.'</b>'
			)
			.(!empty($spbc->settings['traffic_control__enabled'])
				? ''
				: ' ' . sprintf(
					__('You can activate it %shere%s.', 'security-malware-firewall'),
					'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_traffic_control__enabled\', 3);">',
					'</a>'
				)
			)
		.'</p>';
		echo '<br>';
		echo '<p class="spbc_hint spbc_hint--left -display--inline-block">&nbsp;'
			.sprintf(
				__('Web Application Firewall (WAF) is %s.', 'security-malware-firewall'),
				'<b>'.(!empty($spbc->settings['waf__enabled'])
					? __('active', 'security-malware-firewall')
					: __('inactive', 'security-malware-firewall')
					)
				.'</b>'
			)
			.(!empty($spbc->settings['waf__enabled'])
				? ''
				: ' ' . sprintf(
					__('You can activate it %shere%s.', 'security-malware-firewall'),
					'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_setting_waf__enabled\', 3);">',
					'</a>'
				)
			)
		.'</p>';
		
		$table->display();
		
		if($table->items_total > SPBC_LAST_ACTIONS_TO_VIEW){
			echo "<div class='spbc__wrapper--center spbc__wrapper--show_more'>";
				if($spbc->user_token){
					echo '<div class="spbc__show_more_logs">'
						.'<h3 class="-display--inline-block">'
							.__('Proceed to:', 'security-malware-firewall').'&nbsp;'
						.'</h3>'
						.'<a target="_blank" href="https://cleantalk.org/my/logs_firewall?service='.$spbc->service_id.'&user_token='.$spbc->user_token.'" class="spbc_manual_link -display--inline-block">'
							.__('Security Control Panel', 'security-malware-firewall')
						.'</a>'
						.'<h3 class="-display--inline-block">&nbsp;'
							.__('to see more.', 'security-malware-firewall')
						.'</h3>'
					.'</div>';
				}
				echo "<div id='spbc_show_more_fw_logs_button' class='spbc_manual_link'>"
					.__('Show more', 'security-malware-firewall')
				."</div>"
				.'<img class="spbc_preloader" src="'.SPBC_PATH.'/images/preloader.gif" />'
			."</div>";
		}
	}
	echo '</div>';
}

function spbc_field_scanner__prepare_data__files(&$table){
	
	global $wpdb;
	
	if($table->items_count){
		$root_path = spbc_get_root_path();
		
		$signatures = $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES, OBJECT_K);
		
		foreach($table->rows as $key => $row){
			
			// Filtering row actions
			if($row->last_sent > $row->mtime || $row->size == 0 || $row->size > 1048570) unset($row->actions['send']);
			if(!$row->real_full_hash) unset($row->actions['compare']);
			if(!$row->real_full_hash) unset($row->actions['replace']);
			if(!$row->severity) unset($row->actions['view_bad']);
			if($row->status === 'quarantined') unset($row->actions['quarantine']);
			
			$table->items[] = array(
				'cb'       => $row->fast_hash,
				'uid'      => $row->fast_hash,
				'size'     => substr(number_format($row->size, 2, ',', ' '), 0, -3),
				'perms'    => $row->perms,
				'mtime'    => date('M d Y H:i:s', $row->mtime),
				'path'     => strlen($root_path.$row->path) >= 40
					? '<div class="spbcShortText">...'.$row->path.'</div><div class="spbcFullText spbc_hide">'.$root_path.$row->path.'</div>'
					: $root_path.$row->path,
				'actions' => $row->actions,
			);
			
			if(isset($row->weak_spots)){
				$weak_spots = json_decode($row->weak_spots, true);
				if($weak_spots){
					if(!empty($weak_spots['SIGNATURES']) && $signatures){
						foreach ($weak_spots['SIGNATURES'] as $string => $weak_spot_in_string) {
							foreach ($weak_spot_in_string as $weak_spot) {
								$ws_string = '<span class="spbcRed">'. $signatures[$weak_spot]->attack_type .': </span>'
									.(strlen($signatures[$weak_spot]->name) > 30
										? substr($signatures[$weak_spot]->name, 0, 30).'...'
										: $signatures[$weak_spot]->name);
							}
						}
					}elseif(!empty($weak_spots['CRITICAL'])){
						foreach ($weak_spots['CRITICAL'] as $string => $weak_spot_in_string) {
							foreach ($weak_spot_in_string as $weak_spot) {
								$ws_string = '<span class="spbcRed">Heuristic: </span>'
									.(strlen($weak_spot) > 30
										? substr($weak_spot, 0, 30).'...'
										: $weak_spot);
							}
						}
					}else{
						$ws_string = '';
					}
				}else
					$ws_string = '';
				
				$table->items[$key]['weak_spots'] = $ws_string;
			}
		}
	}
}

function spbc_field_scanner__prepare_data__analysis_log(&$table){
	
	if($table->items_count){
	 
		$root_path = spbc_get_root_path();
		$curr_time = time();
		
		foreach($table->rows as $key => $row){
		    
		    // Don't allow user to check analysis status if the file just has been sent
		    if( $curr_time - $row->last_sent < 600 ){
                unset($row->actions['check_analysis_status']);
            }
		    
		    switch( $row->analysis_status ){
                case 'NEW':
                    $analysis_status = __('Queued for inspection', 'security-malware-firewall');
                    break;
                case 'SAFE':
                    $analysis_status = '<span class="spbcGreen">' . __('Checked. File is safe', 'security-malware-firewall') . '</span>';
                    break;
                case 'DANGEROUS':
                    $analysis_status = '<span class="spbcRed">' . __('Checked. File is dangerous', 'security-malware-firewall') . '</span>';
                    break;
                default:
                    $analysis_status = $row->analysis_status;
            }
		    
            $table->items[$key] = array(
                'cb'               => $row->fast_hash,
                'uid'              => $row->fast_hash,
                'path'             => strlen($root_path . $row->path) >= 40
                    ? '<div class="spbcShortText">...' . $row->path . '</div><div class="spbcFullText spbc_hide">' . $root_path . $row->path . '</div>'
                    : $root_path . $row->path,
                'detected_at'      => is_numeric($row->detected_at) ? date('Y-m-d H:i:s', $row->detected_at) : $row->detected_at,
                'last_sent'        => is_numeric($row->last_sent)   ? date('Y-m-d H:i:s', $row->last_sent)   : $row->last_sent,
                'analysis_status'  => $analysis_status,
                'analysis_comment' => strlen($row->analysis_comment) >= 40
                    ? '<div class="spbcShortText">' . substr($row->analysis_comment, 0, 40) . '...</div><div class="spbcFullText spbc_hide">' . $row->analysis_comment . '</div>'
                    : $row->analysis_comment,
                'actions'          => $row->actions,
            );
		    
		}
		
	}
}


function spbc_field_scanner__prepare_data__files_qurantine(&$table){
	
	if($table->items_count){
		$root_path = spbc_get_root_path();
		foreach($table->rows as $key => $row){
			
			$table->items[] = array(
				'cb'       => $row->fast_hash,
				'uid'      => $row->fast_hash,
				'actions'  => $row->actions,
				'path'     => strlen($root_path.$row->path) >= 40
					? '<div class="spbcShortText">...'.$row->path.'</div><div class="spbcFullText spbc_hide">'.$root_path.$row->path.'</div>'
					: $root_path.$row->path,
				'previous_state' => $row->previous_state,
				'severity' => $row->severity,
				'q_time'   => date('M d Y H:i:s', $row->q_time),
				'size'     => substr(number_format($row->size, 2, ',', ' '), 0, -3),
			);
		}
	}
}

function spbc_field_scanner__prepare_data__domains(&$table){
	if($table->items_count){
		$num = $table->sql['offset']+1;
		foreach($table->rows as $row){
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

function spbc_field_scanner__prepare_data__links(&$table){
	if($table->items_count){
		foreach($table->rows as $row){
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

function spbc_field_scanner__prepare_data__frontend(&$table){
	if($table->items_count){
		foreach($table->rows as $row){
			$table->items[] = array(
				'url'            => "<a href='{$row->url}' target='_blank'>{$row->url}</a>",
				'uid'			 => $row->url,
				'actions'		 => $row->actions,
				'dbd_found'      => $row->dbd_found
					? '<span class="spbcRed">'.__('Found', 'security-malware-firewall').'</span>'
					: '<span class="spbcGreen">'.__('Not found', 'security-malware-firewall').'</span>',
				'redirect_found'      => $row->redirect_found
					? '<span class="spbcRed">'.__('Found', 'security-malware-firewall').'</span>'
                    : '<span class="spbcGreen">'.__('Not found', 'security-malware-firewall').'</span>',
                'csrf'      => $row->csrf
                    ? '<span class="spbcRed">'.__('Found', 'security-malware-firewall').'</span>'
                    : '<span class="spbcGreen">'.__('Not found', 'security-malware-firewall').'</span>',
                'signature'      => $row->signature
                    ? '<span class="spbcRed">'.__('Found', 'security-malware-firewall').'</span>'
                    : '<span class="spbcGreen">'.__('Not found', 'security-malware-firewall').'</span>',
			);
		}
	}
}

/**
 * Counts amount of accessible URL
 *
 * @return int
 */
function spbc_field_scanner__files_listing__get_total(){
    global $spbc;

    if (isset($spbc->scanner_listing['accessible_urls']) && is_array($spbc->scanner_listing['accessible_urls'])) {
        return count($spbc->scanner_listing['accessible_urls']);
    }

    return 0;
}

/**
 * Provides data in the correct format for table
 *
 * @return array of objects
 */
function spbc_field_scanner__files_listing__get_data(){
    global $spbc;

    $out = array();

    if (
        isset($spbc->scanner_listing['accessible_urls']) &&
        (is_array($spbc->scanner_listing['accessible_urls']) || is_object($spbc->scanner_listing['accessible_urls']))
    ) {
        foreach( $spbc->scanner_listing['accessible_urls'] as $entry ){
            $out[] = (object) $entry;
        }
    }

    return $out;
}

function spbc_field_scanner__files_listing__data_prepare(&$table){
    if($table->items_count){
        foreach($table->rows as $row){
            $table->items[] = array(
                'url'            => "<a href='{$row->url}' target='_blank'>" . get_option('home'). "{$row->url}</a>",
                'type'			 => ucfirst( $row->type )
                    . '<i setting="' . $row->type . '" class="spbc_long_description__show spbc-icon-help-circled"></i>',
            );
        }
    }
}


function spbc_field_scanner__log(){
	
	global $spbc;
	
	$out = '<div class="spbc_log-wrapper spbc---hidden"></div>';
	
	return $out;
}

function spbc_field_scanner($params = array()){
	
	global $spbc, $wp_version;
	
	echo '<div class="spbc_wrapper_field">';
 
	// Key is bad
    if( ! $spbc->key_is_ok ){
		
		$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
		$link = sprintf(
			'<a
					href="#"
					onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], {target: \'spbc_key\', action: \'highlight\', times: 3});">%s</a>',
			$button
		);
		echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter access key.', 'security-malware-firewall').'</h3>'.$link.'</div>';
    
    // Subscription bad
    }elseif( ! $spbc->moderate ){
		
		$button = '<input type="button" class="button button-primary" value="'.__('RENEW', 'security-malware-firewall').'"  />';
		$link = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
		echo '<div style="margin-top: 10px;"><h3 style="margin: 5px; display: inline-block;">'.__('Please renew your security license.', 'security-malware-firewall').'</h3>'.$link.'</div>';
    
    // All is ok
	}else{
	
		if(preg_match('/^[\d\.]*$/', $wp_version) !== 1){
			echo '<p class="spbc_hint" style="text-align: center;">';
				printf(__('Your WordPress version %s is not supported', 'security-malware-firewall'), $wp_version);
			echo '</p>';
			// return;
		}
		
		echo '<p class="spbc_hint" style="text-align: center;">';
		echo '<span class="spbc_hint__last_scan_title">';
		if(empty($spbc->data['scanner']['last_scan']))
			_e('System hasn\'t been scanned yet. Please, perform the scan to secure the website.', 'security-malware-firewall');
		elseif($spbc->data['scanner']['last_scan'] < time() - 86400 * 7){
			_e('System hasn\'t been scanned for a long time', 'security-malware-firewall');
		}
		else{
			_e('Look below for scan results.', 'security-malware-firewall');
		}
		echo '</span>';
		echo '</br>';
		printf(
			__('%sView all scan results for this website%s', 'security-malware-firewall'),
            "<a target='blank' href='https://cleantalk.org/my/logs_mscan?service={$spbc->service_id}&user_token={$spbc->user_token}'>",
			'</a>'
		);
		echo '</p>';
		
		echo '<div style="text-align: center;">'
			.'<button id="spbc_perform_scan" class="spbc_manual_link" type="button">'
				.__('Perform Scan', 'security-malware-firewall')
			.'</button>'
			.'<img  class="spbc_preloader" src="'.SPBC_PATH.'/images/preloader.gif" />'
		.'</div>';
		
		echo '<p class="spbc_hint" style="text-align: center; margin-top: 5px;">';
			if( ! empty( $spbc->data['scanner']['last_scan'] ) ){
				printf(
					__('The last scan of this website was on %s, files scanned: %d.', 'security-malware-firewall'),
					date('M d Y H:i:s',$spbc->data['scanner']['last_scan']),
					$spbc->data['scanner']['last_scan_amount']
				);
				if($spbc->settings['scanner__outbound_links'])
					printf(' '.__('Outbound links found: %s.', 'security-malware-firewall'), isset($spbc->data['scanner']['last_scan_links_amount']) ? $spbc->data['scanner']['last_scan_links_amount'] : 0);
			}else
				__('Website hasn\'t been scanned yet.', 'security-malware-firewall');
			
			$task = \CleantalkSP\SpbctWP\Cron::getTask( 'scanner__launch' );
            if( $spbc->settings['scanner__auto_start'] &&
                !empty( $spbc->data['scanner']['last_scan'] ) && isset( $task['next_call'] )
            ){
				printf(
					' '.__('The next automatic scan is scheduled on %s.', 'security-malware-firewall'),
					date('M d Y H:i:s', $task['next_call'] )
				);
			}
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
            if( in_array( Server::get_domain(), array( 'lc', 'loc', 'lh','wordpress' ), true ) ){
                echo '<button id="spbc_scanner_clear" class="spbc_manual_link" type="button">'
                     . __('Clear', 'security-malware-firewall')
                     . '</button>'
                     . '<img class="spbc_preloader" src="'.SPBC_PATH.'/images/preloader.gif" />'
                     . '<br /><br />';
            }
		//*/
		
		echo
		'<div id="spbc_scaner_progress_overall" class="spbc_hide" style="padding-bottom: 10px; text-align: center;">'
			.'<span class="spbc_overall_scan_status_get_cms_hashes">'       . __('Receiving core hashes', 'security-malware-firewall')              .'</span> -> '
			.'<span class="spbc_overall_scan_status_get_modules_hashes">'   . __('Receiving plugin and theme hashes', 'security-malware-firewall').'</span> -> '
			.'<span class="spbc_overall_scan_status_clean_results">'        . __('Preparing', 'security-malware-firewall')                          .'</span> -> '
			.'<span class="spbc_overall_scan_status_file_system_analysis">' . __('Scanning for modifications', 'security-malware-firewall')         .'</span> -> '
			.'<span class="spbc_overall_scan_status_get_approved_hashes">'  . __('Updating statuses for the approved files', 'security-malware-firewall').'</span> -> ';

			if($spbc->settings['scanner__signature_analysis'])
				echo '<span class="spbc_overall_scan_status_signature_analysis">'
                     . __('Signature analysis', 'security-malware-firewall')
                     . '</span> -> ';
			
			if($spbc->settings['scanner__heuristic_analysis'])
				echo '<span class="spbc_overall_scan_status_heuristic_analysis">'
                     . __('Heuristic analysis', 'security-malware-firewall')
                     . '</span> -> ';
			
			if($spbc->settings['scanner__auto_cure']){
				echo '<span class="spbc_overall_scan_status_auto_cure_backup">' . __('Creating a backup', 'security-malware-firewall').'</span> -> ';
				echo '<span class="spbc_overall_scan_status_auto_cure">' . __('Curing', 'security-malware-firewall').'</span> -> ';
			}
			
			if($spbc->settings['scanner__outbound_links'])
				echo '<span class="spbc_overall_scan_status_outbound_links">'.__('Scanning links', 'security-malware-firewall').'</span> -> ';
			
			if($spbc->settings['scanner__frontend_analysis']){
				echo '<span class="spbc_overall_scan_status_frontend_analysis">'.__('Scanning public pages', 'security-malware-firewall').'</span> -> ';
			}
			
			if($spbc->settings['scanner__important_files_listing']){
                echo '<span class="spbc_overall_scan_status_important_files_listing">'.__('Scanning for publicly accessible files', 'security-malware-firewall').'</span> -> ';
			}
			
			echo '<span class="spbc_overall_scan_status_send_results">'.__('Sending results', 'security-malware-firewall').'</span>'
			
		.'</div>';
		echo '<div id="spbc_scaner_progress_bar" class="spbc_hide" style="height: 22px;"><div class="spbc_progressbar_counter"><span></span></div></div>';
		
		// Log style output for scanned files
		
		echo '<div id="spbc_dialog" title="File output" style="overflow: initial;"></div>';
        
       
            
            echo '<div id="spbc_scan_accordion">';
        if( ! empty( $spbc->data['scanner']['last_scan'] ) ){
                spbc_field_scanner__show_accordion( true );
        }
        
                echo '<br>';
                echo spbc_field_scanner__log();
        
                echo '<br>';
                echo spbc_bulk_actions_description();
    
            echo '</div>';
	}
	echo '</div>';
}

function spbc_field_scanner__show_accordion( $direct_call = false ) {
	
	if ( ! $direct_call ){
		check_ajax_referer('spbc_secret_nonce', 'security');
	}
	
	global $spbc;
	
	$tables_files = array(
		'critical'    => __('These files may not contain malicious code but they use very dangerous PHP functions and constructions! PHP developers don\'t recommend to use it and it looks very suspicious.', 'security-malware-firewall'),
		'suspicious'  => __('Found modified executable files', 'security-malware-firewall'),
		'approved'    => __('Approved files. When an approved file is added to the CleanTalk cloud, it will be removed from this list.', 'security-malware-firewall'),
		'quarantined' => __('Punished files.', 'security-malware-firewall'),
        'analysis_log' => __('Files sent for analysis.', 'security-malware-firewall')
	);
	
    if( $spbc->settings['scanner__list_unknown'] ){
        $tables_files['unknown'] = __( 'These files do not include known malware signatures or dangerous code. In same time these files do not belong to the WordPress core or any plugin, theme which are hosted on wordpress.org.', 'security-malware-firewall' );
	}
 
	if($spbc->settings['scanner__outbound_links']){
		$tables_files['outbound_links'] = __('Found outgoing links from this website and websites the links are leading to', 'security-malware-firewall');
	}
	
	if($spbc->settings['scanner__frontend_analysis']){
		$tables_files['frontend_malware'] = __('Malware on public pages found', 'security-malware-firewall');
    }
    
    if( $spbc->settings['scanner__important_files_listing'] ){
        $tables_files['files_listing'] = __('Publicly accessible important files found', 'security-malware-firewall');
    }
    
	foreach($tables_files as $type_name => $description){
		
		$args         = spbc_list_table__get_args_by_type($type_name);
		$args['id']   = 'spbc_tbl__scanner_' . $type_name;
		$args['type'] = $type_name;
		
		$table = new ListTable($args);
		$table->get_data();
		
		// Pass output if empty and said to do so
		if($args['if_empty_items'] !== false || $table->items_total !== 0){
			
			echo '<h3><a href="#">'.ucwords(str_replace('_', ' ', $type_name)).' (<span class="spbc_bad_type_count '.$type_name.'_counter">'.$table->items_total.'</span>)</a></h3>';
			echo '<div id="spbc_scan_accordion_tab_'.$type_name.'">';
			
				echo '<p class="spbc_hint">'
				     . $description
			     . '</p>';
				$table->display();
			
			echo "</div>";
			
		}
		
	}
	
	echo '</div>';
	
	if($direct_call)
		return;
	else
		die('');
}

/**
 * Return arguments for ListTable::__constructor()
 *
 * @param string $table_type
 *
 * @return array
 */
function spbc_list_table__get_args_by_type( $table_type ){
	
	global $spbc;
	
	// Default arguments for file tables
	$accordion_default_args = array(
		'sql' => array(
			'add_col'     => array('fast_hash', 'last_sent', 'real_full_hash', 'severity', 'difference', 'status',),
			'table'       => SPBC_TBL_SCAN_FILES,
			'offset'      => 0,
			'limit'       => SPBC_LAST_ACTIONS_TO_VIEW,
			'get_array'  => false,
		),
		'if_empty_items' => 'NOPE',
		'columns' => array(
			'cb'       => array('heading' => '<input type=checkbox>',	'class' => 'check-column',),
			'path'     => array('heading' => 'Path','primary' => true,),
			'size'     => array('heading' => 'Size, bytes',),
			'perms'    => array('heading' => 'Permissions',),
			'mtime'    => array('heading' => 'Last Modified',),
		),
		'actions' => array(
			'delete'  => array('name' => 'Delete',),
			'view'    => array('name' => 'View', 'handler' => 'spbc_scanner_button_file_view_event(this);',),
		),
		'bulk_actions'  => array(
			'delete'  => array('name' => 'Delete',),
		),
		'sortable' => array('path', 'size', 'perms', 'mtime',),
		'pagination' => array(
			'page'     => 1,
			'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
		),
		'order_by'  => array('path' => 'asc'),
	);
	
	switch( $table_type ){
		
		case 'links':
			$args = array(
				'id' => 'spbc_tbl__scanner__outbound_links',
				'sql' => array(
					'table'     => SPBC_TBL_SCAN_LINKS,
					'get_array' => true,
					'where' => ' WHERE domain = "'.Post::get('domain', null, 'word').'"',
					'get_array'  => false,
				),
				'order_by'  => array('spam_active' => 'asc'),
				'html_before' =>
					 sprintf(__('Links for <b>%s</b> domain.', 'security-malware-firewall'), Post::get('domain', null, 'word')).' '
					.sprintf(__('%sSee all domains%s', 'security-malware-firewall'), '<a href="#" onclick="spbc_scanner__switch_table(this, \'domains\');">','</a>')
					.'<br /><br />',
				'func_data_prepare' => 'spbc_field_scanner__prepare_data__links',
				'if_empty_items' => '<p class="spbc_hint">'.__('No links are found', 'security-malware-firewall').'</p>',
				'columns' => array(
					'link_id'     => array('heading' => __('Number', 'security-malware-firewall'), 'class' => ' tbl-width--50px'),
					'link'        => array('heading' => __('Link', 'security-malware-firewall'), 'primary' => true,),
					'page_url'    => array('heading' => __('Post Page', 'security-malware-firewall'),),
					'link_text'   => array('heading' => __('Link Text', 'security-malware-firewall'),),
					'spam_active' => array(
						'heading' => __('Spam-active', 'security-malware-firewall'),
						'hint' => __('Does link spotted in spam?', 'security-malware-firewall'),
					),
				),
				'sortable' => array('link', 'page_url', 'spam_active'),
			);
			break;
			
		case 'domains':
			$args = array(
				'id' => 'spbc_tbl__scanner__outbound_links',
				'actions' => array(
					'edit_post' => array(
						'name'   => 'Edit',
						'type'   => 'link',
						'local'  => true,
						'edit_post_link' => true,
						'target' => '_blank',
					),
					'show_links' => array(
						'name' => 'Show links',
						'handler' => 'spbc_scanner__switch_table(this, "links");'
					),
				),
				'order_by'  => array('spam_active' => 'desc'),
				'func_data_total'   => 'spbc_scanner_links_count_found__domains',
				'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
				'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
				'if_empty_items' => '<p class="spbc_hint">'.__('No links are found', 'security-malware-firewall').'</p>',
				'columns' => array(
					'num'         => array('heading' => __('Number', 'security-malware-firewall'), 'class' => ' tbl-width--50px'),
					'domain'      => array('heading' => __('Domain', 'security-malware-firewall'), 'primary' => true,),
					'spam_active' => array(
						'heading' => __('Spam-active', 'security-malware-firewall'),
						'hint' => __('Does link spotted in spam?', 'security-malware-firewall'),),
					'link_count'  => array(
						'heading' => __('Links of domain', 'security-malware-firewall'),
						'hint' => __('Number of found links to the domain on site.', 'security-malware-firewall'),),
				),
				'sortable' => array('spam_active', 'domain', 'link_count'),
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
					'backup_id' => array('heading' => 'Number', 'primary' => true,),
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
				'id' => 'spbc_tbl__traffic_control_logs',
				'sql' => array(
					'except_cols' => array('country', 'entries'),
					'add_col'     => array('entry_id','pattern'),
					'table'       => SPBC_TBL_FIREWALL_LOG,
					'offset'      => 0,
					'limit'       => SPBC_LAST_ACTIONS_TO_VIEW,
					'get_array'  => false,
				),
				'order_by'  => array('entry_timestamp' => 'desc'),
				'func_data_prepare' => 'spbc_field_traffic_control_logs__prepare_data',
				'if_empty_items' => '<p class=spbc_hint>'.__("Local log is empty.", 'security-malware-firewall').'</p>',
				'columns' => array(
					'ip_entry' => array(
						'heading' => 'IP',
						'primary' => true,
					),
					'country'         => array('heading' => 'Country',),
					'entry_timestamp' => array('heading' => 'Last Request',),
					'status'          => array('heading' => 'Status',),
					'requests'        => array('heading' => 'Requests', 'class' => ' tbl-width--100px'),
					'page_url'        => array('heading' => 'Page',),
					'http_user_agent' => array('heading' => 'User Agent',),
				),
				'sortable' => array('status', 'entry_timestamp'),
			);
			break;
			
		case 'security_logs':
			$args = array(
				'id' => 'spbc_tbl__secuirty_logs',
				'sql' => array(
					'add_col' => array('id', 'page_time'),
					'table'   => SPBC_TBL_SECURITY_LOG,
					'where'   => (SPBC_WPMS ? ' WHERE blog_id = '.get_current_blog_id() : ''),
					'offset'  => 0,
					'limit'   => SPBC_LAST_ACTIONS_TO_VIEW,
					'get_array' => false,
				),
				'order_by'  => array('datetime' => 'desc'),
				'func_data_prepare' => 'spbc_field_security_logs__prepare_data',
				'if_empty_items' => '<p class="spbc_hint">'.__("0 brute-force attacks have been made.", 'security-malware-firewall').'</p>',
				'columns' => array(
					'user_login' => array('heading' => 'User', 'primary' => true,),
					'auth_ip'    => array('heading' => 'IP',),
					'datetime'   => array('heading' => 'Date',),
					'event'      => array('heading' => 'Action',),
					'page'       => array('heading' => 'Page',),
				),
				'sortable' => array('user_login', 'datetime'),
			);
			break;
		
		case 'critical':
			$args = array_replace_recursive(
				$accordion_default_args,
				array(
					'columns' => array(
						'cb'         => array('heading' => '<input type=checkbox>',	'class' => 'check-column',),
						'path'       => array('heading' => 'Path','primary' => true,),
						'size'       => array('heading' => 'Size, bytes',),
						'perms'      => array('heading' => 'Permissions',),
						'weak_spots' => array('heading' => 'Detected'),
						'mtime'      => array('heading' => 'Last Modified',),
					),
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
					'if_empty_items' => '<p class="spbc_hint">'.__('No threats are found', 'security-malware-firewall').'</p>',
					'actions' => array(
						'send'       => array('name' => 'Send for Analysis',     'tip' => 'Send file to the CleanTalk Cloud for analysis'),
						'approve'    => array('name' => 'Approve',               'tip' => 'Approved file will not be scanned again'),
						'quarantine' => array('name' => 'Quarantine it',         'tip' => 'Place file to quarantine'),
						'replace'    => array('name' => 'Replace with Original', 'tip' => 'Restore the initial state of file'),
						'delete'     => array('name' => 'Delete',),
						'compare'    => array('name' => 'Compare',       'handler' => 'spbc_scanner_button_file_compare_event(this);',),
						'view'       => array('name' => 'View',          'handler' => 'spbc_scanner_button_file_view_event(this);',),
						'view_bad'   => array('name' => 'View Bad Code', 'handler' => 'spbc_scanner_button_file_view_bad_event(this);',),
					),
					'bulk_actions'  => array(
						'send'       => array('name' => 'Send for Analysis',),
						'approve'    => array('name' => 'Approve',),
						'delete'     => array('name' => 'Delete',),
						'replace'    => array('name' => 'Replace with original',),
						'quarantine' => array('name' => 'Quarantine it',),
					),
					'sql' => array(
//								'where' => ' WHERE severity IN("CRITICAL", "DANGER", "SUSPICIOUS") AND status <> "QUARANTINED"',
						'where' => ' WHERE severity IN("CRITICAL") AND status <> "QUARANTINED"',
					)
				)
			);
			break;
			
		case 'suspicious':
			$args = array_replace_recursive(
				$accordion_default_args,
				array(
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
					'order_by'  => array('path' => 'asc'),
					'if_empty_items' => false,
					'actions' => array(
						'send'       => array('name' => 'Send for Analysis', 'tip' => 'Send file to the CleanTalk Cloud for analysis'),
						'approve'    => array('name' => 'Approve', 'tip' => 'Approved file will not be scanned again'),
						'quarantine' => array('name' => 'Quarantine it', 'tip' => 'Place file to quarantine'),
						'replace'    => array('name' => 'Replace with Original', 'tip' => 'Restore the initial state of file'),
						'delete'     => array('name' => 'Delete',),
						'compare'    => array('name' => 'Compare',       'handler' => 'spbc_scanner_button_file_compare_event(this);',),
						'view'       => array('name' => 'View',          'handler' => 'spbc_scanner_button_file_view_event(this);',),
						'view_bad'   => array('name' => 'View Bad Code', 'handler' => 'spbc_scanner_button_file_view_bad_event(this);',),
					),
					'bulk_actions'  => array(
						'send'       => array('name' => 'Send for Analysis',),
						'approve'    => array('name' => 'Approve',),
						'delete'     => array('name' => 'Delete',),
						'replace'    => array('name' => 'Replace with original',),
						'quarantine' => array('name' => 'Quarantine it',),
					),
					'sql' => array(
						'where' => ' WHERE status = "MODIFIED" AND severity <> "CRITICAL"',
					)
				)
			);
			break;
			
        case 'analysis_log':
			$args = array_replace_recursive(
				$accordion_default_args,
				array(
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__analysis_log',
					'if_empty_items' => false,
					'sql' => array(
						'where' => ' WHERE last_sent IS NOT NULL',
					)
				)
			);
			$args['columns'] = array(
                'cb'               => array('heading' => '<input type=checkbox>', 'class' => 'check-column',),
                'path'             => array('heading' => 'Path','primary' => true,),
                'detected_at'      => array('heading' => 'Detected at',),
                'last_sent'        => array('heading' => 'Sent for analysis at',),
                'analysis_status'  => array('heading' => 'Status',),
                'analysis_comment' => array('heading' => 'Comment',),
            );
			$args['actions'] = array(
                'check_analysis_status' => array('name' => 'Check analysis status'),
                'view'                  => array('name' => 'View', 'handler' => 'spbc_scanner_button_file_view_event(this);',),
                'approve'               => array('name' => 'Approve',),
            );
			$args['bulk_actions'] = array(
                'check_analysis_status' => array('name' => 'Check analysis status',),
                'approve'               => array('name' => 'Approve',),
            );
			break;
			
		case 'unknown':
			$args = array_replace_recursive(
				$accordion_default_args,
				array(
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
					'if_empty_items' => false,
					'actions' => array(
                        'send'    => array('name' => 'Send for Analysis',),
						'approve' => array('name' => 'Approve',),
						'view'    => array('name' => 'View',),
					),
					'bulk_actions'  => array(
						'approve' => array('name' => 'Approve',),
					),
					'sql' => array(
						'where' => ' WHERE
						    status NOT IN ("APROVED","APPROVED_BY_CT") AND
						    detected_at >= ' . ( time() - $spbc->settings['scanner__list_unknown__older_than'] * 86400 ) . ' AND
						    source IS NULL AND
		                    path NOT LIKE "%wp-content%themes%" AND
                            path NOT LIKE "%wp-content%plugins%" AND
                            path NOT LIKE "%wp-content%cache%" AND
                            path NOT LIKE "%wp-config.php" AND
						    (severity <> "CRITICAL" OR severity IS NULL)',
					)
				)
			);
			break;
			
		case 'approved':
			$args = array_replace_recursive(
				$accordion_default_args,
				array(
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
					'if_empty_items' => false,
					'actions' => array(
						'disapprove' => array('name' => 'Disapprove',),
					),
					'bulk_actions'  => array(
						'disapprove' => array('name' => 'Disapprove',),
					),
					'sql' => array(
						'where' => ' WHERE status = "APROVED"',
					)
				)
			);
			break;
			
		case 'quarantined':
			$args = array_replace_recursive(
				$accordion_default_args,
				array(
					'func_data_prepare' => 'spbc_field_scanner__prepare_data__files_qurantine',
					'columns' => array(
						'cb'       => array('heading' => '<input type=checkbox>',	'class' => 'check-column',),
						'path'     => array('heading' => 'Path','primary' => true,),
						'previous_state' => array('heading' => 'Status',),
						'severity' => array('heading' => 'Severity',),
						'q_time'   => array('heading' => 'Quarantine time',),
						'size'     => array('heading' => 'Size',),
					),
					'if_empty_items' => false,
					'actions' => array(
						'restore'  => array('name' => 'Restore',),
						'delete'   => array('name' => 'Delete',),
						'view'     => array('name' => 'View', 'handler' => 'spbc_scanner_button_file_view_event(this);',),
						'download' => array(
							'name'   => 'Download',
							'type'   => 'link',
							'local'  => true,
							'uid'    => true,
							'target' => '_blank',
							'href'   => '?plugin_name=security&spbc_remote_call_token='.md5($spbc->settings['spbc_key']).'&spbc_remote_call_action=download__quarantine_file&file_id=',
						),
					),
					'bulk_actions'  =>  array(
						'restore'    => array('name' => 'Restore',),
						'delete'     => array('name' => 'Delete',),
					),
					'sql' => array(
						'add_col' => array_merge($accordion_default_args['sql']['add_col'], array('previous_state', 'q_path', 'q_time',)),
						'where' => ' WHERE status = "QUARANTINED"',
					),
					'sortable' => array('path', 'previous_state', 'severity', 'q_time', 'size',),
				)
			);
			break;
			
		case 'outbound_links':
			$args = array(
				'id' => 'spbc_tbl__scanner__outbound_links',
				'actions' => array(
					'edit_post' => array(
						'name'   => 'Edit',
						'type'   => 'link',
						'local'  => true,
						'edit_post_link' => true,
						'target' => '_blank',
					),
					'show_links' => array(
						'name' => 'Show links',
						'handler' => 'spbc_scanner__switch_table(this, "links");'
					),
				),
				'order_by'  => array('spam_active' => 'desc'),
				'func_data_total'   => 'spbc_scanner_links_count_found__domains',
				'func_data_get'     => 'spbc_scanner_links_get_scanned__domains',
				'func_data_prepare' => 'spbc_field_scanner__prepare_data__domains',
				'if_empty_items' => '<p class="spbc_hint">'.__('No links are found', 'security-malware-firewall').'</p>',
				'columns' => array(
					'num'         => array('heading' => __('Number', 'security-malware-firewall'), 'class' => ' tbl-width--50px'),
					'domain'      => array('heading' => __('Domain', 'security-malware-firewall'), 'primary' => true,),
					'spam_active' => array(
						'heading' => __('Spam-active', 'security-malware-firewall'),
						'hint' => __('Does link spotted in spam?', 'security-malware-firewall'),),
					'link_count'  => array(
						'heading' => __('Links of domain', 'security-malware-firewall'),
						'hint' => __('Number of found links to the domain on site.', 'security-malware-firewall'),),
				),
				'sortable' => array('spam_active', 'domain', 'link_count'),
				'pagination' => array(
					'page'     => 1,
					'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
				),
			);
			break;
			
		case 'frontend_malware':
			$args = array(
				'id' => 'spbc_tbl__scanner_frontend_malware',
				'actions' => array (
					'view'       => array('name' => 'View',          'handler' => 'spbc_scanner_button_page_view_event(this);',),
					'view_bad'   => array('name' => 'View Bad Code', 'handler' => 'spbc_scanner_button_page_view_bad_event(this);',),
				),
				'sql' => array(
					'table'       => SPBC_TBL_SCAN_FRONTEND,
					'offset'      => 0,
					'limit'       => 20,
					'get_array'  => false,
				),
				'func_data_prepare' => 'spbc_field_scanner__prepare_data__frontend',
				'if_empty_items' => __('No malware found', 'security-malware-firewall'),
				'columns' => array(
					'url'            => array('heading' => 'Page','primary' => true,),
					'dbd_found'      => array('heading' => 'Drive by Download',),
					'redirect_found' => array('heading' => 'Redirects',),
					'csrf'           => array('heading' => 'CSRF',),
					'signature'     => array('heading' => 'Signatures',),
				),
				'order_by'  => array('url' => 'asc'),
				'sortable' => array('url', 'dbd_found', 'redirect_found', 'signature', 'csrf'),
				'pagination' => array(
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
            );
        break;
		default:
			$args = $accordion_default_args;
    }
    
    $args['type'] = $table_type;
    
    return $args;
}

function spbc_field_backups__get_data($offset = 0, $limit = 20){
	global $wpdb;
	return $wpdb->get_results(
		'SELECT ' . SPBC_TBL_BACKUPS . '.backup_id, ' . SPBC_TBL_BACKUPS . '.datetime, ' . SPBC_TBL_BACKUPS . '.type, ' . SPBC_TBL_BACKUPED_FILES . '.real_path
		FROM ' . SPBC_TBL_BACKUPS . '
		RIGHT JOIN ' . SPBC_TBL_BACKUPED_FILES . ' ON ' . SPBC_TBL_BACKUPS . '.backup_id = ' . SPBC_TBL_BACKUPED_FILES . '.backup_id
		ORDER BY DATETIME DESC
		LIMIT ' . $offset . ',' . $limit . ';'
	);
}

function spbc_field_backups(){
	
	global $spbc;
	
	echo '<div class="spbc_wrapper_field">';
	
		if(!$spbc->key_is_ok){
		
			$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
			$link = sprintf('<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_key\', 3);">%s</a>', $button);
			echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter access key.', 'security-malware-firewall').'</h3>'.$link.'</div>';

		}elseif(!$spbc->moderate){

			$button = '<input type="button" class="button button-primary" value="'.__('RENEW', 'security-malware-firewall').'"  />';
			$link = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
			echo '<div style="margin-top: 10px;"><h3 style="margin: 5px; display: inline-block;">'.__('Please renew your security license.', 'security-malware-firewall').'</h3>'.$link.'</div>';

		}else{
	
			echo '<p class="spbc_hint" style="text-align: center;">';
				_e('Different types of backups', 'security-malware-firewall');
			echo '</p>';

			echo '<div id="spbc_scan_accordion2">';
				
				$table = new ListTable(spbc_list_table__get_args_by_type('cure_backups' ) );
				$table->get_data();

				// Pass output if empty and said to do so
				if( $table->items_total !== 0 ){

					echo '<h3>'
					     . '<a href="#">'
						     . ucwords(str_replace('_', ' ', 'cure_backups'))
						     . ' <span class="spbc_bad_type_count '.'cure_backups'.'_counter">'
						        . $table->items_total
					            . '</span>'
					        .'</a>'
					     .'</h3>';
					echo '<div id="spbc_scan_accordion_tab_'.'cure_backups'.'">';

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

function spbc_field_debug_drop(){
	echo '<div class="spbc_wrapper_field">'
		.'<br>'
		.'<input form="debug_drop" type="submit" name="spbc_debug__drop" value="Drop debug data" />'
		.'<div class="spbc_settings_description">If you don\'t what is this just push the button =)</div>'
	.'</div>';
}

function spbc_field_debug__check_connection(){
	echo '<div class="spbc_wrapper_field">'
		.'<br>'
		.'<input form="debug_check_connection" type="submit" name="spbc_debug__check_connection" value="Check connection to servers" />'
	.'</div>';
}

function spbc_field_debug__set_fw_update_cron()
{
    global $spbc;
    
	echo '<div class="spbc_wrapper_field">'
		.'<br>'
		.'<input form="debug__cron_set" type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
		.'<input form="debug__cron_set" type="hidden" name="plugin_name"             value="security" />'
		.'<input form="debug__cron_set" type="hidden" name="spbc_remote_call_token"  value="' . md5( $spbc->api_key ) . '" />'
		.'<input form="debug__cron_set" type="hidden" name="task"                    value="firewall_update" />'
		.'<input form="debug__cron_set" type="hidden" name="handler"                 value="spbc_security_firewall_update__init" />'
		.'<input form="debug__cron_set" type="hidden" name="period"                  value="86400" />'
		.'<input form="debug__cron_set" type="hidden" name="first_call"              value="' . ( time() + 60 ) . '" />'
		.'<input form="debug__cron_set" type="submit" name="spbc_debug__fw_update_cron_10_seconds" value="Set FW update to 60 seconds from now" />'
	.'</div>';
}

function spbc_field_debug__set_scan_cron()
{
    global $spbc;
    
	echo '<div class="spbc_wrapper_field">'
		.'<br>'
		.'<input form="debug__cron_set" type="hidden" name="spbc_remote_call_action" value="cron_update_task" />'
		.'<input form="debug__cron_set" type="hidden" name="plugin_name"             value="security" />'
		.'<input form="debug__cron_set" type="hidden" name="spbc_remote_call_token"  value="' . md5( $spbc->api_key ) . '" />'
		.'<input form="debug__cron_set" type="hidden" name="task"                    value="scanner__launch" />'
		.'<input form="debug__cron_set" type="hidden" name="handler"                 value="spbc_scanner__launch" />'
		.'<input form="debug__cron_set" type="hidden" name="period"                  value="86400" />'
		.'<input form="debug__cron_set" type="hidden" name="first_call"              value="' . ( time() + 60 ) . '" />'
		.'<input form="debug__cron_set" type="submit" name="spbc_debug__scan_cron_60_seconds" value="Schedule scan 60 seconds from now" />'
	.'</div>';
}

function spbc_field_debug(){
	global $spbc;
	if($spbc->debug){
		$debug = get_option( SPBC_DEBUG );
		$output = print_r($debug, true);
		$output = str_replace("\n", "<br>", $output);
		$output = preg_replace("/[^\S]{4}/", "&nbsp;&nbsp;&nbsp;&nbsp;", $output);
		echo "<div class='spbc_wrapper_field'>";
			echo $output
			."<label for=''>".
			
			"</label>".
			"<div class='spbc_settings_description'>".
			
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
function spbc_sanitize_settings( $settings ){
	
	global $spbc;
	
	// Set missing settings.
	foreach($spbc->default_settings as $setting => $value){
		if(!isset($settings[$setting])){
			$settings[$setting] = null;
			settype($settings[$setting], gettype($value));
		}
	} unset($setting, $value);
	
	//Sanitizing traffic_control__autoblock_amount setting
	if(isset($settings['traffic_control__autoblock_amount'])){
		$settings['traffic_control__autoblock_amount'] = floor(intval($settings['traffic_control__autoblock_amount']));
		$settings['traffic_control__autoblock_amount'] = ($settings['traffic_control__autoblock_amount'] == 0  ? 1000 : $settings['traffic_control__autoblock_amount']);
		$settings['traffic_control__autoblock_amount'] = ($settings['traffic_control__autoblock_amount'] <  20 ? 20   : $settings['traffic_control__autoblock_amount']);
	}
	
	// XSS: sanitize options
	foreach ( $settings as &$setting ) {
		if( is_scalar( $setting ) ) {
			$setting = preg_replace( '/[<"\'>]/', '', trim( $setting ) );
		}
	}
	
	// Sanitize URLs for redirect login page
	$settings['login_page_rename__name'] = preg_match( '@^[a-zA-Z0-9-/]+$@', $settings['login_page_rename__name'] ) &&
                                           ! in_array(
                                               $settings['login_page_rename__name'],
                                               \CleantalkSP\SpbctWP\RenameLoginPage::getForbiddenSlugs(),
                                               true
                                           )
		? $settings['login_page_rename__name']
		: 'login';
	
	$settings['login_page_rename__redirect'] = preg_match( '@^[a-zA-Z0-9-=/]+$@', $settings['login_page_rename__redirect'] )
                                               || $settings['login_page_rename__redirect'] === ''
		? $settings['login_page_rename__redirect']
		: '';
  
	// Send email notification to admin if about changing login URL
	if( empty( $spbc->settings['login_page_rename__enabled'] ) && $settings['login_page_rename__enabled'] ){
        $mail = wp_mail(
            get_option( 'admin_email' ),
            esc_html__( 'Security by CleanTalk: New login URL', 'security-malware-firewall' ),
            sprintf(
                esc_html__( 'New login URL is: %s' , 'security-malware-firewall' ),
                \CleantalkSP\SpbctWP\RenameLoginPage::getURL( $settings['login_page_rename__name'] )
            )
            . "\n\n"
            . esc_html__( 'Please, make sure that you will not forget the URL!', 'security-malware-firewall' )
        );
        
        // If email is not sent, disabling the feature
        if( ! $mail ){
            $spbc->error_add(
                'login_page_rename',
                __( 'New login URL was not sent. Changes aborted.', 'security-malware-firewall' )
            );
            $settings['login_page_rename__enabled'] = '0';
        }else{
            $spbc->error_delete( 'login_page_rename' );
        }
        
    }
	
	// Send logs for 2 previous days
	if($settings['misc__backend_logs_enable'] && !$spbc->settings['misc__backend_logs_enable']){
		$spbc->data['last_php_log_sent'] = time()-86400*2;
		$spbc->save('data');
	}
    
    if ($settings['scanner__auto_start_manual_time']) {
        $hour_minutes                               = explode( ':', $settings['scanner__auto_start_manual_time'] );
        $settings['scanner__auto_start_manual_tz']   = (int) Post::get( 'user_timezone' );
        $scanner_start_time                         = mktime( (int) $hour_minutes[0], (int) $hour_minutes[1] ) - $settings['scanner__auto_start_manual_tz'] * 3600 + 86400;
        $settings['scanner__auto_start_manual_time'] = date( 'H:i', $scanner_start_time );
        \CleantalkSP\SpbctWP\Cron::updateTask(
            'scanner__launch',
            'spbc_scanner__launch',
            86400,
            $scanner_start_time
        );
    }
    
	// Sanitizing website mirrors
	if($settings['scanner__outbound_links_mirrors']){
		if(preg_match('/^[\sa-zA-Z0-9,_\.\-\~]+$/', $settings['scanner__outbound_links_mirrors'])){
			$tmp = explode(',', $settings['scanner__outbound_links_mirrors']);
			$mirrors = array();
			foreach($tmp as $key => $value){
				$value = trim($value);
				if(!empty($value))
					$mirrors[$key] = trim($value);
			} unset ($key, $value);
			$settings['scanner__outbound_links_mirrors'] = implode(', ', $mirrors);
		}
	}
	
	// Sanitizing scanner dirs exceptions
	if( $settings['scanner__dir_exclusions'] ){
		$dirs = CSV::parseNSV($settings['scanner__dir_exclusions'] );
 		$settings['scanner__dir_exclusions'] = array();
		foreach( $dirs as $dir ){
			if( is_dir( ABSPATH . $dir ) )
				$settings['scanner__dir_exclusions'][] = $dir;
		}
		$settings['scanner__dir_exclusions'] = implode( "\n", $settings['scanner__dir_exclusions'] );
	}
    
    // Sanitizing frontend scanner URL exclusions
    if( $settings['scanner__frontend_analysis__domains_exclusions'] ){
        $urls = CSV::parseNSV($settings['scanner__frontend_analysis__domains_exclusions'] );
        $settings['scanner__frontend_analysis__domains_exclusions'] = array();
        foreach( $urls as $url ){
            if( preg_match('/\S+?\.\S+/', $url) )
                $settings['scanner__frontend_analysis__domains_exclusions'][] = $url;
        }
        $settings['scanner__frontend_analysis__domains_exclusions'] = implode( "\n", $settings['scanner__frontend_analysis__domains_exclusions'] );
        
        // Reset the scanner frontend result if the setting was changed
        if(
            is_main_site() &&
	        (
	        	$settings['scanner__frontend_analysis__domains_exclusions'] !== $spbc->settings['scanner__frontend_analysis__domains_exclusions'] ||
	            $settings['scanner__frontend_analysis__csrf'] !== $spbc->settings['scanner__frontend_analysis__csrf']
	        )
        ){
            Scanner\Frontend::resetCheckResult();
        }
    }
	
	// Sanitizing API key
	$settings['spbc_key'] = trim($settings['spbc_key']);
	$settings['spbc_key'] = preg_match('/^[a-z\d]*$/', $settings['spbc_key'] ) ? $settings['spbc_key'] : $spbc->settings['spbc_key']; // Check key format a-z\d
	$settings['spbc_key'] = is_main_site() || $spbc->ms__work_mode != 2                 ? $settings['spbc_key'] : $spbc->network_settings['spbc_key'];
	$spbc->data['key_changed'] = $settings['spbc_key'] !== $spbc->settings['spbc_key'];
	$spbc->data['key_is_ok'] = spbc_api_key__is_correct( $settings['spbc_key'] );
	$spbc->save('data');
    
    if( $spbc->is_network && $spbc->is_mainsite ){
        
        // @todo Should check unset settings because some hook is saving settings twice
        $spbc->network_settings['spbc_key'] = $settings['spbc_key'];
        
        if( isset( $settings['ms__hoster_api_key'] ) ){
            $spbc->network_settings['ms__hoster_api_key'] = $settings['ms__hoster_api_key'];
            unset( $settings['ms__hoster_api_key'] );
        }
        
        if( isset( $settings['ms__work_mode'] ) ){
            $spbc->network_settings['ms__work_mode'] = $settings['ms__work_mode'];
            unset( $settings['ms__work_mode'] );
        }
        
		$spbc->save('network_settings');
        
        $spbc->network_data = array(
            'key_is_ok'  => $spbc->data['key_is_ok'],
            'user_token' => isset( $spbc->data['user_token'] ) ? $spbc->data['user_token'] : '',
            'service_id' => isset( $spbc->data['service_id'] ) ? $spbc->data['service_id'] : '',
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
function  spbc_get_key_auto($direct_call = false) {

	if ( ! $direct_call ) {
		spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	}

	global $spbc;

	$website  = parse_url( get_option( 'home' ),PHP_URL_HOST ) . parse_url( get_option('home'),PHP_URL_PATH );
	$platform = 'wordpress';
	$user_ip  = \CleantalkSP\SpbctWP\Helpers\IP::get();
	$timezone = Post::get('ct_admin_timezone');
	$language = \CleantalkSP\Variables\Server::get('HTTP_ACCEPT_LANGUAGE');
	$wpms     = SPBC_WPMS && defined('SUBDOMAIN_INSTALL') && !SUBDOMAIN_INSTALL ? true : false;
	$white_label    = null;
	$hoster_api_key = $spbc->ms__hoster_api_key;
	$admin_email = get_option('admin_email');

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

	if( ! empty($result['error'] ) ){

		$spbc->data['key_is_ok'] = false;
		$spbc->error_add('get_key', $result);

		$out = array(
			'success' => true,
			'reload'  => false,
		);

	}else{

		$settings['spbc_key'] = trim($result['auth_key']);
		$settings['spbc_key'] = preg_match('/^[a-z\d]*$/', $settings['spbc_key'] ) ? $settings['spbc_key'] : $spbc->settings['spbc_key']; // Check key format a-z\d
		$settings['spbc_key'] = is_main_site() || $spbc->ms__work_mode != 2        ? $settings['spbc_key'] : $spbc->network_settings['spbc_key'];
		
		$spbc->settings['spbc_key'] = $settings['spbc_key'];
		$spbc->save('settings');

		$spbc->data['user_token'] = (!empty($result['user_token']) ? $result['user_token'] : '');
		$spbc->data['key_is_ok'] = spbc_api_key__is_correct( $settings['spbc_key'] );
		$spbc->data['key_changed'] = true;
		$spbc->save('data');

		$templates = \CleantalkSP\SpbctWP\CleantalkSettingsTemplates::get_options_template( $result['auth_key'] );

		if( ! empty( $templates ) ) {
			$templatesObj = new \CleantalkSP\SpbctWP\CleantalkSettingsTemplates( $result['auth_key'] );
			$out = array(
				'success' => true,
				'getTemplates'  => $templatesObj->getHtmlContent( true ),
			);
		} else {
			$out = array(
				'success' => true,
				'reload'  => true,
			);
		}

	}

	if ( $direct_call ) {
		return $result;
	}

	die( json_encode( $out ) );
}

function spbc_show_more_security_logs_callback(){
	
	check_ajax_referer('spbc_secret_nonce', 'security');
	
	// PREPROCESS INPUT
	$args                 = spbc_list_table__get_args_by_type('security_logs');
	$args['sql']['limit'] = Post::get('amount', 'int') ?: SPBC_LAST_ACTIONS_TO_VIEW;
	
	// OUTPUT
	$table = new ListTable($args );
	$table->get_data();
	
	die(
		json_encode(
			array(
				'html' => $table->display__rows('return'),
				'size' => $table->items_count,
			)
		)
	);
}

function spbc_show_more_security_firewall_logs_callback(){
	
	check_ajax_referer('spbc_secret_nonce', 'security');
	
	$args                 = spbc_list_table__get_args_by_type('traffic_control');
	$args['sql']['limit'] = Post::get('amount', 'int') ?: SPBC_LAST_ACTIONS_TO_VIEW;
	
	// OUTPUT
	$table = new ListTable($args );
	$table->get_data();
	
	if( Post::get('full_refresh') ){
		$table->display();
		die();
	}
	
	die(
		json_encode(
			array(
				'html' => $table->display__rows('return'),
				'size' => $table->items_count,
			)
		)
	);
}

function spbc_settings__get_description(){
	
	global $spbc;
	
	check_ajax_referer('spbc_secret_nonce', 'security');
	
	$setting_id = $_POST['setting_id'] ? $_POST['setting_id'] : '';
	
	$descriptions = array(
		'waf__xss_check'              => array(
			'title' => __( 'XSS check', 'security-malware-firewall' ),
			'desc'  => __( 'Cross-Site Scripting (XSS) — prevents malicious code to be executed/sent to any user. As a result malicious scripts can not get access to the cookie files, session tokens and any other confidential information browsers use and store. Such scripts can even overwrite content of HTML pages. CleanTalk WAF monitors for patterns of these parameters and block them.', 'security-malware-firewall' )
		),
		'waf__sql_check'              => array(
			'title' => __( 'SQL-injection check', 'security-malware-firewall' ),
			'desc'  => __( 'SQL Injection — one of the most popular ways to hack websites and programs that work with databases. It is based on injection of a custom SQL code into database queries. It could transmit data through GET, POST requests or cookie files in an SQL code. If a website is vulnerable and execute such injections then it would allow attackers to apply changes to the website\'s MySQL database.', 'security-malware-firewall' )
		),
		'waf__file_check'             => array(
			'title' => __( 'Check uploaded files', 'security-malware-firewall' ),
			'desc'  => __( 'The option checks each uploaded file to a website for malicious code. If it\'s possible for visitors to upload files to a website, for instance a work resume, then attackers could abuse it and upload an infected file to execute it later and get access to your website.', 'security-malware-firewall' )
		),
		'traffic_control__enabled'    => array(
			'title' => __( 'Traffic Control', 'security-malware-firewall' ),
			'desc'  => __( 'It analyzes quantity of requests towards website from any IP address for a certain period of time. For example, for an ordinary visitor it\'s impossible to generate 2000 requests within 1 hour. Big amount of requests towards website from the same IP address indicates that there is a high chance of presence of a malicious program.', 'security-malware-firewall' )
		),
		'scanner__outbound_links'     => array(
			'title' => __( 'Scan links', 'security-malware-firewall' ),
			'desc'  => __( 'This option allows you to know the number of outgoing links on your website and website addresses they lead to. These websites addresses will be checked with the CleanTalk Database and the results will show if they were used in spam messages. The option\'s purpose is to check your website and find hidden, forgotten and spam links. You should always remember if you have links to other websites which have a bad reputation, it could affect your visitors\' trust and your SEO.', 'security-malware-firewall' )
		),
		'scanner__heuristic_analysis' => array(
			'title' => __( 'Heuristic analysis', 'security-malware-firewall' ),
			'desc'  => __( 'Often, authors of malicious code disguise their code which makes it difficult to identify it by their signatures. The malicious code itself can be placed anywhere on the site, for example the obfuscated PHP-code in the "logo.png" file, and the code itself is called by one inconspicuous line in "index.php". Therefore, the usage of plugins to search for malicious code is preferable. Heuristic analysis can indicate suspicious PHP constructions in a file that you should pay attention to.', 'security-malware-firewall' )
		),
		'scanner__signature_analysis' => array(
			'title' => __( 'Signature analysis', 'security-malware-firewall' ),
			'desc'  => __( 'Code signatures — it\'s a code sequence a malicious program consists of. Signatures are being added to the database after analysis of the infected files. Search for such malicious code sequences is performed in scanning by signatures. If any part of code matches a virus code from the database, such files would be marked as critical.', 'security-malware-firewall' )
		),
		'scanner__auto_cure'          => array(
			'title' => __( 'Cure malware', 'security-malware-firewall' ),
			'desc'  => __( 'It cures infected files automatically if the scanner knows cure methods for these specific cases. If the option is disabled then when the scanning process ends you will be presented with several actions you can do to the found files: Cure. Malicious code will be removed from the file. Replace. The file will be replaced with the original file. Delete. The file will be put in quarantine. Do nothing. Before any action is chosen, backups of the files will be created and if the cure is unsuccessful it\'s possible to restore each file.', 'security-malware-firewall' )
		),
		'misc__backend_logs_enable'        => array(
			'title' => __( 'Collect and send PHP logs', 'security-malware-firewall' ),
			'desc'  => __( 'To control appearing errors you have to check log file of your hosting account regularly. It\'s inconvenient and just a few webmasters pay attention to it. Also, errors could appear for a short period of time and only when one specific function is running, they can\'t be spotted in other circumstances so it\'s hard to catch them. PHP errors tell you that some of your website functionality doesn\'t work correctly, furthermore hackers may use these errors to get access to your website. The CleanTalk Scanner will check your website backend once per hour. Statistics of errors is available in your CleanTalk Dashboard.', 'security-malware-firewall' )
		),
		'data__set_cookies'                => array(
			'title' => __( 'Set cookies', 'security-malware-firewall' ),
			'desc'  => __( 'Part of the CleanTalk FireWall functions depend on cookie files, so disabling this option could lead to deceleration of the firewall work. It will affect user identification who are logged in right now. Traffic Control will not be able to determine authorized users and they could be blocked when the request limit is reached. We do not recommend to disable this option without serious reasons. However, you should disable this option is you\'re using Varnish.', 'security-malware-firewall' )
		),
		'2fa__enable'                 => array(
			'title' => __( 'Two factor authentication for administrators', 'security-malware-firewall' ),
			'desc'  => __( 'Two-Factor Authentication for WordPress admin accounts will improve your website security and make it safer, if not impossible, for hackers to breach your WordPress account. Two-Factor Authentication works via e-mail. Authentication code will be sent to your admin email. When authorizing, a one-time code will be sent to your email. While entering the code, make sure that it does not contain spaces. With your first authorization, the CleanTalk Security plugin remembers your browser and you won’t have to input your authorization code every time anymore. However, if you started to use a new device or a new browser then you are required to input your authorization code. The plugin will remember your browser for 30 days.', 'security-malware-firewall' )
		),
		'data__additional_headers'         => array(
			'title' => __( 'Additional Headers', 'security-malware-firewall' ),
			'desc'  => __( '"X-Content-Type-Options" improves the security of your site (and your users) against some types of drive-by-downloads. <br> "X-XSS-Protection" header improves the security of your site against some types of XSS (cross-site scripting) attacks.', 'security-malware-firewall' )
		),
		'wp__disable_xmlrpc'             => array(
			'title' => __( 'Disable XML-RPC', 'security-malware-firewall' ),
			'desc'  => __( 'XML-RPC is an out-of-date technology that can compromise websites. It is still enabled by default in WordPress for the purpose of reverse compatibility for some parts of information systems like old apps on phones and tablets. Please, make sure that you don\'t use such obsolete systems. If you don\'t know anything about it it\'s a good practice to enable this option and disable the XML-RPC.<br><br>Enabled XML-RPC could give hackers a possibility to brute-force your website credentials and access your website.', 'security-malware-firewall' )
		),
        'ms__work_mode' => array(
            'title' => __( 'WordPress Multisite Work Mode', 'security-malware-firewall' ),
            'desc'  => __(
                    '<h4>Mutual Account, Individual Access Keys</h4>'
                    . '<span>Each blog uses a separate key from the network administrator account. Each blog has its own separate security log, settings, personal lists. Key will be provided automatically to each blog once it is created or during the plugin activation process. The key could be changed only by the network administrator.</span>'
                    . '<h4>Mutual Account, Mutual Access Key</h4>'
                    . '<span>All blogs use one mutual key. They also share security logs, settings and personal lists with each other. Network administrator holds the key.</span>'
                    . '<h4>Individual accounts, individual Access keys</h4>'
                    . '<span>Each blog uses its own account and its own key. Separate security logs, settings, personal lists. Blog administrator can change the key on his own.</span>'
                , 'security-malware-firewall' )
        ),
        'ms__hoster_api_key'             => array(
            'title' => __( 'Hoster access key', 'security-malware-firewall' ),
            'desc'  => __( 'You could find it here:<br><a href ="https://cleantalk-screenshots.s3.amazonaws.com/help/hosting-antispam/hapi-ru.png"><img src="https://cleantalk-screenshots.s3.amazonaws.com/help/hosting-antispam/hapi-ru.png"></a><br>Press on the screenshot to zoom.', 'security-malware-firewall' )
        ),
        'listing' => array(
            'title' => __( 'Directory can be listed from the Internet', 'security-malware-firewall' ),
            'desc'  => __( 'The listing of a directory allows an attacker to see the files inside the folder and the very existence of the folder. So if he sees ".git" folder is open for the listing, he can assume that you are using GIT technology and could exploit the known security issues to hack the website.', 'security-malware-firewall' )
        ),
        'accessible' => array(
            'title' => __( 'File is accessible from the Internet', 'security-malware-firewall' ),
            'desc'  => __( 'Anyone who knows the location of the file could download its content. This could sound pretty harmless, but in fact if this file is an error log, the attacker could identify the modules and plugins you are using and get some additional info about his hack attempts.', 'security-malware-firewall' )
        ),
        'action_shuffle_salts'                 => array(
            'title' => 'Shuffle Salts',
            'desc'  => __( 'WordPress secret keys and salts are a random set of symbols that are being used in encrypting the 
                    usernames and passwords that are being stored in the browser cookies. If the site has been hacked, 
                    all data on the site can be considered compromised. One of the first important recommendations is 
                    to change all passwords and security keys. If hackers have the security keys, they can regain 
                    access to the site even if the passwords have been changed. It is very important to change each 
                    security key along with the passwords when the malicious code is removed.', 'security-malware-firewall' )
        ),
	);
	
	die(json_encode($descriptions[$setting_id]));
}

function spbc_show_GDPR_text(){

	return wpautop('The notice requirements remain and are expanded. They must include the retention time for personal data, and contact information for data controller and data protection officer has to be provided.
	Automated individual decision-making, including profiling (Article 22) is contestable, similarly to the Data Protection Directive (Article 15). Citizens have rights to question and fight significant decisions that affect them that have been made on a solely-algorithmic basis. Many media outlets have commented on the introduction of a "right to explanation" of algorithmic decisions, but legal scholars have since argued that the existence of such a right is highly unclear without judicial tests and is limited at best.
	To be able to demonstrate compliance with the GDPR, the data controller should implement measures, which meet the principles of data protection by design and data protection by default. Privacy by design and by default (Article 25) require data protection measures to be designed into the development of business processes for products and services. Such measures include pseudonymising personal data, by the controller, as soon as possible (Recital 78).
	It is the responsibility and the liability of the data controller to implement effective measures and be able to demonstrate the compliance of processing activities even if the processing is carried out by a data processor on behalf of the controller (Recital 74).
	Data Protection Impact Assessments (Article 35) have to be conducted when specific risks occur to the rights and freedoms of data subjects. Risk assessment and mitigation is required and prior approval of the national data protection authorities (DPAs) is required for high risks. Data protection officers (Articles 37–39) are required to ensure compliance within organisations.
	They have to be appointed:')
	.'<ul style="padding: 0px 25px; list-style: disc;">'
		.'<li>for all public authorities, except for courts acting in their judicial capacity</li>'
		.'<li>if the core activities of the controller or the processor are:</li>'
			.'<ul style="padding: 0px 25px; list-style: disc;">'
				.'<li>processing operations, which, by virtue of their nature, their scope and/or their purposes, require regular and systematic monitoring of data subjects on a large scale</li>'
				.'<li>processing on a large scale of special categories of data pursuant to Article 9 and personal data relating to criminal convictions and offences referred to in Article 10;</li>'
			.'</ul>'
		.'</li>'
	.'</ul>';
}

// Ajax handler of spbctGenerateConfirmationCode() from js
function spbctGenerateAndSendConfirmationCode() {

	$user = wp_get_current_user();
	if (isset($user->ID) && $user->ID > 0) {
		$email = $user->user_email;
	} else {
		$email = get_option( 'admin_email' );
	}

	spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    
    $confirmation_code = get_site_option( 'spbc_confirmation_code', false );
    $save_code = true;
    
    // Code is outdated. Generate a new code
    if( ! isset( $confirmation_code['generate_time'] ) || $confirmation_code['generate_time'] + 10 * 60 < time() ){
        
        $confirmation_code = array(
            'code' => rand ( 1000 , 9999 ),
            'generate_time' => time(),
        );
        
        $save_code = update_site_option( 'spbc_confirmation_code', $confirmation_code );
    }
    
    if( isset( $confirmation_code['code'] ) ){
        
        if( $save_code === true ) {
            
            $mail_result = wp_mail(
	            $email,
                esc_html__( 'Security by CleanTalk confirmation code', 'security-malware-firewall' ),
                sprintf(
                    esc_html__( 'Security by CleanTalk. Two-Factor Authentication Code on %s - %s', 'security-malware-firewall' ),
                    get_home_url(),
                    $confirmation_code['code']
                )
            );
            
            if( $mail_result ) {
                wp_send_json_success();
            }else
                wp_send_json_error( __( 'Confirmation code not send!', 'security-malware-firewall' ) );
        }else
            wp_send_json_error( __( 'Confirmation code not saved!', 'security-malware-firewall' ) );
    }else
        wp_send_json_error( __( 'Confirmation code generation error!', 'security-malware-firewall' ) );
}

// Ajax handler of spbctCheckConfirmationCode() from js
function spbctCheckConfirmationCode() {

	spbc_check_ajax_referer('spbc_secret_nonce', 'security');

	if( ! isset( $_POST['code'] ) ) {
		wp_send_json_error('Confirmation code not provided!');
	}

	$code = filter_input( INPUT_POST, 'code', FILTER_SANITIZE_NUMBER_INT );

	$get_code = get_site_option( 'spbc_confirmation_code' );

	if( $get_code && array_key_exists( 'code', $get_code ) && array_key_exists( 'generate_time', $get_code ) ) {
		if( $get_code['code'] == $code && $get_code['generate_time'] + 10*60 > time() ) { //Code is live for 10 minutes
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
function spbc_settings__check_renew_banner() {
	spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	global $spbc;
	die(json_encode(array(
		'close_renew_banner' => $spbc->data['notice_show'] == 0
			? true
			: false
	)));
}

/**
 * Descriptions for scanner results actions.
 * @return string
 */
function spbc_bulk_actions_description() {
	
	$description = __('You are able to perform the following actions on the found files:', 'security-malware-firewall');
	
	$actions = array(
		'delete' => array(
			'title' => esc_html__( 'Delete', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'Delete the chosen file from your website file system in a safe way. You should be careful with this action as there is no turing back.', 'security-malware-firewall' )
		),
		'view' => array(
			'title' => esc_html__( 'View', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'View the chosen file.', 'security-malware-firewall' )
		),
		'send' => array(
			'title' => esc_html__( 'Send for Analysis', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'Send the chosen file to the CleanTalk Cloud for analysis.', 'security-malware-firewall' ),
		),
		'approve' => array(
			'title' => esc_html__( 'Approve', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'Approve the chosen file so it will not be scanned again. You can always disapprove it in the "Approved" category.', 'security-malware-firewall' )
		),
		'quarantine' => array(
			'title' => esc_html__( 'Quarantine', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'Put the chosen file to quarantine where it can not harm the website.', 'security-malware-firewall' )
		),
		'replace' => array(
			'title' => esc_html__( 'Replace', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'Restore the initial state of the chosen file if the file is accessible. It applies only to the WordPress core files.', 'security-malware-firewall' )
		),
		'compare' => array(
			'title' => esc_html__( 'Compare', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'View the difference between the original WordPress core file and the one you have in your website.', 'security-malware-firewall' )
		),
		'view_bad' => array(
			'title' => esc_html__( 'View Malicious Code', 'security-malware-firewall' ),
			'tip'   => esc_html__( 'View malicious code that was found by the scanner, so you can inspect it more clearly.', 'security-malware-firewall' )
		),
	);
	
	$description = '<ul>';
	$description .= esc_html__( 'Available actions on the found files:', 'security-malware-firewall' );
	
	$action_description =array();
	foreach( $actions as $action ){
// @todo description with tooltips
//		$action_description[] =
//			' <u>' . $action['title'] . '</u>'
//            . ' <i class="spbc_popup_tip--spbc-icon---show spbc-icon-help-circled" spbc_tip_title="' . ucfirst( $action['title'] ) . '" spbc_tip_text="' . $action['tip'] . '"></i>';
		$action_description[] =
			'<li><strong>' . ucfirst( $action['title'] ) . ':</strong> ' . $action['tip']  . '</li>';
	}
	
	$description .= implode( '', $action_description );
	$description .= '</u>';
	$description .= __('The actions are available only after scanning your website.', 'security-malware-firewall');
	
	return $description;
	
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
function spbc_settings_field__action_shuffle_salts() {
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
        <button type="button" id="action-shuffle-salts" class="button button-primary <?= $button_disabled; ?>" style="margin: 5px 0 0 10px;">
            <?= __('Shuffle salts', 'security-malware-firewall'); ?>
        </button>
    </div>
    <?php
}