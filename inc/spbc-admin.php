<?php

use CleantalkSP\Common\Helper;
use CleantalkSP\SpbctWp\Helper as SpbcHelper;
use CleantalkSP\SpbctWp\API as SpbcAPI;
use CleantalkSP\Variables\Cookie;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;

// Settings page
require_once('spbc-settings.php'); 

/**
 * Admin action 'admin_init' - Add the admin settings and such
 */
function spbc_admin_init() {
	
	global $spbc;
	
	// Drop debug data
	if(!empty(Post::get('spbc_debug__drop'))){
		$spbc->deleteOption('debug', 'use_prefix');
	}
	
	// Drop debug data
	if(!empty(Post::get('spbc_debug__check_connection'))){
		$result = spbc_test_connection();
		spbc_log($result);
	}
	
	//Get auto key button
	if (isset($_POST['spbc_get_apikey_auto'])){
		
		$website  = parse_url(get_option('siteurl'),PHP_URL_HOST);
		$platform = 'wordpress';
		$user_ip  = SpbcHelper::ip__get(array('real'));
		$timezone = filter_input(INPUT_POST, 'ct_admin_timezone');
		$language = filter_input(INPUT_SERVER, 'HTTP_ACCEPT_LANGUAGE');
		$wpms     = SPBC_WPMS && defined('SUBDOMAIN_INSTALL') && !SUBDOMAIN_INSTALL ? true : false;
		$white_label    = null;
		$hoster_api_key = null;
		
		$result = SpbcAPI::method__get_api_key(
			'security',
			get_option('admin_email'),
			$website,
			$platform,
			$timezone,
			$language,
			$user_ip,
			$wpms,
			$white_label,
			$hoster_api_key
		);
		
		if(!empty($result['error'])){
				
			$spbc->data['key_is_ok'] = false;
			$spbc->error_add('get_key', $result);
			
		}else{
			
			$_POST['spbc_settings']['spbc_key'] = $result['auth_key'];
			
			$spbc->data['user_token'] = (!empty($result['user_token']) ? $result['user_token'] : '');
			$spbc->data['key_is_ok'] = true;
			$spbc->save('data');
			
			$spbc->settings['spbc_key'] = $result['auth_key'];
			$spbc->save('settings');
			
		}
	}
		
	//Logging admin actions
	if(!defined( 'DOING_AJAX' ))
		spbc_admin_log_action();
	
	// Admin bar
	if(spbc_is_user_role_in(array('administrator'))){
		add_action( 'admin_bar_menu', 'spbc_admin__admin_bar__add', 999 );
	}
	
	// AJAX Actions
	
	// Logs
	add_action('wp_ajax_spbc_show_more_security_logs',          'spbc_show_more_security_logs_callback');
	add_action('wp_ajax_spbc_show_more_security_firewall_logs', 'spbc_show_more_security_firewall_logs_callback');
	
	// Scanner
	add_action('wp_ajax_spbc_scanner_get_remote_hashes',     'spbc_scanner_get_remote_hashes');
	add_action('wp_ajax_spbc_scanner_count_plug',            'spbc_scanner_count_hashes_plug');
	add_action('wp_ajax_spbc_scanner_get_remote_hashes_plug','spbc_scanner_get_remote_hashes__plug');
	add_action('wp_ajax_spbc_scanner_get_remote_hashes_approved','spbc_scanner_get_remote_hashes__approved');	
	add_action('wp_ajax_spbc_scanner_clear_table',           'spbc_scanner_clear_table');
	add_action('wp_ajax_spbc_scanner_count_files',           'spbc_scanner_count_files');
	add_action('wp_ajax_spbc_scanner_scan',                  'spbc_scanner_scan');
	add_action('wp_ajax_spbc_scanner_count_files__by_status','spbc_scanner_count_files__by_status');
	add_action('wp_ajax_spbc_scanner_scan_heuristic',        'spbc_scanner_scan_heuristic');
	add_action('wp_ajax_spbc_scanner_scan_signatures',       'spbc_scanner_scan_signatures');
	add_action('wp_ajax_spbc_scanner_backup_sigantures',     'spbc_backup__files_with_signatures');
	add_action('wp_ajax_spbc_scanner_count_cure',            'spbc_scanner_count_cure');
	add_action('wp_ajax_spbc_scanner_cure',                  'spbc_scanner_cure');
	add_action('wp_ajax_spbc_scanner_count_links',		     'spbc_scanner_links_count');	
	add_action('wp_ajax_spbc_scanner_scan_links',		     'spbc_scanner_links_scan');	
	add_action('wp_ajax_spbc_scanner_frontend__count',		 'spbc_scanner_frontend__count');
	add_action('wp_ajax_spbc_scanner_frontend__scan',		 'spbc_scanner_frontend__scan');
	add_action('wp_ajax_spbc_scanner_clear',                 'spbc_scanner_clear');
	
	// Scanner buttons
	add_action('wp_ajax_spbc_scanner_send_results', 'spbc_scanner_send_results');
	add_action('wp_ajax_spbc_scanner_file_send',    'spbc_scanner_file_send');
	add_action('wp_ajax_spbc_scanner_file_delete',  'spbc_scanner_file_delete');
	add_action('wp_ajax_spbc_scanner_file_approve', 'spbc_scanner_file_approve');
	add_action('wp_ajax_spbc_scanner_file_view',    'spbc_scanner_file_view');
	add_action('wp_ajax_spbc_scanner_page_view',    'spbc_scanner_page_view');
	add_action('wp_ajax_spbc_scanner_file_edit',    'spbc_scanner_file_edit');
	add_action('wp_ajax_spbc_scanner_file_compare', 'spbc_scanner_file_compare');
	add_action('wp_ajax_spbc_scanner_file_replace', 'spbc_scanner_file_replace');
	
	// Settings
	add_action('wp_ajax_spbc_settings__draw_elements', 'spbc_settings__draw_elements');
	
	// SPBC Table
	add_action('wp_ajax_spbc_tbl-action--row', array('CleantalkSP\SpbctWp\ListTable', 'ajax__row_action_handler'));
	add_action('wp_ajax_spbc_tbl-pagination',  array('CleantalkSP\SpbctWp\ListTable', 'ajax__pagination_handler'));
	add_action('wp_ajax_spbc_tbl-sort',        array('CleantalkSP\SpbctWp\ListTable', 'ajax__sort_handler'));
	add_action('wp_ajax_spbc_tbl-switch',      array('CleantalkSP\SpbctWp\ListTable', 'ajax__switch_table'));
	
	// Send logs_mscan
	add_action('wp_ajax_spbc_send_traffic_control', 'spbc_send_firewall_logs', 1, 0);
	add_action('wp_ajax_spbc_send_security_log', 'spbc_send_logs', 1, 0);
	
	// WAF. Notification about blocked file.
	add_action('wp_ajax_spbc_check_file_block', array('CleantalkSP\SpbctWp\FireWall\ClassWAF_WP', 'waf_file__get_last_blocked_info'));
	
	// Backups
	add_action('wp_ajax_spbc_rollback',         'spbc_rollback');
	add_action('wp_ajax_spbc_backup__delete',   'spbc_backup__delete');
	
	// Misc
	add_action('wp_ajax_spbc_settings__get_description',   'spbc_settings__get_description');
	add_action('wp_ajax_spbc_settings__check_renew_banner','spbc_settings__check_renew_banner');
	add_action('wp_ajax_spbc_sync',                        'spbc_sync');

	// Confirm the email to activate 2FA
	add_action('wp_ajax_spbc_generate_confirmation_code',   'spbctGenerateConfirmationCode');
	add_action('wp_ajax_spbc_check_confirmation_code',      'spbctCheckConfirmationCode');

}

//
//Admin notice
//
function spbc_admin_notice_message(){
	
	global $spbc;

	$page = get_current_screen();
	$plugin_settings_link = '<a href="'. (is_network_admin() ? 'settings.php' : 'options-general.php' ) .'?page=spbc">'.__('Security by CleanTalk', 'security-malware-firewall').'</a>';
		
	// Auto update notice
	/** Temporary disabled */
	/* if($spbc->notice_auto_update && $spbc->auto_update != -1 && empty($_COOKIE['spbc_update_banner_closed'])){
		$link 	= '<a href="http://cleantalk.org/help/auto-update" target="_blank">%s</a>';
		$button = sprintf($link, '<input type="button" class="button button-primary" value="'.__('Learn more', 'security-malware-firewall').'"  />');
		echo '<div class="error notice is-dismissible spbc_update_notice">'
			.'<h3>'
				.__('Do you know that Security by CleanTalk has auto update option?', 'cleantalk')
				.'</br></br>'
				.$button
			.'</h3>'
		.'</div>';
	} */
	
	// Trial ends
	// On settings page only
	if($spbc->show_notice && $spbc->trial && ($page->id == 'settings_page_spbc' || $page->id == 'settings_page_spbc-network')){
		
		$button = '<input type="button" class="button button-primary" value="'.__('UPGRADE', 'security-malware-firewall').'"  />';
		$link = sprintf(
			'<a  target="_blank"  style="vertical-align: super;" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>',
			$spbc->user_token,
			$button
		);
		
		echo '<div class="error um-admin-notice notice" id="spbc_trial_notice" style="position: relative;">'
				.'<h3>'
					.'<u>'.$plugin_settings_link.'</u>: '
					. __('Trial period is now over, please upgrade to premium version to keep your site secure and safe!', 'security-malware-firewall')
				.'</h3>'
				.'<h4 style = "color: gray;">' . esc_html__( 'Account status updates every minute.', 'security-malware-firewall' ) . '</h4>'
				.'<p>'.$link.'</p>'
			.'</div>';
		return;
	}
	
	// Renew. Licence ends
	if($spbc->show_notice && $spbc->renew){
		
		$spbc->error_delete_all( 'save' );
		
		$button = '<input type="button" class="button button-primary" value="'.__('RENEW', 'security-malware-firewall').'"  />';
		$link = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
		
		echo '<div class="error um-admin-notice notice" id="spbc_renew_notice" style="position: relative;">
				<h3>
					<u>'. $plugin_settings_link .'</u>: '
					. __('Please renew your security license.', 'security-malware-firewall').
				'</h3>'.
				'<h4 style = "color: gray;">Account status updates every minute.</h4>'.
				$link.
				'<br><br>
			</div>';
		return;
	}
	
	// Wrong key
	// On every page except settings page
	if(!$spbc->key_is_ok && $page->id != 'settings_page_spbc' && $page->id != 'settings_page_spbc-network'){
		
		echo '<div class="error um-admin-notice notice" style="position: relative;">';
			
			if(is_network_admin())
				printf('<h3><u>'. $plugin_settings_link .'</u>: ' . __('API key is not valid. Enter into %splugin settings%s in the main site dashboard to get API key.', 'security-malware-firewall') . '</h3>', '<a href="'. get_site_option('siteurl') .'wp-admin/settings.php?page=spbc">', '</a>');
			else
				printf('<h3><u>'. $plugin_settings_link .'</u>: ' . __('API key is not valid. Enter into %splugin settings%s to get API key.', 'security-malware-firewall') . '</h3>', '<a href="options-general.php?page=spbc">', '</a>');
			
			if($spbc->were_updated)
				printf('<h3>'. __('Why do you need an API key? Please, learn more %shere%s.', 'security-malware-firewall'). '</h3>', '<a href="https://wordpress.org/support/topic/why-do-you-need-an-access-key-updated/">', '</a>');
			
			echo '<button type="button" class="notice-dismiss"><span class="screen-reader-text">' .__('Dismiss this notice.', 'security-malware-firewall'). '</span></button>';
		echo '</div>';
	}
}

/**
 * Manage links in plugins list
 * @return array
*/
function spbc_plugin_action_links($links, $file) {
	
	$settings_link = is_network_admin()
		? '<a href="settings.php?page=spbc">' . __( 'Settings' ) . '</a>'
		: '<a href="options-general.php?page=spbc">' . __( 'Settings' ) . '</a>';
	
	array_unshift( $links, $settings_link ); // before other links
	
	// Add "Start scan" link only of the main site
	if(is_main_site()){
		$start_scan = is_network_admin()
			? '<a href="settings.php?page=spbc&spbc_tab=scanner&spbc_target=spbc_perform_scan&spbc_action=click">' . __('Start scan') . '</a>'
			: '<a href="options-general.php?page=spbc&spbc_tab=scanner&spbc_target=spbc_perform_scan&spbc_action=click">' . __('Start scan') . '</a>';
		array_unshift($links, $start_scan); // before other links
	}
	
	$trial = spbc_badge__get_premium(false);
	if(!empty($trial))
		array_unshift($links, spbc_badge__get_premium(false));
	
	return $links;
}

/**
 * Manage links and plugins page
 * @return array
*/
function spbc_plugin_links_meta($meta, $plugin_file){
	
	//Return if it's not our plugin
	if(strpos($plugin_file, SPBC_PLUGIN_BASE_NAME) === false)
		return $meta;
	
	// $links[] = is_network_admin()
		// ? '<a class="ct_meta_links ct_setting_links" href="settings.php?page=spbc">' . __( 'Settings' ) . '</a>'
		// : '<a class="ct_meta_links ct_setting_links" href="options-general.php?page=spbc">' . __( 'Settings' ) . '</a>';
	
	if(substr(get_locale(), 0, 2) != 'en')
		$meta[] = '<a class="spbc_meta_links spbc_translate_links" href="'
				.sprintf('https://translate.wordpress.org/locale/%s/default/wp-plugins/security-malware-firewall', substr(get_locale(), 0, 2))
				.'" target="_blank">'
				.__('Translate', 'security-malware-firewall')
			.'</a>';
	$meta[] = '<a class="spbc_meta_links spbc_faq_links" href="http://wordpress.org/plugins/security-malware-firewall/faq/" target="_blank">' . __('FAQ', 'security-malware-firewall') . '</a>';
	$meta[] = '<a class="spbc_meta_links spbc_support_links" href="https://wordpress.org/support/plugin/security-malware-firewall" target="_blank">' . __('Support', 'security-malware-firewall') . '</a>';
	
	return $meta;
}

/**
 * Register stylesheet and scripts.
 */
function spbc_enqueue_scripts($hook) {

	// If the user is not admin
	if( ! current_user_can( 'upload_files' ) ){
		return;
	}
	
	global $spbc;
	
	// For ALL admin pages
	wp_enqueue_style ('spbc_admin_css', SPBC_PATH . '/css/spbc-admin.min.css', array(), SPBC_VERSION, 'all');

	wp_enqueue_script('spbc-common-js', SPBC_PATH . '/js/spbc-common.min.js', array('jquery'), SPBC_VERSION, false);
	wp_enqueue_script('spbc-admin-js',  SPBC_PATH . '/js/spbc-admin.min.js',  array('jquery'), SPBC_VERSION, false);
	
	wp_localize_script('spbc-common-js', 'spbcSettings', array(
		'wpms'         => (int)is_multisite(),
		'is_main_site' => (int)is_main_site(),
		'tc_enabled'   => $spbc->tc_enabled ? 1 : 0,
		'img_path'     => SPBC_PATH . '/images',
		'key_is_ok'    => $spbc->key_is_ok,
		'ajax_nonce'   => wp_create_nonce("spbc_secret_nonce"),
		'ajaxurl'      => admin_url('admin-ajax.php'),
		'debug'        => !empty($debug) ? 1 : 0,
	));
	
	if($spbc->settings['waf_file_check'] && in_array($hook, array('upload.php', 'media-new.php'))){
		wp_enqueue_script('spbc-upload-js',  SPBC_PATH . '/js/spbc-upload.min.js', array('jquery'), SPBC_VERSION, false);
	}
	
	// For settings page
	if($hook == 'settings_page_spbc'){
		
		$debug = get_option( SPBC_DEBUG );
		
		$button_template = '<button %sclass="spbc_scanner_button_file_%s">%s<img class="spbc_preloader_button" src="'.SPBC_PATH.'/images/preloader.gif" /></button>';
			
		$button_template_send     = sprintf($button_template, '', 'send',     __('Send for analysys', 'security-malware-firewall'));
		$button_template_delete   = sprintf($button_template, '', 'delete',   __('Delete', 'security-malware-firewall'));
		$button_template_approve  = sprintf($button_template, '', 'approve',  __('Approve', 'security-malware-firewall'));
		$button_template_view     = sprintf($button_template, '', 'view',     __('View', 'security-malware-firewall'));
		$button_template_view_bad = sprintf($button_template, '', 'view_bad', __('View bad code', 'security-malware-firewall'));
		$button_template_edit     = sprintf($button_template, '', 'edit',     __('Edit', 'security-malware-firewall'));
		$button_template_replace  = sprintf($button_template, '', 'replace',  __('Replace with original', 'security-malware-firewall'));
		$button_template_compare  = sprintf($button_template, '', 'compare',  __('Show difference', 'security-malware-firewall'));
		
		$actions_unknown  = $button_template_send.$button_template_delete.$button_template_approve.$button_template_view;
		$actions_modified = $button_template_approve.$button_template_replace.$button_template_compare.$button_template_view_bad;
		
		// CSS
		wp_enqueue_style ('spbc-icons',        SPBC_PATH . '/css/spbc-icons.min.css',    array(),          SPBC_VERSION, 'all');
		wp_enqueue_style ('spbc-settings',     SPBC_PATH . '/css/spbc-settings.min.css', array(),          SPBC_VERSION, 'all');
		wp_enqueue_style ('spbc-table',        SPBC_PATH . '/css/spbc-table.min.css',    array(),          SPBC_VERSION, 'all');
		wp_enqueue_style ('jquery-ui',         SPBC_PATH . '/css/jquery-ui.min.css', array(),              '1.12.1',     'all');
		
		// JS
		wp_enqueue_script('jquery-ui',         SPBC_PATH . '/js/jquery-ui.min.js',   array('jquery'),      '1.12.1',     'in_footer');
		wp_enqueue_script('spbc-settings-js',  SPBC_PATH . '/js/spbc-settings.min.js',   array('jquery'),  SPBC_VERSION, 'in_footer');
		wp_enqueue_script('spbc-table-js',     SPBC_PATH . '/js/spbc-table.min.js',      array('jquery'),  SPBC_VERSION, 'in_footer');
		
		wp_localize_script('spbc-settings-js', 'spbcSettingsSecLogs', array(
			'amount'     => SPBC_LAST_ACTIONS_TO_VIEW,
			'clicks'     => 0,
		));
		
		wp_localize_script('spbc-settings-js', 'spbcSettingsFWLogs', array(
			'tc_status'  => $spbc->tc_status ? 1 : 0,
			'amount'     => SPBC_LAST_ACTIONS_TO_VIEW,
			'clicks'     => 0,
		));
		
		wp_localize_script('spbc-settings-js', 'spbcTable', array(
			'warning_bulk'       => __('Are sure you want to perform these actions?', 'security-malware-firewall'),
			'warning_default'    => __('Do you want to proceed?', 'security-malware-firewall'),
			'warning_delte'      => __('This can\'t be undone and could damage your website. Are you sure?', 'security-malware-firewall'),
			'warning_replace'    => __('This can\'t be undone. Are you sure?', 'security-malware-firewall'),
			'warning_quarantine' => __('This can\'t be undone and could damage your website. Are you sure?', 'security-malware-firewall'),
		));
		
		wp_localize_script('spbc-settings-js', 'spbcScaner', array(
			
			// PARAMS
			
			// Settings / Statuses
			'scaner_enabled'    => $spbc->tc_status ? 1 : 0,
			'scaner_status'     => $spbc->tc_status ? 1 : 0,
			'check_links'       => $spbc->settings['scanner_outbound_links']      ? 1 : 0,
			'check_heuristic'   => $spbc->settings['scanner_heuristic_analysis']  ? 1 : 0,
			'check_signature'   => $spbc->settings['scanner_signature_analysis']  ? 1 : 0,
			'auto_cure'         => $spbc->settings['scanner_auto_cure']           ? 1 : 0,
			'check_frontend'    => $spbc->settings['scanner_frontend_analysis']   ? 1 : 0,
			'wp_content_dir'    => realpath(WP_CONTENT_DIR),
			'wp_root_dir'       =>  realpath(ABSPATH),
			// Params
			'on_page' => 20,
			// Templates
			'row_template'  => '<tr type="%s" class="spbc_scan_result_row" file_id="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
			'row_template_links'=>'<tr class="spbc_scan_result_row"><td><a href=%s target="_blank">%s</a></td><td><a href=%s target="_blank">%s</a></td><td>%s</td></tr>',			
			'actions_unknown'  => $actions_unknown,
			'actions_modified' => $actions_modified,
			'page_selector_template' => '<li class="pagination"><a href="#" class="spbc_page" type="%s" page="%s"><span%s>%s</span></a></li>',
			
			//TRANSLATIONS
			
			//Confirmation
			'scan_modified_confiramation' => __('There is more than 30 modified files and this could take time. Do you want to proceed?', 'security-malware-firewall'),
			'warning_about_cancel' => __('Scan will be performed in the background mode soon.', 'security-malware-firewall'),
			'delete_warning' => __('Are you sure you want to delete the file? It can not be undone.'),
			// Buttons
			'button_scan_perform'                   => __('Perform scan', 'security-malware-firewall'),
			'button_scan_pause'                     => __('Pause scan',   'security-malware-firewall'),
			'button_scan_resume'                    => __('Resume scan',  'security-malware-firewall'),
			// Progress bar
			'progressbar_get_hashes'                => __('Receiving hashes', 'security-malware-firewall'),
			'progressbar_count_hashes_plug'         => __('Counting plugins and themes', 'security-malware-firewall'),
			'progressbar_get_hashes_plug'           => __('Receiving plugins hashes', 'security-malware-firewall'),
			'progressbar_get_hashes_approved'       => __('Updating status for approved files', 'security-malware-firewall'),
			'progressbar_clear_table'               => __('Preparing',        'security-malware-firewall'),
			// Scanning core
			'progressbar_count'                     => __('Counting files',             'security-malware-firewall'),
			'progressbar_scan'                      => __('Scanning for modifications', 'security-malware-firewall'),
			'progressbar_count_modified_heur'       => __('Counting not checked',        'security-malware-firewall'),
			'progressbar_scan_modified_heur'        => __('Heuristic analysis',         'security-malware-firewall'),
			'progressbar_count_modified_sign'       => __('Counting not checked',        'security-malware-firewall'),
			'progressbar_scan_modified_sign'        => __('Searching for signatures',    'security-malware-firewall'),
			//Cure
			'progressbar_cure_backup'               => __('Backuping', 'security-malware-firewall'),
			'progressbar_count_cure'                => __('Count cure', 'security-malware-firewall'),
			'progressbar_cure'                      => __('Cure', 'security-malware-firewall'),
			// Links
			'progressbar_count_links'               => __('Counting links', 'security-malware-firewall'),
			'progressbar_scan_links'                => __('Scanning links', 'security-malware-firewall'),
			// Frontend
			'progressbar_frontend_count'            => __('Counting pages', 'security-malware-firewall'),
			'progressbar_frontend_scan'             => __('Scanning pages', 'security-malware-firewall'),
			// Other
			'progressbar_send_results'              => __('Sending results', 'security-malware-firewall'),
			// Warnings
			'result_text_bad_template' => __('Recommend to scan all (%s) of the found files to make sure the website is secure.', 'security-malware-firewall'),
			'result_text_good_template' => __('No threats are found.', 'security-malware-firewall'),
			//Misc
			'look_below_for_scan_res' => __('Look below for scan results.', 'security-malware-firewall'),
			'view_all_results'        => sprintf(
				__('</br>%sView all scan results for this website%s', 'security-malware-firewall'),
				'<a target="blank" href="https://cleantalk.org/my/logs_mscan?service='.$spbc->service_id.'">',
				'</a>'
			),
			'last_scan_was_just_now'        => __('Website last scan was just now. %s files were scanned.', 'security-malware-firewall'),
			'last_scan_was_just_now_links'  => __('Website last scan was just now. %s files were scanned. %s outbound links were found.', 'security-malware-firewall'),
		));
		
		wp_localize_script('spbc-settings-js', 'spbcDescriptions', array(
			'waf_enabled' => __('Bla bla', 'security-malware-firewall'),
			'waf_xss_check' => __('Cross-Site Scripting (XSS) — prevents malicious code to be executed/sent to any user. As a result malicious scripts can not get access to the cookie files, session tokens and any other confidential information browsers use and store. Such scripts can even overwrite content of HTML pages. CleanTalk WAF monitors for patterns of these parameters and block them.', 'security-malware-firewall'),
			'waf_sql_check' => __('SQL Injection — one of the most popular ways to hack websites and programs that work with databases. It is based on injection of a custom SQL code into database queries. It could transmit data through GET, POST requests or cookie files in an SQL code. If a website is vulnerable and execute such injections then it would allow attackers to apply changes to the website\'s MySQL database.', 'security-malware-firewall'),
			'waf_file_check' => __('The option checks each uploaded file to a website for malicious code. If it\'s possible for visitors to upload files to a website, for instance a work resume, then attackers could abuse it and upload an infected file to execute it later and get access to your website.', 'security-malware-firewall'),
			'traffic_control_enabled' => __('It analyzes quantity of requests towards website from any IP address for a certain period of time. For example, for an ordinary visitor it\'s impossible to generate 2000 requests within 1 hour. Big amount of requests towards website from the same IP address indicates that there is a high chance of presence of a malicious program.', 'security-malware-firewall'),
			'scanner_outbound_links' => __('This option allows you to know the number of outgoing links on your website and website addresses they lead to. These websites addresses will be checked with the CleanTalk Database and the results will show if they were used in spam messages. The option\'s purpose is to check your website and find hidden, forgotten and spam links. You should always remember if you have links to other websites which have a bad reputation, it could affect your visitors\' trust and your SEO.', 'security-malware-firewall'),
			'scanner_heuristic_analysis' => __('Often, authors of malicious code disguise their code which makes it difficult to identify it by their signatures. The malicious code itself can be placed anywhere on the site, for example the obfuscated PHP-code in the "logo.png" file, and the code itself is called by one inconspicuous line in "index.php". Therefore, the usage of plugins to search for malicious code is preferable. Heuristic analysis can indicate suspicious PHP constructions in a file that you should pay attention to.', 'security-malware-firewall'),
			'scanner_signature_analysis' => __('Code signatures — it\'s a code sequence a malicious program consists of. Signatures are being added to the database after analysis of the infected files. Search for such malicious code sequences is performed in scanning by signatures. If any part of code matches a virus code from the database, such files would be marked as critical.', 'security-malware-firewall'),
			'scanner_auto_cure' => __('It cures infected files automatically if the scanner knows cure methods for these specific cases. If the option is disabled then when the scanning process ends you will be presented with several actions you can do to the found files: Cure. Malicious code will be removed from the file. Replace. The file will be replaced with the original file. Delete. The file will be put in quarantine. Do nothing. Before any action is chosen, backups of the files will be created and if the cure is unsuccessful it\'s possible to restore each file.', 'security-malware-firewall'),
			'backend_logs_enable' => __('To control appearing errors you have to check log file of your hosting account regularly. It\'s inconvenient and just a few webmasters pay attention to it. Also, errors could appear for a short period of time and only when one specific function is running, they can\'t be spotted in other circumstances so it\'s hard to catch them. PHP errors tell you that some of your website functionality doesn\'t work correctly, furthermore hackers may use these errors to get access to your website. The CleanTalk Scanner will check your website backend once per hour. Statistics of errors is available in your CleanTalk Dashboard.', 'security-malware-firewall'),
			'set_cookies' => __('Part of the CleanTalk FireWall functions depend on cookie files, so disabling this option could lead to deceleration of the firewall work. It will affect user identification who are logged in right now. Traffic Control will not be able to determine authorized users and they could be blocked when the request limit is reached. We do not recommend to disable this option without serious reasons. However, you should disable this option is you\'re using Varnish.', 'security-malware-firewall'),
			'2fa_enable' => __('Two-Factor Authentication for WordPress admin accounts will improve your website security and make it safer, if not impossible, for hackers to breach your WordPress account. Two-Factor Authentication works via e-mail. Authentication code will be sent to your admin email. When authorizing, a one-time code will be sent to your email. While entering the code, make sure that it does not contain spaces. With your first authorization, the CleanTalk Security plugin remembers your browser and you won’t have to input your authorization code every time anymore. However, if you started to use a new device or a new browser then you are required to input your authorization code. The plugin will remember your browser for 30 days.', 'security-malware-firewall'),			
		));
	}
}


function spbc_admin_add_script_attribute($tag, $handle, $src) {
	
	$async_scripts = array(
		//'jquery-ui',
		//'spbc-common-js',
		'spbc-scannerplugin-js',
		'spbc-scaner-events-js',
		'spbc-scaner-callbacks-js',
	);
	
	$defer_scripts = array(
		'spbc-settings-js',
		'spbc-scaner-js',
	);
	
    if(in_array($handle, $async_scripts))
		return str_replace( ' src', ' async="async" src', $tag );
	elseif(in_array($handle, $defer_scripts))
		return str_replace( ' src', ' defer="defer" src', $tag );
	else
		return $tag;
}

/*
 * Logging admin action
*/
function spbc_admin_log_action() {
	
    $user = wp_get_current_user();

	$secure_cookies = array();

	try {
		$secure_cookies = spbc_get_secure_cookies();
	} catch ( Exception $e ) {
		// @ToDo for the handling failing cookies testing
	}

	if( ! empty( $secure_cookies ) ) {
		try {
			spbc_write_timer( $secure_cookies );
		} catch ( Exception $e ) {
			error_log( $e->getMessage() );
		}
	}

    if (isset($user->ID) && $user->ID > 0) {

		$roles = (is_array($user->roles) && !empty($user->roles) ? reset($user->roles) : null); // Takes only first role.

        $log_id = spbc_auth_log(array(
            'username' => $user->get('user_login'),
            'event' => 'view',
			'page' => Server::get('REQUEST_URI'),
			'blog_id' => get_current_blog_id(),
			'roles' => $roles
        ));
    }

	//Seting timer with event ID
	if( isset( $log_id ) ){

		$cookies_arr = array(
			'spbc_log_id' => $log_id,
			'spbc_timer'  => time()
		);

		try {
			spbc_set_secure_cookies( $cookies_arr );
		} catch ( Exception $e ) {
			error_log( $e->getMessage() );
		}

	}

    return;
}

/**
 * Calculates and writes page time to DB
 *
 * @param $timer               array of the row like array('spbc_log_id' => $log_id, 'spbc_timer'  => time())
 *
 * @throws Exception           throws if the query faults
 */
function spbc_write_timer($timer){

	if( empty( $timer ) ) {
		throw new Exception( 'SPBC: Can not update the logs table (cookies was not provided).');
	}

	global $wpdb;

	$result = $wpdb->update(
		SPBC_TBL_SECURITY_LOG,
		array ('page_time' => strval(time()-$timer['timer'])),
		array ('id' => $timer['log_id']),
		'%s',
		'%s'
    );

	if( false === $result ) {
		throw new Exception( 'SPBC: Can not update the logs table.');
	}

}

function spbc_badge__get_premium($print = true, $make_it_right = false, $out = ''){
	
	global $spbc;
	
	if($spbc->data['license_trial'] == 1 && !empty($spbc->user_token)){
		$out = '<b style="display: inline-block; margin-top: 10px;">'
			.($make_it_right ? __('Make it right!', 'cleantalk').' ' : '')
			.sprintf(
				__('%sGet premium%s', 'cleantalk'),
				'<a href="https://cleantalk.org/my/bill/security?user_token='.$spbc->user_token.'" target="_blank">',
				'</a>'
			)
		.'</b>';
	}
	
	if($print)
		echo $out;
	else
		return $out;
}

function spbc_admin__admin_bar__add( $wp_admin_bar ) {
	
	global $spbc;
	
	if ($spbc->trial == 1) {
        
		$args = array(
			'id'	=> 'spbc_parent_node',
			'title' => 
				//'<img src="' . plugin_dir_url(__FILE__) . 'images/logo_small1.png" alt=""  height="" style="margin-top:9px; float: left;" />'
				'<div style="margin: auto 7px;" class="ab-item alignright">'
					.'<div class="ab-label" id="ct_stats">'
						."<span><a style='color: red;' href=\"https://cleantalk.org/my/bill/security?utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%20backend%20renew_security&user_token={$spbc->user_token}&cp_mode=security\" target=\"_blank\">Renew Security</a></span>"
					.'</div>'
				.'</div>' //You could change widget string here by simply deleting variables
		);
		$wp_admin_bar->add_node( $args );
	}
}

/**
 * Setting up secure cookies
 *
 * @param $cookies            array of the cookies to be set
 *
 * @throws Exception          error_log errors of setting cookies
 */
function spbc_set_secure_cookies( $cookies ) {

	if( headers_sent() ) {
		throw new Exception( 'SPBC: Secure cookies does not set (headers already sent).' );
	}

	if( ! is_array( $cookies ) || empty( $cookies ) ) {
		throw new Exception( 'SPBC: Secure cookies does not set (there are not cookies).' );
	}

	global $spbc;
	$domain = parse_url(get_option('siteurl'),PHP_URL_HOST);
	$success = array();

	$cookie_test_value = array(
		'cookies_names' => array(),
		'check_value' => $spbc->settings['spbc_key'],
	);

	foreach( $cookies as $cookie_name => $cookie_value ) {

		$success[] = Helper::cookie_set($cookie_name, $cookie_value, 0, '/', $domain, false, true);

		$cookie_test_value['cookies_names'][] = $cookie_name;
		$cookie_test_value['check_value'] .= $cookie_value;

	}

	$cookie_test_value['check_value'] = md5($cookie_test_value['check_value']);
	$success[] = Helper::cookie_set('spbc_cookies_test', urlencode(json_encode($cookie_test_value)), 0, '/', $domain, false, true);

	if ( in_array( false, $success ) ) {
		throw new Exception( 'SPBC: Secure cookies does not set (setcookie error).' );
	}

}

/**
 * Getting the secure cookies
 *
 * @return array       array of cookies
 * @throws Exception   throws if our $_COOKIE not set
 */
function spbc_get_secure_cookies() {

	$secure_cookies = array();

	if( Cookie::get('spbc_cookies_test') ) {

		$cookie_test = json_decode(urldecode(Cookie::get('spbc_cookies_test')),true);
		if( ! is_array($cookie_test) ) {
			throw new Exception( 'SPBC: Secure cookies does not get (there are not cookies).' );
		}

		$check_secure_cookies = spbc_validate_secure_cookies( $cookie_test );

		if( ! $check_secure_cookies ) {
			throw new Exception( 'SPBC: Secure cookies does not get (cookies was malformed).' );
		} else {

			foreach( $cookie_test['cookies_names'] as $cookie_name ){
				if( Cookie::get($cookie_name) ) {
					$cookie_name_prepared = str_replace( 'spbc_', '', $cookie_name );
					$secure_cookies[$cookie_name_prepared] = Cookie::get($cookie_name);
				}
			}

		}

	}

	return $secure_cookies;

}

/**
 * Check if cookies was not malformed
 *
 * @param $cookies_arr    array of cookies
 *
 * @return bool           true|false
 */
function spbc_validate_secure_cookies( $cookies_arr ) {

	global $spbc;

	$check_string = $spbc->settings['spbc_key'];
	foreach( $cookies_arr['cookies_names'] as $cookie_name ){
		$check_string .= Cookie::get($cookie_name);
	} unset($cookie_name);

	if( $cookies_arr['check_value'] == md5( $check_string ) ){
		return true;
	} else {
		return false;
	}

}