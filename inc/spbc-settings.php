<?php

// Scanner AJAX actions
require_once(SPBC_PLUGIN_DIR . 'inc/spbc-scanner.php');

/*
 * Contactins setting page functions
 * Included from /security-malware-firewall.php -> /inc/spbc-admin.php
 */

/**
 * Admin action 'admin_menu' - Add the admin options page
 */
function spbc_admin_add_page() {
	
	global $spbc;
	
	//Adding setting page
	if(is_network_admin())
		add_submenu_page("settings.php", __( SPBC_NAME . ' Settings', 'security-malware-firewall'), SPBC_NAME, 'manage_options', 'spbc', 'spbc_settings_page');
	else
		add_options_page(                __( SPBC_NAME . ' Settings', 'security-malware-firewall'), SPBC_NAME, 'manage_options', 'spbc', 'spbc_settings_page');
	
	//Adding setting menu
    register_setting(SPBC_SETTINGS, SPBC_SETTINGS, 'spbc_sanitize_settings');
	
	//Adding menu sections
	add_settings_section('spbc_section_status',              '', 'spbc_section_security_status', 'spbc');
	
	add_settings_section('spbc_protection_section',          '', 'spbc_section_protection',      'spbc');
	add_settings_section('spbc_statistics_section',          '', 'spbc_section_statistics',      'spbc');
	
	add_settings_section('spbc_banners_section',             '', 'spbc_section_banners',         'spbc');
	
	
	add_settings_section('spbc_debug_section',               '', 'spbc_section_debug',           'spbc');
	
	add_settings_section('spbc_key_section',                 '', 'spbc_section_key',             'spbc');
	add_settings_section('spbc_security_section',            '', 'spbc_section_security',        'spbc');
	add_settings_section('spbc_misc_section',                '', 'spbc_section_misc',            'spbc');
	
	add_settings_section('spbc_security_log_section',        '', 'spbc_section_security_log',    'spbc');
	add_settings_section('spbc_traffic_control_log_section', '', 'spbc_section_traffic_control', 'spbc');

	add_settings_section('spbc_scaner_section',              '', 'spbc_section_scaner',          'spbc');
	add_settings_section('spbc_scaner_options_section',      '', 'spbc_section_scaner_options',  'spbc');

	//ADDING FIELDS
	
	
	
	// STATUS
		// Security status field
		add_settings_field('spbc_security_status', '', 'spbc_field_security_status', 'spbc', 'spbc_section_status');
		
	// SUMMARY PROTECTION
		// Security status field
		add_settings_field('spbc_security_info', '', 'spbc_field_protection', 'spbc', 'spbc_protection_section');
		
	// SUMMARY STATISTICS
		// Security status field
		add_settings_field('spbc_security_info', '', 'spbc_field_statistics', 'spbc', 'spbc_statistics_section');
	
	//BANNERS
		add_settings_field('spbc_banners', '', 'spbc_field_banners', 'spbc', 'spbc_banners_section');
	
	// SETTINGS GENERAL KEY
		//Key field
		add_settings_field('spbc_apikey', '', 'spbc_field_key', 'spbc', 'spbc_key_section');
		
		//Allow custom key for WPMS field
		if(is_main_site() && SPBC_WPMS){
			add_settings_field('spbc_allow_custom_key', '', 'spbc_field_custom_key', 'spbc', 'spbc_key_section');
		}
		
	// SETTINGS GENERAL TRAFFIC CONTROL
		// Enable TC
		add_settings_field('spbc_traffic_control_enabled', '', 'spbc_field_traffic_control_enabled', 'spbc', 'spbc_security_section');
		// TC amount of request to block 
		add_settings_field('spbc_traffic_control_autoblock_requests_amount', '', 'spbc_field_traffic_control_autoblock_requests_amount', 'spbc', 'spbc_security_section');
	
	// SCANNER SETTINGS
		if($spbc->scaner_status){
			// Scan for outbound links
			add_settings_field('spbc_scan_outbound_links', '', 'spbc_field_scan_outbound_links', 'spbc', 'spbc_scaner_options_section');
			add_settings_field('spbc_scan_outbound_links_mirrors', '', 'spbc_field_scan_outbound_links_mirrors', 'spbc', 'spbc_scaner_options_section');
			// Heuristic analysis
			add_settings_field('spbc_heuristic_analysis', '', 'spbc_field_heuristic_analysis', 'spbc', 'spbc_scaner_options_section');
		}
	
	// SETTINGS GENERAL MISCELLANEOUS
		//Show link in registration form field
		add_settings_field('spbc_show_link_in_login_form', '', 'spbc_field_show_link_login_form', 'spbc', 'spbc_misc_section');
		
		// Settings Only for main blog
		if(is_main_site()){
			
			// Set cookies
			add_settings_field('spbc_set_cookies', '', 'spbc_field_set_cookies', 'spbc', 'spbc_misc_section');
			// Complete deactivation
			add_settings_field('spbc_complete_deactivation', '', 'spbc_field_complete_deactivation', 'spbc', 'spbc_misc_section');
		}
	
	// SECURITY LOG SECTION
		//Security log field
		add_settings_field('spbc_security_logs', '', 'spbc_field_security_logs', 'spbc', 'spbc_security_log_section');
		
	// TRAFFIC CONTROL SECTION
		//Traffic control field
		add_settings_field('spbc_traffic_control_log', '', 'spbc_field_traffic_control_log', 'spbc', 'spbc_traffic_control_log_section');
		
	// SCANER SECTION
		//Scaner field
		if($spbc->scaner_enabled)
			add_settings_field('spbc_scaner', '', 'spbc_field_scaner', 'spbc', 'spbc_scaner_section');
			
	// DEBUG SECTION
		// Debug drop
		add_settings_field('spbc_debug_drop', '', 'spbc_field_debug_drop', 'spbc', 'spbc_debug_section');
		// Debug data
		add_settings_field('spbc_debug', '', 'spbc_field_debug', 'spbc', 'spbc_debug_section');
}

/**
 * Admin callback function - Displays plugin options page
 */
function spbc_settings_page() {
	
	global $spbc, $spbc_tpl;
	
	if(is_network_admin()){
		$link = get_site_option('siteurl').'wp-admin/options-general.php?page=spbc';
		printf("<h2>" . __("Please, enter the %splugin settings%s in main site dashboard.", 'security-malware-firewall') . "</h2>", "<a href='$link'>", "</a>");
		return;
	}
	
	// Waringns counter on Summary tab
	$warnings = '';
	$warnings .= !empty($spcb->data['warnings']['black'])  ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--black">%s</span>',  $spcb->data['warnings']['black'])  : '';
	$warnings .= !empty($spcb->data['warnings']['red'])    ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--red">%s</span>',    $spcb->data['warnings']['red'])    : '';
	$warnings .= !empty($spcb->data['warnings']['orange']) ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--orange">%s</span>', $spcb->data['warnings']['orange']) : '';
	$warnings .= !empty($spcb->data['warnings']['green'])  ? sprintf('<span class="spbc_warning_counter spbc_warning_counter--green">%s</span>',  $spcb->data['warnings']['green'])  : '';
	
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--black">%s</span>',  1);
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--red">%s</span>',    2);
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--orange">%s</span>', 3);
	$warnings .= sprintf('<span class="spbc_warning_counter spbc_warning_counter--green">%s</span>',  4);
	
	
	// allow_url_fopen error
	$allow_url_fopen = strtolower(ini_get('allow_url_fopen'));
	if(($allow_url_fopen !== 'on' && $allow_url_fopen !== '1') && is_admin()){
		$spbc->error_add('allow_url_fopen', '');
	}else{
		$spbc->error_delete('allow_url_fopen');
	}
	
	// Low memory limit error
	$m_limit = ini_get('memory_limit');
	if(is_string($m_limit)){
		$prefix = strtolower(substr($m_limit, -1, 1));
		$numder = substr($m_limit, 0, -1);
		switch($prefix){
			case 'k': $m_limit = $numder * 1000; break;
			case 'm': $m_limit = $numder * 1000000; break;
			case 'g': $m_limit = $numder * 1000000000; break;
		}
	}
	if($m_limit - memory_get_usage(true) < 25 * 1024 * 1024 ){
		$spbc->error_add('memory_limit_low', '');
	}else{
		$spbc->error_delete('memory_limit_low');
	}
	
	// If have error message output error block.
	if(!empty($spbc->data['errors'])){
		
		$errors = $spbc->data['errors'];
		
		$error_texts = array(
			// Scanner
			'perform_scan_wrapper' => __('Error occured while scanning. Error: ', 'security-malware-firewall'),
			'get_hashs' => __('Error occured while getting remote hashs. Error: ', 'security-malware-firewall'),
			'scan' => __('Error occured while scanning. Error: ', 'security-malware-firewall'),
			'count_unchecked' => __('Error occured while counting uncheccked files. Error: ', 'security-malware-firewall'),
			'scan_modified' => __('Error occured while scanning modified files. Error: ', 'security-malware-firewall'),
			'scanner_result_send' => __('Error occurred while sending scan logs. Error: ', 'security-malware-firewall'),
			'allow_url_fopen' => __('PHP setting "allow_url_fopen" is disabled. This could effect malware scan quality.', 'security-malware-firewall'),
			'memory_limit_low' => __('You have less than 25 Mib free PHP memory. Error could occurs while scanning.', 'security-malware-firewall'),
			// Misc
			'apikey' => __('Error occured while API key validating. Error: ', 'security-malware-firewall'),
			'get_key' => __('Error occured while automatically gettings access key. Error: ', 'security-malware-firewall'),
			'send_logs' => __('Error occured while sending sending security logs. Error: ', 'security-malware-firewall'),
			'send_firewall_logs' => __('Error occured while sending sending firewall logs. Error: ', 'security-malware-firewall'),
			'firewall_update' => __('Error occured while updating firewall. Error: '            , 'security-malware-firewall'),
			'notice_paid_till' => __('Error occured while checking account status. Error: ', 'security-malware-firewall'),
			'access_key_notices' => __('Error occured while checking account status. Error: ', 'security-malware-firewall'),
			// Unknown
			'unknown' => __('Unknown error. Error: ', 'security-malware-firewall'),
		);
		
		$errors_out = array();
		
		foreach($errors as $type => $error){
			
			if(!empty($error)){
				
				if(is_array(current($error))){
					
					foreach($error as $sub_type => $sub_error){
						$errors_out[$sub_type] = '';
						if(isset($sub_error['error_time']))
							$errors_out[$sub_type] .= date('Y-m-d H:i:s', $sub_error['error_time']) . ': ';
						$errors_out[$sub_type] .= ucfirst($type).': ';
						$errors_out[$sub_type] .= (isset($error_texts[$sub_type]) ? $error_texts[$sub_type] : $error_texts['unknown']) . $sub_error['error_string'];
					}
					continue;
				}
				
				$errors_out[$type] = '';
				if(isset($error['error_time'])) 
					$errors_out[$type] .= date('Y-m-d H:i:s', $error['error_time']) . ': ';
				$errors_out[$type] .= (isset($error_texts[$type]) ? $error_texts[$type] : $error_texts['unknown']) . (isset($error['error_string']) ? $error['error_string'] : '');
				
			}
		}
		
		if(!empty($errors_out)){
			echo '<div id="spbcTopWarning" class="error" style="position: relative;">'
				.'<h3 style="display: inline-block;">'.__('Errors:', 'security-malware-firewall').'</h3>';
				foreach($errors_out as $value)
					echo '<h4>'.$value.'</h4>';
				echo '<h4 style="text-align: right;">'.sprintf(__('You can get support any time here: %s.', 'security-malware-firewall'), '<a target="blank" href="https://wordpress.org/support/plugin/security-malware-firewall">https://wordpress.org/support/plugin/security-malware-firewall</a>').'</h4>';
			echo '</div>';
		}
	}
	
	?>
	<div class="wrap">
		<form id='spbc_settings_form' method='post' action='options.php'>
		<?php settings_fields(SPBC_SETTINGS); ?>
		<h2 style="display: inline-block;"><?php echo SPBC_NAME; ?></h2>
		<div style="float: right; margin: 10px 0 0 0; font-size: 13px;">
			<?php 
				printf(__('The plugin home page', 'security-malware-firewall') .' <a href="https://wordpress.org/plugins/security-malware-firewall/" target="_blank">%s</a>.', SPBC_NAME);
				echo '<br>';
				echo __('Tech support: ', 'security-malware-firewall') . '<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall">Wordpress.org</a>';
				echo '<br>';
				echo __('CleanTalk is registered Trademark. All rights reserved.', 'security-malware-firewall');
				echo '<br>';
				echo '<b style="display: inline-block; margin-top: 10px;">'
					.sprintf(
						__('Do you like CleanTalk? %sPost your feedback here%s.', 'cleantalk'),
						'<a href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/#new-post" target="_blank">',
						'</a>'
					)
				.'</b>';
				echo '<br />';
				spbc_badge__get_premium();
			?>
		</div>
		</br>
		<form id='spbc_settings_form' method='post' action='options.php'>
			<?php settings_fields(SPBC_SETTINGS); ?>
			<?php do_settings_fields('spbc', 'spbc_section_status'); ?>
			<div class='spbc_wrapper_settings'>
			
			<!-- TABS Navigation -->
				<div class='spbc_tabs_nav_wrapper'>
					
					<h2 class='spbc_tab_nav spbc_tab_nav-summary spbc_tab_nav--active'><i class='icon-info'></i><?php echo __('Summary', 'security-malware-firewall');
					//echo $warnings; 
					?></h2>
					<h2 class='spbc_tab_nav spbc_tab_nav-security_log'><i class='icon-user-secret'></i><?php _e('Security Log', 'security-malware-firewall'); ?></h2>
					
					<?php if(is_main_site()): 
						if($spbc->tc_enabled): ?>
							<h2 class='spbc_tab_nav spbc_tab_nav-traffic_control'><i class='icon-exchange'></i><?php _e('Traffic Control', 'security-malware-firewall'); ?></h2>
						<?php endif; ?>
						<?php if($spbc->scaner_enabled): ?>
							<h2 class='spbc_tab_nav spbc_tab_nav-scanner'><i class='icon-search'></i><?php _e('Malware Scanner', 'security-malware-firewall'); ?><sup class="spbc_new">&nbsp;&nbsp;<a href="https://cleantalk.org/help/security-malware-scanner#heuristic" target="_blank">?</a></sup></h2>
						<?php endif; ?>
					<?php endif; ?>
					<h2 class='spbc_tab_nav spbc_tab_nav-settings_general'><i class='icon-sliders'></i><?php _e('General Settings', 'security-malware-firewall'); ?></h2>
					
					<?php if($spbc->debug): ?>
						<h2 class="spbc_tab_nav spbc_tab_nav-debug">Debug</h2>
					<?php endif; ?>
					
					<?php if($spbc->key_is_ok): ?>
						<div id='goToCleanTalk' class='spbc-div-2' style='display: inline-block; position: relative; top: -2px; left: 8px; margin-right: 7px;'>
							<a id='goToCleanTalkLink' class='spbc_manual_link' target='_blank' href='https://cleantalk.org/my?user_token=<?php echo $spbc->user_token ?>&cp_mode=security'><?php _e('Security Control Panel', 'security-malware-firewall'); ?></a>
						</div>
					<?php endif; ?>
					<a target='_blank' href='https://wordpress.org/support/plugin/security-malware-firewall' style='display: inline-block; position: relative; top: -2px; left: 8px;'>
						<input type='button' class='spbc_auto_link' value='<?php _e('Support', 'security-malware-firewall'); ?>' />
					</a>
				</div>
				
			<!-- TABS -->
			
				<!-- Summary settings -->
				<div class='spbc_tab spbc_tab-summary spbc_tab--active'>
					<!--div class='spbc_tab_fields_group'>
						<h3 class='spbc_group_header'><?php //echo __('Protection', 'security-malware-firewall')?></h3>
						<?php //do_settings_fields('spbc', 'spbc_protection_section'); ?>
					</div-->
					<div class='spbc_tab_fields_group'>
						<h3 class='spbc_group_header'><?php _e('Statistics', 'security-malware-firewall'); ?></h3>
						<?php do_settings_fields('spbc', 'spbc_statistics_section'); ?>
					</div>
					<?php do_settings_fields('spbc', 'spbc_banners_section'); ?>
				</div>
				
				<!-- Security log -->
				<div class='spbc_tab spbc_tab-security_log'>
					<img class="spbc_spinner_big" src="<? echo SPBC_PATH; ?>/images/preloader2.gif" />
				</div>
				
				<!-- Traffic control -->
				<?php if($spbc->tc_enabled): ?>
					<div class='spbc_tab spbc_tab-traffic_control'>
						<img class="spbc_spinner_big" src="<? echo SPBC_PATH; ?>/images/preloader2.gif" />
					</div>
				<?php endif; ?>	
				
				<!-- Debug -->
				<?php if($spbc->debug): ?>
					<div class='spbc_tab spbc_tab-debug'>
						<img class="spbc_spinner_big" src="<? echo SPBC_PATH; ?>/images/preloader2.gif" />
					</div>
				<?php endif; ?>
				
				<!-- Scaner -->
				<?php if($spbc->scaner_enabled): ?>
					<div class='spbc_tab spbc_tab-scanner'>
						<img class="spbc_spinner_big" src="<? echo SPBC_PATH; ?>/images/preloader2.gif" />
					</div>
				<?php endif; ?>
				
				<!-- General settings -->
				<div class='spbc_tab spbc_tab-settings_general'>
					<img class="spbc_spinner_big" src="<? echo SPBC_PATH; ?>/images/preloader2.gif" />
				</div>
				
			</div>
		</form>
		<form id="drop_debug" method="POST"></form>
	</div>
	<?php
}

// function spbc_section_security_status(){}
// function spbc_section_key(){}
// function spbc_section_security(){}
// function spbc_section_misc(){}
// function spbc_section_security_log(){}
// function spbc_section_traffic_control(){}
// function spbc_section_debug(){}
	// submit_button(); 
// }

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
	$scanner_status = ($spbc->key_is_ok && $spbc->scaner_status && !empty($spbc->data['scanner']['last_scan']) && $spbc->data['scanner']['last_scan'] + (86400*7) > current_time('timestamp')) || $spbc->scaner_warning ? true : false;
	$ssl_status = is_ssl();
	$ssl_text   = sprintf('%s' . __('SSL Installed', 'security-malware-firewall') . '%s', 
		$ssl_status || !$spbc->key_is_ok ? '' : '<a href="https://cleantalk.org/my/?cp_mode=ssl'.($spbc->user_token ? '&user_token='.$spbc->user_token : '').'" target="_blank">',
		$ssl_status || !$spbc->key_is_ok ? '' : '</a>'
	);
	
	// Output statuses
	echo '<h2 style="display: inline-block;">'.__('Security status:', 'security-malware-firewall').'</h2>';
	
	echo '<div style="display: inline-block;">';
	
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok ? $img : $img_no).'"/>'.__('Brute Force Protection', 'security-malware-firewall');
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok ? $img : $img_no).'"/>'.__('Security Report', 'security-malware-firewall');
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok ? $img : $img_no).'"/>'.__('Security Audit Log', 'security-malware-firewall');
		echo '<img class="spbc_status_icon" src="'.($spbc->key_is_ok ? $img : $img_no).'"/>'.__('FireWall', 'security-malware-firewall');
		echo '<img class="spbc_status_icon" src="'.($ssl_status      ? $img : $img_no).'"/>'.$ssl_text;
		if($spbc->scaner_enabled)
			echo '<img class="spbc_status_icon" id="spbc_scanner_status_icon" src="'.($scanner_status ? $img : $img_no).'"/>'.__('Malware Scanner', 'security-malware-firewall');
		
		// Autoupdate status
		if($spbc->notice_auto_update == 1){
			echo '<img class="spbc_status_icon" src="'.($spbc->auto_update == 1 ? $img : ($spbc->auto_update == -1 ? $img_no : $img_no_gray)).'"/>'.__('Auto update', 'security-malware-firewall')
				.' <sup><a href="http://cleantalk.org/help/auto-update" target="_blank">?</a></sup>';
		}
		
	echo '</div>';
	// echo '<hr/>';	
}

function spbc_tab__summary(){
	global $spbc_tpl;
	?>
	<!--div class='spbc_tab_fields_group'>
		<h3 class='spbc_group_header'><?php //echo __('Protection', 'security-malware-firewall')?></h3>
		<?php //spbc_field_protection(); ?>
	</div-->
	<div class='spbc_tab_fields_group'>
		<h3 class='spbc_group_header'><?php _e('Statistics', 'security-malware-firewall'); ?></h3>
		<?php spbc_field_statistics(); ?>
	</div>
	
	<?php spbc_field_banners(); ?>
	
	<script src="<?php echo SPBC_PATH; ?>/js/spbc-settings_tab--summary.js?ver=<?php echo SPBC_VERSION; ?>"></script>
	<?php
	
	die();
}

/**
 * Admin callback function - Displays current warinings
 */
function spbc_field_protection(){
	
	global $spbc;
	
	$out = null;
	
	echo "<div class='spbc_wrapper_field'>";
		
		if($out === null)
			$out = __('Seems that everything is fine with your website.', 'security-malware-firewall');
		
		echo $out;
		
	echo '</div>';
}

/**
 * Admin callback function - Displays current statistics
 */
function spbc_field_statistics(){
	
	global $spbc;
	
	echo "<div class='spbc_wrapper_field'>";
	
		// Info block
		echo (isset($spbc->data['logs_last_sent'], $spbc->data['last_sent_events_count'])
			? sprintf(__('%d events have been sent to CleanTalk Cloud on %s.', 'security-malware-firewall'), $spbc->data['last_sent_events_count'], date("M d Y H:i:s", $spbc->data['logs_last_sent']))
			: __('Unknow last logs sending time.', 'security-malware-firewall'));
		echo '<br />';
		echo (isset($spbc->data['last_firewall_send'], $spbc->data['last_firewall_send_count'])
			? sprintf(__('Information about %d blocked entries have been sent to CleanTalk Cloud on %s.', 'security-malware-firewall'), $spbc->data['last_firewall_send_count'], date("M d Y H:i:s", $spbc->data['last_firewall_send']))
			: __('Unknow last filrewall logs sending time.', 'security-malware-firewall'));
		echo '<br />';
		echo (isset($spbc->data['last_firewall_updated'], $spbc->data['firewall_entries'])
			? sprintf(__('Security FireWall database has %d IPs. Last updated at %s.', 'security-malware-firewall'), $spbc->data['firewall_entries'], date('M d Y H:i:s', $spbc->data['last_firewall_updated']))
			: __('Unknow last Security FireWall updating time.', 'security-malware-firewall'));
		if($spbc->scaner_enabled){
			echo '<br />';
			echo (isset($spbc->data['scanner']['last_scan'])
				? sprintf(__('Website last scan was performed on %s', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_scan']))
				: __('Website hasn\'t been scanned yet.', 'security-malware-firewall'));
		
			if(isset($spbc->data['scanner']['last_sent'])){
				echo '<br />';
				printf(__('Scan results were sent to the cloud at %s', 'security-malware-firewall'), date('M d Y H:i:s', $spbc->data['scanner']['last_sent']));
			}
		}
	
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

function spbc_tab__settings_general(){
	global $spbc;
	?>
		<div class='spbc_tab_fields_group'>
			<h3 class='spbc_group_header'><?php _e('Access Key', 'security-malware-firewall'); ?></h3>
			<?php
				spbc_field_key();
				if(is_main_site() && SPBC_WPMS)
					spbc_field_custom_key(); 
			?>
		</div>
		<?php if(is_main_site()): ?>
			<div class='spbc_tab_fields_group'>
				<h3 class='spbc_group_header'><?php _e('Security', 'security-malware-firewall'); ?></h3>
				<?php 
					spbc_field_traffic_control_enabled();
					spbc_field_traffic_control_autoblock_requests_amount();
				?>
			</div>
		<?php endif; ?>
		<?php if($spbc->scaner_status): ?>
			<div class='spbc_tab_fields_group'>
				<h3 class='spbc_group_header'><?php _e('Malware scanner', 'security-malware-firewall'); ?></h3>
				<?php 
					spbc_field_scan_outbound_links();
					spbc_field_scan_outbound_links_mirrors();
					spbc_field_heuristic_analysis();
				?>
			</div>
		<?php endif; ?>					
		<div class='spbc_tab_fields_group'>
			<h3 class='spbc_group_header'><?php _e('Miscellaneous', 'security-malware-firewall'); ?></h3>
			<?php 
				spbc_field_show_link_login_form();
				// Settings Only for main blog
				if(is_main_site()){
					spbc_field_set_cookies();
					spbc_field_complete_deactivation();
				}
			?>
		</div>
		<script src="<?php echo SPBC_PATH; ?>/js/spbc-settings_tab--settings_general.js?ver=<?php echo SPBC_VERSION; ?>"></script>
		<?php submit_button();
	die();
}

/**
 * Admin callback function - Displays field of Api Key
 */
function spbc_field_key( $values = array('id' => 'spbc_key', 'class' => 'spbc_key_section') ) {

	global $spbc;
	
	echo "<div class='spbc_wrapper_field'>";
	
		if($spbc->allow_custom_key || is_main_site()){
			
			if($spbc->key_is_ok){
				
				echo '<input id="'.$values['id'].'" name="spbc_settings[spbc_key]" size="20" type="text" value="'.str_repeat('*', strlen($spbc->settings['spbc_key'])).'" key="'.$spbc->settings['spbc_key'].'" style="font-size: 14pt;" placeholder="' . __('Enter the key', 'security-malware-firewall') . '" />';
				echo '<a id="showHideLink" class="spbc-links" style="color:#666;" href="#">'.__('Show access key', 'security-malware-firewall').'</a>';
				
			}else{
				
				echo '<input id="'.$values['id'].'" name="spbc_settings[spbc_key]" size="20" type="text" value="'.$spbc->settings['spbc_key'].'" style=\'font-size: 14pt;\' placeholder="' . __('Enter the key', 'security-malware-firewall') . '" />';
				echo '<br/><br/>';
				echo '<a target="_blank" href="https://cleantalk.org/register?platform=wordpress&email='.urlencode(get_option('admin_email')).'&website='.urlencode(parse_url(get_option('siteurl'), PHP_URL_HOST)).'&product_name=security" style="display: inline-block;">
						<input type="button" class="spbc_auto_link" value="'.__('Get access key manually', 'security-malware-firewall').'" />
					</a>';
				echo '&nbsp;'.__('or', 'security-malware-firewall').'&nbsp;';
				echo '<input name="spbc_get_apikey_auto" type="submit" class="spbc_manual_link" value="' . __('Get access key automatically', 'security-malware-firewall') . '" />';
				echo '<br/><br/>';
				echo '<div style="font-size: 10pt; color: #666 !important">' . sprintf(__('Admin e-mail (%s) will be used for registration', 'security-malware-firewall'), get_option('admin_email')) . '</div>';
				echo '<div style="font-size: 10pt; color: #666 !important"><a target="__blank" style="color:#BBB;" href="https://cleantalk.org/publicoffer">' . __('License agreement', 'security-malware-firewall') . '</a></div>';
			}
			
		}else{
			_e('<h3>Key is provided by Super Admin.<h3>', 'spbc');
		}
		
	echo '</div>';
	
}

function spbc_field_custom_key( $values = array('id' => 'custom_key', 'class' => 'spbc_key_section')){
	
	global $spbc;
	
	$values['value'] = isset($values['value']) ? $values['value'] : $spbc->allow_custom_key;
	
	echo "<div class='spbc_wrapper_field'>";
		echo "<input type='checkbox' id='".$values['id']."' name='spbc_settings[custom_key]' value='1' " . ($values['value'] == '1' ? 'checked' : '') . " />
		<label for='".$values['id']."'>".
			__('Allow users to use other key', 'security-malware-firewall').
		"</label>".
		"<div class='spbc_settings_description'>".
			__('Allow users to use different Access key in their plugin settings. They could use different CleanTalk account.', 'security-malware-firewall').
		"</div>";
	echo "</div>";
	
}

function spbc_field_traffic_control_enabled( $values = array('id' => 'spbc_traffic_control_enabled', 'class' => 'spbc-settings-section', 'enabled' => true) ){
	global $spbc;
	$values['value'] = isset($values['value']) ? $values['value'] : $spbc->tc_enabled;
	echo "<div class='spbc_wrapper_field'>";
		echo '<input type="checkbox" id="'.$values['id'].'" name="spbc_settings[traffic_control_enabled]" value="1" ' 
			.($values['value'] == '1' ? ' checked' : '')
			.($values['enabled'] ? '' : ' disabled').' onclick="spbcSettingsDependencies(\'spbc_option_traffic_control\')"/>'
		.'<label for="'.$values['id'].'">'.
			__('Traffic control', 'security-malware-firewall').
		'</label>'.
		'<div class="spbc_settings_description">'.
			__('Traffic Control shows a list of visits and hits towards your website. Allows you to ban any visitor, a whole country or a network.', 'security-malware-firewall').
		'</div>';
	echo '</div>';
}

function spbc_field_traffic_control_autoblock_requests_amount( $values = array('id' => 'spbc_option_traffic_control', 'class' => 'spbc-settings-section spbc_short_text_field') ){
	
	global $spbc;
	$values['value']   = isset($spbc->settings['traffic_control_autoblock_amount']) ? $spbc->settings['traffic_control_autoblock_amount'] : 1000;
	$values['enabled'] = $spbc->tc_enabled;
	
	echo "<div class='spbc_wrapper_field'>";
		echo "<input type='text' id='{$values['id']}' class='{$values['class']}' name='spbc_settings[traffic_control_autoblock_amount]' value='{$values['value']}' ". ($values['enabled'] ? '' : 'disabled=\'disabled\'') . " />
		<label for='{$values['id']}'>".
			__('Block user after more than N requests per hour.', 'security-malware-firewall').
		"</label>";
	echo "</div>";
}

function spbc_field_scan_outbound_links($values = array('id' => 'spbc_options_scan_outbound_links', 'class' => 'spbc-settings-section')){
	
	global $spbc;
	$values['value'] = isset($spbc->settings['scan_outbound_links']) ? $spbc->settings['scan_outbound_links'] : false;
	
	echo "<div class='spbc_wrapper_field'>".
		"<input type='checkbox' id='".$values['id']."' name='spbc_settings[scan_outbound_links]' value='1'"
			.($values['value'] == '1' ? 'checked' : '') 
			.' onclick="spbcSettingsDependencies(\'spbc_options_scan_outbound_links_mirrors\')"'
		.'/>'
		."<label for='".$values['id']."'>" . __('Scan links', 'security-malware-firewall') . "</label>
		<div class='spbc_settings_description'>".
			__('Turning this option on may increase scanning time for websites with a lot of pages.', 'security-malware-firewall').
		"</div>";
	echo "</div>";
}

function spbc_field_scan_outbound_links_mirrors($values = array('id' => 'spbc_options_scan_outbound_links_mirrors', 'class' => 'spbc-settings-section spbc_long_text_field')){
	
	global $spbc;
	$values['value'] = isset($spbc->settings['scan_outbound_links_mirrors']) ? $spbc->settings['scan_outbound_links_mirrors'] : '';
	$values['enabled'] = isset($spbc->settings['scan_outbound_links'])         ? $spbc->settings['scan_outbound_links']         : false;
	
	echo '<div class="spbc_wrapper_field">'
		.'<input type="text" id="'.$values['id'].'" class="'.$values['class'].'" name="spbc_settings[scan_outbound_links_mirrors]" value="'.$values['value'].'" '.($values['enabled'] ? '' : 'disabled=\'disabled\'').'/>'
		.'<label for="'.$values['id'].'">'
			.' '.__('Website\'s mirrors', 'security-malware-firewall')
		.'</label>'
		.'<div class="spbc_settings_description">'
			.__('The website\'s mirrors. Separated with comma, without protocols (examle: "some.com, example.com, my.gov").', 'security-malware-firewall').
		'</div>'
	.'</div>';
}

function spbc_field_heuristic_analysis($values = array('id' => 'spbc_options_heuristic_analysis', 'class' => 'spbc-settings-section')){
	
	global $spbc;
	$values['value'] = isset($spbc->settings['heuristic_analysis']) ? $spbc->settings['heuristic_analysis'] : false;
	
	echo "<div class='spbc_wrapper_field'>".
		"<input type='checkbox' id='".$values['id']."' name='spbc_settings[heuristic_analysis]' value='1' " . ($values['value'] == '1' ? 'checked' : '') . " />
		<label for='".$values['id']."'>" . __('Heuristic analysis', 'security-malware-firewall') . "</label>
		<div class='spbc_settings_description'>".
			__('Will search for dangerous constructions in code. Plugins and themes could be checked only with this option.').
		"</div>";
	echo "</div>";
}

function spbc_field_show_link_login_form( $values = array('id' => 'spbc_option_show_link_in_login_form', 'class' => 'spbc-settings-section')) {
	
	global $spbc;
	
	$values['value'] = isset($spbc->settings['show_link_in_login_form']) ? $spbc->settings['show_link_in_login_form'] : false;
	
	echo "<div class='spbc_wrapper_field'>
			<input type='checkbox' id='".$values['id']."' name='spbc_settings[show_link_in_login_form]' value='1' " . ($values['value'] == '1' ? 'checked' : '') . " />
			<label for='".$values['id']."'>" . __('Let them know about protection', 'security-malware-firewall') . "</label>
			<div class='spbc_settings_description'>".
				__('Place a warning under login form: "Brute Force Protection by CleanTalk security. All attempts are logged".', 'security-malware-firewall').
			"</div>";
	echo "</div>";
}

function spbc_field_complete_deactivation( $values = array('id' => 'spbc_option_complete_deactivation', 'class' => 'spbc-settings-section')) {
					
	global $spbc;
	$values['value'] = isset($spbc->settings['complete_deactivation']) ? $spbc->settings['complete_deactivation'] : false;
	
	echo "<div class='spbc_wrapper_field'>".
		"<input type='checkbox' id='".$values['id']."' name='spbc_settings[complete_deactivation]' value='1' " . ($values['value'] == '1' ? 'checked' : '') . " />
		<label for='".$values['id']."'>" . __('Complete deactivation', 'security-malware-firewall') . "</label>
		<div class='spbc_settings_description'>".
			__('The plugin will leave no traces in WordPress after deactivation. It could help if you have problems with the plugin.', 'security-malware-firewall').
			(SPBC_WPMS ? " ".__('It affects ALL websites. Use it wisely!', 'security-malware-firewall') : '').
		"</div>";
	echo "</div>";
}

function spbc_field_set_cookies( $values = array('id' => 'spbc_option_set_cookies', 'class' => 'spbc-settings-section')) {
	
	global $spbc;
	$values['value'] = isset($spbc->settings['set_cookies']) ? $spbc->settings['set_cookies'] : false;
	
	echo "<div class='spbc_wrapper_field'>".
		"<input type='checkbox' id='".$values['id']."' name='spbc_settings[set_cookies]' value='1' " . ($values['value'] == '1' ? 'checked' : '') . " />
		<label for='".$values['id']."'>" . __('Set cookies', 'security-malware-firewall') . "</label>
		<div class='spbc_settings_description'>".
			__('Turn this option off to forbid the plugin to create any cookies on your website front-end. This option is helpful if you use Varnish or other caching solutions. Note that disabling it will slow FireWall down a bit.', 'security-malware-firewall').
			(SPBC_WPMS ? " ".__('It affects ALL websites. Use it wisely!', 'security-malware-firewall') : '').
		"</div>";
	echo "</div>";
}

function spbc_tab__security_log(){
	global $spbc;
	?>
		<div class='spbc_tab_fields_group'>
			<div class='spbc_wrapper_field'>
				<?php spbc_field_security_logs(); ?>
			</div>
		</div>
		<script src="<?php echo SPBC_PATH; ?>/js/spbc-settings_tab--security_log.js?ver=<?php echo SPBC_VERSION; ?>"></script>
	<?php
	die();
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
			$page_time = $row->page_time === null ? 'Calculating' : strval($row->page_time);
			
			$country_part = spbc_report_country_part($ips_c, $row->auth_ip);
			$ip_part = sprintf("<a href=\"https://cleantalk.org/blacklists/%s\" target=\"_blank\">%s</a>,&nbsp;%s",
				$row->auth_ip, 
				SpbcHelper::ip__v6_reduce($row->auth_ip), 
				$country_part
			);
			
			$table->items[] = array(
				'user_login' => $user_part,
				'datetime'   => date("M d Y, H:i:s", strtotime($row->datetime) + $time_offset),
				'event'      => $row->event,
				'page'       => $page,
				'page_time'  => ($row->event == 'view' ? $page_time : '-'),
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
	
	if(!$spbc->key_is_ok){
		$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
		$link = sprintf('<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_key\', 3);">%s</a>', $button);
		echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter API key.', 'security-malware-firewall').'</h3>'.$link.'</div>';
		return;
	}
	
	// HEADER
	$message_about_log = sprintf(__('This list contains details of actions for the past 24 hours and shows only last %d records. To see the full report please use <a target="_blank" href="https://cleantalk.org/my/logs?user_token=%s">Security control panel</a>.', 'security-malware-firewall'),
		SPBC_LAST_ACTIONS_TO_VIEW,
		$spbc->user_token
	);
	echo "<p class='spbc_hint spbc_hint-security_logs -display--inline-block'>$message_about_log</p>";		
		
	// OUTPUT
	$table = new SpbcListTable(
		array(
			'id' => 'spbc_tbl__secuirty_logs',
			'sql' => array(
				'add_col' => array('id'),
				'table'   => SPBC_DB_PREFIX . SPBC_LOG_TABLE,
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
				'datetime'   => array('heading' => 'Date',),
				'event'      => array('heading' => 'Action',),
				'page'       => array('heading' => 'Page',),
				'page_time'  => array('heading' => 'Time on Page',),
				'auth_ip'    => array('heading' => 'IP',),
			),
			'sortable' => array('user_login', 'datetime'),
		)
	);
	
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
}
function spbc_tab__traffic_control(){
	?>
		<div class='spbc_tab_fields_group'>
			<div class='spbc_wrapper_field'>
				<?php spbc_field_traffic_control_log(); ?>
			</div>
		</div>
		<script src="<?php echo SPBC_PATH; ?>/js/spbc-settings_tab--traffic_control.js?ver=<?php echo SPBC_VERSION; ?>"></script>
	<?php
	die();
}


function spbc_field_traffic_control_logs__prepare_data(&$table){
	
	global $spbc;
		
	if($table->items_count){
		
		foreach($table->rows as $row)
			$ip_countries[] = $row->ip_entry;
		$ip_countries = spbc_get_countries_by_ips(implode(',', $ip_countries));
		
		$time_offset = current_time('timestamp') - time();
		
		foreach($table->rows as $row){
			
			$ip = "<a href='https://cleantalk.org/blacklists/{$row->ip_entry}' target='_blank'>".SpbcHelper::ip__v6_reduce($row->ip_entry).'</a>'
				.'&nbsp;<sup>'
					."<a href='https://cleantalk.org/my/show_private?service_id={$spbc->service_id}&add_record={$row->ip_entry}&service_type=securityfirewall' target='_blank' class='spbc_gray'>"
						.__('Manage', 'security-malware-firewall').
					'</a>'
				 .'</sup>';
			
			$entries = ($row->allowed_entry ? '<b class="spbcGreen">'.$row->allowed_entry.'</b>' : 0)
				.' / '
				.($row->blocked_entry ? '<b class="spbcRed">'.$row->blocked_entry.'</b>' : 0);
			
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
				case 'DENY_BY_NETWORK':	        $status = '<span class="spbcRed">'   . __('Blocked. Hazardous network.', 'security-malware-firewall').'</span>';
					break; 
				case 'DENY_BY_DOS':             $status = '<span class="spbcRed">'   . __('Blocked by DOS prevertion system', 'security-malware-firewall').'</span>'; 
					break;
				default:                        $status = __('Unknown', 'security-malware-firewall');
					break;
			}
			
			$table->items[] = array(
				'ip_entry'        => $ip,
				'country'         => spbc_report_country_part($ip_countries, $row->ip_entry),
				'entry_timestamp' => date('M d Y, H:i:s', $row->entry_timestamp + $time_offset),
				'entries'         => $entries,
				'status'          => $status,
				'page_url'        => $page_url,
				'http_user_agent' => $user_agent,
			);
		}		
	}
}

function spbc_field_traffic_control_log( $value = array() ){
	
	global $spbc, $wpdb, $spbc_tpl;
	
	if(!$spbc->key_is_ok){
		$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
		$link = sprintf('<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_key\', 3);">%s</a>', $button);
		echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter API key.', 'security-malware-firewall').'</h3>'.$link.'</div>';
	}elseif(!$spbc->tc_status){
		$button = '<input type="button" class="button button-primary" value="'.__('RENEW', 'security-malware-firewall').'"  />';
		$link = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
		echo '<div style="margin-top: 10px;">'
			.'<h3 style="margin: 5px; display: inline-block;">'.__('Please renew your security license.', 'security-malware-firewall').'</h3>'.$link.
		'</div>';
	}else{		
		
		$table = new SpbcListTable(
			array(
				'id' => 'spbc_tbl__traffic_control_logs',
				'sql' => array(
					'except_cols' => array('country', 'entries'),
					'add_col'     => array('entry_id', 'allowed_entry', 'blocked_entry'),
					'table'       => SPBC_DB_PREFIX . SPBC_FIREWALL_LOG,
					'where'       => (SPBC_WPMS ? ' WHERE blog_id = '.get_current_blog_id() : ''),
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
					'entries'         => array('heading' => 'Allowed/Blocked HTTP requests',),
					'status'          => array('heading' => 'Status',),
					'page_url'        => array('heading' => 'Page',),
					'http_user_agent' => array('heading' => 'User Agent',),
				),
				'sortable' => array('status', 'entry_timestamp'),
			)
		);
		
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
				__('Traffic Control will block visitors if they send more than %s requests per hour.', 'security-malware-firewall'),
				'<b>'.(isset($spbc->settings['traffic_control_autoblock_amount']) ? $spbc->settings['traffic_control_autoblock_amount'] : 1000).'</b>'
			)
			.' '
			.sprintf(
				__('You can adjust it %shere%s.', 'security-malware-firewall'),
				'<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_option_traffic_control\', 3);">',
				'</a>'
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
}

function spbc_tab__scanner(){
	?>
		<script src="<?php echo SPBC_PATH; ?>/js/spbc-scanner-plugin.js?ver=<?php echo   SPBC_VERSION; ?>"></script>
		<div class='spbc_tab_fields_group'>
			<div class='spbc_wrapper_field'>
				<?php spbc_field_scaner(); ?>
			</div>
		</div>
		<script src="<?php echo SPBC_PATH; ?>/js/spbc-settings_tab--scaner.js?ver=<?php echo SPBC_VERSION; ?>"></script>
	<?php
	die();
}

function spbc_field_scanner__prepare_data__files(&$table){
	
	if($table->items_count){
		$root_path = spbc_get_root_path();
		foreach($table->rows as $key => $row){
			
			// Filtering row actions
			if($row->last_sent > $row->mtime || $row->size == 0 || $row->size > 1048570) unset($row->actions['send']);
			if(!$row->real_full_hash || !$row->difference) unset($row->actions['compare']);
			if(!$row->real_full_hash) unset($row->actions['replace']);
			if(!$row->severity) unset($row->actions['view_bad']);
			
			$table->items[] = array(
				'cb'       => $row->fast_hash,
				'uid'      => $row->fast_hash,
				'size'     => spbc_size_to_string($row->size),
				'perms'    => $row->perms,
				'mtime'    => date('M d Y H:i:s', $row->mtime),
				'path'     => strlen($root_path.$row->path) >= 40
					? '<div class="spbcShortText">...'.$row->path.'</div><div class="spbcFullText spbc_hide">'.$root_path.$row->path.'</div>'
					: $root_path.$row->path,
				'actions' => $row->actions,
			);
		}
	}	
}
function spbc_field_scanner__prepare_data__links(&$table){
	if($table->items_count){
		$num = $table->sql['offset']+1;
		foreach($table->rows as $key => $row){
			$table->items[] = array(
				'num'         => $num++,
				'link'        => "<a href='{$key}' target='_blank'>{$key}</a>",
				'page'        => "<a href='{$row['page_url']}' target='_blank'>{$row['page_url']}</a>",
				'link_text'   => htmlspecialchars($row['link_text']),
				'spam_active' => isset($row['spam_active']) ? ($row['spam_active'] ? 'Yes' : 'No') : 'Unknown',
			);
		}
	}	
}

function spbc_field_scaner($params = array()){
	
	global $spbc, $spbc_tpl, $wp_version;
	
	if(!$spbc->key_is_ok){
		
		$button = '<input type="button" class="button button-primary" value="'.__('To setting', 'security-malware-firewall').'"  />';
		$link = sprintf('<a href="#" onclick="spbc_switchTab(document.getElementsByClassName(\'spbc_tab_nav-settings_general\')[0], \'spbc_key\', 3);">%s</a>', $button);
		echo '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'.__('Please, enter API key.', 'security-malware-firewall').'</h3>'.$link.'</div>';
		
	}elseif(!$spbc->scaner_status){
		
		$button = '<input type="button" class="button button-primary" value="'.__('RENEW', 'security-malware-firewall').'"  />';
		$link = sprintf('<a target="_blank" href="https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token=%s">%s</a>', $spbc->user_token, $button);
		echo '<div style="margin-top: 10px;"><h3 style="margin: 5px; display: inline-block;">'.__('Please renew your security license.', 'security-malware-firewall').'</h3>'.$link.'</div>';
		
	}else{
	
		if(preg_match('/^[\d\.]*$/', $wp_version) !== 1){
			echo '<p class="spbc_hint" style="text-align: center;">';
				printf(__('Your Wordpress version %s is not supported', 'security-malware-firewall'), $wp_version);
			echo '</p>';
			return;
		}
		
		echo '<p class="spbc_hint" style="text-align: center;">';
		if(empty($spbc->data['scanner']['last_scan']))
			_e('System hasn\'t been scanned yet. Please, perform the scan to secure the website.', 'security-malware-firewall');
		elseif($spbc->data['scanner']['last_scan'] < time() - 86400 * 7){
			_e('System hasn\'t been scanned for a long time', 'security-malware-firewall');
		}
		else{
			_e('Look below for scan results.', 'security-malware-firewall');
		}
		echo '</br>';
		printf(
			__('%sView all scan results for this website%s', 'security-malware-firewall'),
			'<a target="blank" href="https://cleantalk.org/my/logs_mscan?service='.$spbc->service_id.'">',
			'</a>'
		);
		echo '</p>';
		
		echo '<div style="text-align: center;">'
			.'<button id="spbc_perform_scan" class="spbc_manual_link" type="button">'
				.__('Perform scan', 'security-malware-firewall')
			.'</button>'
			.'<img  class="spbc_preloader" src="'.SPBC_PATH.'/images/preloader.gif" />'
		.'</div>';
		
		echo '<p class="spbc_hint" style="text-align: center; margin-top: 5px;">';
			if(isset($spbc->data['scanner']['last_scan'])){
				printf(
					__('Website last scan was performed on %s, %d files were scanned.', 'security-malware-firewall'),
					date('M d Y H:i:s',$spbc->data['scanner']['last_scan']),
					$spbc->data['scanner']['last_scan_amount']
				);
				if($spbc->settings['scan_outbound_links'])
					printf(' '.__('%s outbound links were found.', 'security-malware-firewall'), isset($spbc->data['scanner']['last_scan_links_amount']) ? $spbc->data['scanner']['last_scan_links_amount'] : 0);
			}else
				__('Website hasn\'t been scanned yet.', 'security-malware-firewall');
		echo '</p>';
					
		/* Debug Buttons
			echo '<button id="spbc_scanner_clear" class="spbc_manual_link" type="button">'
			.__('Clear', 'security-malware-firewall')
			.'</button>'
			.'<img class="spbc_preloader" src="http://wordpress.loc/wp-content/plugins/security-malware-firewall/images/preloader.gif" />'
			.'<br /><br />';
		//*/
		
		echo 
		'<div id="spbc_scaner_progress_overall" class="spbc_hide" style="padding-bottom: 10px; text-align: center;">'
			.'<span class="spbc_overall_scan_status_get_hashes">Recieving hashes</span> -> '
			.'<span class="spbc_overall_scan_status_clear_table">Preparing</span> -> '
			.'<span class="spbc_overall_scan_status_count">Counting core files</span> -> '
			.'<span class="spbc_overall_scan_status_scan">Scanning core for modifications</span> -> '
			.'<span class="spbc_overall_scan_status_count_modified">Counting modified core files</span> -> '
			.'<span class="spbc_overall_scan_status_scan_modified">Scanning modified core files</span> -> ';

			if($spbc->settings['scan_outbound_links'])
				echo '<span class="spbc_overall_scan_status_count_links">Counting links</span> -> '
				.'<span class="spbc_overall_scan_status_scan_links">Scanning links</span> -> ';
			
			if($spbc->settings['heuristic_analysis'])
				echo '<span class="spbc_overall_scan_status_count_plug">Counting plugins and themes files</span> -> '
				.'<span class="spbc_overall_scan_status_scan_plug">Scanning plugins and themes files</span> -> '
				.'<span class="spbc_overall_scan_status_count_modified_plug">Counting modified plugins and themes files</span> -> '
				.'<span class="spbc_overall_scan_status_scan_modified_plug">Scanning modified plugins and themes files</span> -> ';
			
			// echo '<span class="spbc_overall_scan_status_list_results">Output results</span> -> ';
			echo '<span class="spbc_overall_scan_status_send_results">Sending results</span>'
		.'</div>';
		echo '<div id="spbc_scaner_progress_bar" class="spbc_hide" style="height: 22px;"><div class="spbc_progressbar_counter"><span></span></div></div>';
		
		echo '<div id="spbc_dialog" title="File output"></div>';
		echo '<div id="spbc_scan_accordion">';
			
			$args = array(
				'sql' => array(
					// 'except_cols' => array('country', 'entries'),
					'add_col'     => array('fast_hash', 'last_sent', 'real_full_hash', 'severity', 'difference'),
					'table'       => SPBC_DB_PREFIX . SPBC_SCAN_RESULTS,
					'offset'      => 0,
					'limit'       => SPBC_LAST_ACTIONS_TO_VIEW,
					'get_array'  => false,
				),
				'order_by'  => array('path' => 'asc'),
				'func_data_prepare' => 'spbc_field_scanner__prepare_data__files',
				'html_before' => '<p class="spbc_hint">'.sprintf(__('Recommend to scan all (%s) of the found files to make sure the website is secure.', 'security-malware-firewall'), 1).'</p>',
				'if_empty_items' => '<p class="spbc_hint">'.__('No threats are found', 'security-malware-firewall').'</p>',
				'columns' => array(
					'cb'       => array('heading' => '<input type=checkbox>',	'class' => 'check-column',),
					'path'     => array('heading' => 'Path','primary' => true,),
					'size'     => array('heading' => 'Size',),
					'perms'    => array('heading' => 'Permissions',),
					'mtime'    => array('heading' => 'Last Modified',),
				),
				'actions' => array(
					'approve' => array('name' => 'Approve',),
					'delete'  => array('name' => 'Delete',),
					'send'    => array('name' => 'Send for Analysis',),
					'view'    => array('name' => 'View', 'handler' => 'spbc_scanner_button_file_view_event(this);',),
				),
				'bulk_actions'  => array(
					'approve' => array('name' => 'Approve',),
					'delete'  => array('name' => 'Delete',),
					'send'    => array('name' => 'Send',),
				),
				'sortable' => array('path', 'size', 'perms', 'mtime',),
				'pagination' => array(
					'page'     => 1,
					'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
				),
			);
			
			$tables_files = array(
				'unknown'     => __('Unknown executable files spotted in core or plugins. These files don\'t come with wordpress distributive. It could be anything.', 'security-malware-firewall'),
				'compromised' => __('System\'s executable files which has been modified.', 'security-malware-firewall'),
				'suspicious'  => __('Files with suspicious functions and constructions which are used rarely an possibly could be a malicious code.', 'security-malware-firewall'),
				'danger'   => __('Files with dangerous functions and constructions which are used very rarely. For example a console command execution, who gonna need to use that in plugin?', 'security-malware-firewall'),
				'critical'    => __('These files may not contain malicious code but they use very dangerous PHP functions and constructions! Using such doesn\'t recommend by PHP developers or looks very suspicious.', 'security-malware-firewall'),
			);
			
			if($spbc->settings['scan_outbound_links'])
				$tables_files['outbound_links'] = __('Shows you the list of outgoing links from your website and websites on which they linking to.', 'security-malware-firewall');
			
			
			
			foreach($tables_files as $type_name => $description){
				
				if($type_name == 'unknown'){
					$args['sql']['where'] = ' WHERE status = "UNKNOWN"';
				}elseif($type_name == 'compromised'){
					$args['sql']['where'] = ' WHERE status = "COMPROMISED"';
					$args['actions'] = array(
						'approve'  => array('name' => 'Approve',),
						'replace'  => array('name' => 'Replace with Original',),
						'compare'  => array('name' => 'Compare',       'handler' => 'spbc_scanner_button_file_compare_event(this);',),
						'view'     => array('name' => 'View',          'handler' => 'spbc_scanner_button_file_view_event(this);',),
						'view_bad' => array('name' => 'View Bad Code', 'handler' => 'spbc_scanner_button_file_view_bad_event(this);',),
					);
					$args['bulk_actions']  = array(
						'approve' => array('name' => 'Approve',),
						'replace' => array('name' => 'Replace with original',),
					);
				}elseif($type_name == 'critical'){
					$args['sql']['where'] = ' WHERE severity = "CRITICAL"';
				}elseif($type_name == 'danger'){
					$args['sql']['where'] = ' WHERE severity = "danger"';
				}elseif($type_name == 'suspicious'){
					$args['sql']['where'] = ' WHERE severity = "SUSPICIOUS"';
				}elseif($type_name == 'outbound_links'){
					$args = array(	
						'id' => 'spbc_tbl__scanner_outbound_links',
						'sql' => array(
							'table'     => SPBC_DB_PREFIX . SPBC_SCAN_LINKS_LOG,
							'get_array' => true,
						),
						'func_data_total'   => 'spbc_scanner_links_count_found',
						'func_data_get'     => 'spbc_scanner_links_get_scanned',
						'func_data_prepare' => 'spbc_field_scanner__prepare_data__links',
						'if_empty_items' => '<p class="spbc_hint">'.__('No links are found', 'security-malware-firewall').'</p>',
						'columns' => array(
							'num'         => array('heading' => 'Number', 'class' => ' tbl-width--50px'),
							'link'        => array('heading' => 'Link','primary' => true,),
							'page'        => array('heading' => 'Page',),
							'link_text'   => array('heading' => 'Link Text',),
							'spam_active' => array('heading' => 'Spam-active',),
						),
						'pagination' => array(
							'page'     => 1,
							'per_page' => SPBC_LAST_ACTIONS_TO_VIEW,
						),
					);
				}
				
				$args['id'] = 'spbc_tbl__scanner_'.$type_name;
				
				$table = new SpbcListTable($args);
				$table->get_data();
				
				echo '<h3><a href="#">'.ucwords($type_name).' (<span class="spbc_bad_type_count '.$type_name.'_counter">'.$table->items_total.'</span>)</a></h3>';
				echo '<div id="spbc_scan_accordion_tab_'.$type_name.'">';
					
					echo '<p class="spbc_hint spbc_hint_warning	">'.$description.'</p>';
					$table->display();
					
				echo "</div>";
			}
			
		echo '</div>';
	}
}

function spbc_tab__debug(){
	?>
		<div class='spbc_tab_fields_group'>
			<div class='spbc_wrapper_field'>
				<?php
					spbc_field_debug_drop();
					spbc_field_debug();
				?>
			</div>
		</div>
	<?php
	die();
}

function spbc_field_debug_drop(){
	echo '<div class="spbc_wrapper_field">'
		.'<br>'
		.'<input form="drop_debug" type="submit" name="spbc_drop_debug" value="Drop debug data" />'
		.'<div class="spbc_settings_description">If you don\'t what is this just push the button =)</div>'
	.'</div>';
}

function spbc_field_debug(){
	global $spbc;
	$output = print_r($spbc->debug, true);
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

/**
 * Admin callback function - Sanitize settings
 */
function spbc_sanitize_settings( $settings ){
	
	global $spbc;
	
	//Sanitizing traffic_control_autoblock_amount setting
	if(isset($settings['traffic_control_autoblock_amount'])){
		$settings['traffic_control_autoblock_amount'] = floor(intval($settings['traffic_control_autoblock_amount']));
		$settings['traffic_control_autoblock_amount'] = ($settings['traffic_control_autoblock_amount'] == 0  ? 1000 : $settings['traffic_control_autoblock_amount']);
		$settings['traffic_control_autoblock_amount'] = ($settings['traffic_control_autoblock_amount'] <  20 ? 20   : $settings['traffic_control_autoblock_amount']);
	}
	
	if(isset($settings['scan_outbound_links_mirrors'])){
		if(preg_match('/^[\sa-zA-Z0-9,_\.\-\~]+$/', $settings['scan_outbound_links_mirrors'])){
			$tmp = explode(',', $settings['scan_outbound_links_mirrors']);
			foreach($tmp as $key => $value){
				$value = trim($value);
				if(!empty($value))
					$mirrors[$key] = trim($value);
			} unset ($key, $value);
			$settings['scan_outbound_links_mirrors'] = implode(', ', $mirrors);
		}
	}
	
	//Checking the accepted key
	$settings['spbc_key'] = isset($settings['spbc_key']) 
		? trim($settings['spbc_key'])
		: (isset($spbc->network_settings['spbc_key'])
			? $spbc->network_settings['spbc_key']
			: '');
			
			
	if(strpos($settings['spbc_key'], '*') !== false && $settings['spbc_key'] == str_repeat('*', strlen($spbc->settings['spbc_key']))){
		$settings['spbc_key'] = $spbc->settings['spbc_key'];
	}
	preg_match('/^[a-z\d]*$/', $settings['spbc_key'], $matches);
	$sanitized_key = !empty($matches[0]) ? $matches[0] : '';
	
	if($sanitized_key == ''){
		$spbc->data['key_is_ok']          = false;
		$spbc->data['notice_show']        = 0;
		$spbc->data['notice_renew']       = 0;
		$spbc->data['notice_trial']       = 0;
		$spbc->data['notice_auto_update'] = 0;
		$spbc->data['user_token']         = 0;
		$spbc->data['service_id']         = '';
		$spbc->data['moderate']	          = 0;
		$spbc->data['auto_update_app']    = 0;
		$spbc->data['license_trial']      = 0;
		$spbc->error_delete(array(
			'notice_show',
			'notice_renew',
			'notice_trial',
			'notice_were_updated',
			'user_token',
			'service_id',
		));
		$spbc->error_add('apikey', __('Key is empty.', 'security-malware-firewall'));
	}else{
		
		//Clearing all errors
		$spbc->error_delete_all('and_save_data');		
		$result = SpbcHelper::api_method__notice_validate_key($sanitized_key, preg_replace('/http[s]?:\/\//', '', get_option('siteurl'), 1));
		
		if(empty($result['error'])){
				
			if($result['valid'] == '1' ){
				$spbc->data['key_is_ok'] = true;
			}else{
				$spbc->data['key_is_ok']          = false;
				$spbc->data['notice_show']        = 0;
				$spbc->data['notice_renew']       = 0;
				$spbc->data['notice_trial']       = 0;
				$spbc->data['notice_auto_update'] = 0;
				$spbc->data['user_token']         = 0;
				$spbc->data['service_id']         = '';
				$spbc->data['moderate']	          = 0;
				$spbc->data['auto_update_app']    = 0;
				$spbc->data['license_trial']      = 0;
				$spbc->error_delete(array(
					'notice_show',
					'notice_renew',
					'notice_trial',
					'notice_were_updated',
					'user_token',
					'service_id',
				));
				$spbc->error_add('apikey', sprintf(__('Key is not valid. Key: %s.', 'security-malware-firewall'), $sanitized_key));
			}
			
		}else{
			$spbc->error_add('apikey', $result);
		}
	}
	
	// If key is ok
	if($spbc->data['key_is_ok'] == true){
		
		// Sending logs.
		$result = spbc_send_logs($sanitized_key);		
		if(empty($result['error'])){
			$spbc->data['logs_last_sent'] = current_time('timestamp');
			$spbc->data['last_sent_events_count'] = $result;
			$spbc->error_delete('send_logs');
		}else{
			$spbc->error_add('send_logs', $result);
		}
		
		// Updating FW
		$result = spbc_security_firewall_update($sanitized_key);
		if(empty($result['error'])){
			$spbc->data['last_firewall_updated'] = current_time('timestamp');
			$spbc->data['firewall_entries']      = $result;
			$spbc->error_delete('firewall_update');
		}else{
			$spbc->error_add('firewall_update', $result);
		}
		
		// Sending FW logs
		$result = spbc_send_firewall_logs($sanitized_key);
		if(empty($result['error'])){
			$spbc->data['last_firewall_send'] = current_time('timestamp');
			$spbc->data['last_firewall_send_count'] = $result;
			$spbc->error_delete('send_firewall_logs');
		}else{
			$spbc->error_add('send_firewall_logs', $result);
		}
		
		// Checking account status
		$result = SpbcHelper::api_method__notice_paid_till($sanitized_key);
		if(empty($result['error'])){
			if(isset($result['user_token'])) $spbc->data['user_token'] = $result['user_token'];
			$spbc->data['notice_show']	    = $result['show_notice'];
			$spbc->data['notice_renew']     = $result['renew'];
			$spbc->data['notice_trial']     = $result['trial'];
			$spbc->data['auto_update_app']  = isset($result['show_auto_update_notice']) ? $result['show_auto_update_notice'] : 0;
			$spbc->data['service_id']       = $result['service_id'];
			$spbc->data['moderate']	        = $result['moderate'];
			$spbc->data['auto_update_app '] = isset($result['auto_update_app']) ? $result['auto_update_app'] : 0;
			$spbc->error_delete('access_key_notices');
		}else{
			$spbc->error_add('access_key_notices', $result);
		}		
	}
	
	$spbc->save('data');
	
	$settings['spbc_key'] = $sanitized_key;
	
	if(SPBC_WPMS && is_main_site()){
			
		$spbc->network_settings = array(
			'key_is_ok'          => $spbc->data['key_is_ok'],
			'spbc_key'           => $settings['spbc_key'],
			'user_token'         => isset($spbc->data['user_token']) ? $spbc->data['user_token'] : '',
			'allow_custom_key'   => isset($settings['custom_key'])   ? $settings['custom_key']   : false,
			'allow_cleantalk_cp' => isset($settings['allow_ct_cp'])  ? $settings['allow_ct_cp']  : false,
			'service_id'         => isset($spbc->data['service_id']) ? $spbc->data['service_id'] : ''
		);
		$spbc->saveNetworkSettings();
	}
	
	
	$settings = array(
		'spbc_key'                         => $settings['spbc_key'],
		'traffic_control_enabled'          => !empty($settings['traffic_control_enabled'])          ? $settings['traffic_control_enabled']          : false,
		'traffic_control_autoblock_amount' => !empty($settings['traffic_control_autoblock_amount']) ? $settings['traffic_control_autoblock_amount'] : false,
		'show_link_in_login_form'          => !empty($settings['show_link_in_login_form'])          ? $settings['show_link_in_login_form']          : false,
		'set_cookies'                      => !empty($settings['set_cookies'])                      ? $settings['set_cookies']                      : false,
		'complete_deactivation'            => !empty($settings['complete_deactivation'])            ? $settings['complete_deactivation']            : false,
		'scan_outbound_links'			   => !empty($settings['scan_outbound_links'])              ? $settings['scan_outbound_links']              : false,
		'heuristic_analysis'			   => !empty($settings['heuristic_analysis'])               ? $settings['heuristic_analysis']               : false,
		'scan_outbound_links_mirrors'      => !empty($settings['scan_outbound_links_mirrors'])      ? $settings['scan_outbound_links_mirrors']      : '',
	);
		
	return $settings;
}


function spbc_show_more_security_logs_callback(){
	
	check_ajax_referer('spbc_secret_nonce', 'security');
	
	// PREPROCESS INPUT
	$args = $_POST['args'];
	$amount  = isset($_POST['amount']) ? intval($_POST['amount']) : SPBC_LAST_ACTIONS_TO_VIEW;
	
	$args['pagination'] = array();
	$args['sql']['limit'] = $amount;
	
	// OUTPUT
	$table = new SpbcListTable($args);
	
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
	
	// PREPROCESS INPUT
	$args = $_POST['args'];
	$amount  = isset($_POST['amount']) ? intval($_POST['amount']) : SPBC_LAST_ACTIONS_TO_VIEW;
	
	$args['pagination'] = array();
	$args['sql']['limit'] = $amount;
	
	// OUTPUT
	$table = new SpbcListTable($args);
	
	$table->get_data();
	
	if($_POST['full_refresh'])
		die($table->display());
	
	die(
		json_encode(
			array(
				'html' => $table->display__rows('return'),
				'size' => $table->items_count,
			)
		)
	);
}

// INACTIVE
function spbc_field_cleantalk_cp( $values ){
	echo "<input type='checkbox' id='".$values['id']."' name='spbc_settings[allow_ct_cp]' value='1' " . ($values['value'] == '1' ? 'checked' : '') . " /><label for='collect_details1'> " . __('Allow users to access to CleanTalk control panel from their Wordpress dashboard (only "read" access).', 'security-malware-firewall');
}