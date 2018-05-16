<?php

//
// Do updates in SQL database after plugin update.
//
function spbc_run_update_actions($current_version, $new_version) {
	
	$current_version = spbc_version_standartization($current_version);
	$new_version     = spbc_version_standartization($new_version);
	
	$current_version_str = implode('.', $current_version);
	$new_version_str     = implode('.', $new_version);
	
	$exec_time = microtime(true);
	
	for($ver_major = $current_version[0]; $ver_major <= $new_version[0]; $ver_major++){
		for($ver_minor = 0; $ver_minor <= 30; $ver_minor++){
			for($ver_fix = 0; $ver_fix <= 10; $ver_fix++){
				
				if(version_compare("{$ver_major}.{$ver_minor}.{$ver_fix}", $current_version_str, '<='))
					continue;
				
				if(function_exists("spbc_update_to_{$ver_major}_{$ver_minor}_{$ver_fix}")){
					$result = call_user_func("spbc_update_to_{$ver_major}_{$ver_minor}_{$ver_fix}");
					if(!empty($result['error']))
						break;
				}
				
				if(version_compare("{$ver_major}.{$ver_minor}.{$ver_fix}", $new_version_str, '>='))
					break(2);
				
			}
		}
	}
}

function spbc_version_standartization($version){
	
	$version = explode('.', $version);
	$version = !empty($version) ? $version : array();
	
	// Version
	$version[0] = !empty($version[0]) ? (int)$version[0] : 0; // Major
	$version[1] = !empty($version[1]) ? (int)$version[1] : 0; // Minor
	$version[2] = !empty($version[2]) ? (int)$version[2] : 0; // Fix
	
	return $version;
}

function spbc_update_to_1_9_0(){
	
	//Adding send logs cron hook if not exists
	if ( !wp_next_scheduled('spbc_send_logs_hook') )
		wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_logs_hook');
	// Update Security FireWall cron hook
	if ( !wp_next_scheduled('spbc_security_firewall_update_hook') )
		wp_schedule_event(time() + 1800, 'hourly', 'spbc_security_firewall_update_hook');
	// Send logs cron hook
	if ( !wp_next_scheduled('spbc_send_firewall_logs_hook') )
		wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_firewall_logs_hook');
	
	return;
}

function spbc_update_to_1_10_0(){
	
	wp_clear_scheduled_hook('spbc_send_logs_hourly_hook');
	wp_clear_scheduled_hook('spbc_send_daily_report');
	wp_clear_scheduled_hook('spbc_send_daily_report_hook');
	wp_clear_scheduled_hook('spbc_security_firewall_update_hourly_hook');
	wp_clear_scheduled_hook('spbc_send_firewall_logs_hourly_hook');
	
	wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_logs_hook');
	wp_schedule_event(time() + 43200, 'daily', 'spbc_send_report_hook');	
	wp_schedule_event(time() + 43200, 'daily', 'spbc_security_firewall_update_hook');
	wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_firewall_logs_hook');
	wp_schedule_event(time() + 1800, 'hourly', 'spbc_access_key_notices_hook');
}

function spbc_update_to_1_19_0(){
	
	wp_clear_scheduled_hook('spbc_send_logs_hook');
	wp_clear_scheduled_hook('spbc_send_report_hook');
	wp_clear_scheduled_hook('spbc_security_firewall_update_hook');
	wp_clear_scheduled_hook('spbc_send_firewall_logs_hook');
	wp_clear_scheduled_hook('spbc_access_key_notices_hook');
	
	// Self cron system
	SpbcCron::addTask('send_logs',           'spbc_send_logs',                3600,  time()+1800);
	SpbcCron::addTask('send_report',         'spbc_send_daily_report',        86400, time()+43200);
	SpbcCron::addTask('firewall_update',     'spbc_security_firewall_update', 86400, time()+43200);
	SpbcCron::addTask('send_firewall_logs',  'spbc_send_firewall_logs',       3600,  time()+1800);
	SpbcCron::addTask('access_key_notices',  'spbc_access_key_notices',       3600,  time()+3500);
}

function spbc_update_to_1_20_0(){
	
	wp_clear_scheduled_hook('spbc_access_key_notices_hook');
	
}

function spbc_update_to_1_21_0(){
	global $spbc;
	// Clearing errors because format changed
	$spbc->data['errors'] = array();
	
}

function spbc_update_to_1_22_0(){
	global $spbc;
	// Adding service ID and refreshing other account params
	if(!empty($spbc->settings['spbc_key'])){
		$result = SpbcHelper::api_method__notice_paid_till($spbc->settings['spbc_key']);
		if(empty($result['error'])){
			$spbc->data['notice_show']	= $result['show_notice'];
			$spbc->data['notice_renew'] = $result['renew'];
			$spbc->data['notice_trial'] = $result['trial'];
			$spbc->data['service_id']   = $result['service_id'];
			if(SPBC_WPMS && is_main_site()){
				$spbc->network_settings['service_id'] = $result['service_id'];
				$spbc->saveNetworkSettings();
			}
		}
	}
}

function spbc_update_to_2_0_0(){
	global $wpdb;
	// Scanner's cron
	SpbcCron::addTask('perform_scan_wrapper', 'spbc_perform_scan_wrapper', 86400, time()+86400);
	// Drop existing table and create scanner's table
	$wpdb->query("DROP TABLE IF EXISTS $spbc_scan_results_table;");
	$wpdb->query("CREATE TABLE IF NOT EXISTS $spbc_scan_results_table (
		`path` VARCHAR(1024) NOT NULL,
		`size` INT(10) NOT NULL,
		`perms` INT(4) NOT NULL,
		`mtime` INT(11) NOT NULL,
		`status` ENUM('NOT_CHECKED','UNKNOWN','OK','APROVED','COMPROMISED','INFECTED') NOT NULL DEFAULT 'NOT_CHECKED',
		`severity` ENUM('CRITICAL','DANGER','SUSPICIOUS') NULL,
		`weak_spots` VARCHAR(1024) NULL,
		`difference` VARCHAR(1024) NULL,
		`last_sent` INT(11) NOT NULL,
		`fast_hash` VARCHAR(32) NULL DEFAULT NULL,
		`full_hash` VARCHAR(32) NULL DEFAULT NULL,
		`real_full_hash` VARCHAR(32) NULL,
		UNIQUE (`fast_hash`)
	) ENGINE = MYISAM;");
}

function spbc_update_to_2_1_0(){
	global $spbc;
	unset($spbc->data['errors']);
	$spbc->save('data');
}

function spbc_update_to_2_4_0(){
	global $wpdb;
	$wpdb->query("DROP TABLE IF EXISTS $spbc_auth_logs_table;");
	$wpdb->query("CREATE TABLE IF NOT EXISTS $spbc_auth_logs_table (
		`id` int(11) NOT NULL AUTO_INCREMENT,
		`datetime` datetime NOT NULL,
		`user_login` varchar(60) NOT NULL,
		`event` varchar(32) NOT NULL,
		`page` VARCHAR(500) NULL,
		`page_time` VARCHAR(10) NULL,
		`blog_id` int(11) NOT NULL,
		`auth_ip` int(10) unsigned DEFAULT NULL,
		`role` varchar(64) DEFAULT NULL,
		PRIMARY KEY (`id`),
		KEY `datetime` (`datetime`,`event`)
		) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=1;");
	$wpdb->query("DROP TABLE IF EXISTS $spbc_firewall_data_table;");
	$wpdb->query("CREATE TABLE IF NOT EXISTS $spbc_firewall_data_table (
		`spbc_network` int(11) unsigned NOT NULL,
		`spbc_mask` int(11) unsigned NOT NULL,
		`status` TINYINT(1) NULL,
		INDEX (`spbc_network` , `spbc_mask`)
		) ENGINE = MYISAM ;");
	$wpdb->query("DROP TABLE IF EXISTS $spbc_firewall_logs_table;");
	$wpdb->query("CREATE TABLE IF NOT EXISTS $spbc_firewall_logs_table (
		`entry_id` VARCHAR(40) NOT NULL,
		`ip_entry` VARCHAR(15) NULL, 
		`allowed_entry` INT NOT NULL, 
		`blocked_entry` INT NOT NULL,
		`status` ENUM('PASS','PASS_BY_WHITELIST','DENY','DENY_BY_NETWORK','DENY_BY_DOS') NULL,
		`page_url` VARCHAR(4096) NULL,
		`request_method` VARCHAR(5) NULL,
		`x_forwarded_for` VARCHAR(15) NULL,
		`http_user_agent` VARCHAR(300) NULL,
		`entry_timestamp` INT NOT NULL , 
		PRIMARY KEY (`entry_id`)) 
		ENGINE = MYISAM;");
	$wpdb->query("DROP TABLE IF EXISTS $spbc_scan_links_log_table;");
	$wpdb->query("CREATE TABLE IF NOT EXISTS $spbc_scan_links_log_table (
		`log_id` int(11) NOT NULL AUTO_INCREMENT,
		`user_id` int(11) unsigned DEFAULT NULL,
		`service_id` int(11) unsigned DEFAULT NULL,
		`submited` datetime NOT NULL,
		`total_links_found` INT NOT NULL,
		`links_list` TEXT DEFAULT NULL,
		PRIMARY KEY (`log_id`)
		) ENGINE = MYISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=1;");
	// $wpdb->query("ALTER TABLE `$spbc_scan_results_table`
		// ADD COLUMN `last_full_hash` varchar(32) NULL AFTER `real_full_hash`;");
}

function spbc_update_to_2_5_0(){
	global $wpdb;
	$wpdb->update($spbc_scan_results_table,
		array( 'status' => 'UNKNOWN' ),
		array( 'status' => 'NOT_CHECKED' )
	);
	$wpdb->query("ALTER TABLE `$spbc_scan_results_table`
		ADD COLUMN `source` ENUM('CORE', 'PLUGIN') NOT NULL DEFAULT 'CORE' AFTER `mtime`,
		ADD COLUMN `checked` ENUM('NO', 'YES') NOT NULL DEFAULT 'NO' AFTER `source`;");
	$wpdb->query("ALTER TABLE `$spbc_scan_results_table` 
		CHANGE `status` `status` ENUM('UNKNOWN','OK','APROVED','COMPROMISED','INFECTED') NOT NULL DEFAULT 'UNKNOWN',
		CHANGE `severity` `severity` ENUM('CRITICAL', 'DANGER', 'SUSPICIOUS', 'NONE') NULL DEFAULT NULL;");
}

function spbc_update_to_2_6_2(){
	SpbcCron::updateTask('send_logs',            'spbc_send_logs',                3600,  time()+1800);
	SpbcCron::updateTask('send_report',          'spbc_send_daily_report',        86400, time()+43200);
	SpbcCron::updateTask('firewall_update',      'spbc_security_firewall_update', 86400, time()+43200);
	SpbcCron::updateTask('send_firewall_logs',   'spbc_send_firewall_logs',       3600,  time()+1800);
	SpbcCron::updateTask('access_key_notices',   'spbc_access_key_notices',       3600,  time()+3500);
	SpbcCron::updateTask('perform_scan_wrapper', 'spbc_perform_scan_wrapper',     86400, time()+43200);
}

function spbc_update_to_2_8_0(){
	global $spbc, $wpdb;
	// Preparing for IPv6
	unset($spbc->data['cdn'], $spbc->data['private_networks']);
	$wpdb->query('DROP TABLE IF EXISTS ' . SPBC_DB_PREFIX . SPBC_FIREWALL_DATA . ';');
	$wpdb->query("CREATE TABLE IF NOT EXISTS " . SPBC_DB_PREFIX . SPBC_FIREWALL_DATA . " (
		`spbc_network_1` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_network_2` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_network_3` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_network_4` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_mask_1` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_mask_2` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_mask_3` int(10) unsigned NOT NULL DEFAULT '0',
		`spbc_mask_4` int(10) unsigned NOT NULL DEFAULT '0',
		`status` TINYINT(1) NULL,
		`ipv6` TINYINT(1) NOT NULL DEFAULT '0',
		INDEX (`spbc_network_1`, `spbc_network_2`, `spbc_network_3`, `spbc_network_4`,
		`spbc_mask_1`, `spbc_mask_2`, `spbc_mask_3`, `spbc_mask_4`)
		) ENGINE = MYISAM ;");
	$wpdb->query("ALTER TABLE `" . SPBC_DB_PREFIX . SPBC_LOG_TABLE . "` 
		CHANGE `auth_ip` `auth_ip` VARCHAR(50) DEFAULT NULL;");
	$wpdb->query("ALTER TABLE `" . SPBC_DB_PREFIX . SPBC_FIREWALL_LOG . "` 
		CHANGE `ip_entry` `ip_entry` VARCHAR(50) DEFAULT NULL;");
	
	// Drop scan results
	$wpdb->query('DELETE FROM ' . SPBC_DB_PREFIX . SPBC_SCAN_RESULTS . ' WHERE 1;');
	unset($spbc->data['scanner']['last_wp_version']);
	SpbcCron::removeTask('scanner_scan_deep_core');
	SpbcCron::removeTask('scanner_scan_deep_plugin');
}

function spbc_update_to_2_9_0(){
	global $wpdb;
	$wpdb->query("ALTER TABLE `" . SPBC_DB_PREFIX . SPBC_LOG_TABLE . "` 
		CHANGE `user_login` `user_login` VARCHAR(100) NOT NULL;");
}