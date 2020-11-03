<?php

use CleantalkSP\SpbctWp\API as SpbcAPI;
use CleantalkSP\SpbctWp\Cron as SpbcCron;

//
// Do updates in SQL database after plugin update.
//
function spbc_run_update_actions($current_version, $new_version) {
	
	$current_version = spbc_version_standartization($current_version);
	$new_version     = spbc_version_standartization($new_version);
	
	$current_version_str = implode('.', $current_version);
	$new_version_str     = implode('.', $new_version);
		
	for($ver_major = $current_version[0]; $ver_major <= $new_version[0]; $ver_major++){
		for($ver_minor = 0; $ver_minor <= 100; $ver_minor++){
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
	SpbcCron::addTask('send_logs',           'spbc_send_logs',                3600, time() + 1800);
	SpbcCron::addTask('send_report',         'spbc_send_daily_report',        86400, time() + 43200);
	SpbcCron::addTask('firewall_update',     'spbc_security_firewall_update', 86400, time() + 43200);
	SpbcCron::addTask('send_firewall_logs',  'spbc_send_firewall_logs',       3600, time() + 1800);
	SpbcCron::addTask('access_key_notices',  'spbc_access_key_notices',       3600, time() + 3500);
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
		$result = SpbcAPI::method__notice_paid_till($spbc->settings['spbc_key'], preg_replace('/http[s]?:\/\//', '', get_option('siteurl'), 1), 'security');
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
	SpbcCron::addTask('perform_scan_wrapper', 'spbc_perform_scan_wrapper', 86400, time() + 86400);
	// Drop existing table and create scanner's table
	$wpdb->query("DROP TABLE IF EXISTS ". SPBC_TBL_SCAN_FILES .";");
	$wpdb->query("CREATE TABLE IF NOT EXISTS ". SPBC_TBL_SCAN_FILES ." (
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
	);");
}

function spbc_update_to_2_1_0(){
	global $spbc;
	unset($spbc->data['errors']);
	$spbc->save('data');
}

function spbc_update_to_2_4_0(){
	global $wpdb;
	$wpdb->query("DROP TABLE IF EXISTS ".SPBC_TBL_SECURITY_LOG.";");
	$wpdb->query("CREATE TABLE IF NOT EXISTS ".SPBC_TBL_SECURITY_LOG." (
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
		) DEFAULT CHARSET=latin1 AUTO_INCREMENT=1;");
	$wpdb->query("DROP TABLE IF EXISTS ".SPBC_TBL_FIREWALL_DATA.";");
	$wpdb->query("CREATE TABLE IF NOT EXISTS ".SPBC_TBL_FIREWALL_DATA." (
		`spbc_network` int(11) unsigned NOT NULL,
		`spbc_mask` int(11) unsigned NOT NULL,
		`status` TINYINT(1) NULL,
		INDEX (`spbc_network` , `spbc_mask`)
		);");
	$wpdb->query("DROP TABLE IF EXISTS ".SPBC_TBL_FIREWALL_LOG.";");
	$wpdb->query("CREATE TABLE IF NOT EXISTS ".SPBC_TBL_FIREWALL_LOG." (
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
		PRIMARY KEY (`entry_id`));");
	$wpdb->query("DROP TABLE IF EXISTS ".SPBC_TBL_SCAN_LINKS.";");
	$wpdb->query("CREATE TABLE IF NOT EXISTS ".SPBC_TBL_SCAN_LINKS." (
		`log_id` int(11) NOT NULL AUTO_INCREMENT,
		`user_id` int(11) unsigned DEFAULT NULL,
		`service_id` int(11) unsigned DEFAULT NULL,
		`submited` datetime NOT NULL,
		`total_links_found` INT NOT NULL,
		`links_list` TEXT DEFAULT NULL,
		PRIMARY KEY (`log_id`)
		) DEFAULT CHARSET=latin1 AUTO_INCREMENT=1;");
}

function spbc_update_to_2_5_0(){
	global $wpdb;
	$wpdb->update(SPBC_TBL_SCAN_FILES,
		array( 'status' => 'UNKNOWN' ),
		array( 'status' => 'NOT_CHECKED' )
	);
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SCAN_FILES . "`
		ADD COLUMN `source` ENUM('CORE', 'PLUGIN') NOT NULL DEFAULT 'CORE' AFTER `mtime`,
		ADD COLUMN `checked` ENUM('NO', 'YES') NOT NULL DEFAULT 'NO' AFTER `source`;");
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SCAN_FILES . "` 
		CHANGE `status` `status` ENUM('UNKNOWN','OK','APROVED','COMPROMISED','INFECTED') NOT NULL DEFAULT 'UNKNOWN',
		CHANGE `severity` `severity` ENUM('CRITICAL', 'DANGER', 'SUSPICIOUS', 'NONE') NULL DEFAULT NULL;");
}

function spbc_update_to_2_6_2(){
	SpbcCron::updateTask('send_logs',            'spbc_send_logs',                3600, time() + 1800);
	SpbcCron::updateTask('send_report',          'spbc_send_daily_report',        86400, time() + 43200);
	SpbcCron::updateTask('firewall_update',      'spbc_security_firewall_update', 86400, time() + 43200);
	SpbcCron::updateTask('send_firewall_logs',   'spbc_send_firewall_logs',       3600, time() + 1800);
	SpbcCron::updateTask('access_key_notices',   'spbc_access_key_notices',       3600, time() + 3500);
	SpbcCron::updateTask('perform_scan_wrapper', 'spbc_perform_scan_wrapper',     86400, time() + 43200);
}

function spbc_update_to_2_8_0(){
	global $spbc, $wpdb;
	// Preparing for IPv6
	if($spbc->data['cdn'])              unset($spbc->data['cdn']);
	if($spbc->data['private_networks']) unset($spbc->data['private_networks']);

	$wpdb->query('DROP TABLE IF EXISTS ' . SPBC_TBL_FIREWALL_DATA . ';');
	$wpdb->query("CREATE TABLE IF NOT EXISTS " . SPBC_TBL_FIREWALL_DATA . " (
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
		);");
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SECURITY_LOG . "` 
		CHANGE `auth_ip` `auth_ip` VARCHAR(50) DEFAULT NULL;");
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` 
		CHANGE `ip_entry` `ip_entry` VARCHAR(50) DEFAULT NULL;");
	
	// Drop scan results
	$wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE 1;');
	unset($spbc->data['scanner']['last_wp_version']);
	SpbcCron::removeTask('scanner_scan_deep_core');
	SpbcCron::removeTask('scanner_scan_deep_plugin');
}

function spbc_update_to_2_9_0(){
	global $wpdb;
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SECURITY_LOG . "` 
		CHANGE `user_login` `user_login` VARCHAR(100) NOT NULL;");
}

function spbc_update_to_2_12_0(){
	global $wpdb;
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SCAN_FILES . "` 
		CHANGE `status` `status` ENUM('UNKNOWN','OK','APROVED','COMPROMISED','INFECTED','QUARANTINED') NOT NULL DEFAULT 'UNKNOWN',
		ADD COLUMN `q_status` ENUM('UNKNOWN','OK','APROVED','COMPROMISED','INFECTED','QUARANTINED') NULL DEFAULT NULL AFTER `real_full_hash`,
		ADD COLUMN `q_path` VARCHAR(1024) DEFAULT NULL AFTER `q_status`,
		ADD COLUMN `q_time` INT(11) DEFAULT NULL AFTER `q_path`;");
}

function spbc_update_to_2_13_0(){
	update_option('spbc_plugins', array(), 'no');
	update_option('spbc_themes', array(), 'no');
}

function spbc_update_to_2_14_0(){
	global $spbc, $wpdb;
	$spbc->data['cron']['running']  = false;
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SCAN_FILES . "`
		CHANGE `status` `status` ENUM('UNKNOWN','OK','APROVED','MODIFIED','INFECTED','QUARANTINED') NOT NULL DEFAULT 'UNKNOWN';");
	$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "`
		SET `status`='MODIFIED' WHERE status = '';");
}

function spbc_update_to_2_15_0(){
	global $spbc, $wpdb;
	$spbc->data['cron']['running'] = false;
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` 
		CHANGE `status` `status` ENUM('PASS','PASS_BY_WHITELIST','DENY','DENY_BY_NETWORK','DENY_BY_DOS','DENY_BY_WAF') NULL,
		ADD COLUMN `waf_status` ENUM('XSS','SQL','FILE') NULL AFTER `status`");
	spbc_mu_plugin__install();
}

function spbc_update_to_2_16_0(){
	global $spbc, $wpdb;
	$spbc->data['cron']['running'] = false;
	spbc_mu_plugin__uninstall();
	spbc_mu_plugin__install();
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` 
		CHANGE `status` `status` ENUM('PASS','PASS_BY_WHITELIST','DENY','DENY_BY_NETWORK','DENY_BY_DOS','DENY_BY_WAF_XSS','DENY_BY_WAF_SQL','DENY_BY_WAF_FILE') NULL,
		DROP COLUMN `waf_status`;");
}

function spbc_update_to_2_17_0(){
	global $spbc, $wpdb;
	$spbc->data['cron']['running'] = false;
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` 
		DROP COLUMN `allowed_entry`,
		DROP COLUMN `blocked_entry`,
		ADD COLUMN `requests` INT(11) NULL AFTER `status`;");
	$wpdb->query('DROP TABLE IF EXISTS ' . SPBC_TBL_SCAN_LINKS . ';');
	$wpdb->query('CREATE TABLE '. SPBC_TBL_SCAN_LINKS .' (
		`link_id` INT(11) NOT NULL AUTO_INCREMENT,
		`scan_id` INT(11) NOT NULL,
		`domain` TINYTEXT NOT NULL,
		`link` VARCHAR(2048) NOT NULL,
		`link_text` VARCHAR(2048) NOT NULL,
		`page_url` VARCHAR(2048) NOT NULL,
		`spam_active` TINYINT(1) NULL,
		PRIMARY KEY (`link_id`),
		INDEX `spam_active` (`spam_active`),
		INDEX `scan_id` (`scan_id`),
		INDEX `domain` (`domain`(40))
		) ENGINE = InnoDB;');
}

function spbc_update_to_2_20_0(){
	global $wpdb;
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` 
		ADD COLUMN `pattern` VARCHAR(1024) NULL AFTER `status`");
}

function spbc_update_to_2_21_0(){
	global $wpdb;
	$wpdb->query("DELETE FROM `" . SPBC_TBL_FIREWALL_LOG . "` WHERE 1");
}

function spbc_update_to_2_22_0(){
	global $wpdb, $spbc, $wp_version;
	// Alter table. Adding package type, package name and package version
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SCAN_FILES . "`	
		CHANGE COLUMN `source` `source_type` ENUM('CORE', 'PLUGIN', 'THEME') NULL DEFAULT NULL,
		CHANGE COLUMN `checked` `checked` ENUM('NO', 'YES', 'YES_SIGNATURE', 'YES_HEURISTIC') NOT NULL DEFAULT 'NO',
		CHANGE COLUMN `weak_spots` `weak_spots` VARCHAR(2048) NULL DEFAULT NULL,
		ADD COLUMN `source` VARCHAR(300) NULL DEFAULT NULL AFTER `source_type`,
		ADD COLUMN `version` VARCHAR(20) NULL DEFAULT NULL AFTER `source`;");
	// Set source_type = null for custom files
	$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` SET source_type = NULL
		WHERE source_type = 'CORE' && real_full_hash IS NULL;");
	
	// Set source = wordpress and version for core files
	$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` 
		SET source = 'wordpress',
			version = '$wp_version'
		WHERE source_type = 'CORE' && real_full_hash IS NOT NULL;");
	// Updating version and source of plugins
	if($spbc->plugins === false)
		$spbc->plugins = array();
	foreach($spbc->plugins as $name => $version){
		$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` 
		SET source = '$name',
			version = '$version'
		WHERE path LIKE '%$name%' && real_full_hash IS NOT NULL;");
	}
	// Updating version and source of themes
	if($spbc->themes === false)
		$spbc->themes = array();
	foreach($spbc->themes as $name => $version){
		$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` 
		SET source_type = 'THEME',
			source = '$name',
			version = '$version'
		WHERE path LIKE '%$name%' && real_full_hash IS NOT NULL;");
	}
	$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` 
		SET checked = 'YES_HEURISTIC'
		WHERE checked = 'YES' AND real_full_hash <> full_hash;");
		
	// Cron fix
	$spbc->data['cron']['running'] = false;
	
	// Signatures addition
	$wpdb->query('CREATE TABLE '. SPBC_TBL_SCAN_SIGNATURES .' (
		`id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
		`name` VARCHAR(128) NOT NULL,
		`body` VARCHAR(512) NOT NULL,
		`type` ENUM("FILE","CODE_PHP","CODE_JS","CODE_HTML") NOT NULL,
		`attack_type` SET("SQL_INJECTION","XSS","MALWARE") NOT NULL,
		`submitted` DATETIME NOT NULL,
		PRIMARY KEY (`id`),
		UNIQUE KEY (`name`)
		) ENGINE = InnoDB;'
	);
	SpbcCron::addTask('scanner_update_signatures', 'spbc_scanner__signatures_update', 86400, time() + 20);
	$spbc->error_delete('scan_modified', 'and_save_data');
	
}

function spbc_update_to_2_24_0(){
	
	global $wpdb;
	
	// Adding column for signature instructions
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_SCAN_SIGNATURES . "`	
		ADD COLUMN `cci` TEXT NULL DEFAULT NULL AFTER `submitted`;");
	
	$wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` 
		SET weak_spots = NULL,
			checked = 'NO'
		WHERE weak_spots IS NOT NULL;");
	
}

function spbc_update_to_2_25_0(){
	
	global $spbc, $wpdb;
	
	$wpdb->query('DROP TABLE '. SPBC_TBL_SCAN_SIGNATURES);
	$wpdb->query('CREATE TABLE IF NOT EXISTS '. SPBC_TBL_SCAN_SIGNATURES .' (
		`id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
		`name` VARCHAR(128) NOT NULL,
		`body` VARCHAR(512) NOT NULL,
		`type` ENUM("FILE","CODE_PHP","CODE_HTML","CODE_JS") NOT NULL,
		`attack_type` SET("SQL_INJECTION","XSS","MALWARE") NOT NULL,
		`submitted` DATETIME NOT NULL,
		`cci` TEXT NULL DEFAULT NULL,
		PRIMARY KEY (`id`),
		UNIQUE KEY (`name`)
		) ENGINE = InnoDB;');
	
	$spbc->data['last_php_log_sent'] = 0;
	$spbc->save('data');
	
	SpbcCron::addTask('send_php_logs', 'spbc_PHP_logs__send', 3600, time() + 300);
	
}

function spbc_update_to_2_25_1(){
	
	global $spbc;
	
	$spbc->data['last_php_log_sent'] = time();
	$spbc->save('data');
	
}

function spbc_update_to_2_26_1(){

	if(file_exists(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php'))
		unlink(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php');

	spbc_mu_plugin__install();
}

function spbc_update_to_2_27(){
	
	if(file_exists(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php'))
		unlink(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php');
	if(file_exists(WPMU_PLUGIN_DIR . '/0security-malware-firewall-mu.php'))
		unlink(WPMU_PLUGIN_DIR . '/0security-malware-firewall-mu.php');

	spbc_mu_plugin__install();
}

function spbc_update_to_2_28_0(){
	
	global $wpdb;
	
	setcookie('spbc_is_logged_in', '0', time()-30, '/');
	
	// Deleting all SUSPICIOUS severity from scan table
	$wpdb->query("DROP TABLE IF EXISTS ".SPBC_TBL_FIREWALL_LOG.";");
	$wpdb->query("CREATE TABLE IF NOT EXISTS ".SPBC_TBL_FIREWALL_LOG." (
		`entry_id` VARCHAR(40) NOT NULL,
		`ip_entry` VARCHAR(50) NULL, 
		`status` ENUM('PASS','PASS_BY_TRUSTED_NETWORK','PASS_BY_WHITELIST','DENY','DENY_BY_NETWORK','DENY_BY_DOS','DENY_BY_WAF_XSS','DENY_BY_WAF_SQL','DENY_BY_WAF_FILE') NULL,
		`pattern` VARCHAR(1024) NULL,
		`requests` INT NULL,
		`page_url` VARCHAR(1024) NULL,
		`request_method` VARCHAR(5) NULL,
		`x_forwarded_for` VARCHAR(15) NULL,
		`http_user_agent` VARCHAR(300) NULL,
		`entry_timestamp` INT NOT NULL , 
		PRIMARY KEY (`entry_id`));");

}

function spbc_update_to_2_30_0(){
	
	global $wpdb;
	
	// Backup structure
	$wpdb->query('CREATE TABLE IF NOT EXISTS '.SPBC_TBL_BACKUPED_FILES.' (
		`id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
		`backup_id` INT(11) UNSIGNED NOT NULL,
		`real_path` VARCHAR(1024) NOT NULL,
		`back_path` VARCHAR(1024) NOT NULL,
		PRIMARY KEY (`id`)
		) ENGINE = InnoDB;');
	
	$wpdb->query('CREATE TABLE IF NOT EXISTS '.SPBC_TBL_BACKUPS.' (
		`backup_id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
		`type` ENUM("FILE","ALL","SIGNATURES") NOT NULL DEFAULT "FILE",
		`datetime` DATETIME NOT NULL,
		`status` ENUM("PROCESSING", "BACKUPED", "ROLLBACK", "ROLLBACKED", "STOPPED") NOT NULL DEFAULT "PROCESSING",
		PRIMARY KEY (`backup_id`)
		) ENGINE = InnoDB;');
	
	if(!is_dir(SPBC_PLUGIN_DIR.'backups'))
		mkdir(SPBC_PLUGIN_DIR.'backups');
	
	// Personal flag in FW data
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_DATA . "`
		ADD COLUMN `is_personal` TINYINT(1) NULL AFTER `ipv6`;");
	
}

function spbc_update_to_2_31_0(){
	global $spbc, $wpdb;
	SpbcCron::removeTask('perform_scan_wrapper');
	SpbcCron::removeTask('perform_scan_wrapper_act');

	SpbcCron::addTask('scanner__launch', 'spbc_scanner__launch', 86400, isset($spbc->settings['scanner_auto_start_manual_time']) && $spbc->settings['scanner_auto_start_manual_time'] ? $spbc->settings['scanner_auto_start_manual_time'] - time() < 0 ? (3600*24 + $spbc->settings['scanner_auto_start_manual_time'] - time()) : $spbc->settings['scanner_auto_start_manual_time'] - time() : time() + 3600);
	// Deletting all errors
	if(isset($spbc->data['errors'])) unset($spbc->data['errors']);
	// Adding new blocked status. Exploit
	$wpdb->query("ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` 
	CHANGE COLUMN `status` `status` ENUM('PASS','PASS_BY_TRUSTED_NETWORK','PASS_BY_WHITELIST','DENY','DENY_BY_NETWORK','DENY_BY_DOS','DENY_BY_WAF_XSS','DENY_BY_WAF_SQL','DENY_BY_WAF_FILE','DENY_BY_WAF_EXPLOIT') NULL DEFAULT NULL");
}

function spbc_update_to_2_33_0(){
	global $wpdb;
	$wpdb->query('CREATE TABLE IF NOT EXISTS '. SPBC_TBL_SCAN_FRONTEND.' (
		`page_id` VARCHAR(1024) NOT NULL,
		`url` VARCHAR(1024) NOT NULL,
		`dbd_found` TINYINT NULL,
		`redirect_found` TINYINT NULL,
		`signature` TINYINT NULL,
		`bad_code` TINYINT NULL,
		`weak_spots` VARCHAR(1024) NULL
		);'
	);
}

function spbc_update_to_2_35_0(){
	global $wpdb;
	$wpdb->query('ALTER TABLE '.SPBC_TBL_SCAN_FILES.'
		ADD COLUMN `source_status` SET(\'UP_TO_DATE\',\'OUTDATED\',\'NOT_IN_DIRECTORY\',\'UNKNOWN\') NULL AFTER `source`;'
	);
}

function spbc_update_to_2_36_0(){
	global $wpdb;
	$wpdb->query('ALTER TABLE '. SPBC_TBL_SECURITY_LOG .'
		ADD COLUMN `user_agent` VARCHAR(1024) NULL AFTER `role`,
		ADD COLUMN `browser_sign` VARCHAR(32) NULL AFTER `user_agent`;'
	);
}

function spbc_update_to_2_37_0(){
	global $spbc;
	$spbc->error_delete( 'allow_url_fopen', true );
}

function spbc_update_to_2_41_0(){
	$sqls[] = "CREATE TABLE IF NOT EXISTS %sspbc_traffic_control_logs (
		`id` VARCHAR(32) NOT NULL,
		`ip` VARCHAR(40) NOT NULL,
		`entries` INT DEFAULT 0,
		`interval_start` INT NOT NULL,
		PRIMARY KEY (`id`));";
	spbc_activation__create_tables( $sqls );
}

function spbc_update_to_2_42_0() {

	if( SPBC_WPMS ) {

		global $spbc;
		$spbc->network_settings['waf_enabled']       = $spbc->def_network_settings['waf_enabled'];
		$spbc->network_settings['waf_xss_check']     = $spbc->def_network_settings['waf_xss_check'];
		$spbc->network_settings['waf_sql_check']     = $spbc->def_network_settings['waf_sql_check'];
		$spbc->network_settings['waf_file_check']    = $spbc->def_network_settings['waf_file_check'];
		$spbc->network_settings['waf_exploit_check'] = $spbc->def_network_settings['waf_exploit_check'];

		$spbc->saveNetworkSettings();

	}

}

function spbc_update_to_2_44_0() {
	global $wpdb;
	$wpdb->query('ALTER TABLE '. SPBC_TBL_SCAN_FRONTEND .'
		ADD COLUMN `weak_spots` VARCHAR(1024) NULL AFTER `bad_code`;'
	);
}

function spbc_update_to_2_45_0() {
	global $wpdb;
	$wpdb->query('ALTER TABLE '. SPBC_TBL_SCAN_SIGNATURES .'
		CHANGE COLUMN `type` `type` ENUM(\'FILE\',\'CODE_PHP\',\'CODE_HTML\',\'CODE_JS\',\'WAF_RULE\') NOT NULL AFTER `body`,
		CHANGE COLUMN `attack_type` `attack_type` SET(\'SQL_INJECTION\',\'XSS\',\'MALWARE\',\'EXPLOIT\') NOT NULL AFTER `type`;'
	);
}

function spbc_update_to_2_47_1() {
	spbc_mu_plugin__install();
}

function spbc_update_to_2_47_2() {

	global $wpdb;

	$original_show_errors = $wpdb->show_errors;
	$wpdb->show_errors = false;

	$wpdb->query( "ALTER TABLE `". SPBC_TBL_FIREWALL_DATA ."` ADD INDEX `spbc_network_4` (`spbc_network_4`);" );

	$wpdb->show_errors = $original_show_errors;

}

function spbc_update_to_2_48_0() {
	
	global $wpdb;
	
	if( SPBC_WPMS ) {
		
		$initial_blog = get_current_blog_id();
		$blogs        = array_keys( $wpdb->get_results( 'SELECT blog_id FROM ' . $wpdb->blogs, OBJECT_K ) );
		
		foreach ( $blogs as $blog ) {
			
			set_time_limit( 30 );
			
			switch_to_blog( $blog );
			
			// Getting key
			$net_settings = get_site_option( 'spbc_network_settings' );
			$settings     = $net_settings['allow_custom_key']
				? get_option( 'spbc_settings' )
				: $net_settings;
			
			// Update plugin status
			if ( ! empty( $settings['spbc_key'] ) ) {
				
				//Clearing all errors
				delete_option( 'spbc_errors' );
				
				// Checking account status
				$result = SpbcAPI::method__notice_paid_till(
					$settings['spbc_key'],
					preg_replace( '/http[s]?:\/\//', '', get_option( 'siteurl' ), 1 ), // Site URL
					'security'
				);
				
				$data = get_option( 'spbc_data', array() );
				$data['key_is_ok'] = false;
				
				// Passed without errors
				if ( empty( $result['error'] ) ) {
					
					// Key is valid
					if ( $result['valid'] ) {
						
						$data['key_is_ok']        = true;
						$data['user_token']       = isset( $result['user_token'] ) ? $result['user_token'] : '';
						$data['notice_show']      = $result['show_notice'];
						$data['notice_renew']     = $result['renew'];
						$data['notice_trial']     = $result['trial'];
						$data['auto_update_app']  = isset( $result['show_auto_update_notice'] ) ? $result['show_auto_update_notice'] : 0;
						$data['service_id']       = $result['service_id'];
						$data['moderate']         = $result['moderate'];
						$data['auto_update_app '] = isset( $result['auto_update_app'] ) ? $result['auto_update_app'] : 0;
						$data['license_trial']    = isset( $result['license_trial'] ) ? $result['license_trial'] : 0;
						$data['account_name_ob']  = isset( $result['account_name_ob'] ) ? $result['account_name_ob'] : '';
						
					}
				}
				
				update_option( 'spbc_data', $data );
				
			}
			
		}
		
		switch_to_blog( $initial_blog );
		
	}
}

function spbc_update_to_2_49_0() {

	global $wpdb;

	$wpdb->query( 'ALTER TABLE `' . SPBC_TBL_TC_LOG . '` ADD COLUMN `log_type` TINYINT NULL DEFAULT NULL AFTER `id`;' );

	$wpdb->query( "ALTER TABLE `" . SPBC_TBL_FIREWALL_LOG . "` CHANGE `status` `status` ENUM('PASS','PASS_BY_TRUSTED_NETWORK','PASS_BY_WHITELIST','DENY','DENY_BY_NETWORK','DENY_BY_DOS','DENY_BY_WAF_XSS','DENY_BY_WAF_SQL','DENY_BY_WAF_FILE','DENY_BY_WAF_EXPLOIT','DENY_BY_BFP');" );

}

function spbc_update_to_2_49_2() {
	global $spbc;
	$spbc->settings['block_timer__5_fails'] = 3600;
	$spbc->saveSettings();
}

function spbc_update_to_2_55_0() {
	
	global $wpdb;
	$wpdb->query('ALTER TABLE '.SPBC_TBL_SCAN_FILES.'
		CHANGE `q_status` `previous_state` VARCHAR(1024) NULL DEFAULT NULL;'
	);
	
	global $spbc;
	$spbc->remote_calls['update_security_firewall'] = array( 'last_call' => 0, 'cooldown' => 300 );
	$spbc->remote_calls['update_security_firewall__write_base'] = array( 'last_call' => 0, 'cooldown' => 0 );
	$spbc->save('remote_calls');
}

function spbc_update_to_2_57_0() {
	
	$sqls__personal[] = 'DROP TABLE `%sspbc_firewall_data`;';
	$sqls__personal[] = 'CREATE TABLE `%sspbc_firewall__personal_ips` (
		    `id` INT(11) NOT NULL AUTO_INCREMENT,
		    `network` INT(10) UNSIGNED NOT NULL DEFAULT "0",
		    `mask` INT(10) UNSIGNED NOT NULL DEFAULT "0",
		    `status` TINYINT(2) NOT NULL DEFAULT "0",
		    INDEX (`network`, `mask`),
		    PRIMARY KEY (`id`)
		)
		COLLATE="utf8_general_ci"
		ENGINE=InnoDB;';
	$sqls__personal[] = 'CREATE TABLE `%sspbc_firewall__personal_countries` (
		    `id` INT(11) NOT NULL AUTO_INCREMENT,
		    `country_code` CHAR(2) NOT NULL,
		    `status` TINYINT(2) NOT NULL,
		    PRIMARY KEY (`id`)
		)
		COLLATE="utf8_general_ci"
		ENGINE=InnoDB;';
	
	$sqls__common[] = 'CREATE TABLE IF NOT EXISTS `%sspbc_firewall_data`(
			`id` char(32) NOT NULL,
			`network` int(10) unsigned NOT NULL DEFAULT "0",
			`mask` int(10) unsigned NOT NULL DEFAULT "0",
			`country_code` char(2) NULL DEFAULT NULL,
			`status` TINYINT(1) NULL,
			INDEX (`network`, `mask`),
			PRIMARY KEY (`id`)
		);';
	
	global $wpdb;
	
	if ( SPBC_WPMS ){
		// Get all blogs
		$initial_blog = get_current_blog_id();
		$blogs        = array_keys( $wpdb->get_results( 'SELECT blog_id FROM ' . $wpdb->blogs, OBJECT_K ) );
		// Perform all sqls for each blog
		foreach ( $blogs as $blog ) {
			switch_to_blog( $blog );
			spbc_activation__create_tables( $sqls__personal );
		}
		switch_to_blog( $initial_blog );
	}else{
		spbc_activation__create_tables( $sqls__personal );
	}
	
	spbc_activation__create_tables( $sqls__common );
	
	spbc_security_firewall_update();
	
}