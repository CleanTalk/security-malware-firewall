<?php

use CleantalkSP\Variables\Server;

/**
 * Gets user by filed
 *
 * @param $field
 * @param $value
 *
 * @return bool|WP_User
 */
function spbc_get_user_by($field, $value){
	
	$userdata = WP_User::get_data_by($field, $value);
	
	if(!$userdata)
		return false;
	
	$user = new WP_User;
	$user->init($userdata);
	
	return $user;
}

/*
 * Checking if current request is a cron job
 * Support for wordpress < 4.8.0
 *
 * @return bool
 */
function spbc_wp_doing_cron() {

	if( function_exists( 'wp_doing_cron' ) ) {
		return wp_doing_cron();
	} else {
		return ( defined( 'DOING_CRON' ) && DOING_CRON );
	}

}

/**
 * Checks if the plugin is active
 *
 * @param string $plugin relative path from plugin folder like security-malware-firewall/security-malware-firewall.php
 *
 * @return bool
 */
function spbc_is_plugin_active( $plugin ) {
	return in_array( $plugin, (array) get_option( 'active_plugins', array() ) ) || spbc_is_plugin_active_for_network( $plugin );
}

/**
 * Checks if the plugin is active for network
 *
 * @param string $plugin relative path from plugin folder like security-malware-firewall/security-malware-firewall.php
 *
 * @return bool
 */
function spbc_is_plugin_active_for_network( $plugin ){

	if ( ! SPBC_WPMS )
		return false;

	$plugins = get_site_option( 'active_sitewide_plugins' );
	return isset( $plugins[ $plugin ] )
		? true
		: false;
}

function spbc_mailpoet_doing_cron() {
	return (
		// MailPoet cron requests skip
		spbc_is_plugin_active( 'mailpoet/mailpoet.php' ) &&
		Server::get('HTTP_USER_AGENT') === 'MailPoet Cron' &&
		strpos( Server::get('REQUEST_URI'), 'mailpoet_router' ) !== false
	);
}