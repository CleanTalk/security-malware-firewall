<?php

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