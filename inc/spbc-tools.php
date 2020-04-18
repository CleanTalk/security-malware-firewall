<?php

// Returns country part for emails
function spbc_report_country_part($ips_c, $ip = null) {
    
    if (isset($ips_c[$ip]['country_code'])) {
		
        $country_code = strtolower($ips_c[$ip]['country_code']);
		$country_name = (isset($ips_c[$ip]['country_name']) ? $ips_c[$ip]['country_name'] : '-');
		
        $country_part = sprintf('<img src="https://cleantalk.org/images/flags/%s.png" alt="%s" />&nbsp;%s',
            $country_code,
            $country_code,
            $country_name
        );
    }else{
		$country_part = '-';
	}

    return $country_part;
}

function spbc_get_root_path($end_slash = false){
	return $end_slash ? ABSPATH : substr(ABSPATH, 0, -1);
}

//* Write $message to the plugin's debug option
function spbc_log($message = 'empty', $func = null, $params = array()){
	
	$spbc_debug = get_option( SPBC_DEBUG );
	
	$function = $func                         ? " FUNCTION $func" : '';
	$cron     = in_array('cron', $params)     ? true  : false;
	$data     = in_array('data', $params)     ? true  : false;
	$settings = in_array('settings', $params) ? true  : false;
	$to_date  = in_array('to_date', $params)  ? true  : false;
	
	$time_add = microtime(true) % 1000;
	
	if($message)  $spbc_debug[date('H:i:s', time()).'_'.$time_add.' ACTION '.current_action().$func]             = print_r($message, true);
	if($cron)     $spbc_debug[date('H:i:s', time()).'_'.$time_add.' ACTION '.current_action().$func.' cron']     = print_r(get_option('spbc_cron'), true);
	if($data)     $spbc_debug[date('H:i:s', time()).'_'.$time_add.' ACTION '.current_action().$func.' data']     = print_r(get_option('spbc_data'), true);
	if($settings) $spbc_debug[date('H:i:s', time()).'_'.$time_add.' ACTION '.current_action().$func.' settings'] = print_r(get_option('spbc_settings'), true);
	
	if($to_date){
		foreach($spbc_debug as &$value){
			$value = preg_replace_callback('/(15\d{8})/', 'spbc_log_time2date', $value);
		} unset($value);
	}
	
	update_option(SPBC_DEBUG, $spbc_debug, 'no');
}

function spbc_log_time2date($matches){
	if(isset($matches[1]))
		return date('Y-m-d H:i:s', $matches[1]);
	else
		return $matches[0];
}

function spbc_is_windows(){
	return strpos(strtolower(php_uname('s')), 'windows') !== false ? true : false;
}

function spbc_search_page_errors($string_page){
	return (
		   empty($string_page)
		|| strpos($string_page,  'Notice')            !== false
		|| strpos($string_page,  'Warning')           !== false
		|| strpos($string_page,  'Fatal error')       !== false
		|| strpos($string_page,  'Parse error')       !== false
		|| stripos($string_page, 'internal server error') !== false
		|| stripos($string_page, 'there has been a critical error on your website') !== false
	);
}

function spbc_get_plugins(){
	$output = array();
	foreach(glob(WP_PLUGIN_DIR.'/*') as $plugin_dir){
		if(is_dir($plugin_dir)){
			foreach(glob($plugin_dir.'/*') as $plugin_file){
				if(is_file($plugin_file)){
					$plugin = get_file_data($plugin_file, array('Name' => 'Plugin Name', 'Version' => 'Version'));
					if(!empty($plugin['Version'])){
						$plugin['plugin'] = substr($plugin_file, strlen(WP_PLUGIN_DIR)+1);
						$output[preg_replace('/^(.*)(\/|\\\\).*/', '$1', substr($plugin_file, strlen(WP_PLUGIN_DIR)+1))] = $plugin;
					}
				}
			}
		}
	}
	return $output;
}

function spbc_get_themes(){
	$output = array();
	foreach(glob(get_theme_root().'/*') as $theme_dir){
		if(is_dir($theme_dir)){
			foreach(glob($theme_dir.'/*') as $theme_file){
				if(strpos($theme_file, 'style.css') !== false){
					$theme = get_file_data($theme_file,	array('Name' => 'Theme Name', 'Version' => 'Version'));
					if(!empty($theme['Version'])){
						$theme['theme'] = substr($theme_file, strlen(get_theme_root())+1, -(strlen('/style.css')));
						$output[substr($theme_file, strlen(get_theme_root())+1, -(strlen('/style.css')))] = $theme;
					}
				}
			}
		}
	}
	return $output;
}

/**
 * Checks if the current user has role
 *  
 * @param array $roles
 * @param int $user User ID to check
 * @return boolean Does the user has this role|roles
 */
function spbc_is_user_role_in( $roles, $user = false ){
	
	if( is_numeric($user) && function_exists('get_userdata'))        $user = get_userdata( $user );
	if( is_string($user)  && function_exists('get_user_by'))         $user = get_user_by('login', $user );
	if( ! $user           && function_exists('wp_get_current_user')) $user = wp_get_current_user();
	
	if( empty($user->ID) )
		return false;

	foreach( (array) $roles as $role ){
		if( isset($user->caps[ strtolower($role) ]) || in_array(strtolower($role), $user->roles) )
			return true;
	}
	
	return false;
}