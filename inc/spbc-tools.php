<?php

use CleantalkSP\SpbctWP\Scanner;

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
function spbc_log($message, $func = null, $params = array()){
	
	sleep(1);
	
	global $spbc;
	
	$time_Ms = (int) substr( microtime(), 2, 6);
	
	$key = date('Y-m-d H:i:s' ).':'.$time_Ms.' ACTION '.current_action().' FUNCTION '.$func;
	
	if( $message )                           $spbc_debug[$key]              = $message;
	if( in_array('cron', $params)    ) $spbc->debug[$key]['cron']     = $spbc->cron;
	if( in_array('data', $params)    ) $spbc->debug[$key]['data']     = $spbc->data;
	if( in_array('to_date', $params) ) $spbc->debug[$key]['settings'] = $spbc->settings;
	
	$spbc->save('debug');
}

function spbc_is_windows(){
	return strpos(strtolower(php_uname('s')), 'windows') !== false ? true : false;
}

function spbc_search_page_errors($string_page){
	return
		   empty($string_page)
		|| strpos($string_page,  'PHP Notice')            !== false
		|| strpos($string_page,  'PHP Warning')        !== false
		|| strpos($string_page,  'Fatal error')       !== false
		|| strpos($string_page,  'Parse error')       !== false
		|| stripos($string_page, 'internal server error') !== false
		|| stripos($string_page, 'has been a critical error on this website') !== false;
}

/**
 * @param $module_type
 *
 * @return string
 */
function spbc_get_module_folder_by_type( $module_type ){
    if( $module_type === 'plugins' ){
        return WP_PLUGIN_DIR;
    }
    
    if( $module_type === 'themes' ){
        return get_theme_root();
    }
}

function spbc_get_modules_by_type( $module_type ){
    
    $output      = array();
    $modules_dir = spbc_get_module_folder_by_type($module_type);
    
    foreach(glob($modules_dir.'/*') as $module_dir){
        if( is_dir($module_dir) ){
            foreach( glob($module_dir . '/*') as $module_file ){
                if( ! is_file( $module_file ) || ( $module_type === 'themes' && strpos($module_file, 'style.css' ) === false )){
                    continue;
                }
                $module = get_file_data($module_file, array('Name' => "$module_type name", 'Version' => 'Version',));
                if( ! empty( $module['Version'] ) ){
                    if( $module_type === 'plugins' ){
                        $module[ $module_type ] = substr($module_file, strlen(WP_PLUGIN_DIR)+1);
                        $output[preg_replace('/^(.*)(\/|\\\\).*/', '$1', substr($module_file, strlen(WP_PLUGIN_DIR)+1))] = $module;
                    }
                    if( $module_type === 'themes' ){
                        $module[ $module_type ] = substr($module_file, strlen(get_theme_root())+1, -(strlen('/style.css')));
                        $output[substr($module_file, strlen(get_theme_root())+1, -(strlen('/style.css')))] = $module;
                    }
                }
            }
        }
    }
    
    return $output;
}

/**
 * Defines the source and its params depending on a file path
 *
 * @param string $file_path relative (WP root) path to the file
 *
 * @return array|false Keys in the array are 'slug', 'name, type', 'version'
 */
function spbc_get_source_info_of( $file_path ){
    
    $absolute_file_path = spbc_get_root_path() . $file_path;
    
    if( strpos( $absolute_file_path, WP_PLUGIN_DIR ) !== false ){
        $source_dir = explode( DIRECTORY_SEPARATOR, pathinfo( substr( $absolute_file_path, strlen( WP_PLUGIN_DIR ) ),  PATHINFO_DIRNAME ) )[0];
        if( $source_dir ){
            foreach(glob($source_dir.'/*') as $plugin_file){
                $source_info = get_file_data( $plugin_file, array( 'Name' => null, 'Version' => null ) );
                if( isset( $source_info['Version'], $source_info['Name'] ) ){
                    $source_info = array(
                        'source_type' => 'PLUGIN',
                        'source'      => $source_dir,
                        'name'        => $source_info['Name'],
                        'version'     => $source_info['Version'],
                    );
                }
            }
        }
        
    }elseif( strpos( $absolute_file_path, get_theme_root() ) !== false ){
        $source_dir = explode( DIRECTORY_SEPARATOR, pathinfo( substr( $absolute_file_path, strlen( get_theme_root() ) ),  PATHINFO_DIRNAME ) )[0];
        $source_info_file = $source_dir . DIRECTORY_SEPARATOR . 'style.css';
        if( $source_dir && file_exists( $source_info_file ) ){
            $source_info = get_file_data( $source_info_file, array( 'Name' => null, 'Version' => null ) );
            if( isset( $source_info['Version'], $source_info['Name'] ) ){
                $source_info = array(
                    'source_type' => 'THEME',
                    'source'      => $source_dir,
                    'name'        => $source_info['Name'],
                    'version'     => $source_info['Version'],
                );
            }
        }
        
    }elseif( empty( $source_info ) ){
        global $wp_version;
        $result = Scanner\Helper::getHashesForCMS('wordpress', $wp_version );
        if( empty( $result['error'] ) ){
            foreach( $result['checksums'] as $path => $real_full_hash ){
                if( $file_path === $path ){
                    $source_info = array(
                        'source_type' => 'CORE',
                        'source'      => 'wordpress',
                        'name'        => 'WordPress',
                        'version'     => $wp_version,
                    );
                }
            }
        }
    }
    
    return isset( $source_info ) ;
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

/**
 * Does ey has correct symbols? Checks against regexp ^[a-z\d]{3,15}$
 * @param string api_key
 * @return bool
 */
function spbc_api_key__is_correct($api_key = null){
	global $spbc;
	$api_key = $api_key !== null
		? $api_key
		: $spbc->api_key;
	return $api_key && preg_match('/^[a-z\d]{3,15}$/', $api_key);
}

/**
 * Copies wp_timezone_string() function accessible only from WP 5.3
 *
 * ***
 *
 * Retrieves the timezone from site settings as a string.
 *
 * Uses the `timezone_string` option to get a proper timezone if available,
 * otherwise falls back to an offset.
 *
 * @since 5.3.0
 *
 * @return string PHP timezone string or a ±HH:MM offset.
 */
function spbc_wp_timezone_string(){
    
    $timezone_string = get_option( 'timezone_string' );
    
    if( $timezone_string ){
        return $timezone_string;
    }
    
    $offset  = (float) get_option( 'gmt_offset' );
    $hours   = (int) $offset;
    $minutes = ( $offset - $hours );
    
    $sign     = ( $offset < 0 ) ? '-' : '+';
    $abs_hour = abs( $hours );
    $abs_mins = abs( $minutes * 60 );
    
    return sprintf( '%s%02d:%02d', $sign, $abs_hour, $abs_mins );
}

/**
 * Checks if the string is ASCII
 *
 * @param $string
 *
 * @return bool
 */
function spbc_check_ascii($string)
{
    if( function_exists('mb_check_encoding') ){
        if( mb_check_encoding($string, 'ASCII') ){
            return true;
        }
    }elseif( ! preg_match('/[^\x00-\x7F]/', $string) ){
        return true;
    }
    
    return false;
}