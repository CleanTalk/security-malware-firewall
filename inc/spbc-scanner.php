<?php

use CleantalkSP\SpbctWP\Helper as SpbcHelper;
use CleantalkSP\SpbctWP\API as SpbcAPI;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Request;
use CleantalkSP\SpbctWP\Scanner\Cure;
use CleantalkSP\SpbctWP\Scanner\Links;
use CleantalkSP\SpbctWP\Scanner;

function spbc_scanner__launch(){
	
	global $spbc;
    
    if( ! $spbc->moderate || ! $spbc->settings['scanner__auto_start'] ){
        return true;
    }
	
	return SpbcHelper::http__request(
		get_option( 'home' ),
		array(
			'plugin_name' => 'security',
			'spbc_remote_call_token' => md5($spbc->settings['spbc_key']),
			'spbc_remote_call_action' => 'scanner__controller',
			'state'                   => 'get_hashes'
		),
		'async'
	);
}

function spbc_scanner__controller(){
	
	global $spbc;
	
	sleep(5);
	
	$state = Request::get( 'state' ) ?: 'get_hashes';
	
	$prev_state = $state;
	$additional_params = array();
	
	switch($state){
		
	// Preparing
		case 'get_hashes':
			// Getting hashes
			$result = spbc_scanner_get_remote_hashes(true);
			$state = 'get_hashes_plug';
			$spbc->data['scanner']['cron']['total_scanned'] = 0;
			$spbc->save('data');
			break;
			
		case 'get_hashes_plug':
			$result = spbc_scanner_get_remote_hashes__plug(true);
			if(empty($result['error'])){
				$state = $result['processed'] < 2 
					? 'clear_table' 
					: 'get_hashes_plug';
			}
			break;
					
		// Clearing table
		case 'clear_table':
			spbc_scanner_clear_table(true);
			$state = 'surface_scan';
			break;
		
		// Surface
		case 'surface_scan':
			
			$offset = (int) Request::get( 'offset' );
			$result = spbc_scanner_scan(true, $offset, SPBC_SCAN_SURFACE_AMOUNT);
			if(empty($result['error'])){
				$result['processed'] < SPBC_SCAN_SURFACE_AMOUNT
					? $state = 'get_hashes_approved'
					: $additional_params['offset'] = $offset + SPBC_SCAN_SURFACE_AMOUNT;

				if(isset($result['processed'])){
					$spbc->data['scanner']['cron']['total_scanned'] += $result['processed'];
					$spbc->save('data');
				}
			}
			break;

		case 'get_hashes_approved':
			$result = spbc_scanner_get_remote_hashes__approved(true);
			if (empty($result['error'])) {
				$state = 'signature_scan';
			}
			break;	
				
		// Signatures
		case 'signature_scan':
			
			$offset = (int) Request::get( 'offset' );
			if(empty($spbc->settings['scanner__signature_analysis'])){
				$state = 'heuristic_scan';
				break;
			}
			
			$result = spbc_scanner_scan_signatures(true, 'UNKNOWN,MODIFIED,OK,INFECTED', SPBC_SCAN_SIGNATURE_AMOUNT);
			if(empty($result['error'])){
				if($result['processed'] != SPBC_SCAN_SIGNATURE_AMOUNT)
					$state = 'heuristic_scan';
			}
			break;
		
		// Heuristic
		case 'heuristic_scan':
			
			$offset = (int) Request::get( 'offset' );
			if(empty($spbc->settings['scanner__heuristic_analysis'])){
				$state = 'cure_backup';
				break;
			}
			
			$result = spbc_scanner_scan_heuristic(true, 'UNKNOWN,MODIFIED,OK,INFECTED', SPBC_SCAN_MODIFIED_AMOUNT);
			if(empty($result['error'])){
				if($result['processed'] != SPBC_SCAN_MODIFIED_AMOUNT)
					$state = 'cure_backup';
			}
			break;
		
		// Backup
		case 'cure_backup':
			
			if(empty($spbc->settings['scanner__auto_cure'])){
				$state = 'cure';
				break;
			}
			
			$result = spbc_backup__files_with_signatures(true);
			$state = 'cure';
			
			break;
		
		// Cure
		case 'cure':
			
			if(empty($spbc->settings['scanner__auto_cure'])){
				$state = 'links_scan';
				break;
			}
			
			$result = spbc_scanner_cure(true);
			if(empty($result['error'])){
				if($result['processed'] != SPBC_SCAN_MODIFIED_AMOUNT)
					$state = 'links_scan';
			}
			break;
			
		// Links
		case 'links_scan':
			
			if(empty($spbc->settings['scanner__outbound_links'])){
				$state = 'send_results';
				break;
			}
			
			$result = spbc_scanner_links_scan(true, SPBC_SCAN_LINKS_AMOUNT);	
			if(empty($result['error'])){
				if($result['processed'] === 0){
					$state = 'frontend_scan';
				}
			}
			break;
		
		// Frontend
		case 'frontend_scan':
			
			if(empty($spbc->settings['scanner__frontend_analysis'])){
				$state = 'send_results';
				break;
			}
			
			$result = spbc_scanner_frontend__scan(true, SPBC_SCAN_FRONTEND_AMOUNT);
			if(empty($result['error'])){
				if($result['processed'] === 0){
					$state = 'send_results';
				}
			}
			break;
		
		// Send result
		case 'send_results':
			
			$result = spbc_scanner_send_results(true, $spbc->data['scanner']['cron']['total_scanned']);
			$end = true;
			
		break;
	}
	
	// Make next call if everything is ok
	if(!isset($end) && empty($result['error'])){		
		$def_params = array(
			'plugin_name'             => 'security',
			'spbc_remote_call_token'  => md5($spbc->settings['spbc_key']),
			'spbc_remote_call_action' => 'scanner__controller',
			'state'                   => $state
		);
		SpbcHelper::http__request(
			get_option( 'home' ),
			array_merge($def_params, $additional_params),
			'get async'
		);
	}
	
	// Delete or add an error
	empty($result['error'])
		? $spbc->error_delete($prev_state, 'and_save_data', 'cron_scan')
		: $spbc->error_add($prev_state, $result, 'cron_scan');
	
	return true;
}

function spbc_scanner_get_remote_hashes($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	global $spbc, $wp_version, $wpdb;

	if(preg_match('/^\d*\.?\d*\.?\d*$/', $wp_version) === 1){
	  
			if(
				!isset($spbc->data['scanner']['last_wp_version'])
				|| (isset($spbc->data['scanner']['last_wp_version']) && $spbc->data['scanner']['last_wp_version'] != $wp_version)
				|| !$wpdb->query('SELECT path FROM '.SPBC_TBL_SCAN_FILES.' LIMIT 1')
			){
				
				if(empty($result['error'])){
					
					// Getting hashes
					$result = Scanner\Helper::getHashesForCMS('wordpress', $wp_version);
					
					if(empty($result['error'])){
                        
                        $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE source_type = "CORE";');
                        
						$is_windows = spbc_is_windows() ? true : false;
						$sql = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES . ' (`fast_hash`, `path`, `real_full_hash`, `source_type`, `source`, `version`) VALUES ';
						$data = array();
						foreach($result['checksums'] as $path => $real_full_hash){
							$path = $is_windows ? str_replace('/', '\\', $path) : $path;
							$fast_hash = md5($path);
							$path = addslashes($path);
							$data[] = sprintf('("%s","%s","%s","CORE", "wordpress", "%s")', $fast_hash, $path, $real_full_hash, $wp_version);
						} unset($path, $real_full_hash);
						$result = $wpdb->query($sql . implode(',', $data) . ';');
						
						if($result !== false){
							$out  = array(
								'files_count' => $result,
							);
						}else
							$out['error'] = 'COULDNT_INSERT with error: ' . $wpdb->last_error;

						$spbc->data['scanner']['last_wp_version'] = $wp_version;
						$spbc->error_delete('get_hashs', 'and_save_data');
						$spbc->save('data');
						
					}else
						$out = $result;
				}else
					$out  = $result;
			}else
				$out = array('comment' => 'Already up to date.',);
	}else
		$out = array('error' => 'Your WordPress version is not supported');
		
	if($direct_call) return $out; else die(json_encode($out));
}

/**
 * Count total amount of plugins and themes
 *
 * @param bool $direct_call
 *
 * @return array|void
 */
function spbc_scanner_count_hashes_plug($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	global $spbc;
    
    $output = array(
        'total'   => 0,
        'plugins' => 0,
        'themes'  => 0,
    );
	
    // Preparing plugins to check again
	$plugins = spbc_get_plugins();
    $spbc->plugins;
    if( empty($spbc->plugins) ){
        $spbc->plugins = $plugins;
    }
    
    foreach( array_keys($plugins) as $plugin_slug ){
        if( isset($spbc->plugins[$plugin_slug]) ){
            if( empty($spbc->plugins[$plugin_slug]['checked']) ){
                $output['total']++;
                $output['plugins']++;
            }
            if( ! empty($spbc->plugins[$plugin_slug]['should_be_checked_again']) ){
                $spbc->plugins[$plugin_slug]['checked'] = 0;
                $output['total']++;
                $output['plugins']++;
                unset($spbc->plugins[$plugin_slug]['should_be_checked_again']);
            }
            if( $spbc->plugins[$plugin_slug]['Version'] !== $plugins[$plugin_slug]['Version'] ){
                $spbc->plugins[$plugin_slug]['checked'] = 0;
                $output['total']++;
                $output['themes']++;
            }
        }else{
            $output['total']++;
            $output['plugins']++;
        }
    }
    $spbc->save('plugins', true, false);
    
    // Preparing themes to check again
	$themes  = spbc_get_themes();
	$spbc->themes;
    if( empty($spbc->themes) ){
        $spbc->themes = $themes;
    }
    
    foreach( array_keys($themes) as $theme_slug ){
        if( isset($spbc->themes[$theme_slug]) ){
            if( empty($spbc->themes[$theme_slug]['checked']) ){
                $output['total']++;
                $output['themes']++;
            }
            if( ! empty($spbc->themes[$theme_slug]['should_be_checked_again']) ){
                $spbc->themes[$theme_slug]['checked'] = 0;
                $output['total']++;
                $output['themes']++;
                unset($spbc->themes[$theme_slug]['should_be_checked_again']);
            }
            if( $spbc->themes[$theme_slug]['Version'] !== $themes[$theme_slug]['Version'] ){
                $spbc->themes[$theme_slug]['checked'] = 0;
                $output['total']++;
                $output['themes']++;
            }
        }else{
            $output['total']++;
            $output['themes']++;
        }
    }
    
    $spbc->save('themes', true, false);
	
	if($direct_call) return $output; else die(json_encode($output));
}

/**
 *
 * @param boolean                     $direct_call
 * @param integer                     $amount
 *
 * @return array
 * @global \CleantalkSP\SpbctWP\State $spbc
 * @global \wpdb                      $wpdb
 */
function spbc_scanner_get_remote_hashes__plug($direct_call = false, $amount = 2){
	
	if(!$direct_call){
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
		$amount = (int) Request::get( 'amount' ) ?: $amount;
	}
	
	global $spbc, $wpdb;
	
	$out = array('processed' => 0);
	
	// Get all plugins
	$plugins = spbc_get_plugins();
	$is_windows = spbc_is_windows();
	
	// @todo crunch. this calls magic method __get on $spbc->plugins property.
	$spbc->plugins;
	
	foreach($plugins as $plugin_slug => $plugin){
	 
		if($out['processed'] >= $amount){
            break;
        }
		
        if(
            ! empty($spbc->plugins[$plugin_slug]['checked']) &&
            $spbc->plugins[$plugin_slug]['Version'] === $plugin['Version']
        ){
			continue;
		}
        
        $spbc->plugins[$plugin_slug] = $plugin;
        
        // Check plugin's version relevance
        require_once(ABSPATH . 'wp-admin/includes/plugin-install.php');
        $result_wp_api_plugins = plugins_api(
            'plugin_information',
            array('slug' => $plugin_slug, 'fields' => array('version' => true,),)
        );
        if ( !is_wp_error($result_wp_api_plugins) && property_exists($result_wp_api_plugins, 'version')) {
            $source_status = version_compare($plugin['Version'], $result_wp_api_plugins->version, '>=') ? 'UP_TO_DATE' : 'OUTDATED';
        } else if (method_exists($result_wp_api_plugins, 'get_error_message')) {
            $source_status = $result_wp_api_plugins->get_error_message() === 'Plugin not found.'                   ? 'NOT_IN_DIRECTORY' : 'UNKNOWN';
        } else {
            $source_status = 'UNKNOWN';
        }
        $out['outdated'] = $source_status === 'OUTDATED';
        $out['checked_plugins'][] = $plugin_slug;
        
        // Get Cleantalk's hash
        $result_hashes = Scanner\Helper::getHashesForModules('wordpress', 'plugin', $plugin_slug, $plugin['Version']);
        if(empty($result_hashes['error'])){
            $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE path LIKE "%' . $plugin_slug . '%";');
            $sql = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES . ' (`fast_hash`, `path`, `real_full_hash`, `source_type`, `source`, `source_status`, `version`) VALUES ';
            $values = array();
            foreach($result_hashes as $value){
                $path = '/' . substr(WP_PLUGIN_DIR . '/' . $value[0], strlen(ABSPATH));
                $path = $is_windows ? str_replace('/', '\\', $path) : $path;
                $fast_hash = md5($path);
                $path = addslashes($path);
                $real_full_hash = $value[1];
                $values[] = "('$fast_hash', '$path', '$real_full_hash', 'PLUGIN', '$plugin_slug', '$source_status', '{$plugin['Version']}')";
            } unset($value);
            // @todo do not execute request with empty values
            $sql .= implode(',', $values);
            $wpdb->query($sql);

        // Error
        }else{
            // Cloud should refresh the hash for this plugin
            if( $result_hashes['error'] === 'REMOTE_FILE_NOT_FOUND_OR_VERSION_IS_NOT_SUPPORTED__PLUG' ){
                $to_refresh['wordpress']['plugins'][] = array(
                    'name'    => $plugin_slug,
                    'version' => $plugin['Version'],
                );
            }

            // Saving it.
            $spbc->plugins[$plugin_slug]['error'] = $result_hashes['error'];
        }
        
        if( $source_status === 'NOT_IN_DIRECTORY' || $source_status === 'UNKNOWN' || ! empty( $spbc->plugins[$plugin_slug]['error'] ) ){
            $spbc->plugins[$plugin_slug]['should_be_checked_again'] = true;
        }
        
        $out['processed']++;
        $spbc->plugins[$plugin_slug]['checked'] = true;
    }
	
	$spbc->save('plugins', true, false);
	
	// Get all themes
	$themes = spbc_get_themes();
	$theme_path = get_theme_root();
    
    // @todo crunch. this calls magic method __get on $spbc->$themes property.
    $spbc->themes;
	
	foreach($themes as $theme_slug => $theme){
		if($out['processed'] >= $amount){
            break;
        }
        
        if(
            ! empty($spbc->themes[$theme_slug]['checked']) &&
            $spbc->themes[$theme_slug]['Version'] === $theme['Version']
        ){
			continue;
		}
        
        $spbc->themes[$theme_slug] = $theme;
        
        // Check plugin's version relevance
        require_once(ABSPATH . 'wp-admin/includes/theme.php');
        $result_wp_api_themes = themes_api(
            'theme_information',
            array('slug' => $theme_slug, 'fields' => array('version' => true,),)
        );
        $source_status = !is_wp_error($result_wp_api_themes)
            ? (version_compare($theme['Version'], $result_wp_api_themes->version, '>=') ? 'UP_TO_DATE' : 'OUTDATED')
            : ($result_wp_api_themes->get_error_message() === 'Plugin not found.'               ? 'NOT_IN_DIRECTORY' : 'UNKNOWN');
        
        $out['outdated'] = $source_status === 'OUTDATED';
        $out['checked_themes'][] = $theme_slug;
        
        // Get Cleantalk's hash
        $result_hashes = Scanner\Helper::getHashesForModules('wordpress', 'theme', $theme_slug, $theme['Version']);
        if(empty($result_hashes['error'])){
            $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE path LIKE "%' . $theme_slug . '%";');
            $sql = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES . ' (`fast_hash`, `path`, `real_full_hash`, `source_type`, `source`, `source_status`, `version`) VALUES ';
            $values = array();
            foreach($result_hashes as $value){
                $path = '/' . substr($theme_path . '/' . $value[0], strlen(ABSPATH));
                $path = $is_windows ? str_replace('/', '\\', $path) : $path;
                $fast_hash = md5($path);
                $path = addslashes($path);
                $real_full_hash = $value[1];
                $values[] = "('$fast_hash', '$path', '$real_full_hash', 'THEME', '$theme_slug', '$source_status', '{$theme['Version']}')";
            } unset($value);
            // @todo do not execute request with empty values
            $sql .= implode(',', $values);
            $wpdb->query($sql);
            
        // Error
        }else{
            // Cloud should refresh the hash for this plugin
            if( $result_hashes['error'] == 'REMOTE_FILE_NOT_FOUND_OR_VERSION_IS_NOT_SUPPORTED__PLUG' ){
                $to_refresh['wordpress']['themes'][] = array(
                    'name'    => $theme_slug,
                    'version' => $theme['Version'],
                );
            }

            // Saving it.
            $spbc->themes[$theme_slug]['error'] = $result_hashes['error'];
        }
        
        if( $source_status === 'NOT_IN_DIRECTORY' || $source_status === 'UNKNOWN' || ! empty($spbc->themes[$theme_slug]['error']) ){
            $spbc->themes[$theme_slug]['should_be_checked_again'] = true;
        }
        
        $out['processed']++;
        $spbc->themes[$theme_slug]['checked'] = true;
    }
	$spbc->save('themes', true, false);
	
	if(!empty($to_refresh)){
		$to_refresh = json_encode($to_refresh);
		SpbcAPI::method__request_checksums($spbc->settings['spbc_key'], $to_refresh);
	}
	
	if($direct_call){
        return $out;
    }else{
        die(json_encode($out));
    }
}

/**
 * Getting remote hashes of approved files
 *
 * @param boolean    $direct_call
 *
 * @return array
 * @global SpbcState $spbc
 * @global wpdb      $wpdb
 */
function spbc_scanner_get_remote_hashes__approved($direct_call = false) {
    
    if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    
    global $wpdb;
    
    $result = Scanner\Helper::getHashesForApprovedFiles('wordpress', 'approved', '1.0.0');
    
    if (empty($result['error'])) {
        
        $where = array_column( $result, 1 );
        
        $result_db = $wpdb->query('UPDATE '. SPBC_TBL_SCAN_FILES
                                  .' SET
            checked  =   \'YES\',
            status   =   \'OK\',
            severity =   NULL
            WHERE full_hash IN (\'' . implode( "','", $where ) . '\');'
        );
    }
    
    $out = array(
        'total' => empty($result['error']) ? count($result) : 0,
    );
    
    if(!$direct_call) die(json_encode($out)); else return $out;
}

/**
 * Delete non-existing files from table (except quarantined files)
 *
 * @param bool  $direct_call
 * @param int   $offset
 * @param int   $amount
 *
 * @return mixed
 * @global type $wpdb
 */
function spbc_scanner_clear_table($direct_call = false, $offset = 0, $amount = 50000){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$offset = (int) Request::get( 'offset' ) ?: $offset;
		$amount = (int) Request::get( 'amount' ) ?: $amount;
	}
	
	global $wpdb, $spbc;
	
	$result = $wpdb->get_results(
		'SELECT path, fast_hash, status'
			.' FROM ' . SPBC_TBL_SCAN_FILES
			." LIMIT $offset, $amount;",
		ARRAY_A
	);
	
	$root_path = spbc_get_root_path();
	
	$to_delete = array();
	foreach($result as $value){
		if(!file_exists($root_path.$value['path']) && $value['status'] != 'QUARANTINED'){
			$to_delete[] = "'{$value['fast_hash']}'";
		}
	} unset($value);
	
	$deleted = 0;
	if(!empty($to_delete))
		$deleted = $wpdb->query(
			'DELETE FROM ' . SPBC_TBL_SCAN_FILES
			.' WHERE fast_hash IN ('.implode(',',$to_delete).');'
		);
    
    // Deleting newly added exclusions
    foreach( explode( "\n", $spbc->settings['scanner__dir_exclusions'] ) as $exclusion ){
        if( $exclusion ){
            $sql = $wpdb->prepare(
                'DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE path LIKE %s',
                '%' . $wpdb->esc_like( $exclusion ) . '%'
            );
            $wpdb->query( $sql );
        }
    }
	
	$out = array(
		'processed' => (int)$deleted,
		'deleted'   => (int)$deleted,
	);
	if($deleted === false)
		$out['error'] = 'COULDNT_DELETE';
		
	if(!$direct_call) die(json_encode($out)); else return $out;
	
}

function spbc_scanner_clear($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	global $wpdb, $spbc;
	
	$spbc->plugins = array();
	$spbc->save('plugins');
	
	$spbc->themes = array();
	$spbc->save('themes');
	
	$spbc->data['scanner'] = array(
		'last_wp_version'      => null,
		'cron' => array(
			'state'         => 'get_hashes',
			'total_scanned' => 0,
			'offset'        => 0,
		),
	);
	$spbc->save('data');
	
	$deleted = $wpdb->query('DELETE FROM `' . SPBC_TBL_SCAN_FILES . '` WHERE 1');
	
	$out = array(
		'processed' => (int)$deleted,
		'deleted'   => (int)$deleted,
		);
	if($deleted === false)
		$out['error'] = 'COULDNT_DELETE';
	
	if($direct_call) return $out; else die(json_encode($out));
}

function spbc_scanner_count_files($direct_call = false, $path = ABSPATH){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	ini_set( 'max_execution_time', 120 );
	
	$start = microtime( true );
	
	global $spbc;
	
	$path_to_scan = realpath($path);
	$root_path    = realpath(ABSPATH);
	$init_params  = array(
		'count'          => true,
		'file_exceptions' => 'wp-config.php',
		'extensions'      => 'php, html, htm',
		'files_mandatory' => array(),
        'dir_exceptions'  => array( SPBC_PLUGIN_DIR . 'quarantine' )
	);
	if( ! empty( $spbc->settings['scanner__dir_exclusions'] ) )
		$init_params['dir_exceptions'] = array_merge( $init_params['dir_exceptions'], explode( "\n", $spbc->settings['scanner__dir_exclusions'] ) );
	
	$scaner = new Scanner\Surface($path_to_scan, $root_path, $init_params);
	
	$output = array(
		'total' => $scaner->files_count,
		'exec_time' => microtime( true ) - $start,
	);
	
	if($direct_call) return $output; else die(json_encode($output));
}

function spbc_scanner_count_files__by_status($status = null, $checked = null, $direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$status  = stripslashes( Request::get('status') )  ?: $status;
		$checked = stripslashes( Request::get('checked') ) ?: $checked;
	}
	
	if(is_string($status))  if(explode(',',$status))  $status = explode(',',$status);
	if(is_array($status))                             $status = '\''.implode('\',\'', $status).'\'';
	
	if(is_string($checked)) if(explode(',',$checked)) $checked = explode(',',$checked);
	if(is_array($checked))                            $checked = '\''.implode('\',\'', $checked).'\'';
	
	global $wpdb;
	
	$result = $wpdb->get_row('SELECT COUNT(fast_hash) AS cnt'
		.' FROM '.SPBC_TBL_SCAN_FILES
		.' WHERE checked IN ('.$checked.') AND status IN ('.$status.');');
	
	$output = $result === null 
		? array('error' => __FUNCTION__.' query error')
		: array('total' => $result->cnt);
	
	if($direct_call) return $output; else die(json_encode($output));
}

function spbc_scanner_scan($direct_call = false, $offset = 0, $amount = 1500, $path = ABSPATH){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$offset = (int) Request::get( 'offset' ) ?: $offset;
		$amount = (int) Request::get( 'amount' ) ?: $amount;
	}
	
	global $spbc, $wpdb;
	
	$_slash = spbc_is_windows() ? '\\' : '/';
	
	$path_to_scan = realpath($path);
	$root_path    = realpath(ABSPATH);
	$init_params = array(
		'fast_hash'        		=> true,
		'full_hash'       		=> true,
		'offset'                => $offset,
		'amount'                => $amount,
		'extensions'            => 'php, html, htm',
		'extensions_exceptions' => '', //array('jpg', 'jpeg', 'png', 'gif', 'css', 'txt', 'zip', 'xml', 'json')
		'file_exceptions'       => 'wp-config.php',
		'files_mandatory' => array(),
        'dir_exceptions'  => array( SPBC_PLUGIN_DIR . 'quarantine' )
	);
	if( ! empty( $spbc->settings['scanner__dir_exclusions'] ) )
		$init_params['dir_exceptions'] = array_merge( $init_params['dir_exceptions'], explode( "\n", $spbc->settings['scanner__dir_exclusions'] ) );
	
	$time_start = microtime(true);
	
	$scaner = new Scanner\Surface($path_to_scan, $root_path, $init_params);
	
	if($scaner->files_count){
		
		$sql = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES 
			. ' (`path`, `size`, `perms`, `mtime`,`status`,`fast_hash`, `full_hash`, `detected_at`) VALUES ';
        $detected_at = time();
		foreach($scaner->files as $key => $file){
			$file['path'] = addslashes($file['path']);
			$sql .="('{$file['path']}','{$file['size']}','{$file['perms']}','{$file['mtime']}','UNKNOWN','{$file['fast_hash']}','{$file['full_hash']}','$detected_at'),";
		} unset($key, $file);
		$sql = substr($sql, 0, -1);
		$sql .= " ON DUPLICATE KEY UPDATE
			
			size        = VALUES(`size`),
			perms       = VALUES(`perms`),
			source      = source,
			source_type = source_type,
			version     = version,

			fast_hash = fast_hash,
			full_hash = VALUES(`full_hash`),
			real_full_hash = real_full_hash,
			
			checked = 
				IF(real_full_hash IS NOT NULL AND real_full_hash = VALUES(`full_hash`),
					'YES',
					IF(mtime <> VALUES(`mtime`) OR mtime IS NULL,
						'NO',
						checked
					)
				),
			
			status = 
				IF(mtime <> VALUES(`mtime`) OR mtime IS NULL,
					IF(real_full_hash IS NULL,
						IF(checked = 'YES',
							status,
							'UNKNOWN'
						),
						IF(real_full_hash = VALUES(`full_hash`),
							'OK',
							'MODIFIED'
						)
					),
					status
				),
			
			mtime     = VALUES(`mtime`),
			
			detected_at   = detected_at,
			
			severity  =
				IF(status <> 'OK' AND checked <> 'NO',
					severity,
					NULL
				),
				
			weak_spots  =
				IF(checked <> 'NO',
					weak_spots,
					NULL
				);";
		
		$success = $wpdb->query($sql);
	}else
		$output  = array('error' => __FUNCTION__ . ' No files to scan',);
	
	if(isset($success) && $success === false){
		$output  = array('error' => __FUNCTION__ . ' DataBase write error while scanning files.', 'comment' => substr($wpdb->last_error, 0, 1000));
		if(!$spbc->debug)
			spbc_log($wpdb->last_query);
	}elseif(isset($success)){
		$output  = array(
			'processed'     => $scaner->files_count,
			'files_count' => $scaner->files_count,
			'dirs_count'  => $scaner->dirs_count,
			'exec_time'   => round(microtime(true) - $time_start, 3),
			'offset'      => $offset,
			'amount'      => $amount,
		);
	}
	
	if(!$direct_call) die(json_encode($output)); else return $output;

}

function spbc_scanner_scan_signatures($direct_call = false, $status = 'UNKNOWN,MODIFIED,OK,INFECTED', $amount = 10, $path = ABSPATH){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$amount = Request::get( 'amount' ) ?: $amount;
		$path   = realpath( Request::get( 'path' ) ) ?: realpath( $path );
		$status = stripslashes( Request::get( 'status' ) ) ?: $status;
	}
	
	if(is_string($status)) if(explode(',',$status)) $status = explode(',',$status);
	if(is_array($status))                           $status = implode('\',\'', $status);
	
	global $wpdb;
	
	$time_start = microtime(true);

	$files_to_check = $wpdb->get_results(
		'SELECT path, source_type, source, version, status, checked, fast_hash, real_full_hash, full_hash, weak_spots, difference, severity'
			.' FROM ' . SPBC_TBL_SCAN_FILES
			." WHERE checked IN ('NO', 'YES_HEURISTIC') AND status IN ('$status')"
			." LIMIT $amount",
	ARRAY_A);
	
	$processed_items = array();
	foreach ( $files_to_check as $file ){
		$processed_items[ $file['fast_hash'] ] = array(
			'path'   => $file['path'],
			'status' => 0,
		);
	}
	
	if(is_array($files_to_check)){
        
        $scanned = 0;
		
		if(!empty($files_to_check)){

			$root_path = spbc_get_root_path();
			$signatures = $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);

			foreach($files_to_check as $file){

				$result = Scanner\Controller::scanFileForSignatures($root_path, $file, $signatures);
				
				$processed_items[ $file['fast_hash'] ]['status'] = ! empty( $file['status'] ) && $file['status']  === 'MODIFIED'
					? 'MODIFIED'
					: $result['status'];
				
				$checked    = ! empty( $file['checked'] )  && $file['checked'] === 'NO'       ? 'YES_SIGNATURE'                      : 'YES';
				$status     = ! empty( $file['status'] )   && $file['status']  === 'MODIFIED' ? 'MODIFIED'                           : $result['status'];
				$weak_spots = ! empty( $result['weak_spots'] )                                ? json_encode( $result['weak_spots'] ) : 'NULL';
				$severity   = ! empty( $file['severity'] )
					? $file['severity']
					: ($result['severity'] ?  $result['severity'] : 'NULL');
				
				$result_db = $wpdb->query('UPDATE '. SPBC_TBL_SCAN_FILES
					.' SET 
					checked =  \''. $checked  .'\',
					status =   \''. $status   .'\',
					severity = ' .  SpbcHelper::db__prepare_param( $severity ) .',
					weak_spots = '. SpbcHelper::db__prepare_param( $weak_spots ) .'
					WHERE fast_hash = \''.$file['fast_hash'].'\';'
				);
                $result_db !== null ? $scanned++ : $scanned;
			}
		}
        
        $out  = array(
            'found'     => count($files_to_check),
            'processed' => (int)$scanned,
            'exec_time' => round(microtime(true) - $time_start, 3),
        );
        if( $processed_items )
            $out['processed_items'] = $processed_items;
		
	}else
		$out  = array('error' => __FUNCTION__ . ' DataBase write error while receiving files.', 'comment' => substr($wpdb->last_error, 0, 1000));
	
	if(!$direct_call) die(json_encode($out)); else return $out;

}

function spbc_scanner_scan_heuristic($direct_call = false, $status = 'MODIFIED', $amount = 10, $path = ABSPATH){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
        $amount = (int) Request::get( 'amount' ) ?: $amount;
        $path   = realpath( Request::get( 'path' ) ?: $path );
        $status = stripslashes( Request::get( 'status' ) ) ?: $status;
	}
	
	if(is_string($status)) if(explode(',',$status)) $status = explode(',',$status);
	if(is_array($status))                           $status = implode('\',\'', $status);
	
	global $wpdb;
	
	$time_start = microtime(true);
	
	$files_to_check = $wpdb->get_results(
		'SELECT path, source_type, source, version, status, checked, fast_hash, real_full_hash, full_hash, weak_spots, difference, severity'
			.' FROM ' . SPBC_TBL_SCAN_FILES
			." WHERE checked IN ('NO', 'YES_SIGNATURE') AND status IN ('$status') AND (source_status <> 'OUTDATED' OR source_status IS NULL)"
			." LIMIT $amount",
		ARRAY_A
	);
	
	$processed_items = array();
	foreach ( $files_to_check as $file ){
		$processed_items[ $file['fast_hash'] ] = array(
			'path'   => $file['path'],
			'status' => 0,
		);
	}
	
	if(is_array($files_to_check)){
		
		$scanned = 0;
		
		if(count($files_to_check)){

			$root_path = spbc_get_root_path();

			foreach($files_to_check as $file){

				$result = Scanner\Controller::scanFileForHeuristic($root_path, $file);

				if(empty($result['error'])){
					
					$processed_items[ $file['fast_hash'] ]['status'] = $file['status'] === 'MODIFIED' ? 'MODIFIED' : $result['status'];
					
					// Insert found bad includes
					foreach( $result['includes'] as $include ){
         
					    if( $include['status'] === false && $include['exists'] && $include['path'] ){
             
					        unset( $include['include'] );
					        
                            // Cutting file's path, leave path from CMS ROOT to file
                            $real_path = $include['path'];
                            $path = str_replace( $root_path, '', $real_path);
                            $mtime = filemtime( $real_path );
                            $size  = filesize( $real_path );
                            $perms = substr( decoct( fileperms( $real_path ) ), 3 );
                            $fast_hash  = md5( $real_path );
                            $full_hash = is_readable( $real_path )
                                ? md5_file( $real_path )
                                : 'unknown';
                            
                            $wpdb->query($wpdb->prepare(
                                'INSERT INTO '. SPBC_TBL_SCAN_FILES
                                                         .' (`path`, `size`, `perms`, `mtime`,`status`,`fast_hash`, `full_hash`) VALUES'
                                                         ."(%s, %d, %d, %d, 'UNKNOWN', %s, %s)"
                                                         .'ON DUPLICATE KEY UPDATE
                                    size = VALUES(`size`)',
                                    array($path, $size, $perms, $mtime, $fast_hash, $full_hash)
                                )
                            );
                            
                            // Make 'processed' counter big enough to make an another iteration with new files
                            $scanned = 5;
                        }
                    }
					
					$result_db = $wpdb->query('UPDATE '. SPBC_TBL_SCAN_FILES
						.' SET 
						checked = \''. ($file['checked'] === 'NO' ? 'YES_HEURISTIC' : 'YES').'\',
						status = \''.  ($file['status'] === 'MODIFIED' ? 'MODIFIED' : $result['status']).'\',
						severity = '.  ($file['severity'] ? '\''.$file['severity'].'\'' : ($result['severity'] ? '\''.$result['severity'].'\'' : 'NULL')).',
						weak_spots = '. ($result['weak_spots'] ? SpbcHelper::db__prepare_param(json_encode($result['weak_spots'])) : 'NULL') .'
						WHERE fast_hash = \''.$file['fast_hash'].'\';'
					);
					$result_db !== null ? $scanned++ : $scanned;
				}
			}
		}
		$out  = array(
			'found'     => count($files_to_check),
			'processed' => (int)$scanned,
			'exec_time' => round(microtime(true) - $time_start),
		);
		if( $processed_items )
			$out['processed_items'] = $processed_items;
		
	}else
		$out  = array('error' => __FUNCTION__ . ' DataBase write error while receiving files.', 'comment' => substr($wpdb->last_error, 0, 1000));
	
	if(!$direct_call) die(json_encode($out)); else return $out;

}

function spbc_scanner_count_cure($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	global $wpdb;
	
	$result_db = $wpdb->get_row(
		'SELECT COUNT(*) AS cnt FROM '. SPBC_TBL_SCAN_FILES .' WHERE weak_spots LIKE "%SIGNATURES%";',
		OBJECT
	);
	
	if($result_db !== null){
		$out  = array(
			'total' => $result_db->cnt,
		);
	}else
		$out  = array('error' => __FUNCTION__ . ' DataBase write error while counting files.', 'comment' => substr($wpdb->last_error, 0, 1000));
	
	if(!$direct_call) die(json_encode($out)); else return $out;
}

function spbc_scanner_cure($direct_call = false, $offset = 0, $amount = 1){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$offset = (int) Request::get( 'offset' ) ?: $offset;
		$amount = (int) Request::get( 'amount' ) ?: $amount;
	}
	
	global $wpdb, $spbc;
	
	$files = $wpdb->get_results(
		'SELECT * FROM '. SPBC_TBL_SCAN_FILES .' WHERE weak_spots LIKE "%{\"SIGNATURES\":%";',
		ARRAY_A
	);
	
	if($files !== null){
		
		$cured = array();
		
		if(count($files)){

			foreach ($files as $file) {

				$weak_spots = json_decode($file['weak_spots'], true);

				if(!empty($weak_spots['SIGNATURES'])){
					$signtures_in_file = array();
					foreach ($weak_spots['SIGNATURES'] as $signatures_in_string) {
						$signtures_in_file = array_merge($signtures_in_file, array_diff($signatures_in_string, $signtures_in_file));
					}
					$signtures_in_file = implode(',', $signtures_in_file);
				}

				$signatures_with_cci = !empty($signtures_in_file)
					? $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES .' WHERE id IN ('. $signtures_in_file .') AND cci IS NOT NULL')
					: null;

				if(!empty($signatures_with_cci)){

					$cure = new Cure($file);

					if(!empty($cure->result['error'])){
						$out = $cure->result;
						break;
					}else{
						
						$cured[$file['path']] = 'CURED';

						$ws = json_decode($file['weak_spots'], true);
						unset($ws['SIGNATURES']);
						if(empty($ws)){
							$ws = 'NULL';
							$severity = 'NULL';
							$status = 'OK';
						}else{
							$ws = SpbcHelper::db__prepare_param(json_encode($ws));
							$severity = $file['severity'];
							$status = $file['status'];
						}
						$wpdb->query('UPDATE '. SPBC_TBL_SCAN_FILES .' SET weak_spots = '. $ws .', severity = "'. $severity .'", status = "'. $status .'" WHERE fast_hash = "'. $file['fast_hash'] .'";');
						
						// Scanning file with heuristic after the cure
						$file_to_check_with_heuristic = $wpdb->get_results(
							'SELECT * FROM '. SPBC_TBL_SCAN_FILES .' WHERE fast_hash = "' . $file['fast_hash'] . '";',
							ARRAY_A
						);
						$file_to_check_with_heuristic = $file_to_check_with_heuristic[0];
						
						$result = Scanner\Controller::scanFileForHeuristic(spbc_get_root_path(), $file_to_check_with_heuristic );
						
						if(empty($result['error'])){
							
							$processed_items[ $file['fast_hash'] ]['status'] = $file_to_check_with_heuristic['status'] === 'MODIFIED' ? 'MODIFIED' : $result['status'];
							
							$wpdb->query('UPDATE '. SPBC_TBL_SCAN_FILES
								.' SET
								checked = \''. ($file_to_check_with_heuristic['checked'] === 'NO' ? 'YES_HEURISTIC' : 'YES').'\',
								status = \''.  $result['status'] .'\',
								severity = '.  ($result['severity'] ? '\''.$result['severity'].'\'' : 'NULL').',
								weak_spots = '. ($result['weak_spots'] ? SpbcHelper::db__prepare_param(json_encode($result['weak_spots'])) : 'NULL') .'
								WHERE fast_hash = \''.$file_to_check_with_heuristic['fast_hash'].'\';'
							);
							
						}else
							$out = $result;
					}
				}
			}
		}
		
		$out = !empty($out) 
			? $out
			: array(
				'processed' => count($cured),
				'cured'     => count($cured),
			);
		
		$spbc->data['scanner']['cured'] = $cured;
		$spbc->save('data');
		
	}else
		$out  = array('error' => __FUNCTION__ . ' DataBase write error while receiving files.', 'comment' => substr($wpdb->last_error, 0, 1000));
	
	if(!$direct_call) die(json_encode($out)); else return $out;
}

function spbc_scanner_links_count($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	$links_scanner = new Links(array('count' => true));
	
	$output  = array(
		'success' => true,
		'total'   => $links_scanner->posts_total,
	);
		
	if($direct_call) return $output; else die(json_encode($output));
}

function spbc_scanner_links_scan($direct_call = false, $amount = 10){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$amount = (int) Request::get( 'amount' ) ?: $amount;
	}
	
	global $wpdb, $spbc;
	$time_start = microtime(true);
	
	$init_params = array(
		'amount' =>$amount,
		'check_default' => false,
		'mirrors' => !empty($spbc->settings['scanner__outbound_links_mirrors']) ? $spbc->settings['scanner__outbound_links_mirrors'] : '',
	);
	$scanner = new Links($init_params);
		
	if (!empty($scanner->links)){
		
		// Getting only new links
		$prev_scanned_links = $wpdb->get_results(
			'SELECT link
				FROM ' . SPBC_TBL_SCAN_LINKS,
			OBJECT_K
		);
		$new_links = array_diff_key($scanner->links, $prev_scanned_links);
				
		if (count($new_links)>0){

			// Preparing hosts for backlinks_check_cms
			foreach(array_keys($new_links) as $link){

				if (preg_match('/;|\'+/', $link)) {
					$format_link = preg_replace('/;|\'+/', '', $link);
					$new_links[$format_link] = $new_links[$link];
					unset($new_links[$link]);					
				} else 
					$format_link = $link;

				$parsed = parse_url($format_link);
				// Adding $parsed['host'] for link like some.thing
				if(!isset($parsed['host'])){
					preg_match('/^[a-zA-Z0-9-.]+/', '', $matches);
					$parsed['host'] = $matches[0];
				}

				// Check only http links
				if($parsed && (!isset($parsed['sheme']) || (isset($parsed['sheme']) || $parsed['sheme'] === 'http' || $parsed['sheme'] === 'https'))){
					$links_to_check[$format_link] = preg_replace('/;|\'+/', '', $parsed['host']);
				}
			} unset($link);

			// Checking links against blacklists
			$result = SpbcAPI::method__backlinks_check_cms($spbc->settings['spbc_key'], $links_to_check);

			// Adding spam_active flag to newly detected links
			foreach($links_to_check as $link => $host){
				$new_links[$link]['spam_active'] = (empty($result['error']) && isset($result[$host]['appears'])) ? $result[$host]['appears'] : 'null';
			} unset($link, $host);

			//Getting current scan_id
			$scan_id = $wpdb->get_results(
				'SELECT MAX(scan_id) AS scan_num
					FROM ' . SPBC_TBL_SCAN_LINKS . ';',
				OBJECT
			);
			$scan_id = $scan_id[0]->scan_num + 1;
			
			// Preparing request
			$sql = 
				'INSERT INTO '. SPBC_TBL_SCAN_LINKS .'
					(`scan_id`, `link`, `domain`, `link_text`, `page_url`, `spam_active`)
				VALUES ';
			// Preparing data
			$new_links = SpbcHelper::db__prepare_param($new_links);

			foreach($new_links as $link => $param){
				$link = SpbcHelper::db__prepare_param($link);
				$sql .= "($scan_id, $link, {$param['domain']}, {$param['link_text']}, {$param['page_url']}, {$param['spam_active']}),";
			} unset($link, $param);
			$sql = substr($sql, 0, -1).';';

			// Adding results to storage table
			$success = $wpdb->query($sql);

		}								
	}
	
	$output  = array(		
		'found'     => $scanner->links_found,
		'processed' => $scanner->posts_checked,
		'exec_time' => round(microtime(true) - $time_start),
	);
		
	if($direct_call) return $output; else die(json_encode($output));
}

function spbc_scanner_links_count_found($total = true, /* Out */ $count = 0)
{
	global $wpdb;
	
	$sql_result = $wpdb->get_results(
		'SELECT COUNT(*) AS cnt FROM '. SPBC_TBL_SCAN_LINKS
		.(!$total ? ' WHERE scan_id = (SELECT MAX(scan_id) FROM ' . SPBC_TBL_SCAN_LINKS . ');' : ''), // only latest scan
		ARRAY_A);
	
	if ($sql_result)
		$count = !$sql_result[0]['cnt'] ? 0 : $sql_result[0]['cnt'];
		
	return $count;
	}
	
function spbc_scanner_links_count_found__domains(/* Out */ $count = 0)
{
	global $wpdb;
	$count = $wpdb->get_results(
		'SELECT COUNT(link_id) AS cnt FROM '. SPBC_TBL_SCAN_LINKS,
		OBJECT_K);
	return $count ? key($count) : 0;
}

function spbc_scanner_links_get_scanned__domains($offset = 0, $amount = 20, $order = null, $by = null, $get_array = false){
	global $wpdb;
	$offset = intval($offset);
	$amount = intval($amount);
	$data = $wpdb->get_results(
		'SELECT domain, spam_active, page_url, COUNT(domain) as link_count
				FROM '. SPBC_TBL_SCAN_LINKS .' 
			GROUP BY domain
			'.($order && $by  ? "ORDER BY $by $order" : '').'
			LIMIT '.$offset.','.$amount.';',
		$get_array === true ? ARRAY_A : OBJECT
	);
	return $data;
}

function spbc_scanner_frontend__count($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	global $spbc;
	
	$last_scan = isset($spbc->data['scanner']['last_scan__front_end'])
		? date('Y-m-d H:i:s', $spbc->data['scanner']['last_scan__front_end'])
		: date('Y-m-d H:i:s', time() - 86400 * 30);
	
	$out = array(
		'success' => true,
		'total' => Scanner\Frontend::count_unchecked_pages($last_scan),
	);
	
	if($direct_call) return $out; else die(json_encode($out));
	
}

/**
 * Scan for files listing and accessibility
 *
 * @param bool $direct_call
 *
 * @return array
 */
function spbc_scanner_check_listing($direct_call = false){
    
    if(!$direct_call){
        spbc_check_ajax_referer( 'spbc_secret_nonce', 'security' );
    }
    
    $time_start = microtime(true);
    
    $out = array(
        'processed'          => 0,
        'accessible_urls'    => array(),
        'accessible_listing' => array(),
        'exec_time'          => round(microtime(true) - $time_start),
    );
    
    $addresses_to_check_accessibility = array(
        '/wp-content/debug.log',
        '/.svn/entries',
        '/.git/config',
    );
    
    $addresses_to_check_listing = array(
        '/.svn',
        '/.git',
    );
    
    foreach( $addresses_to_check_accessibility as $address ){
        $url_to_check = get_option('home') . $address;
        if( SpbcHelper::http__request__get_response_code( $url_to_check ) === 200 ){
            $out['accessible_urls'][] = array('url' => $address, 'type' => 'accessible');
        }
    }
    
    foreach( $addresses_to_check_listing as $address ){
        $url_to_check = get_option('home') . $address;
        if(
            SpbcHelper::http__request__get_response_code( $url_to_check ) === 200
        ){
            $page = SpbcHelper::http__request( $url_to_check, array(), 'get dont_split_to_array no_cache' );
            if( strpos( $page, 'Index of ' . $address ) !== false ){
                $out['accessible_urls'][] = array('url' => $address, 'type' => 'listing');
            }
        }
    }
    
    $out['processed'] = count($addresses_to_check_accessibility) + count($addresses_to_check_listing);
    $out['exec_time'] = round( microtime( true ) - $time_start );
    
    // Saving the result
    global $spbc;
    $spbc->scanner_listing['accessible_urls'] = $out['accessible_urls'];
    $spbc->save('scanner_listing');
    
    if($direct_call) return $out; else die(json_encode($out));
    
}

function spbc_scanner_frontend__scan($direct_call = false, $amount = 2){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	if(!$direct_call){
		$amount = (int) Request::get( 'amount' ) ?: $amount;
	}
	
	$time_start = microtime(true);

	if( ! class_exists( '\DOMDocument' ) ) {

		error_log( 'Front-end scanning skipped: DOMDocument not exist.' );

		$out = array(
			'processed' => 0,
			'exec_time' => round( microtime( true ) - $time_start ),
		);

	} else {

		global $wpdb, $spbc;

		$front_scanner = new Scanner\Frontend(
			array(
				'amount'    => $amount,
				'last_scan' => isset( $spbc->data['scanner']['last_scan__front_end'] )
					? date( 'Y-m-d H:i:s', $spbc->data['scanner']['last_scan__front_end'] )
					: date( 'Y-m-d H:i:s', time() - 86400 * 30 ),
				'signatures' => $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES, ARRAY_A),
                'domains_exceptions' => \CleantalkSP\Common\Helper::buffer__parse__nsv($spbc->settings['scanner__frontend_analysis__domains_exclusions']),
			)
		);

		foreach ( $front_scanner->pages as $page ) {

			if ( $page['bad'] ) {

				$guid       = SpbcHelper::db__prepare_param( $page['guid'] );
				$id         = SpbcHelper::db__prepare_param( $page['ID'] );
				$weak_spots = $page['found']['weak_spots'] ? SpbcHelper::db__prepare_param( $page['found']['weak_spots'] ) : 'NULL';
				$sql        =
					'INSERT INTO ' . SPBC_TBL_SCAN_FRONTEND . '
						(`page_id`, `url`, `dbd_found`, `redirect_found`, `signature`, `bad_code`, `weak_spots`)
					VALUES ';

				// Preparing data
				$sql .= "({$id}, {$guid}, {$page['found']['dbd']}, {$page['found']['redirects']}, NULL, NULL, {$weak_spots}),";
				$sql = substr( $sql, 0, - 1 );
				$sql .= " ON DUPLICATE KEY
				UPDATE
					url            = $guid,
					dbd_found      = {$page['found']['dbd']},
					redirect_found = {$page['found']['redirects']},
					signature      = NULL,
					bad_code       = NULL,
					weak_spots	   = {$weak_spots};";

				// Adding results to storage table
				$success = $wpdb->query( $sql );
			}
		}

		$out = array(
			'processed' => $front_scanner->posts_count,
			'exec_time' => round( microtime( true ) - $time_start ),
		);
	}
	
	if($direct_call) return $out; else die(json_encode($out));
}

function spbc_scanner_send_results($direct_call = false, $total_scanned = 0){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	global $spbc, $wpdb;
    
    $is_windows = spbc_is_windows();
    
	// Getting modified files
    $sql_result__critical = $wpdb->get_results(
        'SELECT full_hash, mtime, size, source_type, source, source_status, path, status, severity
		FROM ' . SPBC_TBL_SCAN_FILES . '
		WHERE
		    severity = "CRITICAL" AND
		    status <> "QUARANTINED" AND
		    status <> "APROVED"',
        ARRAY_A
    );
    $modified  = array();
    foreach( $sql_result__critical as $row ){
        $path = $is_windows ? str_replace( '\\', '/', $row['path'] ) : $row['path'];
        unset( $row['path'], $row['status'], $row['severity'] );
        $modified[ $path ] = array_values( $row );
    }
    
	$unknown  = array();
    if( $spbc->settings['scanner__list_unknown'] ){
        // Getting unknown files (without source)
        
        $sql_result__unknown = $wpdb->get_results(
            'SELECT full_hash, mtime, size, path, source, severity, detected_at
		FROM ' . SPBC_TBL_SCAN_FILES . '
		WHERE source IS NULL AND
		    status <> "APROVED" AND
		    detected_at >= ' . ( time() - $spbc->settings['scanner__list_unknown__older_than'] * 86400 )  . ' AND
            path NOT LIKE "%wp-content%themes%" AND
            path NOT LIKE "%wp-content%plugins%" AND
            path NOT LIKE "%wp-content%cache%" AND
            (severity <> "CRITICAL" OR severity IS NULL)',
            ARRAY_A
        );
        foreach( $sql_result__unknown as $row ){
            $path = $is_windows ? str_replace('\\', '/', $row['path']) : $row['path'];
            unset($row['path'], $row['severity'], $row['source']);
            $unknown[$path] = array_values($row);
        }
    }
	
	// Count files to scan
	$scanned_total = spbc_scanner_count_files(true);
	$scanned_total = $scanned_total['total'];
	
	// API. Sending files scan result
	$result = SpbcAPI::method__security_mscan_logs(
		$spbc->settings['spbc_key'],
        $spbc->settings['scanner__list_unknown'],
		$spbc->service_id,
		current_time('Y-m-d H:i:s'),
        $modified ? 'warning' : 'passed',
		$scanned_total,
		$modified,
		$unknown
	);
	
	if(empty($result['error'])){
	
		// Sending links scan result
		if($spbc->settings['scanner__outbound_links']){
		
			$links = $wpdb->get_results(
				'SELECT `link`, `link_text`, `page_url`, `spam_active`
					FROM '. SPBC_TBL_SCAN_LINKS .' 
					WHERE scan_id = (SELECT MAX(scan_id) FROM '. SPBC_TBL_SCAN_LINKS .');',
				OBJECT);
			$links_to_send = array();
			foreach($links as $link){
				$links_to_send[$link->link] = array(
					'link_text'   => $link->link_text,
					'page_url'    => $link->page_url,
					'spam_active' => $link->spam_active,
				);
			}
			$links_to_send = json_encode($links_to_send);
			
			$result = SpbcAPI::method__security_linksscan_logs(
				$spbc->settings['spbc_key'],           // 
				current_time('Y-m-d H:i:s'),           // 
				$wpdb->num_rows ? 'failed' : 'passed', // 
				$wpdb->num_rows,                       // Number of links found for last scan
				$links_to_send                         // Links found for last scan
			);
		}
		
		// Sending info about backup
		if($spbc->settings['scanner__auto_cure'] && !empty($spbc->data['scanner']['cured'])){
			$result = SpbcAPI::method__security_mscan_repairs(
				$spbc->settings['spbc_key'],            // API key
				'SUCCESS',                              // Repair result
				'ALL_DONE',                             // Repair comment
				(array)$spbc->data['scanner']['cured'], // Files
				count($spbc->data['scanner']['cured']), // Links found for last scan
				$spbc->data['scanner']['last_backup']   // Last backup num
			);
		}
		
		if(empty($result['error'])){
			$spbc->data['scanner']['last_sent']        = current_time('timestamp');
			$spbc->data['scanner']['last_scan']        = current_time('timestamp');
			$spbc->data['scanner']['last_scan_amount'] = Request::get( 'total_scanned' ) ?: $total_scanned;
			$spbc->data['scanner']['last_scan_links_amount'] = $wpdb->num_rows;
			if(isset($spbc->setting['scanner__frontend_analysis']) && $spbc->setting['scanner__frontend_analysis'])
				$spbc->data['scanner']['last_scan__front_end'] = current_time('timestamp');
			$spbc->error_delete('scanner_result_send');
		}else
			$spbc->error_add('scanner_result_send', $result);
		
	}else
		$spbc->error_add('scanner_result_send', $result);
	
	if( $spbc->settings['scanner__auto_start'] && $spbc->settings['scanner__auto_start_manual_time'] ){
		
		$hour_minutes       = $spbc->settings['scanner__auto_start_manual_time']
			? explode( ':', $spbc->settings['scanner__auto_start_manual_time'] )
			: explode( ':', date('H:i') );
		$scanner_start_time = mktime( (int) $hour_minutes[0], (int) $hour_minutes[1] ) - $spbc->settings['scanner__auto_start_manual_tz'] * 3600 + 86400;
		
		\CleantalkSP\SpbctWP\Cron::updateTask( 'scanner__launch', 'spbc_scanner__launch', 86400, $scanner_start_time );
	}

	$spbc->save('data');
	
	if($direct_call) return $result; else die(json_encode($result));
}

function spbc_scanner_file_send($direct_call = false, $file_id = null){
	
	if( ! $direct_call ){
		check_ajax_referer( 'spbc_secret_nonce', 'security' );
		$file_id = preg_match( '@[a-zA-Z0-9]{32}@', Post::get( 'file_id' ) ) ? Post::get( 'file_id' ) : null;
	}
		
	global $spbc, $wpdb;
	
	$root_path = spbc_get_root_path();
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT fast_hash, path, source_type, source, source_status, version, mtime, weak_spots, full_hash, real_full_hash, status, checked
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		// Scan file before send it
		// Heuristic
		$result_heur = Scanner\Controller::scanFileForHeuristic($root_path, $file_info);
		if(!empty($result['error'])){
			$output = array('error' =>'RESCANNING_FAILED');
			if($direct_call) return $output; else die(json_encode($output));
		}
		// Signature
		$signatures = $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);
		$result_sign = Scanner\Controller::scanFileForSignatures($root_path, $file_info, $signatures);
		if(!empty($result['error'])){
			$output = array('error' =>'RESCANNING_FAILED');
			if($direct_call) return $output; else die(json_encode($output));
		}
		
		$result = SpbcHelper::array_merge__save_numeric_keys__recursive($result_sign, $result_heur);
				
		$wpdb->update(
			SPBC_TBL_SCAN_FILES,
			array(
				'checked'    => $file_info['checked'],
				'status'     => $file_info['status'] === 'MODIFIED' ? 'MODIFIED' : $result['status'],
				'severity'   => $result['severity'],
				'weak_spots' => json_encode($result['weak_spots']),
				'full_hash'  => md5_file($root_path.$file_info['path']),
			),
			array( 'fast_hash' => $file_info['fast_hash'] ),
			array( '%s', '%s', '%s', '%s', '%s' ),
			array( '%s' )
		);
		$file_info['weak_spots'] = $result['weak_spots'];
		$file_info['full_hash']  = md5_file($root_path.$file_info['path']);
		
		if(!empty($file_info)){
			if(file_exists($root_path.$file_info['path'])){
				if(is_readable($root_path.$file_info['path'])){
					if(filesize($root_path.$file_info['path']) > 0){					
						if(filesize($root_path.$file_info['path']) < 1048570){
          
						    // Updating file_info if file source is unknown
						    if( ! isset( $file_info['version'], $file_info['source'], $file_info['source_type'] ) ){
                                $file_info_updated = spbc_get_source_info_of( $file_info['path'] );
                                if( $file_info_updated ){
                                    $file_info = array_merge( $file_info, $file_info_updated );
                                }
                            }
						    
							// Getting file && API call
							$file = file_get_contents($root_path.$file_info['path']);
							$result = SpbcAPI::method__security_mscan_files(
                                $spbc->settings['spbc_key'],
                                $file_info['path'],
                                $file,
                                $file_info['full_hash'],
                                $file_info['weak_spots'],
                                $file_info['version'],
                                $file_info['source'],
                                $file_info['source_type'],
                                $file_info['source_status'],
                                $file_info['real_full_hash']
                                
                            );
							
							if(empty($result['error'])){
								if($result['result']){
									
									// Updating "last_sent"
									$sql_result = $wpdb->query('UPDATE '.SPBC_TBL_SCAN_FILES.' SET last_sent = '.current_time('timestamp').' WHERE fast_hash = "'.$file_id.'"');
									
									if($sql_result !== false){
										$output = array('success' => true, 'result' => $result);
									}else
										$output = array('error' =>'DB_COULDNT_UPDATE_ROW');
								}else
									$output = array('error' =>'API_RESULT_IS_NULL');
							}else
								$output = $result;
						}else
							$output = array('error' =>'FILE_SIZE_TO_LARGE');
					}else
						$output = array('error' =>'FILE_SIZE_ZERO');
				}else
					$output = array('error' =>'FILE_NOT_READABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	if($direct_call) return $output; else die(json_encode($output));
}

function spbc_scanner_file_delete($direct_call = false, $file_id = null){
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $wpdb;
	
	$root_path = spbc_get_root_path();
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT *
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			
			$file_path = $file_info['status'] == 'QUARANTINED' ? $file_info['q_path'] : $root_path.$file_info['path'];
			
			if(file_exists($file_path)){
				if(is_writable($file_path)){
					
					// Getting file && API call
					$remeber = file_get_contents($file_path);
					$result = unlink($file_path);
					if( $result ){
                        
                        $response       = SpbcHelper::http__request(get_option( 'home' ),array(),'get dont_split_to_array no_cache');
                        $response_admin = SpbcHelper::http__request(get_option( 'home' ) . '/wp-admin/',array(),'get dont_split_to_array no_cache');
                        $response_code       = SpbcHelper::http__request__get_response_code(get_option( 'home' ), true);
                        $response_code_admin = SpbcHelper::http__request__get_response_code(get_option( 'home' ), true);
                        if(
                            isset( $response['error'], $response_admin['error'], $response_code['error'], $response_code_admin['error'] ) ||
                            preg_match('/5\d\d/', $response_code) || preg_match('/5\d\d/', $response_code_admin) ||
							spbc_search_page_errors( $response ) ||
							spbc_search_page_errors( $response_admin )
						){
							$output          = array( 'error' => 'WEBSITE_RESPONSE_BAD' );
							$result          = file_put_contents( $file_path, $remeber );
							$output['error'] .= $result === false ? ' REVERT_FAILED' : ' REVERT_OK';
						}else{
							
							// Deleting row from DB
							if( $wpdb->query( 'DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE fast_hash = "' . $file_id . '"' ) !== false )
								$output = array( 'success' => true );
							else
								$output = array( 'error' => 'DB_COULDNT_DELETE_ROW' );
							
						}
						
					}else
						$output = array('error' =>'FILE_COULDNT_DELETE');
					unset( $remeber );
				}else
					$output = array('error' =>'FILE_NOT_WRITABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return spbc_humanize_output($output);
	else
		die(json_encode($output));
}

function spbc_scanner_file_approve($direct_call = false, $file_id = null){
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb;
	
	$root_path = spbc_get_root_path();
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if( $file_id ){
		
		// Getting file info.
		$sql = 'SELECT path, full_hash, status, severity
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if( ! empty( $file_info ) ){
			
			if( file_exists( $root_path . $file_info['path'] ) ){
				
				if( is_readable( $root_path . $file_info['path'] ) ){
					
					// Getting file && API call
					$md5 = md5_file( $root_path . $file_info['path'] );
					
					if( $md5 ){
						
						$previous = json_encode( array( 'status' => $file_info['status'], 'severity' => $file_info['severity'] ) );
						
						// Updating all other statuses
						$wpdb->update(
							SPBC_TBL_SCAN_FILES,
							array(
								'status'         => 'APROVED',
								'real_full_hash' => $md5,
								'previous_state' => $previous,
							),
							array('fast_hash' => $file_id),
							array('%s', '%s', '%s'),
							array('%s')
						);
						
						// Set severity to NULL
						// Using strait query because WPDB doesn't support NULL values
						$sql = 'UPDATE '.SPBC_TBL_SCAN_FILES.'
							SET severity = NULL
							WHERE fast_hash = "'.$file_id.'"';
						$sql_result = $wpdb->query( $sql, ARRAY_A );

						if( $sql_result !== false ){
							$output = array('success' => true);
						}else
							$output = array('error' =>'DB_COULDNT_UPDATE_ROW_APPROVE');
					}else
						$output = array('error' =>'FILE_COULDNT_MD5');
				}else
					$output = array('error' =>'FILE_NOT_READABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return $output;
	else
		die(json_encode($output));
}

function spbc_scanner_file_approve__bulk( $ids = array() ){
    
    if( ! $ids )
        return array( 'error' => 'Noting to approve');
    
    $out = array( 'success' => true );
    
    foreach( $ids as $id ){
        $result = spbc_scanner_file_approve( true, $id );
        
        if( ! empty( $result['error'] ) ){
            $out['error'] = 'Some files where not updated.';
            $out['errors'][] = $result['error'];
        }
    }
    
    return $out;
}

function spbc_scanner_file_disapprove__bulk( $ids = array() ){
    
    if( ! $ids )
        return array( 'error' => 'Noting to disapprove');
    
    $out = array( 'success' => true );
    
    foreach( $ids as $id ){
        $result = spbc_scanner_file_disapprove( true, $id );
        
        if( ! empty( $result['error'] ) ){
            $out['error'] = 'Some files where not updated.';
            $out['errors'][] = $result['error'];
        }
    }
    
    return $out;
}

function spbc_scanner_get_files_by_status( $status ){

    global $wpdb;
    
    $ids = array();
    
    switch( $status ){
        case 'critical':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES. ' WHERE severity = "CRITICAL" AND status <> "QUARANTINED"'); break;
        case 'suspicious':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES. ' WHERE status = "MODIFIED" AND severity <> "CRITICAL"'); break;
        case 'unknown':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES. ' WHERE status <> "APROVED" AND source IS NULL AND path NOT LIKE "%wp-content%themes%" AND path NOT LIKE "%wp-content%plugins%" AND (severity <> "CRITICAL" OR severity IS NULL)'); break;
        case 'approved':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES. ' WHERE status = "APROVED"');
            break;
    }
    
    foreach( $res as $tmp ){
        $ids[] = $tmp->fast_hash;
    }
    
    return $ids;
}

function spbc_scanner_file_disapprove($direct_call = false, $file_id = null){
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb;
	
	$root_path = spbc_get_root_path();
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT path, full_hash, previous_state
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			if(file_exists($root_path.$file_info['path'])){
				if(is_readable($root_path.$file_info['path'])){
					
					// Getting file && API call
					$md5 = md5_file($root_path.$file_info['path']);
					
					if($md5){
						
						$previous = json_decode( $file_info['previous_state'], true );
						
						$wpdb->update(
							SPBC_TBL_SCAN_FILES,
							array(
								'status'         => $previous['status'],
								'severity'       => $previous['severity'],
								'real_full_hash' => $md5,
							),
							array('fast_hash' => $file_id),
							array('%s', '%s', '%s'),
							array('%s')
						);
							
						if($sql_result !== false){
							$output = array('success' => true);
						}else
							$output = array('error' =>'DB_COULDNT_UPDATE_ROW_APPROVE');
					}else
						$output = array('error' =>'FILE_COULDNT_MD5');
				}else
					$output = array('error' =>'FILE_NOT_READABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return $output;
	else
		die(json_encode($output));
}

function spbc_scanner_page_view($direct_call = false, $page_url = null) {

	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb;
	
	$root_path = spbc_get_root_path();

	$page_url = $direct_call
		? ($page_url ? $page_url : false)
		: (Post::get('page_url') ? Post::get('page_url') : false);

	if ($page_url) {

		$page_content = SpbcHelper::http__request__get_content($page_url);

		if(!empty($page_content)){

			$page_text = array();

			// Getting file info.
			$sql = 'SELECT weak_spots
				FROM '.SPBC_TBL_SCAN_FRONTEND.'
				WHERE url = "'.$page_url.'"
				LIMIT 1';
			$sql_result = $wpdb->get_results($sql, ARRAY_A);
			$result = $sql_result[0];

			foreach(preg_split("/((\r?\n)|(\r\n?))/", $page_content) as $line){
				$page_text[] = htmlspecialchars($line);
			}
			$output = array(
				'success' => true,
				'file' => $page_text,
				'file_path' => null,
				'difference' => null,
				'weak_spots' => $result['weak_spots']
			);
		}else
			$output = array('error' =>'FILE_TEXT_EMPTY');		
	}else
		$output = array('error' =>'WRONG_PAGE_URL');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return $output;
	else
		die(json_encode($output));
}

function spbc_scanner_file_view($direct_call = false, $file_id = null){
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb;
	
	$root_path = spbc_get_root_path();
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT *
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			
			$file_path = $file_info['status'] == 'QUARANTINED' ? $file_info['q_path'] : $root_path.$file_info['path'];
			
			if(file_exists($file_path)){
				if(is_readable($file_path)){
					
					// Getting file && API call
					$file = file($file_path);
					
					if($file !== false && count($file)){
						
						$file_text = array();
						for($i=0; isset($file[$i]); $i++){
							$file_text[$i+1] = htmlspecialchars($file[$i]);
							$file_text[$i+1] = preg_replace("/[^\S]{4}/", "&nbsp;", $file_text[$i+1]);
						}
							
						if(!empty($file_text)){
							$output = array(
								'success' => true,
								'file' => $file_text,
								'file_path' => $file_path,
								'difference' => $file_info['difference'],
								'weak_spots' => $file_info['weak_spots']
							);
						}else
							$output = array('error' =>'FILE_TEXT_EMPTY');
					}else
						$output = array('error' =>'FILE_EMPTY');
				}else
					$output = array('error' =>'FILE_NOT_READABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return $output;
	else
		die(json_encode($output));
}

function spbc_scanner_file_compare($direct_call = false, $file_id = null, $platform = 'wordpress'){
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb, $wp_version;
	
	$cms_version = $wp_version;
	$root_path = spbc_get_root_path();
	
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT path, source_type, source, version, status, severity, weak_spots, difference
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			if(file_exists($root_path.$file_info['path'])){
				if(is_readable($root_path.$file_info['path'])){
					
					// Getting file && API call
					$file = file($root_path.$file_info['path']);
					
					if($file !== false && count($file)){
						
						$file_text = array();
						for($i=0; isset($file[$i]); $i++){
							$file_text[$i+1] = htmlspecialchars($file[$i]);
							$file_text[$i+1] = preg_replace("/[^\S]{4}/", "&nbsp;", $file_text[$i+1]);
						}
						if(!empty($file_text)){
							
							$file_original = Scanner\Helper::getOriginalFile($file_info);
							
							if($file_original){
								
								$file_original = explode("\n", $file_original);
								for($i=0; isset($file_original[$i]); $i++){
									$file_original_text[$i+1] = htmlspecialchars($file_original[$i]);
									$file_original_text[$i+1] = preg_replace("/[^\S]{4}/", "&nbsp;", $file_original_text[$i+1]);
								}
								if(!empty($file_original_text)){
									$output = array( 'success'       => true,
									                 'file'          => $file_text,
									                 'file_original' => $file_original_text,
									                 'file_path'     => $root_path . $file_info['path'],
//									                 'weak_spots'    => $file_info['weak_spots'],
									                 'difference'    => Scanner\Helper::getDifferenceFromOriginal($root_path, $file_info, $file_original )
									);
								}else
									$output = array('error' =>'FILE_ORIGINAL_TEXT_EMPTY');
							}else
								$output = array('error' =>'GET_FILE_REMOTE_FAILED');
						}else
							$output = array('error' =>'FILE_TEXT_EMPTY');
					}else
						$output = array('error' =>'FILE_EMPTY');
				}else
					$output = array('error' =>'FILE_NOT_READABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return $output;
	else
		die(json_encode($output));
}

function spbc_scanner_file_replace($direct_call = false, $file_id = null, $platform = 'wordpress'){
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb, $wp_version;
	
	$cms_version = $wp_version;
	$root_path = spbc_get_root_path();
	
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT path, source_type, source, version, status, severity, source_type
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
							
			if(file_exists($root_path.$file_info['path'])){

				if(is_writable($root_path.$file_info['path'])){

					// Getting file && API call
					$original_file = Scanner\Helper::getOriginalFile($file_info);

					if($original_file){

						$file_desc = fopen($root_path.$file_info['path'], 'w');

						if($file_desc){

							$res_fwrite = fwrite($file_desc, $original_file);

							if($res_fwrite){

								$res_fclose = fclose($file_desc);

								$db_result = $wpdb->query(
									'DELETE FROM '.SPBC_TBL_SCAN_FILES
									.' WHERE fast_hash = "'.$file_id.'";'
								);

								if($db_result){
									$output = array('success' => true,);
								}else
									$output = array('error' =>'FILE_DB_DELETE_FAIL');
							}else
								$output = array('error' =>'FILE_COULDNT_WRITE');
						}else
							$output = array('error' =>'FILE_COULDNT_OPEN');
					}else
						$output = array('error' =>'GET_FILE_FAILED');
				}else
					$output = array('error' =>'FILE_NOT_WRITABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	$exec_time = round(microtime(true) - $time_start);
	$output['exec_time'] = $exec_time;
	
	if($direct_call)
		return $output;
	else
		die(json_encode($output));
}

function spbc_scanner_file_quarantine($direct_call = false, $file_id = null){
	
	global $wpdb, $spbc;
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$root_path = spbc_get_root_path();
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT *
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			if(file_exists($root_path.$file_info['path'])){
				if(is_writable($root_path.$file_info['path'])){
					$q_path = SPBC_PLUGIN_DIR.'quarantine/'
						.str_replace('/', '__', str_replace('\\', '__', $file_info['path'])).'___'
						.md5($file_info['path'].rand(0, 99999999)).'.punished';
					if(!is_dir(SPBC_PLUGIN_DIR.'quarantine/'))
						mkdir(SPBC_PLUGIN_DIR.'quarantine/');
					if(copy($root_path.$file_info['path'], $q_path)){
						
						$result = $wpdb->update(
							SPBC_TBL_SCAN_FILES,
							array(
								'status'         => 'QUARANTINED',
								'q_path'         => $q_path,
								'q_time'         => time(),
								'previous_state' => json_encode( array(
									'status' => $file_info['status'],
								)),
							),
							array( 'path' => $file_info['path'] ),
							array( '%s', '%s', '%d', '%s' ),
							array( '%s' )
						);
						if($result !== false && $result > 0){
							
							if(unlink($root_path.$file_info['path'])){
								
								$response       = SpbcHelper::http__request(get_option( 'home' ),array(),'get dont_split_to_array no_cache');
								$response_admin = SpbcHelper::http__request(get_option( 'home' ) . '/wp-admin/',array(),'get dont_split_to_array no_cache');
								$response_code       = SpbcHelper::http__request__get_response_code(get_option( 'home' ), true);
								$response_code_admin = SpbcHelper::http__request__get_response_code(get_option( 'home' ), true);
								if(
									isset( $response['error'], $response_admin['error'], $response_code['error'], $response_code_admin['error'] ) ||
									preg_match('/5\d\d/', $response_code) || preg_match('/5\d\d/', $response_code_admin) ||
									spbc_search_page_errors( $response ) ||
									spbc_search_page_errors( $response_admin )
								){
									$output          = array( 'error' => 'WEBSITE_RESPONSE_BAD' );
									$result          = spbc_scanner_file_quarantine__restore( true, $file_info['fast_hash'] );
									$output['error'] .= ! empty( $result['error'] ) ? ' REVERT_FAILED ' . $result['error'] : ' REVERT_OK';
								}else{
									$output = array( 'success' => true, );
								}
							
							}else
								$output = array('error' =>'DELETE_FAILED');
						}else
							$output = array('error' =>'UPDATE_TABLE_FAILED');
					}else
						$output = array('error' =>'COPY_FAILED');
				}else
					$output = array('error' =>'FILE_NOT_WRITABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	if($direct_call) return spbc_humanize_output($output); else die(json_encode($output));
}

function spbc_scanner_file_quarantine__restore($direct_call = false, $file_id = null){
	
	global $wpdb;
	
	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$root_path = spbc_get_root_path();
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT *
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			if(file_exists($file_info['q_path'])){
				if(is_writable($file_info['q_path'])){
					if(copy($file_info['q_path'], $root_path.$file_info['path'])){
						
						$previous = json_decode( $file_info['previous_state'], true );
						
						$result = $wpdb->update(
							SPBC_TBL_SCAN_FILES,
							array( 'status'   => $previous['status'],
							       'q_path'   => null,
							       'q_time'   => null,
							),
							array ('fast_hash' => $file_info['fast_hash']),
							array ( '%s', '%s', '%d', ),
							array ( '%s' )
						);
						if($result !== false && $result > 0){
							if(unlink($file_info['q_path'])){
								$output = array('success' => true,);
							}else
								$output = array('error' =>'DELETE_FAILED');
						}else
							$output = array('error' =>'UPDATE_TABLE_FAILED');
					}else
						$output = array('error' =>'COPY_FAILED');
				}else
					$output = array('error' =>'FILE_NOT_WRITABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	if($direct_call) return $output; else die(json_encode($output));
}

function spbc_scanner_file_download($direct_call = false, $file_id = null){
	
	global $wpdb;
	
	$file_id = $direct_call
		? ($file_id ? $file_id : false)
		: (Post::get('file_id') ? Post::get('file_id') : false);
	
	if($file_id){
		
		// Getting file info.
		$sql = 'SELECT *
			FROM '.SPBC_TBL_SCAN_FILES.'
			WHERE fast_hash = "'.$file_id.'"
			LIMIT 1';
		$sql_result = $wpdb->get_results($sql, ARRAY_A);
		
		$file_info = $sql_result[0];
		
		if(!empty($file_info)){
			
			if(file_exists($file_info['q_path'])){
				
				if(is_readable($file_info['q_path'])){
					
					// Getting file && API call
					$file_path = substr($file_info['q_path'], stripos($file_info['q_path'],'wp-content'));
					$file = SpbcHelper::http__request__get_content(get_home_url() . '/' . $file_path);
					
					if($file !== false){
						
						$output = array(
							'file_name'    => preg_replace('/.*(\/|\\\\)(.*)/', '$2', $file_info['path']),
							'file_content' => $file,
						);
						
					}else
						$output = array('error' =>'FILE_EMPTY');
				}else
					$output = array('error' =>'FILE_NOT_READABLE');
			}else
				$output = array('error' =>'FILE_NOT_EXISTS');
		}else
			$output = array('error' =>'FILE_NOT_FOUND');
	}else
		$output = array('error' =>'WRONG_FILE_ID');
	
	if($direct_call) return $output; else die(json_encode($output));
}

/**
 * Replacing error codes by readable and translatable format.
 * We have to add new error descriptions here future.
 *
 * @param $output_array
 *
 * @return array
 */
function spbc_humanize_output( $output_array ) {

	if( is_array( $output_array ) &&  array_key_exists( 'error', $output_array ) ) {
		$errors_codes = array(
			'WEBSITE_RESPONSE_BAD',
			'REVERT_OK'
		);
		$errors_texts = array(
			esc_html__( 'The requested action caused a website error.', 'security-malware-firewall' ), // WEBSITE_RESPONSE_BAD
			esc_html__( 'The changes were reverted.', 'security-malware-firewall' ),          // REVERT_OK
		);
		foreach ( $output_array as $key => $item ) {
			$output_array[$key] = str_replace( $errors_codes, $errors_texts, $item );
		}
	}

	return $output_array;

}