<?php

use CleantalkSP\SpbctWP\Helper as SpbcHelper;
use CleantalkSP\SpbctWP\API as SpbcAPI;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Request;
use CleantalkSP\SpbctWP\Scanner\Cure;
use CleantalkSP\SpbctWP\Scanner\Links;
use CleantalkSP\SpbctWP\Scanner;

/**
 * * Cron wrapper function for launchBackground
 *
 * @return bool|true
 */
function spbc_scanner__launch(){
	$result = \CleantalkSP\SpbctWP\Scanner\ScannerQueue::launchBackground();
	
	if( \CleantalkSP\SpbctWP\RemoteCalls::check() ){
		$result = empty( $result['error'] )
			? 'OK'
			: 'FAIL ' . die( json_encode($result) );
	}
	
	return $result;
}

/**
 * Cron wrapper function for controllerBackground
 *
 * @param null $transaction_id
 * @param null $stage
 * @param null $offset
 * @param null $amount
 *
 * @return bool|string|string[]
 */
function spbc_scanner__controller( $transaction_id = null, $stage = null, $offset = null, $amount = null ){
	
	$result = \CleantalkSP\SpbctWP\Scanner\ScannerQueue::controllerBackground( $transaction_id, $stage, $offset, $amount );
	
	if( \CleantalkSP\SpbctWP\RemoteCalls::check() ){
		$result = empty( $result['error'] )
			? 'OK'
			: 'FAIL ' . die( json_encode($result) );
	}
	
	return $result;
}

/**
 * For debug purpose
 * Clear table from results
 *
 * @param bool $direct_call
 *
 * @return int[]
 */
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

function spbc_scanner_links_count($direct_call = false){
	
	if(!$direct_call) spbc_check_ajax_referer('spbc_secret_nonce', 'security');
	
	$links_scanner = new Links(array('count' => true));
	
	$output  = array(
		'success' => true,
		'total'   => $links_scanner->posts_total,
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
		$result_heur = Scanner\Controller::scanFileForHeuristic($file_info, $root_path);
		if(!empty($result['error'])){
			$output = array('error' =>'RESCANNING_FAILED');
			if($direct_call) return $output; else die(json_encode($output));
		}
		// Signature
		$signatures = $wpdb->get_results('SELECT * FROM '. SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);
		$result_sign = Scanner\Controller::scanFileForSignatures($file_info, $root_path, $signatures);
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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

function spbc_scanner_page_view($direct_call = false, $page_url = false) {

	if(!$direct_call)
		check_ajax_referer('spbc_secret_nonce', 'security');
	
	$time_start = microtime(true);
	
	global $spbc, $wpdb;
	
	$root_path = spbc_get_root_path();

	$page_url = $direct_call
		? $page_url
		: Post::get('page_url');
	
    $page_url = strpos( $page_url, get_home_url() ) !== false
        ? $page_url
        : false;

	if ($page_url) {

		$page_content = SpbcHelper::http__request__get_content($page_url);

		if(!empty($page_content)){

			$page_text = array();

			// Getting file info.
			$sql_result = $wpdb->get_results(
			    $wpdb->prepare(
                    'SELECT weak_spots'
                        . ' FROM ' . SPBC_TBL_SCAN_FRONTEND
                        . ' WHERE url = %s'
                        . ' LIMIT 1',
                    $page_url
                ),
                ARRAY_A
            );
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
        ? $file_id
        : Post::get('file_id', 'hash');
	
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
		? $file_id
		: Post::get('file_id', 'hash');
	
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