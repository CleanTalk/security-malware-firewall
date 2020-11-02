<?php
/**
 * CleanTalk Security FireWall class.
 * Compatible with any CMS.
 *
 * @version       2.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since        2.49
 */

namespace CleantalkSP\Security\FireWall;

use CleantalkSP\SpbctWp\API;
use CleantalkSP\SpbctWp\Helper;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;

/**
 * CleanTalk Security Firewall class
 * 
 * @package Security Plugin by CleanTalk
 * @subpackage Firewall
 * @Version 2.1
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */

class FireWall {

	private static $db_handler;

	private $spbc_key;

	private $default_options = array(
		'set_cookies' => true,
	);

	private $options = array();

	private $fw_modules = array();

	public $ip_array = array(); // array with detected IPs

	private $statuses_priority = array(
		'PASS',
		'DENY',
		'DENY_BY_NETWORK',
		'DENY_BY_BFP',
		'DENY_BY_DOS',
		'DENY_BY_WAF_SQL',
		'DENY_BY_WAF_XSS',
		'DENY_BY_WAF_EXPLOIT',
		'DENY_BY_WAF_FILE',
		'PASS_BY_WHITELIST',
		'PASS_BY_TRUSTED_NETWORK', // Highest
	);
	
	function __construct( $spbc_key = '', $options = array() ) {

		$this->options = array_merge( $this->default_options, $options );

		$this->spbc_key = $spbc_key;

		$result = (array) Helper::ip__get( array( 'real' ) );

		if( isset( $spbc_key ) && Get::get('spbct_test') == md5( $spbc_key ) ){
			$ip_type = Helper::ip__validate( Get::get('spbct_test_ip') );
			$test_ip = $ip_type == 'v6' ? Helper::ip__v6_normalize( Get::get('spbct_test_ip') ) : Get::get('spbct_test_ip');
			if($ip_type)
				$result['test'] = $test_ip;
		}

		$this->ip_array = $result;

		//self::set_db_handler( $db_handler );

	}

	/**
	 * @param FireWall_database $db_handler
	 */
	public static function set_db_handler( FireWall_database $db_handler ) {
		self::$db_handler = $db_handler;
	}

	/**
	 * Loads the FireWall module to the array.
	 * For inner usage only.
	 * Not returns anything, the result is private storage of the modules.
	 *
	 * @param \CleantalkSP\Security\FireWall\FireWall_module $module
	 */
	public function load_fw_module( \CleantalkSP\Security\FireWall\FireWall_module $module ) {

		if( ! in_array( $module, $this->fw_modules ) ) {
			$this->fw_modules[] = $module;
			$module->setIpArray( $this->ip_array );
		}

	}

	/**
	 * Do main logic of the module.
	 *
	 * @return void   returns die page or set cookies
	 */
	public function run() {

		$results = array();

		foreach ( $this->fw_modules as $module ) {

			$module_results = $module->check();
			if( ! empty( $module_results ) ) {
				$results[] = $this->prioritize( $module_results );
			}

			if( $this->is_whitelisted( $results ) ) {
				// Break protection logic if it whitelisted or trusted network.
				break;
			}

		}

		$result = $this->prioritize( $results );

		// CleanTalk's cloud remote call passing
		if( strpos( $result['status'], 'DENY') !== false ) {
			if( isset( $_GET['spbc_remote_call_token'], $_GET['spbc_remote_call_action'], $_GET['plugin_name'] ) ){
				$resolved = gethostbyaddr( $result['blocked_ip'] );
				if( $resolved && preg_match( '/cleantalk\.org/', $resolved ) === 1 || $resolved === 'back' ){
					$result['status'] = 'PASS_BY_TRUSTED_NETWORK';
					$result['passed_ip'] = $result['blocked_ip'];
				}
			}
		}

		// Blacklisted in DB
		if( strpos( $result['status'], 'DENY') !== false ){
			$this->update_logs( $result['blocked_ip'], $result['status'], $result['pattern'] );
			$this->_die( $result['blocked_ip'], $result['status'], $module->getServiceId() );
		// Whitelisted in DB
		}elseif( strpos( $result['status'], 'PASS' ) !== false ){
			$this->update_logs( $result['passed_ip'], $result['status'] );
			if( ! empty( $this->options['set_cookies'] ) && $this->options['set_cookies'] && ! headers_sent() ){
				setcookie( 'spbc_firewall_pass_key', md5($result['passed_ip'].$this->spbc_key), 300, '/' );
			}
		}

	}
	
	/**
	 * Gets multifile with data to update Firewall.
	 *
	 * @param $spbc_key
	 *
	 * @return array
	 */
	static public function firewall_update__get_multifiles( $spbc_key ){
		
		
		// Getting remote file name
		$result = API::method__security_firewall_data_file( $spbc_key, 'multifiles' );
		
		sleep(3);
		
		if(empty($result['error'])){
			
			if( !empty($result['file_url']) ){
				
				$file_url = $result['file_url'];
				
				$response_code = Helper::http__request__get_response_code($file_url);
				
				if( empty( $response_code['error'] ) ){
					
					if( $response_code === 200 || $response_code === 501 ){
						
						self::$db_handler->fw_clear_table();
						
						if (preg_match('/multifiles/', $file_url)) {
							
							$gz_data = Helper::http__request__get_content($file_url);
							
							if( empty( $gz_data['error'] ) ){
								
								if(Helper::get_mime_type($gz_data, 'application/x-gzip')){
									
									if(function_exists('gzdecode')) {
										
										$data = gzdecode( $gz_data );
										
										if($data !== false){
											
											$lines = Helper::buffer__parse__csv($data);
											
											return array(
												'multifile_url' => $file_url,
												'file_urls'     => $lines,
											);
											
										}else
											return array('error' => 'COULDNT_UNPACK');
									}else
										return array('error' => 'Function gzdecode not exists. Please update your PHP to version 5.4');
								}else
									return array('error' => 'WRONG_REMOTE_FILE');
							}else
								return array('error' => 'COULD_NOT_GET_MULTIFILE: ' . $gz_data['error'] );
						}else
							return array('error' => 'WRONG_REMOTE_FILE');
					} else
						return array('error' => 'NO_REMOTE_FILE_FOUND');
				}else
					return array('error' => 'MULTIFILE_COULD_NOT_GET_RESPONSE_CODE: '. $response_code['error'] );
			}else
				return array('error' => 'BAD_RESPONSE');
		}else
			return $result;
	}
	
	/**
	 * Writes entries from remote files to Firewall database.
	 *
	 * @param null $file_url
	 *
	 * @return array|bool|int|mixed|string
	 */
	static public function firewall_update__write_to_db( $file_url = null ){
		
		$response_code = Helper::http__request__get_response_code( $file_url );
		
		if( empty( $response_code['error'] ) ){
			
			if( $response_code === 200 || $response_code === 501 ){ // Check if it's there
				
				$gz_data = Helper::http__request__get_content( $file_url );
				
				if( empty( $gz_data['error'] ) ){
					
					if( Helper::get_mime_type( $gz_data, 'application/x-gzip' ) ){
						
						if( function_exists('gzdecode') ) {
							
							$data = gzdecode( $gz_data );
							
							if( $data !== false ){
								
								$lines = Helper::buffer__parse__csv( $data );
								
							}else
								return array( 'error' => 'COULDNT_UNPACK' );
						}else
							return array( 'error' => 'Function gzdecode not exists. Please update your PHP to version 5.4' );
					}else
						return array( 'error' => 'Wrong mime type');
				}else
					return array('error' => 'COULD_NOT_GET_MULTIFILE: ' . $gz_data['error'] );
				
				reset( $lines );
				
				for( $count_result = 0; current($lines) !== false; ) {
					
					for ( $i=0; SPBC_WRITE_LIMIT !== $i && current($lines) !== false; $i++, $count_result++, next($lines) ) {
						
						$entry = current($lines);
						
						if ( empty( $entry ) ) {
							continue;
						}
						if ( SPBC_WRITE_LIMIT !== $i ) {
							
							$network   = $entry[0];
							$mask = $entry[1];
							// $comment = $entry[2]; // Comment from user
							$status      = isset( $entry[3] ) ? $entry[3] : 0;
							$is_personal = isset( $entry[4] ) ? intval( $entry[4] ) : 0;
							$country     = isset( $entry[5] ) ? trim( $entry[5], '"' ) : 0;
							
							// IPv4
							if ( is_numeric( $network ) ) {
								
								$mask = sprintf(
									'%u',
									bindec( str_pad( str_repeat( '1', $mask ), 32, 0, STR_PAD_RIGHT ) )
								);
								
								if( $country || ! $is_personal ) {
									$unique = md5( $network . $mask . $country );
									$sql__common[] = "('$unique', $network, $mask, $status, '$country')";
								}
								if( $is_personal && $country )
									$sql__personal_country[] = "('$country',$status)";
								
								if( $is_personal && ! $country )
									$sql__personal_ip[] = "($network, $mask, $status)";
								
							}
						}
					}
					
					// Insertion to common table
					$sql_result__common___result = self::$db_handler->fw_insert_data(
						'INSERT INTO ' . SPBC_TBL_FIREWALL_DATA
						. ' (id, network, mask, status, country_code) '
						. ' VALUES '
						. implode( ',', $sql__common)
						. ' ON DUPLICATE KEY UPDATE'
						. ' network=network'
						. ';'
					);
					
					// @todo self::$db_handler->fw_insert_data() could return false on good query
					// because of $wpdb->query()
//					if( $sql_result__common___result === false )
//						return array( 'error' => 'COULD_NOT_WRITE_TO_DB 1: ' . self::$db_handler->get_last_error() );
					
					// Insertion to personal IPs table
					if( ! empty( $sql__personal_ip ) ) {
						$sql_result__common___result = self::$db_handler->fw_insert_data(
							'INSERT INTO ' . SPBC_TBL_FIREWALL_DATA__IPS . ' (network,mask,status) VALUES '
							. implode( ',', $sql__personal_ip ) . ';'
						);
						unset( $sql__personal_ip );
						if ( $sql_result__common___result === false )
							return array( 'error' => 'COULD_NOT_WRITE_TO_DB 2: ' . self::$db_handler->get_last_error() );
					}
					
					// Insertion to personal countries table
					if( ! empty( $sql__personal_country ) ){
						$sql__personal_country = array_unique( $sql__personal_country ); // Filtering duplicate entries
						$sql_result__common___result = self::$db_handler->fw_insert_data(
							'INSERT INTO ' . SPBC_TBL_FIREWALL_DATA__COUNTRIES . '(country_code,status) VALUES '
							. implode( ',', $sql__personal_country) . ';'
						);
						unset( $sql__personal_country );
						if( $sql_result__common___result === false )
							return array( 'error' => 'COULD_NOT_WRITE_TO_DB 3: ' . self::$db_handler->get_last_error() );
					}
				}
				
				return $count_result;
				
			}else
				return array('error' => 'NO_REMOTE_FILE_FOUND');
		}else
			return array('error' => 'FILE_COULD_NOT_GET_RESPONSE_CODE: '. $response_code['error'] );
	}
	
	/**
	 * Adding local exclusions to to the FireWall database.
	 *
	 * @param array $exclusions
	 *
	 * @return array|bool|int|mixed|string
	 */
	static public function firewall_update__write_to_db__exclusions( $exclusions = array() ){
		
		$query = 'INSERT INTO `' . SPBC_TBL_FIREWALL_DATA__IPS . '` (network,mask,status) VALUES ';
		
		//Exclusion for servers IP (SERVER_ADDR)
		if ( ! empty( Server::get('HTTP_HOST') ) ) {
			$exclusions[] = Helper::dns__resolve( Server::get('HTTP_HOST') );
			$exclusions[] = '127.0.0.1';
			foreach ( $exclusions as $exclusion ) {
				if ( Helper::ip__validate( $exclusion ) && sprintf( '%u', ip2long( $exclusion ) ) ) {
					$query .= '(' . sprintf( '%u', ip2long( $exclusion ) ) . ', ' . sprintf( '%u', bindec( str_repeat( '1', 32 ) ) ) . ', 2),';
				}
			}
		}
		
		$sql_result = self::$db_handler->fw_insert_data( substr( $query, 0, - 1 ) . ';' );
		
		if( $sql_result === false )
			return array( 'error' => 'COULD_NOT_WRITE_TO_DB 4: ' . self::$db_handler->get_last_error() );

		return count( $exclusions );
		
	}
	
	/**
	 * Updating entries of the FireWall database.
	 * Usually used by CRON or by direct calling.
	 *
	 * @param $spbc_key
	 * @param null $file_url
	 * @param bool $immediate
	 *
	 * @return array|bool|int|mixed|string
	 */
	static public function firewall_update( $spbc_key, $file_url = null, $immediate = false ){

		// Getting remote file name
		if( ! $file_url ){

			// @todo switch updating to remote calls only even on the first call
			if ( ! $immediate )
				sleep(5);

			$result = API::method__security_firewall_data_file( $spbc_key, 'multifiles' );

			if(empty($result['error'])){
			
				if( !empty($result['file_url']) ){
					
					$file_url = $result['file_url'];
					
					$response_code = Helper::http__request__get_response_code($file_url);
					
					if( empty( $response_code['error'] ) ){
					
						if( $response_code === 200 || $response_code === 501 ){
	
							self::$db_handler->fw_clear_table();
		
							if (preg_match('/multifiles/', $file_url)) {
	
								$gz_data = Helper::http__request__get_content($file_url);
								
								if( empty( $gz_data['error'] ) ){
	
									if(Helper::get_mime_type($gz_data, 'application/x-gzip')){
										
										if(function_exists('gzdecode')) {
						
											$data = gzdecode( $gz_data );
	
											if($data !== false){
						
												$lines = Helper::buffer__parse__csv($data);
	
												return Helper::http__request(
													get_option('siteurl'),
													array(
														'spbc_remote_call_token'  => md5( $spbc_key ),
														'spbc_remote_call_action' => 'update_security_firewall',
														'plugin_name'             => 'spbc',
														'file_urls'               => $file_url,
														'url_count'               => count( $lines ),
														'current_url'             => 0,
													),
													array('get', 'async')
												);
						
											}else
												return array('error' => 'COULDNT_UNPACK');
										}else
											return array('error' => 'Function gzdecode not exists. Please update your PHP to version 5.4');
									}else
										return array('error' => 'Wrong mime type');
								}else
									return array('error' => 'COULD_NOT_GET_MULTIFILE: ' . $gz_data['error'] );
							}else{
								return Helper::http__request(
									get_option('siteurl'),
									array(
										'spbc_remote_call_token'  => md5( $spbc_key ),
										'spbc_remote_call_action' => 'update_security_firewall',
										'plugin_name'             => 'spbc',
										'file_urls'                => $file_url,
									),
									array('get', 'async')
								);
							}
	
						} else
							return array('error' => 'NO_REMOTE_FILE_FOUND');
					}else
						return array('error' => 'MULTIFILE_COULD_NOT_GET_RESPONSE_CODE: '. $response_code['error'] );
				}else
					return array('error' => 'BAD_RESPONSE');
			}else
				return $result;
		}
			
		// Check for remote file
		if( $file_url ){
			
			$response_code = Helper::http__request__get_response_code($file_url);
			
			if( empty( $response_code['error'] ) ){
			
				if( $response_code === 200 || $response_code === 501 ){ // Check if it's there
					
					$gz_data = Helper::http__request__get_content( $file_url );
					
					if( empty( $gz_data['error'] ) ){
					
						if( Helper::get_mime_type( $gz_data, 'application/x-gzip' ) ){
							
							if( function_exists('gzdecode') ) {
			
								$data = gzdecode( $gz_data );
			
								if( $data !== false ){
			
									$lines = Helper::buffer__parse__csv( $data );
			
								}else
									return array( 'error' => 'COULDNT_UNPACK' );
							}else
								return array( 'error' => 'Function gzdecode not exists. Please update your PHP to version 5.4' );
						}else
							return array( 'error' => 'Wrong mime type');
					}else
						return array('error' => 'COULD_NOT_GET_MULTIFILE: ' . $gz_data['error'] );
					
					reset( $lines );
					
					for( $count_result = 0; current($lines) !== false; ) {
	
						$query = "INSERT INTO `" . SPBC_TBL_FIREWALL_DATA . "` VALUES ";
	
						for ( $i=0; SPBC_WRITE_LIMIT !== $i && current($lines) !== false; $i++, $count_result++, next($lines) ) {
	
							$entry = current($lines);
	
							if ( empty( $entry ) ) {
								continue;
							}
							if ( SPBC_WRITE_LIMIT !== $i ) {
	
								$ip   = $entry[0];
								$mask = $entry[1];
								// $comment = $entry[2]; // Comment from user
								$status      = isset( $entry[3] ) ? $entry[3] : 0;
								$is_personal = isset( $entry[4] ) ? intval( $entry[4] ) : 0;
	
								// IPv4
								if ( is_numeric( $ip ) ) {
									$mask = sprintf( '%u', bindec( str_pad( str_repeat( '1', $mask ), 32, 0, STR_PAD_RIGHT ) ) );
									$query .= "(0, 0, 0, $ip, 0, 0, 0, $mask, $status, 0, $is_personal),";
									// IPv6
								} else {
									$ip = substr( $ip, 1, - 1 ); // Cut ""
									$ip = Helper::ip__v6_normalize( $ip ); // Normalize
									$ip = explode( ':', $ip );
	
									$ip_1 = hexdec( $ip[0] . $ip[1] );
									$ip_2 = hexdec( $ip[2] . $ip[3] );
									$ip_3 = hexdec( $ip[4] . $ip[5] );
									$ip_4 = hexdec( $ip[6] . $ip[7] );
	
									$ip_1 = $ip_1 ? $ip_1 : 0;
									$ip_2 = $ip_2 ? $ip_2 : 0;
									$ip_3 = $ip_3 ? $ip_3 : 0;
									$ip_4 = $ip_4 ? $ip_4 : 0;
	
									for ( $k = 1; $k < 5; $k ++ ) {
										$curr = 'mask_' . $k;
										$curr = pow( 2, 32 ) - pow( 2, 32 - ( $mask - 32 >= 0 ? 32 : $mask ) );
										$mask = ( $mask - 32 <= 0 ? 0 : $mask - 32 );
									}
									$query .= "($ip_1, $ip_2, $ip_3, $ip_4, $mask_1, $mask_2, $mask_3, $mask_4, $status, 1, $is_personal),";
								}
							}
	
						};
	
						//Exclusion for servers IP (SERVER_ADDR)
						if ( ! empty( Server::get('HTTP_HOST') ) ) {
							$exclusions[] = Helper::dns__resolve( Server::get('HTTP_HOST') );
							$exclusions[] = '127.0.0.1';
							foreach ( $exclusions as $exclusion ) {
								if ( Helper::ip__validate( $exclusion ) && sprintf( '%u', ip2long( $exclusion ) ) ) {
									$query .= '(0, 0, 0, ' . sprintf( '%u', ip2long( $exclusion ) ) . ', 0, 0, 0, ' . sprintf( '%u', bindec( str_repeat( '1', 32 ) ) ) . ', 2, 0, 0),';
								}
							}
						}
	
						$sql_result = self::$db_handler->fw_insert_data( substr( $query, 0, - 1 ) . ';' );
	
						if( ! $sql_result ){
							return array( 'error' => 'COULD_NOT_WRITE_TO_DB: ' . self::$db_handler->get_last_error() );
						}
						
					}
	
					return $count_result;
	
				}else
					return array('error' => 'NO_REMOTE_FILE_FOUND');
			}else
				return array('error' => 'FILE_COULD_NOT_GET_RESPONSE_CODE: '. $response_code['error'] );
		}
	}
	
	// Send and wipe SFW log
	public static function send_logs( $spbc_key ){

		//Getting logs
		$result = self::$db_handler->fw_get_logs();
		
		if(count($result)){
			//Compile logs
			$data = array();
			
			foreach($result as $key => $value){
				
				//Compile log
				$to_data = array(
					'datetime'        => date('Y-m-d H:i:s', $value['entry_timestamp']),
					'page_url'        => $value['page_url'],
					'visitor_ip'      => Helper::ip__validate($value['ip_entry']) == 'v4' ? (int)sprintf('%u', ip2long($value['ip_entry'])) : (string)$value['ip_entry'],
					'http_user_agent' => $value['http_user_agent'],
					'request_method'  => $value['request_method'],
					'x_forwarded_for' => $value['x_forwarded_for'],
					'hits'            => (int)$value['requests'],
				);
				
				// Legacy
				switch($value['status']){
					case 'PASS_BY_TRUSTED_NETWORK': $to_data['status_efw'] = 3;  break;
					case 'PASS_BY_WHITELIST':       $to_data['status_efw'] = 2;  break;
					case 'PASS':                    $to_data['status_efw'] = 1;  break;
					case 'DENY':                    $to_data['status_efw'] = 0;  break;
					case 'DENY_BY_NETWORK':         $to_data['status_efw'] = -1; break;
					case 'DENY_BY_DOS':             $to_data['status_efw'] = -2; break;
					case 'DENY_BY_WAF_XSS':         $to_data['status_efw'] = -3; $to_data['waf_attack_type'] = 'XSS';           $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_SQL':         $to_data['status_efw'] = -4; $to_data['waf_attack_type'] = 'SQL_INJECTION'; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_FILE':        $to_data['status_efw'] = -5; $to_data['waf_attack_type'] = 'MALWARE';       $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_EXPLOIT':     $to_data['status_efw'] = -6; $to_data['waf_attack_type'] = 'EXPLOIT';       $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_BFP':             $to_data['status_efw'] = -7; break;
				}
				
				switch($value['status']){
					case 'PASS_BY_TRUSTED_NETWORK': $to_data['status'] = 3;  break;
					case 'PASS_BY_WHITELIST':       $to_data['status'] = 2;  break;
					case 'PASS':                    $to_data['status'] = 1;  break;
					case 'DENY':                    $to_data['status'] = 0;  break;
					case 'DENY_BY_NETWORK':         $to_data['status'] = -1; break;
					case 'DENY_BY_DOS':             $to_data['status'] = -2; break;
					case 'DENY_BY_WAF_XSS':         $to_data['status'] = -3; $to_data['waf_attack_type'] = 'XSS';           $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_SQL':         $to_data['status'] = -4; $to_data['waf_attack_type'] = 'SQL_INJECTION'; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_FILE':        $to_data['status'] = -5; $to_data['waf_attack_type'] = 'MALWARE';       $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_EXPLOIT':     $to_data['status'] = -6; $to_data['waf_attack_type'] = 'EXPLOIT';       $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_BFP':             $to_data['status'] = -7; break;
				}
				
				$data[] = $to_data;
			
			} unset($key, $value, $result, $to_data);
			
			// Sendings request
			$result = API::method__security_logs__sendFWData($spbc_key, $data);
			
			// Checking answer and deleting all lines from the table
			if(empty($result['error'])){
				if($result['rows'] == count($data)){
					self::$db_handler->fw_logs_clear_table();
					return count($data);
				}
			}else{
				return $result;
			}
		}
		
		return array(
			'error' => 'NO_LOGS_TO_SEND'
		);
	}

	/**
	 * Use this method to handle logs updating by the module.
	 *
	 * @return void
	 */
	public function update_logs( $ip, $status = '', $pattern = array() ) {

		if( empty( $ip ) || empty( $status ) )
			return;

		// Parameters
		$time            = time();
		$page_url        = addslashes(( Server::get('HTTPS') != 'off' ? 'https://' : 'http://') . Server::get('HTTP_HOST').Server::get('REQUEST_URI'));
		$page_url        = substr($page_url, 0 , 4096);
		$http_user_agent = !empty(Server::get('HTTP_USER_AGENT'))
			? addslashes(htmlspecialchars(substr(Server::get('HTTP_USER_AGENT'), 0, 300)))
			: 'unknown';
		$request_method  = Server::get('REQUEST_METHOD');
		$x_forwarded_for = Server::get('HTTP_X_FORWARDED_FOR');
		$x_forwarded_for = addslashes(htmlspecialchars(substr($x_forwarded_for, 0 , 15)));
		$id              = md5($ip.$http_user_agent.$status);
		$pattern         = !empty($pattern)
			? json_encode($pattern)
			: '';

		$log_item = array(
			'id'              => $id,
			'ip'              => $ip,
			'time'            => $time,
			'status'          => $status,
			'pattern'         => $pattern,
			'page_url'        => $page_url,
			'http_user_agent' => $http_user_agent,
			'request_method'  => $request_method,
			'x_forwarded_for' => $x_forwarded_for
		);

		self::$db_handler->fw_logs_insert_data( $log_item );

	}


	/**
	 * Sets priorities for firewall results.
	 * It generates one main result from multi-level results array.
	 *
	 * @return array   Single element array of result
	 */
	private function prioritize( $results ){

		$current_fw_result_priority = 0;
		$result = array( 'status' => 'PASS', 'passed_ip' => '' );

		if( is_array( $results ) ) {
			foreach ( $results as $fw_result ) {
				$priority = array_search( $fw_result['status'], $this->statuses_priority ) + ( isset($fw_result['is_personal']) && $fw_result['is_personal'] ? count ( $this->statuses_priority ) : 0 );
				if( $priority >= $current_fw_result_priority ){
					$current_fw_result_priority = $priority;
					$result['status'] = $fw_result['status'];
					$result['passed_ip'] = isset( $fw_result['ip'] ) ? $fw_result['ip'] : $fw_result['passed_ip'];
					$result['blocked_ip'] = isset( $fw_result['ip'] ) ? $fw_result['ip'] : $fw_result['blocked_ip'];
					$result['pattern'] = isset( $fw_result['pattern'] ) ? $fw_result['pattern'] : array();
				}
			}
		}

		return $result;

	}

	/**
	 * Check the result if it whitelisted or trusted network
	 *
	 * @param array $results
	 *
	 * @return bool
	 */
	private function is_whitelisted( $results ) {

		foreach ( $results as $fw_result ) {
			if (
				strpos( $fw_result['status'], 'PASS_BY_TRUSTED_NETWORK' ) !== false ||
				strpos( $fw_result['status'], 'PASS_BY_WHITELIST' ) !== false
			) {
				return true;
			}
		}
		return false;

	}

	/**
	 * The method generates block page.
	 *
	 * @param $ip
	 * @param string $reason
	 * @param string $service_id
	 *
	 * @return void   Doing die() and stops script working.
	 */
	private function _die( $ip, $reason = '', $service_id = '' ){

		// Adding block reason
		switch( $reason ){
			case 'DENY':                $reason = __('Blacklisted', 'security-malware-firewall');                      break;
			case 'DENY_BY_NETWORK':	    $reason = __('Hazardous network', 'security-malware-firewall');	               break;
			case 'DENY_BY_DOS':         $reason = __('Blocked by DoS prevention system', 'security-malware-firewall'); break;
			case 'DENY_BY_WAF_XSS':	    $reason = __('Blocked by Web Application Firewall: XSS attack detected.',    'security-malware-firewall'); break;
			case 'DENY_BY_WAF_SQL':	    $reason = __('Blocked by Web Application Firewall: SQL-injection detected.', 'security-malware-firewall'); break;
			case 'DENY_BY_WAF_EXPLOIT':	$reason = __('Blocked by Web Application Firewall: Exploit detected.',       'security-malware-firewall'); break;
			case 'DENY_BY_WAF_FILE':    $reason = __('Blocked by Web Application Firewall: Malicious files upload.', 'security-malware-firewall'); break;
			case 'DENY_BY_BFP':         $reason = __('Blocked by BruteForce Protection: Too many invalid logins.',   'security-malware-firewall'); break;
			default :                   $reason = __('Blacklisted', 'security-malware-firewall');                      break;
		}

		$spbc_die_page = file_get_contents( __DIR__ . '/spbc_die_page.html' );

		$spbc_die_page = str_replace( "{TITLE}", __('Blocked: Security by CleanTalk', 'security-malware-firewall'),     $spbc_die_page );
		$spbc_die_page = str_replace( "{REMOTE_ADDRESS}", $ip,                   $spbc_die_page );
		$spbc_die_page = str_replace( "{SERVICE_ID}",     $service_id,           $spbc_die_page );
		$spbc_die_page = str_replace( "{HOST}",           Server::get('HTTP_HOST'), $spbc_die_page );
		$spbc_die_page = str_replace( "{TEST_TITLE}",     ( ! empty( Get::get('spbct_test') )
			? __('This is the testing page for Security FireWall', 'security-malware-firewall')
			: ''), $spbc_die_page );
		$spbc_die_page = str_replace( "{REASON}",         $reason, $spbc_die_page );
		$spbc_die_page = str_replace( "{GENERATED_TIMESTAMP}",    time(), $spbc_die_page );
		$spbc_die_page = str_replace(
			"{FALSE_POSITIVE_WARNING}",
			__('Maybe you\'ve been blocked by a mistake. Please refresh the page (press CTRL + F5) or try again later.', 'security-malware-firewall'),
			$spbc_die_page
		);

		if( headers_sent() === false ){
			header('Expires: '.date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Cache-Control: post-check=0, pre-check=0', FALSE);
			header('Pragma: no-cache');
			header("HTTP/1.0 403 Forbidden");
			$spbc_die_page = str_replace("{GENERATED}", "", $spbc_die_page);
		} else {
			$spbc_die_page = str_replace("{GENERATED}", "<h2 class='second'>The page was generated at&nbsp;".date("D, d M Y H:i:s")."</h2>", $spbc_die_page );
		}

		die( $spbc_die_page );

	}

}

/**
 * Fix for compatibility for any CMS
 */
if( ! function_exists( '__' ) ) {
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}