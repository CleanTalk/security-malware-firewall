<?php

namespace CleantalkSP\SpbctWP;

/**
 * Security by Cleantalk API class.
 * Extends CleantalkAPI base class.
 * Compatible only with WordPress and Security by Cleantalk plugin.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class API extends \CleantalkSP\Common\API
{
	
	const RETRIES = 1;
	const API_SERVER_CHECK_PERIOD = 3600;
	
	/**
	 * Function sends raw request to API server
	 *
	 * @param array   $data    to send
	 * @param string  $url     of API server
	 * @param integer $timeout timeout in seconds
	 * @param boolean $ssl     use ssl on not
	 * @param integer $retries count of retries. Indicates that this is recursion
	 *
	 * @return array|bool
	 */
	public static function send_request($data, $url = self::URL, $timeout = 5, $ssl = true, $ssl_path = '', $retries = 0 )
	{
		global $spbc;
		
		// Possibility to switch API url
		$url = defined('SPBC_API_URL') ? SPBC_API_URL : $url;
		
		// Adding agent version to data
		$data['agent'] = SPBC_AGENT;
		
		if($spbc->settings['wp__use_builtin_http_api']){
			
			$args = array(
				'body' => $data,
				'timeout' => $timeout,
				'user-agent' => SPBC_AGENT.' '.get_bloginfo( 'url' ),
			);
			
			$result = wp_remote_post($url, $args);
			
			$result = is_wp_error( $result )
				? array( 'error' => $result->get_error_message() )
				: wp_remote_retrieve_body( $result );
			
		// Call via CURL
		}else{
			$ssl_path = $ssl_path ?: ( defined( 'SPBC_CASERT_PATH' ) ? SPBC_CASERT_PATH : '' );
			$result = parent::send_request($data, $url, $timeout, $ssl, $ssl_path);
		}
		
		// If bad response and it's time to check servers
		if(
			! empty( $result['error'] ) &&
			time() - (int) get_option( 'spbc_api_servers_last_checked' ) > self::API_SERVER_CHECK_PERIOD
		){
			$api_servers = self::getAPIServersOrderedByResponseTime();
			update_option( 'spbc_api_servers_by_response_time', $api_servers );
			update_option( 'spbc_api_servers_last_checked', time() );
		}
		
		// Retry if error noticed
		// And we did less than maximum retries
		if(
			isset( $result['error'] ) &&
			$retries < self::RETRIES
		){
			$api_servers = get_option( 'spbc_api_servers_by_response_time' );
			if( $api_servers ){
				$result = self::send_request( $data, $api_servers[ $retries ]['dns'], $timeout, $ssl, $ssl_path, ++$retries );
			}
		}
		
		return $result;
	}
	
	/**
	 * @return array
	 */
	public static function getAPIServersOrderedByResponseTime(){
		
		foreach( Helper::$cleantalks_servers as $dns_name => $ip ){
			if( strpos( $dns_name, 'api' ) === 0 ){
				$api_servers[ $dns_name] = $ip;
			}
		}
		
		return self::sortIPBYResponseTime( $api_servers );
	}
	
	/**
	 * Returns sorted by response time
	 *
	 * @param array $input_records cosider array( 'DNS_NAME1' => 'IP1', 'DNS_NAME2' => 'IP2' ) array as input
	 *
	 * @return array
	 *
	 * 0 => array (size=3)
	 *   'ping' =>  79.3
	 *   'ip' => string '1.1.1.1'
	 *   'dns' => string 'dns.name'
	 * 1 => array (size=3)
	 *   'ping' => float 165.6
	 *   'ip' => string '2.2.2.2'
	 *   'dns' => string 'dns.name'
	 *
	 */
	public static function sortIPBYResponseTime( $input_records ){
		
		$output_records = array();
		// Get all API servers and response time
		foreach( $input_records as $dns_name => $ip ){
			$output_records[] = array(
				'ping' => self::httpPing( $ip ) * 1000,
				'ip'   => $ip,
				'dns'  => $dns_name,
			);
		}
		
		// Sort by key which is ping
		$pings = array_column( $output_records, 'ping' );
		array_multisort( $pings, SORT_ASC, SORT_NUMERIC, $output_records );
		
		return $output_records;
	}
	
	/**
	 * Function to check response time for given domain/IP
	 * param string
	 *
	 * @return int
	 */
	public static function httpPing( $host ){
		
		$starttime = microtime( true );
		$file      = @fsockopen( $host, 80, $errno, $errstr, 1500 / 1000 );
		$stoptime  = microtime( true );
		
		if( ! $file ){
			$ping = 1500 / 1000;  // Site is down
		}else{
			fclose( $file );
			$ping = ( $stoptime - $starttime );
			$ping = round( $ping, 4 );
		}
		
		return $ping;
	}
	
}