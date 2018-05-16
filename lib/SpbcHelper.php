<?php

/*
 * 
 * CleanTalk Security Helper class
 * 
 * @package Security Plugin by CleanTalk
 * @subpackage Helper
 * @Version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */
 
class SpbcHelper
{
	const URL = 'https://api.cleantalk.org';
	
	public static $cdn_pool = array(
		'cloud_flare' => array(
			'v4' => array(
				'103.21.244.0/22',
				'103.22.200.0/22',
				'103.31.4.0/22',
				'104.16.0.0/12',
				'108.162.192.0/18',
				'131.0.72.0/22',
				'141.101.64.0/18',
				'162.158.0.0/15',
				'172.64.0.0/13',
				'173.245.48.0/20',
				'188.114.96.0/20',
				'190.93.240.0/20',
				'197.234.240.0/22',
				'198.41.128.0/17',
			),
			'v6' => array(
				'2400:cb00:0:0:0:0:0:0/32',
				'2405:8100:0:0:0:0:0:0/32',
				'2405:b500:0:0:0:0:0:0/32',
				'2606:4700:0:0:0:0:0:0/32',
				'2803:f800:0:0:0:0:0:0/32',
				'2c0f:f248:0:0:0:0:0:0/32',
				'2a06:98c0:0:0:0:0:0:0/29',
			),
		),
	);
	
	public static $private_networks = array(
		'v4' => array(
			'10.0.0.0/8',
			'100.64.0.0/10',
			'172.16.0.0/12',
			'192.168.0.0/16',
			'127.0.0.1/32',
		),
		'v6' => array(
			'0:0:0:0:0:0:0:1/128',
		),
	);
	
	static public function ip_get($ip_types = array('real', 'remote_addr', 'x_forwarded_for', 'x_real_ip', 'cloud_flare'))
	{
		$ips = array();
		foreach($ip_types as $ip_type){
			$ips[$ip_type] = '';
		} unset($ip_type);
		
		$headers = apache_request_headers();
		
		// REMOTE_ADDR
		if(isset($ips['remote_addr'])){
			$ip_type = self::ip__validate($_SERVER['REMOTE_ADDR']);
			if($ip_type){
				$ips['remote_addr'] = $ip_type == 'v6' ? self::ip__v6_normalizе($_SERVER['REMOTE_ADDR']) : $_SERVER['REMOTE_ADDR'];
			}
		}
		
		// X-Forwarded-For
		if(isset($ips['x_forwarded_for'])){
			if(isset($headers['X-Forwarded-For'])){
				$tmp = explode(",", trim($headers['X-Forwarded-For']));
				$ips['x_forwarded_for']= trim($tmp[0]);
			}
		}
		
		// X-Real-Ip
		if(isset($ips['x_real_ip'])){
			if(isset($headers['X-Real-Ip'])){
				$tmp = explode(",", trim($headers['X-Real-Ip']));
				$ips['x_real_ip']= trim($tmp[0]);
			}
		}
		
		// Cloud Flare
		if(isset($ips['cloud_flare'])){
			if(isset($headers['Cf_Connecting_Ip'])){			
				$ip_type = self::ip__validate($_SERVER['REMOTE_ADDR']);
				if($ip_type){
					$remote_addr = $ip_type == 'v6' ? self::ip__v6_normalizе($_SERVER['REMOTE_ADDR']) : $_SERVER['REMOTE_ADDR'];
					if(self::ip__mask_match($remote_addr, self::$cdn_pool['cloud_flare'][$ip_type], $ip_type)){
						$ips['cloud_flare'] = $headers['Cf_Connecting_Ip'];
					}
				} 
			}
		}
		// Getting real IP from REMOTE_ADDR or Cf_Connecting_Ip if set or from (X-Forwarded-For, X-Real-Ip) if REMOTE_ADDR is local.
		if(isset($ips['real'])){
			
			$ip_type = self::ip__validate($_SERVER['REMOTE_ADDR']);
			if($ip_type){
				$ips['real'] = $ip_type == 'v6' ? self::ip__v6_normalizе($_SERVER['REMOTE_ADDR']) : $_SERVER['REMOTE_ADDR'];
			}else{
				$ips['real'] = '0.0.0.0';
				$ip_type = 'v4';
			}
			
			// Cloud Flare
			if(isset($headers['Cf_Connecting_Ip'])){
				if(self::ip__mask_match($ips['real'], self::$cdn_pool['cloud_flare'][$ip_type], $ip_type)){
					$ips['real'] = $headers['Cf_Connecting_Ip'];
				}
			// Incapsula proxy
			}elseif(isset($headers['Incap-Client-Ip'])){
				$ips['real'] = $headers['Incap-Client-Ip'];
			// Private networks. Looking for X-Forwarded-For and X-Real-Ip
			}elseif(self::ip__mask_match($ips['real'], self::$private_networks[$ip_type], $ip_type)){
				if(isset($headers['X-Forwarded-For'])){
					$ips['real'] = $headers['X-Forwarded-For'];
				}elseif(isset($headers['X-Real-Ip'])){
					$ips['real'] = $headers['X-Real-Ip'];
				}
			}			
		}
		
		// Validating IPs
		$result = array();
		foreach($ips as $key => $ip){
			$ip_version = self::ip__validate($ip);
			if($ip && $ip_version){
				$result[$key] = $ip;
			}
		}
		
		// Return
		$result = array_unique($result);
		return count($ip_types) > 1 
			? $result
			: reset($result);
	}
	
	/*
	 * Check if the IP belong to mask.  Recursive.
	 * Octet by octet for IPv4
	 * Hextet by hextet for IPv6
	 * @param ip string  
	 * @param cird mixed (string|array of strings)
	 * @param ip_type string
	 * @param cird mixed (string|array of strings)
	*/
	static public function ip__mask_match($ip, $cidr, $ip_type = 'v4', $xtet_count = 0){
		
		if(is_array($cidr)){
			foreach($cidr as $curr_mask){
				if(self::ip__mask_match($ip, $curr_mask, $ip_type)){
					return true;
				}
			} unset($curr_mask);
			return false;
		}
		
		if($ip_type == 'v4') $xtet_base = 8;
		if($ip_type == 'v6') $xtet_base = 16;
			
		// Calculate mask
		$exploded = explode('/', $cidr);
		
		// Exit condition
		$xtet_end = ceil($exploded[1] / $xtet_base);
		if($xtet_count == $xtet_end)
			return true;
		
		$mask = $exploded[1] - $xtet_base * $xtet_count >= 0 ? $xtet_base : $exploded[1] - $xtet_base * ($xtet_count - 1);
		$mask = 4294967295 << ($xtet_base - $mask);
		
		// Calculate first ip X-tet
		$ip_xtet = explode($ip_type == 'v4' ? '.' : ':', $ip);
		$ip_xtet = $ip_type == 'v4' ? $ip_xtet[$xtet_count] : hexdec($ip_xtet[$xtet_count]);
		
		// Calculate first net X-tet
		$net_xtet = explode($ip_type == 'v4' ? '.' : ':', $exploded[0]);
		$net_xtet = $ip_type == 'v4' ? $net_xtet[$xtet_count] : hexdec($net_xtet[$xtet_count]);
		
		$result = ($ip_xtet & $mask) == ($net_xtet & $mask);
		
		if($result)
			$result = self::ip__mask_match($ip, $cidr, $ip_type, $xtet_count + 1);
		
		return $result;
	}
	
	/**
	 * Expand IPv6
	 * param (string) $ip
	 * returns (string) IPv6
	 */
	static public function ip__v6_normalizе($ip) {
		// Normalizing hextets number
		if(strpos($ip, '::') !== false){
			$ip = str_replace('::', str_repeat(':0', 8 - substr_count($ip, ':')).':', $ip);
			$ip = strpos($ip, ':') === 0 ? '0'.$ip : $ip;
			$ip = strpos(strrev($ip), ':') === 0 ? $ip.'0' : $ip;
		}
		// Simplifyng hextets
		if(preg_match('/:0(?=[a-z0-9]+)/', $ip)){
			$ip = preg_replace('/:0(?=[a-z0-9]+)/', ':', strtolower($ip));
			$ip = self::ip__v6_normalizе($ip);
		}
		return $ip;
	}
	
	/**
	 * Reduce IPv6
	 * param (string) $ip
	 * returns (string) IPv6
	 */
	static public function ip__v6_reduce($ip){
		if(strpos($ip, ':') !== false){
			$ip = preg_replace('/:0{1,4}/', ':',  $ip);
			$ip = preg_replace('/:{2,}/',   '::', $ip);
			$ip = strpos($ip, '0') === 0 ? substr($ip, 1) : $ip;
		}
		return $ip;
	}
	
	/*
	*	Validating IPv4, IPv6
	*	param (string) $ip
	*	returns (string) 'v4' || (string) 'v6' || (bool) false
	*/
	static public function ip__validate($ip)
	{
		if(!$ip)                                                  return false; // NULL || FALSE || '' || so on...
		if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return 'v4';  // IPv4
		if(filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return 'v6';  // IPv6
																  return false; // Unknown
	}
	
	static public function api_method__get_api_key($email, $website, $platform, $wpms = false, $do_check = true)
	{
		$request = array(
			'agent' => SPBC_AGENT,
			'method_name' => 'get_api_key',
			'email' => $email,
			'website' => $website,
			'platform' => $platform,
			'product_name' => 'security',
			'wpms_setup' => $wpms,
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	static public function api_method__notice_validate_key($api_key, $path_to_cms, $do_check = true)
	{
		$request = array(
			'agent' => SPBC_AGENT,
			'method_name' => 'notice_validate_key',
			'auth_key' => $api_key,
			'path_to_cms' => $path_to_cms	
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result, 'notice_validate_key') : $result;
		
		return $result;
	}
	
	static public function api_method__notice_paid_till($api_key, $do_check = true)
	{
		$request = array(
			'agent' => SPBC_AGENT,
			'method_name' => 'notice_paid_till',
			'auth_key' => $api_key
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	static public function api_method__ip_info($data, $do_check = true)
	{
		$request = array(
			'method_name' => 'ip_info',
			'data' => $data
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		return $result;
	}
	
	static public function api_method__security_logs($api_key, $data, $do_check = true)
	{
		$request = array(
			'agent' => SPBC_AGENT,
			'auth_key' => $api_key,
			'method_name' => 'security_logs',
			'timestamp' => current_time('timestamp'),
			'data' => json_encode($data),
			'rows' => count($data),
		);
		
		$result = self::api__send_request($request);
		// $result = '{"data":{"rows":1}}';
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	static public function api_method__security_logs__sendFWData($api_key, $data, $do_check = true){
		
		$request = array(
			'agent' => SPBC_AGENT,
			'auth_key' => $api_key,
			'method_name' => 'security_logs',
			'timestamp' => current_time('timestamp'),
			'data_fw' => json_encode($data),
			'rows_fw' => count($data),
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	static public function api_method__security_logs__feedback($api_key, $do_check = true)
	{
		$request = array(
			'agent' => SPBC_AGENT,
			'auth_key' => $api_key,
			'method_name' => 'security_logs',
			'data' => '0',
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	static public function api_method__security_firewall_data($api_key, $do_check = true){
				
		$request = array(
			'agent' => SPBC_AGENT,
			'auth_key' => $api_key,
			'method_name' => 'security_firewall_data',
		);
		
		$result = self::api__send_request($request);
		// $result = '{"data":[[167772160,8,0,0],["2a06:98c0:0:0:0:0:0:0",29,0,0]]}';
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	
	
	static public function api_method__security_mscan_logs($api_key, $service_id, $scan_time, $scan_result, $scanned_total, $modified, $unknown, $do_check = true)
	{
		$request = array(
			'agent'              => SPBC_AGENT,
			'method_name'        => 'security_mscan_logs',
			'auth_key'           => $api_key,
			'service_id'         => $service_id,
			'started'            => $scan_time,
			'result'             => $scan_result,
			'total_core_files'   => $scanned_total,
		);
		
		if(!empty($modified)){
			$request['failed_files']      = json_encode($modified);
			$request['failed_files_rows'] = count($modified);
		}
		if(!empty($unknown)){
			$request['unknown_files']      = json_encode($unknown);
			$request['unknown_files_rows'] = count($unknown);
		}
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	static public function api_method__security_mscan_files($api_key, $file_path, $file, $file_md5, $do_check = true)
	{
		$request = array(
			'agent' => SPBC_AGENT,
			'method_name' => 'security_mscan_files',
			'auth_key' => $api_key,
			'path_to_sfile' => $file_path,
			'attached_sfile' => $file,
			'md5sum_sfile' => $file_md5,
		);
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result) : $result;
		
		return $result;
	}
	
	/**
	 * Function gets spam domains report
	 *
	 * @param string api key
	 * @param integer report days
	 * @return type
	 */
	static public function api_method__backlinks_check_cms($api_key, $data, $date = null, $do_check = true)
	{
		$request = array(
			'agent'       => APBCT_AGENT,
			'method_name' => 'backlinks_check_cms',
			'auth_key'    => $api_key,
			'data'        => is_array($data) ? implode(',',$data) : $data,
		);
		
		if($date) $request['date'] = $date;
		
		$result = self::api__send_request($request);
		$result = $do_check ? self::api__check_response($result, 'backlinks_check_cms') : $result;
		
		return $result;
	}
	
	static public function api__send_request($data, $url = self::URL, $isJSON = false, $timeout = 6, $ssl = false)
	{	
		$original_data = $data;
		$result = null;
		$curl_error = false;
		
		if(!$isJSON){
			$data = http_build_query($data);
			$data = str_replace("&amp;", "&", $data);
		}else{
			$data = json_encode($data);
		}
		
		if (function_exists('curl_init') && function_exists('json_decode')){
		
			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
			curl_setopt($ch, CURLOPT_POST, true);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('Expect:'));
			
			if ($ssl === true) {
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
				curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
				curl_setopt($ch, CURLOPT_CAINFO, SPBC_CASERT_PATH);
            }else{
				curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
				curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			}
			
			$result = curl_exec($ch);
			
			if($result === false){
				if($ssl === false){
					return self::api__send_request($original_data, $url, $isJSON, $timeout, true);
				}
				$curl_error = curl_error($ch);
			}
			
			curl_close($ch);
			
		}else{
			$curl_error = 'CURL_NOT_INSTALLED';
		}
		
		if($curl_error){
			
			$opts = array(
				'http' => array(
					'method'  => "POST",
					'timeout' => $timeout,
					'content' => $data,
				)
			);
			$context = stream_context_create($opts);
			$result = @file_get_contents($url, 0, $context);
		}
		
		if(!$result && $curl_error)
			return array('error' => true, 'error_string' => $curl_error);
		
		return $result;
	}
	
	/**
	 * Function checks server response
	 *
	 * @param string result
	 * @param string request_method
	 * @return mixed (array || array('error' => true))
	 */
	static public function api__check_response($result, $method_name = null)
	{		
		// Errors handling
		
		// Bad connection
		if(is_array($result) && isset($result['error'])){
			return array(
				'error' => true,
				'error_string' => 'CONNECTION_ERROR' . (isset($result['error_string']) ? ' '.$result['error_string'] : ''),
			);
		}
		
		// JSON decode errors
		$result = json_decode($result, true);
		if(empty($result)){
			return array(
				'error' => true,
				'error_string' => 'JSON_DECODE_ERROR'
			);
		}
		
		// Server errors
		if($result && (isset($result['error_no']) || isset($result['error_message']))){
			return array(
				'error' => true,
				'error_string' => "SERVER_ERROR NO: {$result['error_no']} MSG: {$result['error_message']}",
				'error_no' => $result['error_no'],
				'error_message' => $result['error_message']
			);
		}
		
		// Pathces for different methods
		
		// mehod_name = notice_validate_key
		if($method_name == 'notice_validate_key' && isset($result['valid'])){
			return $result;
		}
		
		// Other methods
		if(isset($result['data']) && is_array($result['data'])){
			return $result['data'];
		}
	}
}
