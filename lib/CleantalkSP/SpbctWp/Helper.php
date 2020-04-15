<?php

namespace CleantalkSP\SpbctWp;

/**
 * CleanTalk Security Helper class
 *
 * @depends       CleantalkSP\Common\Helper
 *
 * @package       Security Plugin by CleanTalk
 * @subpackage    Helper
 * @Version       2.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */

class Helper extends \CleantalkSP\Common\Helper
{
	/**
	 * Function sends raw http request
	 *
	 * May use 4 presets(combining possible):
	 * get_code - getting only HTTP response code
	 * async    - async requests
	 * get      - GET-request
	 * ssl      - use SSL
	 *
	 * @param string       $url     URL
	 * @param array        $data    POST|GET indexed array with data to send
	 * @param string|array $presets String or Array with presets: get_code, async, get, ssl, dont_split_to_array
	 * @param array        $opts    Optional option for CURL connection
	 *
	 * @return mixed|array|string (array || array('error' => true))
	 */
	static public function http__request($url, $data = array(), $presets = null, $opts = array())
	{
		// Set APBCT User-Agent and passing data to parent method
		$opts = self::array_merge__save_numeric_keys(
			array(
				CURLOPT_USERAGENT => 'SPBCT-wordpress/' . (defined('SPBC_VERSION') ? SPBC_VERSION : 'unknown') . '; ' . get_bloginfo('url'),
			),
			$opts
		);
		
		return parent::http__request($url, $data, $presets, $opts);
	}
	
	/**
	 * Wrapper for http_request
	 * Requesting HTTP response code for $url
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	static public function http__request__get_response_code( $url ){
		return static::http__request( $url, array(), 'get_code');
	}
	
	/**
	 * Wrapper for http_request
	 * Requesting data via HTTP request with GET method
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	static public function http__request__get_content( $url ){
		return static::http__request( $url, array(), 'get dont_split_to_array');
	}
	
	/**
	 * Escapes MySQL params
	 *
	 * @param string|int $param
	 * @param string     $quotes
	 *
	 * @return int|string
	 */
	public static function db__prepare_param($param, $quotes = '\'')
	{
		if(is_array($param)){
			foreach($param as &$par){
				$par = self::db__prepare_param($par);
			}
		}
		switch(true){
			case is_numeric($param):
				$param = intval($param);
				break;
			case is_string($param) && strtolower($param) == 'null':
				$param = 'NULL';
				break;
			case is_string($param):
				global $wpdb;
//				$param = preg_match('/;|\'+/', $param) ? preg_replace('/;|\'+/', '', $param) : $param;
				$param = $quotes . $wpdb->_real_escape($param) . $quotes;
				break;
		}
		return $param;
	}
	
	/**
	 * Escapes MySQL params
	 *
	 * @param string|int $param
	 * @param string     $quotes
	 *
	 * @return int|string
	 */
	public static function db__unescape_string($param)
	{
		$patterns = array(
			'/\//',
			'/\;/',
			'/\|/',
			'/\\\\\r/',
			'/\\\\\\\\/',
			"/\\\\\'/",
			'/\\\\\"/',
		);
		$replacements = array(
			'/',
			';',
			'|',
			'\r',
			'\\',
			'\'',
			'"',
		);
		$param = preg_replace($patterns, $replacements, $param );
		return $param;
	}
	
	public static function time__get_interval_start( $interval = 300 ){
		return time() - ( ( time() - strtotime( date( 'd F Y' ) ) ) % $interval );
	}
}
