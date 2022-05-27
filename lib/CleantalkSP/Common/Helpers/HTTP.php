<?php

namespace CleantalkSP\Common\Helpers;

use CleantalkSP\Templates\Singleton;
use CleantalkSP\Common\HTTP\Request;

/**
 * Class HTTP
 * Gather static functions designed to work with Common\HTTP\Request lib
 * Such as request and URL-related things
 *
 * Uses "singleton" template to store already discovered HTTP-headers, requests results and whole requests
 *
 * @version       1.0.0
 * @package       CleantalkSP\Common\Helpers
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class HTTP {
    
    use Singleton;
    
    /**
     * @var array Stored HTTP headers
     */
    private $http_headers = [];
    
    /**
     * Appends given parameter(s) to URL considering other parameters
     * Adds ? or & before the append
     *
     * @param string       $url
     * @param string|array $parameters
     *
     * @return string
     */
    public static function appendParametersToURL( $url, $parameters ){
        
        if( empty($parameters) ){
            return $url;
        }
        
        $parameters = is_array( $parameters )
            ? http_build_query( $parameters )
            : $parameters;
        
        $url .= strpos( $url, '?' ) === false
            ? ('?' . $parameters)
            : ('&' . $parameters);
        
        return $url;
    }
    
    /**
     * Remove given parameter(s) from URL considering other parameters
     * Adds ? or & before the appendix
     *
     * @param string       $url
     * @param string|array $parameters
     *
     * @return string
     */
    public static function removeParametersFromURL( $url, $parameters )
    {
        foreach((array)$parameters as $parameter){
            $url = preg_replace('/([?&]' . $parameter . '=.+?($|&))/', '', $url);
        }
        
        return $url;
    }
    
    /**
     * Wrapper for http_request
     * Requesting HTTP response code for $url
     *
     * @param string $url
     *
     * @return int
     */
    public static function getResponseCode($url)
    {
        $http = new Request();
        return $http->setUrl($url)
            ->setPresets(['get_code'])
            ->request();
    }
 
	/**
	 * Wrapper for http_request
	 * Requesting data via HTTP request with GET method
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
    public static function getContentFromURL($url)
    {
        $http = new Request();
        
        return $http
            ->setUrl($url)
            ->setPresets(array('get'))
            ->request();
    }
 
	/**
     * Get and unpack data from local or remote GZ archive
     *
     * @param $url
     *
     * @return array|mixed|string|string[]
     */
    public static function getDataFromGZ( $url )
    {
        // Check if the URL is remote address or not, and use a proper function to extract data
        $url_scheme = parse_url( $url, PHP_URL_SCHEME );
        return $url_scheme !== false && in_array( $url_scheme, array('ftp','http','https',) )
            ? static::getDataFromRemoteGZ( $url )
            : static::getDataFromLocalGZ( $url );
    }
    
    /**
	 * Wrapper for http_request
	 * Requesting HTTP response code for $url
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function getDataFromRemoteGZ( $url ){
		
	    // Check the response code
		$response_code = static::getResponseCode($url);
		if ( is_int($response_code) && $response_code !== 200 ){ // Check if it's there
            return array('error' => 'Bad HTTP response from file location: ' . $response_code);
        }
		
		// Get data
        $data = static::getContentFromURL($url);
        if ( ! empty( $data['error'] ) ){
            return array('error' => 'Getting datafile ' . $data['error']);
        }
        
        // Check if the 'gzdecode' function exists
        if( ! function_exists('gzdecode') ){
            return array('error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4');
        }
        
		$data = @gzdecode( $data );
						
        if ( $data !== false ){
            return $data;
        }
        
        return array('error' => 'Can not unpack datafile');
    }
    
    /**
     * Wrapper for http_request
     * Requesting HTTP response code for $url
     *
     * @param string $path
     *
     * @return array|mixed|string
     */
    public static function getDataFromLocalGZ( $path )
    {
        if( ! file_exists($path) ){
            return array('error' => 'File doesn\'t exists: ' . $path);
        }
        
        if( ! is_readable($path) ){
            return array( 'error' => 'File is not readable: ' . $path );
        }
        
        $data = file_get_contents( $path );
        if ( $data === false ){
            return array( 'error' => 'Couldn\'t get data' );
        }
        
        // Check if the 'gzdecode' function exists
        if( ! function_exists('gzdecode') ){
            return array('error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4');
        }
        
        $data = @gzdecode( $data );
        if ( $data !== false ){
            return $data;
        }
        
        return array( 'error' => 'Can not unpack datafile');
    }
    
    /**
     * Gets every HTTP_ headers from super global variable $_SERVER
     *
     * If Apache web server is missing then making
     * Patch for apache_request_headers()
     *
     * returns array
     */
    public static function getHTTPHeaders(){
        
        // If headers have already been got, return them
        $headers = self::getInstance()->http_headers;
        if( ! empty( $headers ) ){
            return $headers;
        }
        
        foreach($_SERVER as $key => $val){
            if( 0 === stripos( $key, 'http_' ) ){
                $server_key = preg_replace('/^http_/i', '', $key);
                $key_parts = explode('_', $server_key);
                if(count($key_parts) > 0 && strlen($server_key) > 2){
                    foreach($key_parts as $part_index => $part){
                        if( $part_index === '' || $part === '' ){
                            continue;
                        }
                        $key_parts[$part_index] = function_exists('mb_strtolower') ? mb_strtolower($part) : strtolower($part);
                        $key_parts[$part_index][0] = strtoupper($key_parts[$part_index][0]);
                    }
                    $server_key = implode('-', $key_parts);
                }
                $headers[$server_key] = $val;
            }
        }
        
        // Store headers to skip the work next time
        self::getInstance()->http_headers = $headers;
        
        return $headers;
    }
    
    /**
     * Returns sorted by response time
     *
     * @param array $hosts Expects the similar arrays in input^
     *
     *                     array(
     *                         'DNS_NAME1' => 'HOST1',
     *                         'DNS_NAME2' => 'HOST2'
     *                     )
     *                     OR
     *                     array(
     *                         'HOST1',
     *                         'HOST2'
     *                     )
     *
     *                     DNS_NAME example: 'example.com'
     *                     HOST example: 'example.com'
     *                     HOST example: '1.1.1.1'
     *
     * @return array formatted in special way:
     *               array(
     *                   0 => array(
     *                     'ping' => 79.3
     *                     'host' => '1.1.1.1'
     *                     'dns' => 'dns.name'
     *                   )
     *                   1 => array(
     *                     'ping' => 165.6
     *                     'host' => '2.2.2.2'
     *                     'dns' => 'dns.name'
     *                   )
     *               )
     */
    public static function sortHostsByResponseTime($hosts)
    {
        // Get response time for each passed url/host
        $output_records = array();
        foreach( $hosts as $dns_name => $host ){
            $output_records[] = array(
                'ping' => self::ping($host),
                'host' => $host,
                'dns'  => is_numeric($dns_name) ? 'unknown' : $dns_name,
            );
        }
        
        // Sort by ping value
        $pings = array_column($output_records, 'ping');
        array_multisort(
            $pings,
            SORT_ASC,
            SORT_NUMERIC,
            $output_records
        );
        
        return $output_records;
    }
    
    /**
     * Function to check response time for given host or IP
     *
     * @param string $host Host URL or string representation of IP address
     *
     * @return double Response time in milliseconds
     */
    public static function ping($host)
    {
        $starttime = microtime(true);
        $file      = @fsockopen($host, 80, $errno, $errstr, 1500 / 1000);
        $stoptime  = microtime(true);
        
        if( ! $file ){
            $ping = 1500 / 1000;  // Site is down
        }else{
            $ping = ($stoptime - $starttime);
            $ping = round($ping, 4); // Cut microseconds part
            fclose($file);
        }
        
        // Convert seconds to milliseconds (0.712 s to 712 ms)
        return (float)$ping * 1000;
    }
}