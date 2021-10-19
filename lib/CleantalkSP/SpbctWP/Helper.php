<?php

namespace CleantalkSP\SpbctWP;

/**
 * CleanTalk Security Helper class
 *
 * @depends       \CleantalkSP\Common\Helper
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
	public static function http__request($url, $data = array(), $presets = null, $opts = array())
	{
		// Set SPBCT User-Agent and passing data to parent method
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
	 * @param bool $no_cache
	 *
	 * @return array|mixed|string
	 */
	public static function http__request__get_response_code( $url, $no_cache = false ){
		return static::http__request( $url, array(), 'get_code' . ( $no_cache ? ' no_cache' : '' ) );
	}
	
	/**
	 * Wrapper for http_request
	 * Requesting data via HTTP request with GET method
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function http__request__get_content( $url ){
		return static::http__request( $url, array(), 'get dont_split_to_array');
	}
    
    /**
     * Performs remote call to the current website
     *
     * @param string $rc_action
     * @param array  $request_params
     * @param array  $patterns
     * @param bool   $do_check Perform check before main remote call or not
     *
     * @return bool|string[]
     */
    public static function http__request__rc_to_host( $rc_action, $request_params, $patterns = array(), $do_check = true ){
        
        global $spbc;
        
        $request_params = array_merge( array(
            'spbc_remote_call_token'  => md5( $spbc->api_key ),
            'spbc_remote_call_action' => $rc_action,
            'plugin_name'             => 'spbc',
        ), $request_params );
        $patterns = array_merge(
            array(
                'dont_split_to_array',
            ),
            $patterns );
        
        if( $do_check ){
            $result__rc_check_website = static::http__request__rc_to_host__test( $rc_action, $request_params, $patterns );
            if( ! empty( $result__rc_check_website['error'] ) ){
                return $result__rc_check_website;
            }
        }
        
        return static::http__request(
            get_option( 'home' ),
            $request_params,
            $patterns
        );
    }
    
    /**
     * Performs test remote call to the current website
     * Expects 'OK' string as good response
     *
     * @param array $request_params
     * @param array $patterns
     *
     * @return array|bool|string
     */
    public static function http__request__rc_to_host__test( $rc_action, $request_params, $patterns = array() ){
        
        // Delete async pattern to get the result in this process
        $key = array_search( 'async', $patterns, true );
        if( $key ){
            unset( $patterns[ $key ] );
        }
        
        $result = static::http__request(
            get_option( 'home' ),
            array_merge( $request_params, array( 'test' => 'test' ) ),
            $patterns
        );
        
        // Considering empty response as error
        if( $result === '' ){
            $result = array( 'error' => 'WRONG_SITE_RESPONSE TEST ACTION : ' . $rc_action . ' ERROR: EMPTY_RESPONSE' );
            
        // Wrap and pass error
        }elseif( ! empty( $result['error'] ) ){
            $result = array( 'error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $rc_action . ' ERROR: ' . $result['error'] );
            
            // Expects 'OK' string as good response otherwise - error
        }elseif( ! preg_match( '@^.*?OK$@', $result ) ){
            $result = array(
                'error' => 'WRONG_SITE_RESPONSE ACTION: ' . $rc_action . ' RESPONSE: ' . '"' . htmlspecialchars( substr(
                        ! is_string( $result )
                            ? print_r( $result, true )
                            : $result,
                        0,
                        400
                    ) )
                           . '"'
            );
        }
        
        return $result;
    }
    
    
    /**
	 * Wrapper for http_request
	 * Requesting HTTP response code for $url
	 *
	 * @param string $url
	 *
	 * @return array|mixed|string
	 */
	public static function http__get_data_from_remote_gz( $url ){
		
		$response_code = static::http__request__get_response_code( $url );
		
		if ( $response_code === 200 ) { // Check if it's there
			
			$data = static::http__request__get_content( $url );
			
			if ( empty( $data['error'] ) ){
				
				if( static::get_mime_type( $data, 'application/x-gzip' ) ){
				
					if(function_exists('gzdecode')) {
						
						$data = gzdecode( $data );
						
						if ( $data !== false ){
							return $data;
						}else
							return array( 'error' => 'Can not unpack datafile');
						
					}else
						return array( 'error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4 ' . $data['error'] );
				}else
					return array('error' => 'WRONG_REMOTE_FILE_MIME_TYPE');
			}else
				return array( 'error' => 'Getting datafile ' . $data['error'] );
		}else
			return array( 'error' => 'Bad HTTP response from file location' );
	}
    
    /**
     * Wrapper for http_request
     * Requesting HTTP response code for $url
     *
     * @param string $path
     *
     * @return array|mixed|string
     */
    public static function get_data_from_local_gz( $path ){
        
        if ( file_exists( $path ) ) {
            
            if ( is_readable( $path ) ) {
            
                $data = file_get_contents( $path );
                
                if ( $data !== false ){
                    
                    if( static::get_mime_type( $data, 'application/x-gzip' ) ){
                        
                        if( function_exists('gzdecode') ) {
                            
                            $data = gzdecode( $data );
                            
                            if ( $data !== false ){
                                return $data;
                            }else
                                return array( 'error' => 'Can not unpack datafile');
                            
                        }else
                            return array( 'error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4 ' . $data['error'] );
                    }else
                        return array('error' => 'WRONG_REMOTE_FILE_MIME_TYPE');
                }else
                    return array( 'error' => 'Couldn\'t get data' );
            }else
                return array( 'error' => 'File is not readable: ' . $path );
        }else
            return array( 'error' => 'File doesn\'t exists: ' . $path );
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
