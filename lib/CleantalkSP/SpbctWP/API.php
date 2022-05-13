<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\SpbctWP\HTTP\Request;
use CleantalkSP\SpbctWP\Helpers\HTTP;

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
	const URL = 'https://api.cleantalk.org';
	
	public static function sendRequest($data, $presets = array() )
    {
        $data['agent'] = SPBC_AGENT;
        
        $request = new Request();
        $api_result = $request->setUrl(static::URL)
                              ->setData($data)
                              ->setPresets(array_merge($presets, ['retry_with_socket', 'ssl']))
                              ->addCallback(
                                  __CLASS__ . '::processResponse',
                                  [$data['method_name']]
                              )
                              ->request();
        
        //Recheck servers response time if it's time
        if( time() - (int)get_option('spbc_api_servers_last_checked') > self::API_SERVER_CHECK_PERIOD ){
        
			$api_servers = HTTP::getCleantalksAPIServersOrderedByResponseTime();
   
			// Save API servers ordered by response time
			update_option( 'spbc_api_servers_by_response_time', $api_servers, false );
			update_option( 'spbc_api_servers_last_checked',     time(),       false );
		}
	
        //Retry if error noticed
        //And we did less than maximum retries
        if( ! empty($result['error']) ){
            return self::retryRequestToFastestServers($request);
        }
	
		return $api_result;
    }
    
    /**
     * @param Request $request
     *
     * @return array|bool|mixed|string[]
     */
    private static function retryRequestToFastestServers($request)
    {
	    $api_servers = get_option('spbc_api_servers_by_response_time', array());
        if( $api_servers ){
            return ['error' => 'No API servers provided to retry'];
        }
        
        for( $retries = 0; $retries < self::RETRIES; $retries++ ){
            $api_result = $request->setUrl($api_servers[$retries]['dns'])
                                  ->request();
            if( empty($api_result['error']) ){
                return $api_result;
            }
        }
        
        return ['error' => 'Failed to retry API request'];
    }
}