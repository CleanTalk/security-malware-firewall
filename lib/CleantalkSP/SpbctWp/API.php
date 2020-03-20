<?php

namespace CleantalkSP\SpbctWp;

/**
 * Security by Cleantalk API class.
 * Extends CleantalkAPI base class.
 * Compatible only with Wordpress and Security by Cleantalk plugin.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */
class API extends \CleantalkSP\Common\API
{
	/**
	 * Function sends raw request to API server
	 *
	 * @param array   $data    to send
	 * @param string  $url     of API server
	 * @param integer $timeout timeout in seconds
	 * @param boolean $ssl     use ssl on not
	 *
	 * @return array|bool
	 */
	static public function send_request($data, $url = self::URL, $timeout = 5, $ssl = false, $ssl_path = '')
	{
		global $spbc;
		
		// Possibility to switch API url
		$url = defined('SPBC_API_URL') ? SPBC_API_URL : $url;
		
		// Adding agent version to data
		$data['agent'] = SPBC_AGENT;
		
		if($spbc->settings['use_buitin_http_api']){
			
			$args = array(
				'body' => $data,
				'timeout' => $timeout,
				'user-agent' => SPBC_AGENT.' '.get_bloginfo( 'url' ),
			);
			
			$result = wp_remote_post($url, $args);
			
			if( is_wp_error( $result ) ) {
				$errors = $result->get_error_message();
				$result = false;
			}else{
				$result = wp_remote_retrieve_body($result);
			}
			
			// Call CURL version if disabled
		}else{
			$ssl_path = $ssl_path
				? $ssl_path
				: (defined('SPBC_CASERT_PATH') ? SPBC_CASERT_PATH : '');
			$result = parent::send_request($data, $url, $timeout, $ssl, $ssl_path);
		}
		
		return empty($result) || !empty($errors)
			? array('error' => $errors)
			: $result;
	}
}