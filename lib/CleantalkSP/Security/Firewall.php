<?php

namespace CleantalkSP\Security;

use CleantalkSP\Common\Helper;
use CleantalkSP\Security\Firewall\FirewallModule;
use CleantalkSP\SpbctWP\Variables\Cookie;
use CleantalkSP\Variables\Get;

/**
 * CleanTalk SpamFireWall base class.
 * Compatible with any CMS.
 *
 * @depends       \CleantalkSP\SpbctWP\Helper class
 * @depends       \CleantalkSP\SpbctWP\API class
 * @depends       \CleantalkSP\SpbctWP\DB class
 *
 * @version       4.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */
class Firewall
{
	
	public $ip_array = Array();
	
	// Database
	protected $db;
	
	//Debug
	public $debug;
	
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
	
	private $fw_modules = array();
	
	/**
	 * Creates Database driver instance.
	 *
	 * @param mixed $db database handler
	 */
	public function __construct( $db = null  ){
		
		$this->debug    = !! Get::get( 'debug' );
		$this->ip_array = $this->ip__get( 'real', true );
		
		if( isset( $db ) )
			$this->db       = $db;
	}
	
	/**
	 * Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
	 *
	 * @param string $ip_type type of IP you want to receive
	 *
	 * @return array|mixed|null
	 */
	public function ip__get( $ip_type ){
		
		$result = Helper::ip__get( $ip_type );
		
		return ! empty( $result ) ? array( 'real' => $result ) : array();
		
	}
	
	/**
	 * Loads the FireWall module to the array.
	 * For inner usage only.
	 * Not returns anything, the result is private storage of the modules.
	 *
	 * @param FirewallModule $module
	 */
	public function load_fw_module( FirewallModule $module ) {
		
		if( ! in_array( $module, $this->fw_modules ) ) {
			$module->setDb( $this->db );
			$module->ip__append_additional( $this->ip_array );
			$this->fw_modules[ $module->module_name ] = $module;
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
			
			// Check
			$module_results = $module->check();
			
			// Prioritize
			$module_result = $this->prioritize( $module_results );
			
			// Perform middle action if module require it
			if( method_exists( $module, 'middle_action') )
				$module->middle_action( $module_result );
			
			// Push to all results
			if( ! empty( $module_result ) )
				$results[ $module->module_name ] = $module_result;
			
			// Break protection logic if it whitelisted or trusted network.
			if( $this->is_whitelisted( $results ) )
				break;
			
		}

        // Get the prime result
		$result = $this->prioritize( $results );
		
		// Write log
		$this->update_log( $result );
		
		// Do finish action - die or set cookies
		// Blocked
		if( isset( $result['module'] ) ){
			if( strpos( $result['status'], 'DENY' ) !== false ){
				$this->fw_modules[ $result['module'] ]->actions_for_denied( $result );
				$this->fw_modules[ $result['module'] ]->_die( $result );
				
				// Allowed
			}else{
				$this->fw_modules[ $result['module'] ]->actions_for_passed( $result );
			}
		}
	}
	
	/**
	 * Sets priorities for firewall results.
	 * It generates one main result from multi-level results array.
	 *
	 * @param array $results
	 *
	 * @return array Single element array of result
	 */
	private function prioritize( $results ){
		
		$current_fw_result_priority = 0;
		$result = array();
		
		if( is_array( $results ) ) {
			foreach ( $results as $fw_result ) {
				$priority = array_search( $fw_result['status'], $this->statuses_priority ) + ( isset($fw_result['is_personal']) && $fw_result['is_personal'] ? count ( $this->statuses_priority ) : 0 );
				if( $priority >= $current_fw_result_priority ){
					$current_fw_result_priority = $priority;
					$result = array(
						'module'       => $fw_result['module'],
						'ip'           => $fw_result['ip'],
						'status'       => !empty( $fw_result['status'] ) ? $fw_result['status'] : 'PASS' ,
						'is_personal'  => !empty( $fw_result['is_personal'] ) ? (int)$fw_result['is_personal'] : 0,
						'country_code' => !empty( $fw_result['country_code'] ) ? $fw_result['country_code'] : '',
						'network'      => !empty( $fw_result['network'] ) ? $fw_result['network'] : 0,
						'mask'         => !empty( $fw_result['mask'] ) ? $fw_result['mask'] : 0,
						'pattern'      => !empty( $fw_result['pattern'] ) ? $fw_result['pattern'] : array(),
					);
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

		global $spbc;

		foreach ( $results as $fw_result ) {
			if (
				strpos( $fw_result['status'], 'PASS_BY_TRUSTED_NETWORK' ) !== false ||
				strpos( $fw_result['status'], 'PASS_BY_WHITELIST' ) !== false
			) {
				if( ! headers_sent() ) {
					$cookie_val = md5( $fw_result['ip'] . $spbc->spbc_key );
					Cookie::set( 'spbc_secfw_ip_wl', $cookie_val, time() + 86400 * 30, '/', null, false, true, 'Lax' );
				}
				return true;
			}
		}
		return false;
		
	}
	
	/**
	 * Use this method to handle logs updating by the module.
	 *
	 * @param array $fw_result
	 *
	 * @return void
	 */
	public function update_log( $fw_result ){}
}
