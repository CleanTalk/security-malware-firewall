<?php

namespace CleantalkSP\Security;

use CleantalkSP\Common\Helper;
use CleantalkSP\Security\Firewall\FirewallModule;
use CleantalkSP\SpbctWP\Variables\Cookie;
use CleantalkSP\Variables\Get;
use CleantalkSP\Security\Firewall\Result;
use CleantalkSP\SpbctWP\Helpers\IP;

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
		'DENY_BY_SEC_FW',
		'DENY_BY_SPAM_FW',
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
		
        $this->debug    = (bool)Get::get( 'debug' );
		$this->ip_array = $this->ip__get( 'real' );
		
        if( isset( $db ) ){
            $this->db = $db;
        }
	}
	
	/**
	 * Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
	 *
	 * @param string $ip_type type of IP you want to receive
	 *
	 * @return array|mixed|null
	 */
	public function ip__get( $ip_type ){
		
		$result = IP::get( $ip_type );
		
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
		
        if( ! in_array($module, $this->fw_modules, true) ) {
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
		
		// Check requests by all enabled modules
		foreach ( $this->fw_modules as $module ) {
			
			// Perform module check
			$module_results = $module->check();
			
			// Reduce module results to one
            $results[ $module->module_name ] = $this->reduceFirewallResultsByPriority($module_results);
            
			// Perform middle action if module provide it
            if( method_exists( $module, 'middle_action') ){
                $module->middle_action( $results[ $module->module_name ] );
            }
			
			// Don't use other modules if the IP is whitelisted
            if( $this->is_whitelisted( $results ) ){
				break;
            }
		}
		
        // Reduce all modules results to one
		$result = $this->reduceFirewallResultsByPriority( $results );

		// Write log
		$this->update_log( $result );
		
		// Do finish action - die or set cookies
        if( isset( $result->module ) ){
        
		    // Blocked
            if( strpos( $result->status, 'DENY' ) !== false ){
                $this->fw_modules[ $result->module ]->actions_for_denied( $result );
                $this->fw_modules[ $result->module ]->_die( $result );
				
            // Allowed
			}else{
                $this->fw_modules[ $result->module ]->actions_for_passed( $result );
			}
		}
	}
	
	/**
	 * Sets priorities for firewall results.
	 * It generates one main result from multi-level results array.
	 *
	 * @param Result[] $firewall_results
	 *
     * @return Result Single element array of result
	 */
    private function reduceFirewallResultsByPriority(array $firewall_results)
    {
		$priority_final         = 0;
		$firewall_result__final = new Result(
            array(
                'module' => 'FW',
                'ip'     => end($this->ip_array),
                'status' => 'PASS',
            )
        );
			
        foreach ( $firewall_results as $firewall_result__current ) {
            
            // Pick the result with the smallest network. Don't count priority if fires.
            if(
                ! empty($firewall_result__current->mask) && ! empty($firewall_result__final->mask) && // The mask are not empty
                $firewall_result__current->mask !== $firewall_result__final->mask &&                  // The masks are not equal
                $firewall_result__current->mask > $firewall_result__final->mask
            ){
                $firewall_result__final = $firewall_result__current;
                continue;
            }
            
            $priority_current = $this->calculatePriorityForFirewallResult($firewall_result__current);
            
            if( $priority_current >= $priority_final ){
                $priority_final         = $priority_current;
                $firewall_result__final = $firewall_result__current;
            }
        }
		
		return $firewall_result__final;
	}
    
    /**
     * Calculates the priority of the passed Firewall Result
     *
     * @param Result $firewall_result
     *
     * @return int
     */
	private function calculatePriorityForFirewallResult( Result $firewall_result )
    {
        $point_for_status           = array_search($firewall_result->status, $this->statuses_priority, true);
        $points_for_personal_list   = $firewall_result->is_personal                          ? 13  : 0;
        $points_for_trusted_network = $firewall_result->status === 'PASS_BY_TRUSTED_NETWORK' ? 100 : 0;
        
        return
            $point_for_status +
            $points_for_personal_list +
            $points_for_trusted_network;
    }
	
	/**
	 * Check the result if it whitelisted or trusted network
	 *
     * @param Result[] $results
	 *
	 * @return bool
	 */
	private function is_whitelisted( $results ) {

		global $spbc;

		foreach ( $results as $fw_result ) {
			if (
                strpos( $fw_result->status, 'PASS_BY_TRUSTED_NETWORK' ) !== false ||
                strpos( $fw_result->status, 'PASS_BY_WHITELIST' ) !== false
			) {
				if( ! headers_sent() ) {
                    $cookie_val = md5( $fw_result->ip . $spbc->spbc_key );
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
     * @param Result $fw_result
	 *
	 * @return void
	 */
	public function update_log( Result $fw_result ){}
}
