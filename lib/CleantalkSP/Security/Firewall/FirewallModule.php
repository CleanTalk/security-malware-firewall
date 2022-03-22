<?php

namespace CleantalkSP\Security\Firewall;

/*
 * The abstract class for any FireWall modules.
 * Compatible with any CMS.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\State;

class FirewallModule extends FirewallModule_abstract {
	
	public $module_name;
	
	/**
	 * @var DB
	 */
	protected $db;
	protected $data_table;
	protected $log_table;
	
    /**
     * @var State
     */
	protected $state = array();
	
	protected $service_id;
	
	protected $result_code = '';
	
	protected $ip_array = array();
	
	protected $test_ip;
	
	protected $die_page__file;
	
	/**
	 * FireWall_module constructor.
	 * Use this method to prepare any data for the module working.
	 *
	 * @param array $params
	 */
	public function __construct( $params = array() ){
		
		foreach( $params as $param_name => $param ){
			$this->$param_name = isset( $this->$param_name ) ? $param : false;
		}
		
	}
	
	public function ip__append_additional( &$ips ){}
	
	/**
	 * Use this method to execute main logic of the module.
	 *
	 * @return array  Array of the check results
	 */
	public function check(){}
	
	public function actions_for_denied( $result ){}
	
	public function actions_for_passed( $result ){}
	
	/**
	 * @param mixed $db
	 */
	public function setDb( $db ) {
		$this->db = $db;
	}
	
	/**
	 * @param array $ip_array
	 */
	public function setIpArray( $ip_array ) {
		$this->ip_array = $ip_array;
	}
 
	/**
	 * Add no-cache headers
	 *
     * @param Result $result
	 */
	public function _die( Result $result ){
		
		// Headers
		if(headers_sent() === false){
			header('Expires: '.date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
			header('Cache-Control: no-store, no-cache, must-revalidate');
			header('Cache-Control: post-check=0, pre-check=0', FALSE);
			header('Pragma: no-cache');
			header("HTTP/1.0 403 Forbidden");
		}
		
	}
}