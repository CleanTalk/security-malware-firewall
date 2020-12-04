<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWp\API;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Helper;
use CleantalkSP\Variables\Cookie;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;

class TC extends \CleantalkSP\SpbctWP\Firewall\FirewallModule {
	
	public $module_name = 'TC';
	
	// Table names
	public $data_table = '';
	public $log_table = '';
	
	// Additional params
	protected $api_key = false;
	protected $set_cookies = false;
	
	// Default params
	protected $store_interval = 300;
	protected $chance_to_clean = 100;
	protected $tc_limit = 1000;
	protected $block_period = 3600;
	protected $is_logged_in = false;
	
	/**
	 * FireWall_module constructor.
	 * Use this method to prepare any data for the module working.
	 *
	 * @param array $params
	 */
	public function __construct( $params = array() ){
		
		parent::__construct( $params );
		
	}
	
	/**
	 * Use this method to execute main logic of the module.
	 * @return array
	 */
	public function check(){
		
		$results = array();
		
		if( ! $this->is_logged_in ) {
			
			$this->clear_table();
			
			$time = time();
			
			foreach($this->ip_array as $ip_origin => $current_ip){
				$result = $this->db->fetch_all(
					"SELECT SUM(entries) as total_count"
					. ' FROM `' . $this->data_table . '`'
					. " WHERE ip = '$current_ip' AND interval_start < '$time';",
					OBJECT
				);
				if(!empty($result) && $result[0]->total_count >= $this->tc_limit){
					$results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_BY_DOS',);
				}
			}
		}
		
		return $results;
		
	}
	
	public function middle_action( $result ){
		
		if( ! $this->is_logged_in )
			$this->clear_table();
		
		$this->update_log();
		
	}
	
	private function update_log() {
		
		$interval_time = Helper::time__get_interval_start( $this->store_interval );
		
		foreach( $this->ip_array as $ip_origin => $current_ip ){
			$id = md5( $current_ip . $interval_time );
			$this->db->execute(
				"INSERT INTO " . $this->log_table . " SET
					id = '$id',
					log_type = 0,
					ip = '$current_ip',
					entries = 1,
					interval_start = $interval_time
				ON DUPLICATE KEY UPDATE
					ip = ip,
					entries = entries + 1,
					interval_start = $interval_time;"
			);
		}
		
	}
	
	private function clear_table() {
		
		if( rand( 0, 1000 ) < $this->chance_to_clean ){
			$interval_start = Helper::time__get_interval_start( $this->block_period );
			$this->db->execute(
				'DELETE
				FROM ' . $this->log_table . '
				WHERE interval_start < '. $interval_start .'
				AND log_type  = 0
				LIMIT 100000;'
			);
		}
	}
}