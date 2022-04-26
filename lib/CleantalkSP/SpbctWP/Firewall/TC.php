<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\Helpers\Helper;
use CleantalkSP\Security\Firewall\Result;

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
	protected $count_period = 900;
	protected $is_logged_in = false;
	
	/**
	 * FireWall_module constructor.
	 * Use this method to prepare any data for the module working.
	 *
	 * @param array $params
	 */
	public function __construct( $params = array() ){
	    
	    $params['block_period'] = $params['block_period'] ?: $this->block_period;
	    
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
				$rand = rand( 1, 100000 );
				$result = $this->db->fetch_all(
					"SELECT SUM(entries) as total_count"
					. ' FROM `' . $this->log_table . '`'
					. " WHERE
						ip = '$current_ip' AND
						interval_start < '$time' AND
						$rand;",
					OBJECT
				);
				if(!empty($result) && $result[0]->total_count >= $this->tc_limit){
                    $results[] = new Result(
                        array(
                            'module'      => 'TC',
                            'ip'          => $current_ip,
                            'status'      => 'DENY_BY_DOS',
                        )
                    );
                }
            }
		}
		
		return $results;
	}
	
	public function middle_action( $result = null ){
		
		if( ! $this->is_logged_in )
			$this->clear_table();
		
		$this->update_log();
		
	}
	
	private function update_log() {
		
		$interval_time = Helper::getTimeIntervalStart($this->store_interval );
		
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
			$interval_start = Helper::getTimeIntervalStart($this->block_period );
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