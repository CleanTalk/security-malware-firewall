<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Helpers\Helper;
use CleantalkSP\Variables\Cookie;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;
use CleantalkSP\Security\Firewall\Result;

class BFP extends \CleantalkSP\SpbctWP\Firewall\FirewallModule {
	
	public $module_name = 'BFP';
	
	protected $is_logged_in    = false;
	protected $is_login_page    = false;
	protected $bf_limit = 5; // Count of allowed wrong attempts
	protected $block_period = 3600; // Default block period for $bf_limit wrong attempts
	protected $count_period = 900; // Counting login attempts in this interval
	
	protected $chance_to_clean = 100; // Chance to clean log table from old entries. In percents.
	
	protected $api_key = false;
	
	/**
	 * FireWall_module constructor.
	 * Use this method to prepare any data for the module working.
	 *
	 * @param array $params
	 */
	public function __construct( $params = array() ){
	    
        $params['count_period'] = $params['count_period'] ?: $this->count_period;
        $params['block_period'] = $params['block_period'] ?: $this->block_period;
	    
		parent::__construct( $params );
		
	}
	
	public function check() {
		
		$results = array();
		
		if( $this->is_login_page )
			$this->clear_table();
		
		if( $this->is_login_page && ! $this->is_logged_in  ) {
			
			$time = time();
			
			foreach( $this->ip_array as $ip_origin => $current_ip ){
				$rand = rand( 1, 100000 );
				$query = "SELECT ip as blocked
				         FROM `" . SPBC_TBL_BFP_BLOCKED . "`
				         WHERE
				            ip = '$current_ip' AND
				            " . $rand . ";";
				$this->result[$current_ip] = $this->db->fetch( $query, OBJECT );
				
				if(
					isset( $this->result, $this->result[$current_ip]->blocked ) &&
					$this->result[$current_ip]->blocked != 0
				){
                    $results[] = new Result(
                        array(
                            'module'      => 'BFP',
                            'ip'          => $current_ip,
                            'status'      => 'DENY_BY_BFP',
                        )
                    );
                }
            }
		}
		
		return $results;
		
	}
	
	public function middle_action( $result = null ){
		add_action( 'spbc_log_wrong_auth',  array( $this, 'update_logs' ) );
	}
	
	public function update_logs() {
		
		foreach( $this->ip_array as $current_ip ){
			
			$interval_time = Helper::getTimeIntervalStart($this->count_period );
			
			$id = md5( $current_ip . 'bfp' );
			$result = $this->db->execute(
				"INSERT INTO " . SPBC_TBL_TC_LOG . " SET
				id = '$id',
				log_type = 1,
				ip = '$current_ip',
				entries = 1,
				interval_start = $interval_time
			ON DUPLICATE KEY UPDATE
				ip = ip,
				entries = entries + 1,
				interval_start = $interval_time;"
			);
			$rand = rand( 1, 100000 );
			$query = 'SELECT SUM(entries) as total_count
				         FROM `' . SPBC_TBL_TC_LOG . '`
				         WHERE
				            ip = \'' . $current_ip . '\' AND
				            log_type = 1 AND
				            ' . $rand . ';';
			$result = $this->db->fetch( $query, OBJECT );
			
			if( isset( $result, $result->total_count ) && $result->total_count >= $this->bf_limit ){
				$query =
					'INSERT INTO `' . SPBC_TBL_BFP_BLOCKED . '`
					SET
						id = \'' . md5( $current_ip ) . '\',
						ip = \'' . $current_ip . '\',
						start_time_of_blocking = '. time() . '
					ON DUPLICATE KEY UPDATE
						id = id,
						ip = ip,
						start_time_of_blocking = ' . time() . ';';
				$this->db->execute( $query, OBJECT );
			}
		}
		
	}
	
	private function clear_table() {
		
		if( rand( 0, 100 ) < $this->chance_to_clean ){
			
			$interval_start = Helper::getTimeIntervalStart($this->count_period );
			$result = $this->db->execute(
				'DELETE
				FROM ' . SPBC_TBL_TC_LOG . '
				WHERE
					interval_start < ' . $interval_start . ' AND
					log_type  = 1
				LIMIT 100000;'
			);
			
			foreach($this->ip_array as $current_ip){
				
				$a = time() - (int) $this->block_period;
				$result = $this->db->execute(
					'DELETE
					FROM ' . SPBC_TBL_BFP_BLOCKED . '
					WHERE
						ip = \'' . $current_ip . '\' AND
						start_time_of_blocking <= ' . $a . '
					LIMIT 10000;'
				);
				
				if( is_int( $result ) && $result > 0){
					$result = $this->db->execute(
						'DELETE
						FROM ' . SPBC_TBL_TC_LOG . '
						WHERE
							ip = \'' . $current_ip . '\'
							AND log_type  = 1;'
					);
				}
			}
		}
	}
	
	
}