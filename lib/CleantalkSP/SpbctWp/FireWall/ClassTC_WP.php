<?php
/*
 * Traffic Control FireWall module.
 * Compatible with WP only.
 *
 * @version 1.1
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

namespace CleantalkSP\SpbctWp\FireWall;


use CleantalkSP\SpbctWp\Helper;

class ClassTC_WP extends FireWall_module_tc {

	private $store_interval = 300;

	/**
	 * Use this method to execute main logic of the module.
	 * @return array
	 */
	public function check() {

		global $wpdb;

		$results = array();

		if( ! $this->was_logged_in ) {

			$this->clear_table();

			$time = time();

			foreach($this->ip_array as $ip_origin => $current_ip){
				$result = $wpdb->get_results(
					"SELECT SUM(entries) as total_count"
					. ' FROM `' . SPBC_TBL_TC_LOG . '`'
					. " WHERE ip = '$current_ip' AND interval_start < '$time';",
					OBJECT
				);
				if(!empty($result) && $result[0]->total_count >= $this->tc_limit){
					$results[] = array('ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_BY_DOS',);
				}
			}
		}

		if ( ! empty( $results ) ) {
			// Do block page
			return $results;
		} else {
			// Do logging entries
			$this->update_logs();
		}

		return $results;

	}

	private function update_logs() {

		global $wpdb;

		$interval_time = Helper::time__get_interval_start( $this->store_interval );

		foreach( $this->ip_array as $ip_origin => $current_ip ){
			$id = md5( $current_ip . $interval_time );
			$wpdb->query(
				"INSERT INTO " . SPBC_TBL_TC_LOG . " SET
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

		global $wpdb;

		if( rand( 0, 1000 ) < $this->chance_to_clean ){
			$interval_start = Helper::time__get_interval_start( $this->block_period );
			$wpdb->query(
				'DELETE
				FROM ' . SPBC_TBL_TC_LOG . '
				WHERE interval_start < '. $interval_start .' 
				AND log_type  = 0 
				LIMIT 100000;'
			);
		}
	}

}