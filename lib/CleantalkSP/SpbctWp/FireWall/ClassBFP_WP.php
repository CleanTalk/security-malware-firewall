<?php
/*
 * BruteForce protection FireWall module.
 *
 * @version 1.1
 * @since 2.49
 * @see FireWall_module
 */

namespace CleantalkSP\SpbctWp\FireWall;


use CleantalkSP\SpbctWp\Helper;
use CleantalkSP\Variables\Server;

class ClassBFP_WP extends FireWall_module_tc {

	/*
	 * Results of the DB query
	 */
	private $result = array();

	/*
	 * Default wrong login count to checking brute force.
	 */
	private $bf_limit = 5;

	/*
	 * Default time interval for allowing the wrong login count.
	 */
	private $allowed_interval = 900;

	private $is_login_page;

	public function __construct() {

		parent::__construct();

		$this->is_login_page = strpos( Server::get('REQUEST_URI'), 'wp-login.php' ) !== false ;
		$this->block_period  = $this->spbc->settings['block_timer__5_fails'];

	}

	public function check() {

		global $wpdb;

		$results = array();

		if( $this->is_login_page && ! $this->was_logged_in  ) {

			$this->clear_table();

			$time = time();

			foreach( $this->ip_array as $ip_origin => $current_ip ){
				$query = "SELECT SUM(entries) as total_count 
				         FROM `" . SPBC_TBL_TC_LOG . "` 
				         WHERE ip = '$current_ip' 
				         AND log_type = 1 
				         AND interval_start < '$time';";
				$this->result[$current_ip] = $wpdb->get_row( $query, OBJECT );

				if( ! empty( $this->result ) && ! is_null( $this->result[$current_ip]->total_count ) && $this->result[$current_ip]->total_count >= $this->bf_limit ){
					$results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'DENY_BY_BFP' );
				}
			}

			if ( ! empty( $results ) ) {
				// Do block page
				return $results;
			} else {
				// Handle login actions
				add_action( 'apbct_log_wrong_auth',  array( $this, 'update_logs' ) );
			}

		}

		return $results;

	}

	public function update_logs() {

		global $wpdb;

		foreach( $this->ip_array as $ip_origin => $current_ip ){

			$interval_time = Helper::time__get_interval_start( $this->allowed_interval );

			$id = md5( $current_ip . 'bfp' );
			$wpdb->query(
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
				AND log_type  = 1 
				LIMIT 100000;'
			);
		}
	}

}