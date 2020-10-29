<?php
/**
 * CleanTalk Security FireWall database actions handler interface.
 * Compatible with WordPress only.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since        2.49
 */

namespace CleantalkSP\SpbctWp\FireWall;


class FireWall_database implements \CleantalkSP\Security\FireWall\FireWall_database {

	private $db;

	private $db_error = '';

	public function __construct() {

		global $wpdb;
		$this->db = $wpdb;

	}

	public function fw_clear_table() {
		
		// Clear personal tables
		$this->db->query('TRUNCATE TABLE `'. SPBC_TBL_FIREWALL_DATA__IPS .'`;');
		$this->db->query('TRUNCATE TABLE `'. SPBC_TBL_FIREWALL_DATA__COUNTRIES .'`;');
		
		// Clean common table from unused countries
		// Get all personal country tables
		$res = $this->db->get_results('SHOW TABLES LIKE "%spbc_firewall__personal_countries%"', ARRAY_A);
		
		// Get all countries for all blogs
		foreach( $res as $tbl )
			$sql[] = '(SELECT country_code FROM ' . current( $tbl ) . ')';
		$res = $this->db->get_results( implode( ' UNION ', $sql ), ARRAY_A );
		
		// Delete all IP/mask for every other countries no in list
		$in[] = "'0'";
		foreach( $res as $country_code )
			$in[] = "'".current( $country_code )."'";
		$this->db->query( 'DELETE FROM ' . 'wp_spbc_firewall_data' . ' WHERE country_code NOT IN (' . implode( ',', $in ) . ')');
		

	}

	public function fw_insert_data( $query ) {
		
		$result = $this->db->query( $query );
		
		if ( $result ) {
			return $result;
		} else {
			$this->error = $this->db->last_error;
			return false;
		}

	}

	public function fw_logs_clear_table() {

		$this->db->query('TRUNCATE TABLE `'. SPBC_TBL_FIREWALL_LOG .'`;');

	}

	public function fw_logs_insert_data( $log_item ) {

		$id              = $log_item['id'];
		$ip              = $log_item['ip'];
		$time            = $log_item['time'];
		$status          = $log_item['status'];
		$pattern         = $log_item['pattern'];
		$page_url        = $log_item['page_url'];
		$http_user_agent = $log_item['http_user_agent'];
		$request_method  = $log_item['request_method'];
		$x_forwarded_for = $log_item['x_forwarded_for'];

		$this->db->query(
			"INSERT INTO ". SPBC_TBL_FIREWALL_LOG ." SET
				entry_id = '$id',
				ip_entry = '$ip',
				entry_timestamp = $time,
				status = '$status',
				pattern = IF('$pattern' = '', NULL, '$pattern'),
				requests = 1,
				page_url = '$page_url',
				http_user_agent = '$http_user_agent',
				request_method = '$request_method',
				x_forwarded_for = IF('$x_forwarded_for' = '', NULL, '$x_forwarded_for')
			ON DUPLICATE KEY UPDATE
				ip_entry = ip_entry,
				entry_timestamp = $time,
				status = '$status',
				pattern = IF('$pattern' = '', NULL, '$pattern'),
				requests = requests + 1,
				page_url = '$page_url',
				http_user_agent = http_user_agent,
				request_method = '$request_method',
				x_forwarded_for = IF('$x_forwarded_for' = '', NULL, '$x_forwarded_for')"
		);

	}

	public function fw_get_logs() {

		return $this->db->get_results("SELECT * FROM `". SPBC_TBL_FIREWALL_LOG ."` LIMIT ".SPBC_SELECT_LIMIT, ARRAY_A);

	}

	public function get_last_error() {

		return $this->db_error;

	}

}