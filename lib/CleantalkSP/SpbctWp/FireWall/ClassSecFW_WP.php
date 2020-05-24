<?php
/*
 * FireWall module: Security FireWall.
 * Compatible with WordPress only.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

namespace CleantalkSP\SpbctWp\FireWall;


use CleantalkSP\SpbctWp\Helper;

class ClassSecFW_WP extends FireWall_module_fw {

	/**
	 * Check every IP using FireWall data table.
	 *
	 * @return array
	 */
	public function check() {

		global $wpdb;

		$results = array();

		foreach( $this->ip_array as $ip_origin => $current_ip ) {

			$ip_type = Helper::ip__validate($current_ip);

			// IPv4 query
			if( $ip_type && $ip_type == 'v4' ){

				$current_ip_v4 = sprintf( "%u", ip2long( $current_ip ) );

				for ( $needles = array(), $m = 6; $m <= 32; $m ++ ) {
					$mask      = sprintf( "%u", ip2long( long2ip( - 1 << ( 32 - (int) $m ) ) ) );
					$needles[] = bindec( decbin( $mask ) & decbin( $current_ip_v4 ) );
				}
				$needles = array_unique( $needles );

				$query = "SELECT status, is_personal
					FROM `". SPBC_TBL_FIREWALL_DATA ."` 
					WHERE spbc_network_4 IN (". implode( ',', $needles ) .") 
					AND	spbc_network_4 = " . $current_ip_v4 . " & spbc_mask_4
					AND ipv6 = 0
					ORDER BY status DESC LIMIT 1;";

				$result = $wpdb->get_results( $query, ARRAY_A );

			}

			// IPv6 query
			if( $ip_type && $ip_type == 'v6' ){

				$current_ip_txt = explode( ':', $current_ip );
				$current_ip_1   =  hexdec( $current_ip_txt[0] . $current_ip_txt[1] );
				$current_ip_2   =  hexdec( $current_ip_txt[2] . $current_ip_txt[3] );
				$current_ip_3   =  hexdec( $current_ip_txt[4] . $current_ip_txt[5] );
				$current_ip_4   =  hexdec( $current_ip_txt[6] . $current_ip_txt[7] );

				$query = 'SELECT status, is_personal
				FROM `'. SPBC_TBL_FIREWALL_DATA ."` 
				WHERE spbc_network_1 = $current_ip_1 & spbc_mask_1
				AND   spbc_network_2 = $current_ip_2 & spbc_mask_2
				AND   spbc_network_3 = $current_ip_3 & spbc_mask_3
				AND   spbc_network_4 = $current_ip_4 & spbc_mask_4
				AND   ipv6 = 1;";

				$result = $wpdb->get_results( $query, ARRAY_A );

			}

			// In base
			if( ! empty( $result ) ) {

				foreach( $result as $entry ) {
					switch ( $entry['status'] ) {
						case 2:	 $results[] = array('ip' => $current_ip, 'is_personal' => (bool)$entry['is_personal'], 'status' => 'PASS_BY_TRUSTED_NETWORK',); break;
						case 1:	 $results[] = array('ip' => $current_ip, 'is_personal' => (bool)$entry['is_personal'], 'status' => 'PASS_BY_WHITELIST',);       break;
						case 0:	 $results[] = array('ip' => $current_ip, 'is_personal' => (bool)$entry['is_personal'], 'status' => 'DENY',);                    break;
						case -1: $results[] = array('ip' => $current_ip, 'is_personal' => (bool)$entry['is_personal'], 'status' => 'DENY_BY_NETWORK',);         break;
						case -2: $results[] = array('ip' => $current_ip, 'is_personal' => (bool)$entry['is_personal'], 'status' => 'DENY_BY_DOS',);             break;
					}
				}

			// Not in base
			}else {

				$results[] = array( 'ip' => $current_ip, 'is_personal' => false, 'status' => 'PASS' );

			}

		}

		return $results;

	}

}