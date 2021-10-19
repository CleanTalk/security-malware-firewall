<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Helper;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;

class FW extends FirewallModule{
	
	public $module_name = 'FW';
	
	public $data_table__common = '';
	public $data_table__personal = '';
	public $data_table__personal_countries = '';
	
	/**
	 * @var bool
	 */
	protected $test;
	
	// Additional params
	protected $api_key = false;
	protected $set_cookies = false;
	
	protected $real_ip;
	protected $debug;
	
	/**
	 * @param $ips
	 */
	public function ip__append_additional( &$ips ){
		
		$this->real_ip = isset( $ips['real'] ) ? $ips['real'] : null;
		
		$test_ip = Get::get('spbct_test_ip');
		if( Get::get('spbct_test') === md5( $this->api_key ) && Helper::ip__validate( $test_ip ) ){
			$ips = array( 'test' => $test_ip );
			$this->test_ip = $test_ip;
			$this->test    = true;
		}
	}
	
	/**
	 * Check every IP using FireWall data table.
	 *
	 * @return array
	 */
	public function check() {
		
		$results = array();
		
		foreach( $this->ip_array as $ip_origin => $current_ip ) {
				
			$current_ipv4s = Helper::ip__v6_to_v4( Helper::ip__v6_extend( Helper::ip__v6_normalize( $current_ip ) ) );
			
			foreach( $current_ipv4s as $key => $current_ipv4 ){
				$needles[ $key ] = implode(
					',',
					array_unique( Helper::ip__calculate_masked_ip_mass( $current_ipv4, 6, 32 ) )
				);
			}
			
			$query = '(
				SELECT 0 AS is_personal, 1 AS is_ip, status, country_code, network1, network2, network3, network4, mask1, mask2, mask3, mask4
				FROM ' . $this->data_table__common . '
				WHERE
					    network1 IN (' . $needles[0] . ')
					AND network2 IN (' . $needles[1] . ')
					AND network3 IN (' . $needles[2] . ')
					AND network4 IN (' . $needles[3] . ')
					AND network1 = ' . $current_ipv4s[0] . ' & mask1
					AND network2 = ' . $current_ipv4s[1] . ' & mask2
					AND network3 = ' . $current_ipv4s[2] . ' & mask3
					AND network4 = ' . $current_ipv4s[3] . ' & mask4
					AND country_code = "0"
			) UNION (
				SELECT 1 AS is_personal, 1 AS is_ip, status, 0 AS country_code, network1, network2, network3, network4, mask1, mask2, mask3, mask4
				FROM ' . $this->data_table__personal . '
				WHERE
					    network1 IN (' . $needles[0] . ')
					AND network2 IN (' . $needles[1] . ')
					AND network3 IN (' . $needles[2] . ')
					AND network4 IN (' . $needles[3] . ')
					AND network1 = ' . $current_ipv4s[0] . ' & mask1
					AND network2 = ' . $current_ipv4s[1] . ' & mask2
					AND network3 = ' . $current_ipv4s[2] . ' & mask3
					AND network4 = ' . $current_ipv4s[3] . ' & mask4
			) UNION (
				SELECT 1 AS is_personal, 0 AS is_ip, tbl_private.status, country_code, network1, network2, network3, network4, mask1, mask2, mask3, mask4
				FROM ' . $this->data_table__personal_countries . ' AS tbl_private
				RIGHT JOIN ' . $this->data_table__common . ' AS tbl_common USING(country_code)
				WHERE
					    network1 IN (' . $needles[0] . ')
					AND network2 IN (' . $needles[1] . ')
					AND network3 IN (' . $needles[2] . ')
					AND network4 IN (' . $needles[3] . ')
					AND network1 = ' . $current_ipv4s[0] . ' & mask1
					AND network2 = ' . $current_ipv4s[1] . ' & mask2
					AND network3 = ' . $current_ipv4s[2] . ' & mask3
					AND network4 = ' . $current_ipv4s[3] . ' & mask4
					AND tbl_private.status IS NOT NULL
					AND ' . rand( 1, 100000 ) . ' <> 0
			)';
			
			$db_results = $this->db->fetch_all( $query, ARRAY_A );
			
			// In base
			if( ! empty( $db_results ) ) {
				
				foreach( $db_results as $entry ) {
					
					$result_entry = array(
						'module' => $this->module_name,
						'ip' => $current_ip,
						'is_personal' => (int)$entry['is_personal'],
						'country_code' => $entry['country_code'],
						'network' => $entry['network4'],
						'mask' => $entry['mask4'],
					);
					
					switch ( $entry['status'] ) {
						case 2:	 $result_entry = array_merge( $result_entry, array('status' => 'PASS_BY_TRUSTED_NETWORK', ) ); break;
						case 1:	 $result_entry = array_merge( $result_entry, array('status' => 'PASS_BY_WHITELIST', ) );       break;
						case 0:	 $result_entry = array_merge( $result_entry, array('status' => 'DENY', ) );                    break;
						case -1: $result_entry = array_merge( $result_entry, array('status' => 'DENY_BY_NETWORK', ) );         break;
						case -2: $result_entry = array_merge( $result_entry, array('status' => 'DENY_BY_DOS', ) );             break;
						case -3: $result_entry = array_merge( $result_entry, array('status' => 'DENY_BY_SEC_FW', ) );          break;
						case -4: $result_entry = array_merge( $result_entry, array('status' => 'DENY_BY_SPAM_FW', ) );         break;
					}
					
					$results[] = $result_entry;
				}
			}
		}
		
		if( empty ( $results ) ){
			if (isset( $this->ip_array['test'] )) {
				$ip = $this->ip_array['test'];
			} elseif ( isset( $this->ip_array['real'] ) ) {
				$ip = $this->ip_array['real'];
			} else {
				$ip = null;
			}
			$results[ 'real' ] = array(
				'module' => $this->module_name,
				'ip' => $ip,
				'is_personal' => false,
				'country_code' => null,
				'network' => null,
				'mask' => null,
				'status' => 'PASS',
			);
		}
		
		return $results;
		
	}
	
	/**
	 * Sends and wipe SFW log
	 *
	 * @param $db
	 * @param $log_table
	 * @param string $ct_key API key
	 *
	 * @return array|bool array('error' => STRING)
	 */
	public static function send_log( $db, $log_table, $ct_key ) {
		
		//Getting logs
		$query = 'SELECT * FROM ' . $log_table . ' LIMIT ' . SPBC_SELECT_LIMIT . ';';
		$db->fetch_all( $query );
		
		if( count( $db->result ) ){
			
			//Compile logs
			$data = array();
			foreach ( $db->result as $key => $value ) {
				
				//Compile log
				$to_data = array(
					'datetime'         => date( 'Y-m-d H:i:s', $value['entry_timestamp'] ),
					'page_url'         => $value['page_url'],
					'visitor_ip'       => Helper::ip__validate( $value['ip_entry'] ) === 'v4' ? (int) sprintf( '%u', ip2long( $value['ip_entry'] ) ) : (string) $value['ip_entry'],
					'http_user_agent'  => $value['http_user_agent'],
					'request_method'   => $value['request_method'],
					'x_forwarded_for'  => $value['x_forwarded_for'],
					'matched_networks' => $value['network'] ? $value['network'] . '/' . $value['mask'] : NULL,
					'matched_country'  => $value['country_code'],
					'is_personal'      => $value['is_personal'],
					'hits'             => (int) $value['requests'],
                    'datetime_gmt'     => $value['entry_timestamp'],
				);
				
				// Legacy
				switch($value['status']){
					case 'PASS_BY_TRUSTED_NETWORK': $to_data['status_efw'] = 3;  break;
					case 'PASS_BY_WHITELIST':       $to_data['status_efw'] = 2;  break;
					case 'PASS':                    $to_data['status_efw'] = 1;  break;
					case 'DENY':                    $to_data['status_efw'] = 0;  break;
					case 'DENY_BY_NETWORK':         $to_data['status_efw'] = -1; break;
					case 'DENY_BY_DOS':             $to_data['status_efw'] = -2; break;
					case 'DENY_BY_WAF_XSS':         $to_data['status_efw'] = -3; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_SQL':         $to_data['status_efw'] = -4; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_FILE':        $to_data['status_efw'] = -5; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_EXPLOIT':     $to_data['status_efw'] = -6; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_BFP':             $to_data['status_efw'] = -7; break;
					case 'DENY_BY_SEC_FW':          $to_data['status_efw'] = -8; break;
					case 'DENY_BY_SPAM_FW':         $to_data['status_efw'] = -9; break;
				}
				
				switch($value['status']){
					case 'PASS_BY_TRUSTED_NETWORK': $to_data['status'] = 3;  break;
					case 'PASS_BY_WHITELIST':       $to_data['status'] = 2;  break;
					case 'PASS':                    $to_data['status'] = 1;  break;
					case 'DENY':                    $to_data['status'] = 0;  break;
					case 'DENY_BY_NETWORK':         $to_data['status'] = -1; break;
					case 'DENY_BY_DOS':             $to_data['status'] = -2; break;
					case 'DENY_BY_WAF_XSS':         $to_data['status'] = -3; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_SQL':         $to_data['status'] = -4; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_FILE':        $to_data['status'] = -5; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_WAF_EXPLOIT':     $to_data['status'] = -6; $to_data['waf_comment'] = $value['pattern']; break;
					case 'DENY_BY_BFP':             $to_data['status'] = -7; break;
					case 'DENY_BY_SEC_FW':          $to_data['status'] = -8; break;
					case 'DENY_BY_SPAM_FW':         $to_data['status'] = -9; break;
				}
				
				$data[] = $to_data;
				
			} unset($key, $value, $result, $to_data);
            
			//Sending the request
			$result = API::method__security_logs__sendFWData( $ct_key, $data );
			
			//Checking answer and deleting all lines from the table
			if( empty( $result['error'] ) ){
				
				if( $result['rows'] == count( $data ) ){
					$db->execute( "TRUNCATE TABLE " . $log_table . ";" );
					return count($data);
				}else
					return array( 'error' => 'SENT_AND_RECEIVED_LOGS_COUNT_DOESNT_MACH' );
			}else
				return $result;
		}else
			return array( 'error' => 'NO_LOGS_TO_SEND' );
	}
	
	/**
	 * Gets multifile with data to update Firewall.
	 *
	 * @param string $spbc_key
	 *
	 * @return array
	 */
	public static function firewall_update__get_multifiles( $spbc_key ){
		
		// Getting remote file name
		$result = API::method__security_firewall_data_file( $spbc_key, 'multifiles' );
		
		if(empty($result['error'])){
			
			if( ! empty($result['file_url']) ){
				
				$data = Helper::http__get_data_from_remote_gz( $result['file_url'] );
				
				if( empty( $data['error'] ) ){
					return array(
						'multifile_url' => $result['file_url'],
						'file_urls'     => array_column( Helper::buffer__parse__csv($data), 0 ),
					);
				}else
					return array( 'error' => 'FW. Get multifile. ' . $data['error'] );
			}else
				return array('error' => 'FW. Get multifile. BAD_RESPONSE');
		}else
			return $result;
	}
	
	/**
	 * Writes entries from remote files to Firewall database.
	 *
	 * @param DB $db database handler
	 * @param string $data_table__common Table name with common data
	 * @param string $data_table__personal Table name with personal IPs
	 * @param string $data_table__personal_countries Table name with with personal country list
	 * @param string $file_url
	 *
	 * @return array|bool|int|mixed|string
	 */
	public static function update__write_to_db( $db, $data_table__common, $data_table__personal, $data_table__personal_countries, $file_url ){
		
		$data = Helper::get_data_from_local_gz( $file_url );
		
		if( empty( $data['error'] ) ){
			
			$inserted = 0;
			while( $data !== '' ){
				
				for(
					$i = 0, $sql__common = array(), $sql__personal_ip = array();
					$i < SPBC_WRITE_LIMIT && $data !== '';
					$i++
				){
					
					$entry = Helper::buffer__csv__pop_line_to_array( $data );
					
					// Skipping bad data
                    if( empty( $entry[0] )  || empty ($entry[1] ) ){
                        continue;
                    }
                    
                    // IP processing
					// IPv4
                    if( is_numeric( $entry[0] ) ){
	                    $networks = array( 0, 0, 0, $entry[0] );
                    //IPv6
                    }else{
						$networks = Helper::ip__v6_to_v4( Helper::ip__v6_extend( Helper::ip__v6_normalize( $entry[0] ) ) );
                    }
                    
                    // Versatility for mask for v6 and v4
					for ( $masks = array(), $mask = $entry[1], $k = 4; $k >= 1; $k-- ) {
						$masks[ $k ] = ( 2 ** 32 ) - ( 2 ** ( 32 - ( $mask > 32 ? 32 : $mask ) ) );
						$mask -= 32;
						$mask = $mask > 0 ? $mask : 0;
					}
					
					// $comment = $entry[2]; // Comment from user
					$status      = isset( $entry[3] ) ? $entry[3] : 0;
					$is_personal = isset( $entry[4] ) ? (int) $entry[4] : 0;
					$country     = isset( $entry[5] ) ? trim( $entry[5], '"' ) : 0;
					
					// IPv4
					if ( is_numeric( $networks[0] ) && is_numeric( $networks[1] ) && is_numeric( $networks[2] ) && is_numeric( $networks[3] ) ) {
						
						$mask = sprintf(
							'%u',
							bindec( str_pad( str_repeat( '1', $mask ), 32, 0, STR_PAD_RIGHT ) )
						);
						
						if( $country || ! $is_personal ) {
							$unique = md5( implode( '', $networks ) . $mask . $country );
							$sql__common[] = "('$unique', $networks[0], $networks[1], $networks[2], $networks[3], $masks[1], $masks[2], $masks[3], $masks[4], $status, '$country')";
						}
						if( $is_personal && $country )
							$sql__personal_country[] = "('$country',$status)";
						
						if( $is_personal && ! $country )
							$sql__personal_ip[] = "($networks[0], $networks[1], $networks[2], $networks[3], $masks[1], $masks[2], $masks[3], $masks[4], $status)";
						
					}
				}
				
				// Insertion to common table
				$sql_result__common___result = $db->execute(
					'INSERT INTO ' . $data_table__common
					. ' (id, network1, network2, network3, network4, mask1, mask2, mask3, mask4, status, country_code) '
					. ' VALUES '
					. implode( ',', $sql__common)
					. ' ON DUPLICATE KEY UPDATE'
					. ' network1=network1'
					. ';'
				);
				
				if( $sql_result__common___result === false ){
					return array( 'error' => 'COULD_NOT_WRITE_TO_DB 1: ' . $db->get_last_error() );
				}
				// Replacing result counter because SQL result won't count all contained entries
				$sql_result__common___result = count( $sql__common );
				
				$sql_result__personal___result = 0;
				// Insertion to personal IPs table
				if( ! empty( $sql__personal_ip ) ) {
					$sql_result__personal___result = $db->execute(
						'INSERT INTO ' . $data_table__personal . ' (network1,network2,network3,network4,mask1,mask2,mask3,mask4,status) VALUES '
						. implode( ',', $sql__personal_ip ) . ';'
					);
					unset( $sql__personal_ip );
					if ( $sql_result__personal___result === false )
						return array( 'error' => 'COULD_NOT_WRITE_TO_DB 2: ' . $db->get_last_error() );
				}
				
				$sql_result__country___result = 0;
				// Insertion to personal countries table
				if( ! empty( $sql__personal_country ) ){
					$sql__personal_country = array_unique( $sql__personal_country ); // Filtering duplicate entries
					$sql_result__country___result = $db->execute(
						'INSERT INTO ' . $data_table__personal_countries . '(country_code,status) VALUES '
						. implode( ',', $sql__personal_country) . ';'
					);
					unset( $sql__personal_country );
					if( $sql_result__country___result === false )
						return array( 'error' => 'COULD_NOT_WRITE_TO_DB 3: ' . $db->get_last_error() );
				}
				
				$inserted += ( $sql_result__common___result + $sql_result__personal___result );
			}
			
            if( ! is_int( $inserted ) ){
                return array( 'error' => 'WRONG RESPONSE FROM update__write_to_db' );
            }
            
            return $inserted;
		}else
			return $data;
	}
    
    /**
     * Adding local exclusions to to the FireWall database.
     *
     * @param DB     $db                        database handler
     * @param string $db__table__data__personal table name with personal IPs
     * @param string $db__table__data__common   table name with common IPs
     * @param array  $exclusions
     *
     * @return array|bool|int|mixed|string
     */
	public static function update__write_to_db__exclusions( $db, $db__table__data__personal, $db__table__data__common, $exclusions = array() ){
		
		$query = 'INSERT INTO `' . $db__table__data__personal . '`  (network1,network2,network3,network4,mask1,mask2,mask3,mask4,status) VALUES ';
		
		//Exclusion for servers IP (SERVER_ADDR)
		if ( Server::get('HTTP_HOST') ) {
			
			// Exceptions for local hosts
			if( ! in_array( Server::get_domain(), array( 'lc', 'loc', 'lh' ) ) ){
				$exclusions[] = Helper::dns__resolve( Server::get( 'HTTP_HOST' ) );
				$exclusions[] = '127.0.0.1';
            
            // And delete all 127.0.0.1 entries for local hosts
            // From both tables personal and common
			}else{
                $db->execute( 'DELETE FROM ' . $db__table__data__personal . ' WHERE network4 = ' . ip2long( '127.0.0.1') . ';');
                $db->execute( 'DELETE FROM ' . $db__table__data__common . ' WHERE network4 = ' . ip2long( '127.0.0.1') . ';');
            }
		}
		
		foreach ( $exclusions as $exclusion ) {
			
			if ( Helper::ip__validate( $exclusion ) && sprintf( '%u', ip2long( $exclusion ) ) ) {
				
				$networks = Helper::ip__v6_to_v4( Helper::ip__v6_extend( Helper::ip__v6_normalize( $exclusion ) ) );
				
				for( $masks = array(), $mask = 128, $k = 4; $k >= 1; $k-- ){
					$masks[ $k ] = ( 2 ** 32 ) - ( 2 ** ( 32 - ( $mask > 32 ? 32 : $mask ) ) );
					$mask -= 32;
					$mask = $mask > 0 ? $mask : 0;
				}
				
				$query .= "( $networks[0], $networks[1], $networks[2], $networks[3], $masks[1], $masks[2], $masks[3], $masks[4] , 2),";
			}
		}
		
		if( $exclusions ){
			
			$sql_result = $db->execute( substr( $query, 0, - 1 ) . ';' );
			
			return $sql_result === false
				? array( 'error' => 'COULD_NOT_WRITE_TO_DB 4: ' . $db->get_last_error() )
				: count( $exclusions );
		}
		
		return 0;
		
	}
    
    /**
     * Creates temporary tables for update
     *
     * @param DB $db database handler
     * @param array $table_names Array with table names to create
     *
     * @return bool|array
     */
	public static function data_tables__createTemporaryTablesForTables( $db, $table_names ){
        
        // Cast it to array for simple input
        $table_names = (array) $table_names;
	    
		foreach( $table_names as $table_name ){
		 
			$table_name__temp = $table_name . '_temp';
			
			if( ! $db->execute( 'CREATE TABLE IF NOT EXISTS `'. $table_name__temp .'` LIKE  `'. $table_name .'`; ' ) )
                return array( 'error' => 'CREATE TABLES: COULD NOT CREATE ' . $table_name__temp );
			
			if( ! $db->execute( 'TRUNCATE `'. $table_name__temp .'`; ' ) )
                return array( 'error' => 'CREATE TABLES: COULD NOT TRUNCATE ' . $table_name__temp );
		}
		
		return true;
	}
	
	/**
	 * Copying data from permanent table to temporary
	 * Deletes all common entries from temporary table
	 *
	 * @param DB $db database handler
	 * @param string $data_table__common Table name with common data
	 */
	public static function data_tables__copyCountiesDataFromMainTable( $db, $data_table__common ){
	 
		$data_table__common__temp = $data_table__common . '_temp';
		
		// Copying data
        $offset = 0;
		do{
            $sql = 'INSERT `'. $data_table__common__temp .'` ( SELECT * FROM `'. $data_table__common .'` WHERE `country_code` <> "0" LIMIT ' . $offset . ',' . SPBC_WRITE_LIMIT . ');';
            $res = $db->execute( $sql );
            if( $res === false ){
                return array( 'error' => 'COPYING DATA: ' . substr( $sql, 0, 6 ) );
            }
            $offset += SPBC_WRITE_LIMIT;
        }while( $db->getRowsAffected() === SPBC_WRITE_LIMIT );
		
        // Deleting
        if( $db->execute( 'DELETE FROM `'. $data_table__common__temp .'` WHERE `country_code` <> "0"' ) === false ){
            return array( 'error' => 'COPYING DATA: ' . substr( $sql, 0, 6 ) );
        }
        
        return true;
	}
	
	/**
	 * Delete tables with given names if they exists
	 *
	 * @param DB $db
	 * @param array $table_names Array with table names to delete
     *
     * @return bool|array
	 */
	public static function data_tables__delete( $db, $table_names ){
        
        // Cast it to array for simple input
        $table_names = (array) $table_names;
        
		foreach( $table_names as $table_name ){
            if( $db->isTableExists( $table_name ) && ! $db->execute( 'DROP TABLE ' . $table_name . ';' ) ){
                return array( 'error' => 'DELETE TABLE: TABLE IS NOT EXISTS: ' . $table_name );
            }
		}
		
		return true;
	}
	
	/**
     * Wrapper for self::data_tables__delete()
	 * Delete tables with given 'names + _temp' if they exists
	 *
	 * @param DB $db
	 * @param array $table_names Array with table names to delete
     *
     * @return bool|array
	 */
	public static function data_tables__deleteTemporary( $db, $table_names ){
        
        // Cast it to array for simple input
        $table_names = (array) $table_names;
        
        foreach( $table_names as &$table_name ){
            $table_name .= '_temp';
        }
        
	    return self::data_tables__delete( $db, $table_names );
	}
	
	/**
	 * Renames temporary tables to permanent
	 *
	 * @param DB $db
	 * @param array $table_names Array with table names to create
	 */
	public static function data_tables__makeTemporaryPermanent( $db, $table_names ){
        
        // Cast it to array for simple input
        $table_names = (array) $table_names;
	    
		foreach( $table_names as $table_name ){
		 
			$table_name__temp = $table_name . '_temp';
			
            if( ! $db->isTableExists( $table_name__temp ) )
                return array( 'error' => 'RENAME TABLE: TEMPORARY TABLE IS NOT EXISTS: ' . $table_name__temp);
            
            if( $db->isTableExists( $table_name ) )
                return array( 'error' => 'RENAME TABLE: MAIN TABLE IS STILL EXISTS: ' . $table_name);
            
            if( ! $db->execute( 'ALTER TABLE `' . $table_name__temp . '` RENAME `' . $table_name . '`;' ) ){
                return array( 'error' => 'RENAME TABLE: RANAME FAILS: ' );
            }
		}
		
		return true;
	}
    
    /**
     * Clear FW table
     * Clears unused country IPs from common table
     * Gathering country codes by parsing country personal tables for all blogs
     *
     * @param DB $db
     *
     * @return bool|array
     */
	public static function data_tables__clearUnusedCountriesDataFromMainTable( $db ) {
		
		// Clean common table from unused countries
		// Get all personal country tables
		$res = $db->fetch_all('SHOW TABLES LIKE "%spbc_firewall__personal_countries%"');
		
		// Get all countries for all blogs
		foreach( $res as $tbl )
			$sql[] = '(SELECT country_code FROM ' . current( $tbl ) . ')';
		$res = $db->fetch_all( implode( ' UNION ', $sql ) );
		
		// Delete all IP/mask for every other countries not in the list
		$in[] = "'0'";
		foreach( $res as $country_code ){
            $in[] = "'" . current( $country_code ) . "'";
        }
		
		if( $db->execute( 'DELETE FROM ' . SPBC_TBL_FIREWALL_DATA . ' WHERE country_code NOT IN (' . implode( ',', $in ) . ')') === false ){
		    return array( 'error' => 'CLEAR TABLE: CLEAR FAILS' );
        }
		
		return true;
	}
}