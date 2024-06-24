<?php

namespace CleantalkSP\SpbctWP\Firewall;

use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Server;
use CleantalkSP\Security\Firewall\Result;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\SpbctWP\Helpers\HTTP;
use CleantalkSP\SpbctWP\Helpers\CSV;

class FW extends FirewallModule
{
    public $module_name = 'FW';

    public $data_table__personal_countries = '';

    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $test;

    // Additional params
    protected $api_key = false;

    /**
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $real_ip;

    /**
     * @psalm-suppress PossiblyUnusedProperty
     */
    protected $debug;

    /**
     * @param $ips
     */
    public function ipAppendAdditional(&$ips)
    {
        $this->real_ip = isset($ips['real']) ? $ips['real'] : null;

        $test_ip = Get::get('spbct_test_ip');
        if ( IP::validate($test_ip) && Get::get('spbct_test') === md5($this->api_key) ) {
            $ips['test']   = $test_ip;
            $this->test_ip = $test_ip;
            $this->test    = true;
        }
    }

    /**
     * Check every IP using FireWall data table.
     *
     * @return array
     */
    public function check()
    {
        $results = array();

        foreach ( $this->ip_array as $_ip_origin => $current_ip ) {
            try {
                $version = IP::validate($current_ip);
                if ( $version === 'v6' ) {
                    //IPV6 handling logic
                    $db_results = $this->ipv6GetResultsFromDb($current_ip);
                } elseif ($version === 'v4') {
                    //IPV4 handling logic
                    $db_results = $this->ipv4GetResultsFromDb($current_ip);
                } else {
                    throw new \Exception('IP address record is invalid.');
                }
            } catch (\Exception $e) {
                error_log('Security by CleanTalk. Firewall IP handling error: ' . $e->getMessage());
                continue;
            }

            // In base
            if ( ! empty($db_results) ) {
                foreach ( $db_results as $entry ) {
                    switch ( $entry['status'] ) {
                        case 2:
                            $text_status = 'PASS_BY_TRUSTED_NETWORK';
                            break;
                        case 1:
                            $text_status = 'PASS_BY_WHITELIST';
                            break;
                        case 0:
                            $text_status = 'DENY';
                            break;
                        case -1:
                            $text_status = 'DENY_BY_NETWORK';
                            break;
                        case -2:
                            $text_status = 'DENY_BY_DOS';
                            break;
                        case -3:
                            $text_status = 'DENY_BY_SEC_FW';
                            break;
                        case -4:
                            $text_status = 'DENY_BY_SPAM_FW';
                            break;
                        case 99:
                            $text_status = 'PASS_AS_SKIPPED_NETWORK';
                            break;
                        default:
                            $text_status = 'PASS';
                            break;
                    }

                    $results[] = new Result(
                        array(
                            'module'       => $this->module_name,
                            'ip'           => $current_ip,
                            'is_personal'  => $entry['is_personal'],
                            'country_code' => $entry['country_code'],
                            'network'      => $version === 'v4' ? $entry['network'] : $entry['network4'],
                            'mask'         => $version === 'v4' ? $entry['mask'] : $entry['mask4'],
                            'status'       => $text_status,
                        )
                    );
                }
            }
        }

        // Set a PASS  result if no results from DB
        if ( empty($results) ) {
            $results[] = new Result(
                array(
                    'module' => $this->module_name,
                    'ip'     => reset($this->ip_array),
                    'status' => 'PASS',
                )
            );
        }

        return $results;
    }

    /**
     * Return array of database search result for IP (ipv4)
     * @param $ip
     * @return array|null|object
     */
    protected function ipv4GetResultsFromDb($ip)
    {
        $current_ipv4 = sprintf('%u', ip2long($ip));
        $needles = IP::getNetworkNeedles([$current_ipv4]);
        $data_table__common_v4 = SPBC_TBL_FIREWALL_DATA_V4;
        $data_table__personal_v4 = SPBC_TBL_FIREWALL_DATA__IPS_V4;

        $query_ipv4 = '(
				SELECT 0 AS is_personal, 1 AS is_ip, status, country_code, network, mask
				FROM ' . $data_table__common_v4 . '
				WHERE network IN (' . current($needles) . ')
					AND network = ' . $current_ipv4 . ' & mask
					AND country_code = "0"
			) UNION (
				SELECT 1 AS is_personal, 1 AS is_ip, status, 0 AS country_code, network, mask
				FROM ' . $data_table__personal_v4 . '
				WHERE network IN (' . current($needles) . ')
					AND network = ' . $current_ipv4 . ' & mask
			) UNION (
				SELECT 1 AS is_personal, 0 AS is_ip, tbl_private.status, country_code, network, mask
				FROM ' . $this->data_table__personal_countries . ' AS tbl_private
				RIGHT JOIN ' . $data_table__common_v4 . ' AS tbl_common USING(country_code)
				WHERE network IN (' . current($needles) . ')
					AND network = ' . $current_ipv4 . ' & mask
					AND tbl_private.status IS NOT NULL
					AND ' . mt_rand(1, 100000) . ' <> 0
			)';

        $db_results = $this->db->fetchAll($query_ipv4, ARRAY_A);

        return $db_results;
    }

    /**
     * Return database search result for IP (ipv6)
     * @param $ip
     * @return array
     * @throws \Exception
     */
    protected function ipv6GetResultsFromDb($ip)
    {
        $needles = IP::getNetworkNeedles(IP::getFourIPv4FromIP($ip));
        $data_table__common_v6 = SPBC_TBL_FIREWALL_DATA_V6;
        $data_table__personal_v6 = SPBC_TBL_FIREWALL_DATA__IPS_V6;

        $query_ipv6 = '(
				SELECT 0 AS is_personal, 1 AS is_ip, status, country_code, network1, network2, network3, network4, mask1, mask2, mask3, mask4
				FROM ' . $data_table__common_v6 . '
				WHERE
					    network1 IN (0,' . $needles[0] . ')
					AND network2 IN (0,' . $needles[1] . ')
					AND network3 IN (0,' . $needles[2] . ')
					AND network4 IN (0,' . $needles[3] . ')
					AND country_code = "0"
			) UNION (
				SELECT 1 AS is_personal, 1 AS is_ip, status, 0 AS country_code, network1, network2, network3, network4, mask1, mask2, mask3, mask4
				FROM ' . $data_table__personal_v6 . '
				WHERE
					    network1 IN (0,' . $needles[0] . ')
					AND network2 IN (0,' . $needles[1] . ')
					AND network3 IN (0,' . $needles[2] . ')
					AND network4 IN (0,' . $needles[3] . ')
			) UNION (
				SELECT 1 AS is_personal, 0 AS is_ip, tbl_private.status, country_code, network1, network2, network3, network4, mask1, mask2, mask3, mask4
				FROM ' . $this->data_table__personal_countries . ' AS tbl_private
				RIGHT JOIN ' . $data_table__common_v6 . ' AS tbl_common USING(country_code)
				WHERE
					    network1 IN (0,' . $needles[0] . ')
					AND network2 IN (0,' . $needles[1] . ')
					AND network3 IN (0,' . $needles[2] . ')
					AND network4 IN (0,' . $needles[3] . ')
					AND tbl_private.status IS NOT NULL
					AND ' . mt_rand(1, 100000) . ' <> 0
			)';

        $db_results = $this->db->fetchAll($query_ipv6, ARRAY_A);

        $output_db_results = array();

        $error = '';

        foreach ($db_results as $current_result) {
            //collecting data
            if ( !isset(
                $current_result['network1'],
                $current_result['network2'],
                $current_result['network3'],
                $current_result['network4'],
                $current_result['mask1'],
                $current_result['mask2'],
                $current_result['mask3'],
                $current_result['mask4']
            ) ) {
                $error = 'db data is not correct;';
                continue;
            }
            $hex_network_from_db = str_pad(dechex($current_result['network1']), 8, '0', STR_PAD_LEFT);
            $hex_network_from_db .= str_pad(dechex($current_result['network2']), 8, '0', STR_PAD_LEFT);
            $hex_network_from_db .= str_pad(dechex($current_result['network3']), 8, '0', STR_PAD_LEFT);
            $hex_network_from_db .= str_pad(dechex($current_result['network4']), 8, '0', STR_PAD_LEFT);

            if ( strlen($hex_network_from_db) <> 32) {
                $error = 'can not collect hex string from db';
                continue;
            }

            $mask =  IP::convertLongIntmaskToDec($current_result['mask1']);
            $mask += IP::convertLongIntmaskToDec($current_result['mask2']);
            $mask += IP::convertLongIntmaskToDec($current_result['mask3']);
            $mask += IP::convertLongIntmaskToDec($current_result['mask4']);

            if ( !is_int($mask) || $mask < 0 || $mask > 128 ) {
                $error = 'can not collect network mask from db';
                continue;
            }

            //converting stuff
            $ipv6_network_from_db = implode(':', str_split($hex_network_from_db, 4));

            if ( IP::validate($ipv6_network_from_db) !== 'v6' ) {
                $error = 'can not construct ipv6 subnet from db';
                continue;
            }

            $ip = IP::extendIPv6(IP::normalizeIPv6($ip));

            //belonging check logic
            $ip_in_network = IP::isIpv6AddrInIpv6Network($ip, $ipv6_network_from_db, $mask);

            if ( false === $ip_in_network ) {
                $error = 'can not check if address belongs to network';
                continue;
            }

            if ($ip_in_network === 1) {
                //output found result
                $output_db_results[] = $current_result;
            }
        }

        if ( !empty($error) ) {
            throw new \Exception($error);
        }

        return $output_db_results;
    }

    /**
     * Sends and wipe SFW log
     *
     * @param $db
     * @param $log_table
     * @param string $ct_key API key
     *
     * @return array|int array('error' => STRING)
     */
    public static function sendLog($db, $log_table, $ct_key)
    {
        //Getting logs
        $query = 'SELECT * FROM ' . $log_table . ' WHERE send_status IS NULL LIMIT ' . SPBC_SELECT_LIMIT . ';';
        $db->fetchAll($query);

        if ( count($db->result) ) {
            //Compile logs
            $data = array();
            foreach ( $db->result as $_key => $value ) {
                //Compile log
                $to_data = array(
                    'datetime'         => date('Y-m-d H:i:s', $value['entry_timestamp']),
                    'page_url'         => $value['page_url'],
                    'visitor_ip'       => IP::validate($value['ip_entry']) === 'v4' ? (int)sprintf(
                        '%u',
                        ip2long($value['ip_entry'])
                    ) : (string)$value['ip_entry'],
                    'http_user_agent'  => $value['http_user_agent'],
                    'request_method'   => $value['request_method'],
                    'x_forwarded_for'  => $value['x_forwarded_for'],
                    'matched_networks' => $value['network'] ? $value['network'] . '/' . $value['mask'] : null,
                    'matched_country'  => $value['country_code'],
                    'is_personal'      => $value['is_personal'],
                    'hits'             => (int)$value['requests'],
                    'datetime_gmt'     => $value['entry_timestamp'],
                    //signature_id always persists for WAF rules
                    'signature_id'     => !empty($value['signature_id']) ? $value['signature_id'] : null,
                );

                // Legacy
                switch ( $value['status'] ) {
                    case 'PASS_BY_TRUSTED_NETWORK':
                        $to_data['status_efw'] = 3;
                        break;
                    case 'PASS_BY_WHITELIST':
                        $to_data['status_efw'] = 2;
                        break;
                    case 'PASS':
                        $to_data['status_efw'] = 1;
                        if ( $value['pattern'] && $value['triggered_for'] ) {
                            $to_data['waf_comment']     = $value['pattern'];
                            $to_data['suspicious_code'] = $value['triggered_for'];
                        }
                        break;
                    case 'DENY':
                        $to_data['status_efw'] = 0;
                        break;
                    case 'DENY_BY_NETWORK':
                        $to_data['status_efw'] = -1;
                        break;
                    case 'DENY_BY_DOS':
                        $to_data['status_efw'] = -2;
                        break;
                    /**
                     * WAF checks
                     */
                    case 'DENY_BY_WAF_XSS':
                        $to_data['status_efw']  = -3;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    case 'DENY_BY_WAF_SQL':
                        $to_data['status_efw']  = -4;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    case 'DENY_BY_WAF_EXPLOIT':
                        $to_data['status_efw']  = -6;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    /**
                     * UploadChecker module
                     */
                    case 'DENY_BY_WAF_FILE':
                        $to_data['status_efw']  = -5;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    /**
                     * Brute force
                     */
                    case 'DENY_BY_BFP':
                        $to_data['status_efw'] = -7;
                        break;
                    /**
                     * Brute force temp 24h block
                     */
                    case 'DENY_BY_WAF_BLOCKER':
                        $to_data['status_efw'] = -10;
                        $to_data['waf_comment'] = 'Blocked for 24 hours - several WAF attacks in a row';
                        break;
                    case 'DENY_BY_SEC_FW':
                        $to_data['status_efw'] = -8;
                        break;
                    case 'DENY_BY_SPAM_FW':
                        $to_data['status_efw'] = -9;
                        break;
                }

                switch ( $value['status'] ) {
                    case 'PASS_BY_TRUSTED_NETWORK':
                        $to_data['status'] = 3;
                        break;
                    case 'PASS_BY_WHITELIST':
                        $to_data['status'] = 2;
                        break;
                    case 'PASS':
                        $to_data['status'] = 1;
                        if ( $value['pattern'] && $value['triggered_for'] ) {
                            $to_data['waf_comment']     = $value['pattern'];
                            $to_data['suspicious_code'] = $value['triggered_for'];
                        }
                        break;
                    case 'DENY':
                        $to_data['status'] = 0;
                        break;
                    case 'DENY_BY_NETWORK':
                        $to_data['status'] = -1;
                        break;
                    case 'DENY_BY_DOS':
                        $to_data['status'] = -2;
                        break;
                    case 'DENY_BY_WAF_XSS':
                        $to_data['status']      = -3;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    case 'DENY_BY_WAF_SQL':
                        $to_data['status']      = -4;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    case 'DENY_BY_WAF_FILE':
                        $to_data['status']      = -5;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    case 'DENY_BY_WAF_EXPLOIT':
                        $to_data['status']      = -6;
                        $to_data['waf_comment'] = $value['pattern'];
                        break;
                    case 'DENY_BY_BFP':
                        $to_data['status'] = -7;
                        break;
                    case 'DENY_BY_SEC_FW':
                        $to_data['status'] = -8;
                        break;
                    case 'DENY_BY_SPAM_FW':
                        $to_data['status'] = -9;
                        break;
                }

                $data[] = $to_data;
            }

            //Sending the request
            $result = API::method__security_logs__sendFWData($ct_key, $data);

            //Checking answer and deleting all lines from the table
            if ( empty($result['error']) ) {
                if ( (int)$result['rows'] === count($data) ) {
                    $db->execute("DELETE FROM " . $log_table . " WHERE entry_id NOT IN (" .
                                 "SELECT entry_id FROM (" .
                                 "SELECT entry_id, entry_timestamp FROM " . $log_table . " ORDER BY entry_timestamp DESC LIMIT 20) too );");
                    $db->execute("UPDATE " . $log_table . " SET send_status = 1;");
                    return count($data);
                }

                return array('error' => 'SENT_AND_RECEIVED_LOGS_COUNT_DOESNT_MACH');
            }

            return (array) $result;
        }

        return array('error' => 'NO_LOGS_TO_SEND');
    }

    /**
     * Gets multifile with data to update Firewall.
     *
     * @param string $spbc_key
     *
     * @return array
     */
    public static function firewallUpdateGetMultifiles($spbc_key)
    {
        // Getting remote file name
        $result = API::method__security_firewall_data_file($spbc_key, 'multifiles', '3');

        if ( empty($result['error']) ) {
            if ( ! empty($result['file_url']) ) {
                $data = HTTP::getDataFromRemoteGZ($result['file_url']);

                if ( empty($data['error']) ) {
                    return array(
                        'multifile_url' => $result['file_url'],
                        'file_urls'     => CSV::parseCSV($data),
                    );
                }

                return array('error' => 'FW. Get multifile. ' . $data['error']);
            }

            return array('error' => 'FW. Get multifile. BAD_RESPONSE');
        }

        return (array) $result;
    }

    /**
     * Writes entries from remote files to Firewall database.
     *
     * @param DB $db database handler
     * @param string $data_table__common Table name with common data
     * @param string $data_table__personal Table name with personal IPs
     * @param string $data_table__personal_countries Table name with with personal country list
     * @param string $file_url Local or remote URL
     *
     * @return array|bool|int|mixed|string
     */
    public static function updateWriteToDb(
        $db,
        $data_table__common,
        $data_table__personal,
        $data_table__personal_countries,
        $file_url
    ) {
        // Check if the URL is remote address or not, and use a proper function to extract data
        $data = HTTP::getDataFromGZ($file_url);

        if ( empty($data['error']) ) {
            $inserted = 0;
            $data_table__common_v4 = str_replace('_temp', '_v4_temp', $data_table__common);
            $data_table__common_v6 = str_replace('_temp', '_v6_temp', $data_table__common);
            $data_table__personal_v4 = str_replace('_temp', '_v4_temp', $data_table__personal);
            $data_table__personal_v6 = str_replace('_temp', '_v6_temp', $data_table__personal);

            while ( $data !== '' ) {
                for (
                    $i = 0, $sql__common_v4 = $sql__common_v6 = $sql__personal_ip_v4 = $sql__personal_ip_v6 = $sql__personal_country = [];
                    $i < SPBC_WRITE_LIMIT && $data !== '';
                    $i++
                ) {
                    $entry = CSV::popLineFromCSVToArray($data);

                    // Skipping bad data
                    if ( empty($entry[0]) || empty($entry[1]) ) {
                        continue;
                    }

                    // IP processing
                    $network_v4 = '';
                    $network_v6 = [];

                    // IPv4
                    if ( is_numeric($entry[0]) ) {
                        $network_v4 = $entry[0];
                        //IPv6
                    } else {
                        $network_v6 = IP::convertIPv6ToFourIPv4(
                            IP::extendIPv6(
                                IP::normalizeIPv6(
                                    trim($entry[0], '"')
                                )
                            )
                        );
                    }

                    $mask        = $entry[1];
                    $status      = isset($entry[3]) ? $entry[3] : 0;
                    $is_personal = isset($entry[4]) ? (int)$entry[4] : 0;
                    $country     = isset($entry[5]) ? trim($entry[5], '"') : 0;

                    // IPv4
                    if ( $network_v4 !== '' ) {
                        $mask = sprintf(
                            '%u',
                            bindec(str_pad(str_repeat('1', $mask), 32, 0, STR_PAD_RIGHT))
                        );

                        if ( $country || ! $is_personal ) {
                            $sql__common_v4[] = "($network_v4, $mask, $status, '$country')";
                        }
                        if ( $is_personal && $country ) {
                            $sql__personal_country[] = "('$country',$status)";
                        }

                        if ( $is_personal && ! $country ) {
                            $sql__personal_ip_v4[] = "($network_v4, $mask, $status)";
                        }
                    }

                    // IPv6
                    if ( count($network_v6) ) {
                        for ( $masks = array(), $k = 4; $k >= 1; $k-- ) {
                            $masks[$k] = (2 ** 32) - (2 ** (32 - ($mask > 32 ? 32 : $mask)));
                            $mask      -= 32;
                            $mask      = $mask > 0 ? $mask : 0;
                        }
                        if ( $country || ! $is_personal ) {
                            $sql__common_v6[] = "($network_v6[0], $network_v6[1], $network_v6[2], $network_v6[3], $masks[1], $masks[2], $masks[3], $masks[4], $status, '$country')";
                        }
                        if ( $is_personal && $country ) {
                            $sql__personal_country[] = "('$country',$status)";
                        }

                        if ( $is_personal && ! $country ) {
                            $sql__personal_ip_v6[] = "($network_v6[0], $network_v6[1], $network_v6[2], $network_v6[3], $masks[1], $masks[2], $masks[3], $masks[4], $status)";
                        }
                    }
                }

                // Insertion to common table v4
                if ( count($sql__common_v4) ) {
                    $sql_result__common_v4___result = $db->execute(
                        'INSERT INTO ' . $data_table__common_v4
                        . ' (network, mask, status, country_code) '
                        . ' VALUES '
                        . implode(',', $sql__common_v4)
                        . ' ON DUPLICATE KEY UPDATE'
                        . ' network=network'
                        . ';'
                    );

                    if ( $sql_result__common_v4___result === false ) {
                        return array('error' => 'COULD_NOT_WRITE_TO_DB_COMMON_V4: ' . $db->getLastError());
                    }
                }


                // Insertion to common table v6
                if ( count($sql__common_v6) ) {
                    $sql_result__common_v6___result = $db->execute(
                        'INSERT INTO ' . $data_table__common_v6
                        . ' (network1, network2, network3, network4, mask1, mask2, mask3, mask4, status, country_code) '
                        . ' VALUES '
                        . implode(',', $sql__common_v6)
                        . ' ON DUPLICATE KEY UPDATE'
                        . ' network1=network1'
                        . ';'
                    );

                    if (  $sql_result__common_v6___result === false ) {
                        return array('error' => 'COULD_NOT_WRITE_TO_DB_COMMON_V6: ' . $db->getLastError());
                    }
                }

                // Replacing result counter because SQL result won't count all contained entries
                $sql_result__common___result = count($sql__common_v4) + count($sql__common_v6);

                $sql_result__personal___result = 0;
                // Insertion v4 to personal IPs table
                if ( count($sql__personal_ip_v4) ) {
                    $sql_result__personal_v4___result = $db->execute(
                        'INSERT INTO ' . $data_table__personal_v4 . ' (network,mask,status) VALUES '
                        . implode(',', $sql__personal_ip_v4) . ';'
                    );
                    unset($sql__personal_ip_v4);
                    if ( $sql_result__personal_v4___result === false ) {
                        return array('error' => 'COULD_NOT_WRITE_TO_DB_PERSONAL_V4: ' . $db->getLastError());
                    }
                    $sql_result__personal___result += $sql_result__personal_v4___result;
                }

                // Insertion v6 to personal IPs table
                if ( count($sql__personal_ip_v6) ) {
                    $sql_result__personal_v6___result = $db->execute(
                        'INSERT INTO ' . $data_table__personal_v6 . ' (network1,network2,network3,network4,mask1,mask2,mask3,mask4,status) VALUES '
                        . implode(',', $sql__personal_ip_v6) . ';'
                    );
                    unset($sql__personal_ip_v6);
                    if ( $sql_result__personal_v6___result === false ) {
                        return array('error' => 'COULD_NOT_WRITE_TO_DB_PERSONAL_V6: ' . $db->getLastError());
                    }
                    $sql_result__personal___result += $sql_result__personal_v6___result;
                }

                // Insertion to personal countries table
                if ( count($sql__personal_country) ) {
                    $sql__personal_country        = array_unique($sql__personal_country); // Filtering duplicate entries
                    $sql_result__country___result = $db->execute(
                        'INSERT INTO ' . $data_table__personal_countries . '(country_code,status) VALUES '
                        . implode(',', $sql__personal_country) . ';'
                    );
                    unset($sql__personal_country);
                    if ( $sql_result__country___result === false ) {
                        return array('error' => 'COULD_NOT_WRITE_TO_DB_COUNTRIES: ' . $db->getLastError());
                    }
                }

                $inserted += ($sql_result__common___result + $sql_result__personal___result);
            }

            if ( ! is_int($inserted) ) {
                return array('error' => 'WRONG RESPONSE FROM update__write_to_db');
            }

            return $inserted;
        }

        return $data;
    }

    /**
     * Adding local exclusions to to the FireWall database.
     *
     * @param DB $db database handler
     * @param string $db__table__data__personal table name with personal IPs
     * @param string $db__table__data__common table name with common IPs
     * @param array $exclusions
     *
     * @return array|bool|int|mixed|string
     */
    public static function updateWriteToDbExclusions(
        $db,
        $db__table__data__personal,
        $db__table__data__common,
        $exclusions = array()
    ) {
        $data_table__personal_v4 = str_replace('_temp', '_v4_temp', $db__table__data__personal);
        $data_table__common_v4 = str_replace('_temp', '_v4_temp', $db__table__data__common);
        $query = 'INSERT INTO `' . $data_table__personal_v4 . '`  (network,mask,status) VALUES ';

        //Exclusion for servers IP (SERVER_ADDR)
        if ( Server::get('HTTP_HOST') ) {
            // Exceptions for local hosts
            if ( ! in_array(Server::getDomain(), array('lc', 'loc', 'lh')) ) {
                $exclusions[] = \CleantalkSP\SpbctWP\Helpers\Helper::resolveDNS(Server::get('HTTP_HOST'));
                $exclusions[] = '127.0.0.1';

                // And delete all 127.0.0.1 entries for local hosts
                // From both tables personal and common
            } else {
                $db->execute(
                    'DELETE FROM ' . $data_table__personal_v4 . ' WHERE network = ' . ip2long('127.0.0.1') . ';'
                );
                $db->execute(
                    'DELETE FROM ' . $data_table__common_v4 . ' WHERE network = ' . ip2long('127.0.0.1') . ';'
                );
            }
        }

        foreach ( $exclusions as $exclusion ) {
            if ( IP::validate($exclusion) ) {
                $network = sprintf('%u', ip2long($exclusion));
                $mask = 4294967295;
                $query .= "( $network, $mask, 2),";
            }
        }

        if ( $exclusions ) {
            $sql_result = $db->execute(substr($query, 0, -1) . ';');

            return $sql_result === false
                ? array('error' => 'COULD_NOT_WRITE_TO_DB_EXCLUSIONS: ' . $db->getLastError())
                : count($exclusions);
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
    public static function dataTablesCreateTemporaryTablesForTables($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';

            if ( ! $db->execute(
                'CREATE TABLE IF NOT EXISTS `' . $table_name__temp . '` LIKE  `' . $table_name . '`; '
            ) ) {
                return array('error' => 'CREATE TABLES: COULD NOT CREATE ' . $table_name__temp);
            }

            if ( ! $db->execute('TRUNCATE `' . $table_name__temp . '`; ') ) {
                return array('error' => 'CREATE TABLES: COULD NOT TRUNCATE ' . $table_name__temp);
            }
        }

        return true;
    }

    /**
     * Copying data from permanent table to temporary
     * Deletes all common entries from temporary table
     *
     * @param DB $db database handler
     * @param string $data_table__common Table name with common data
     *
     * @return bool|string[]
     */
    public static function dataTablesCopyCountiesDataFromMainTable($db, $data_table__common)
    {
        $data_table__common__temp = $data_table__common . '_temp';

        // Copying data
        $offset = 0;
        do {
            $sql = 'INSERT INTO `' . $data_table__common__temp
                   . '` ( SELECT * FROM `' . $data_table__common . '` WHERE `country_code` <> "0" LIMIT ' . $offset . ',' . SPBC_WRITE_LIMIT . ');';
            $res = $db->execute($sql);
            if ( $res === false ) {
                return array('error' => 'COPYING DATA: ' . substr($sql, 0, 6));
            }
            $offset += SPBC_WRITE_LIMIT;
        } while ( $db->getRowsAffected() === SPBC_WRITE_LIMIT );

        // Deleting
        if ( $db->execute('DELETE FROM `' . $data_table__common__temp . '` WHERE `country_code` <> "0"') === false ) {
            return array('error' => 'COPYING DATA: ' . substr($sql, 0, 6));
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
    public static function dataTablesDelete($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            if ( $db->isTableExists($table_name) && $db->execute('DROP TABLE ' . $table_name . ';') !== true ) {
                return array(
                    'error' => 'DELETE TABLE: ' . $table_name . ' DB Error: ' . substr($db->getLastError(), 0, 1000),
                );
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
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function dataTablesDeleteTemporary($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as &$table_name ) {
            $table_name .= '_temp';
        }

        return self::dataTablesDelete($db, $table_names);
    }

    /**
     * Renames temporary tables to permanent
     *
     * @param DB $db
     * @param array $table_names Array with table names to create
     *
     * @return bool|string[]
     */
    public static function dataTablesMakeTemporaryPermanent($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';

            if ( ! $db->isTableExists($table_name__temp) ) {
                return array('error' => 'RENAME TABLE: TEMPORARY TABLE IS NOT EXISTS: ' . $table_name__temp);
            }

            if ( $db->isTableExists($table_name) ) {
                return array('error' => 'RENAME TABLE: MAIN TABLE IS STILL EXISTS: ' . $table_name);
            }

            if ( ! $db->execute('ALTER TABLE `' . $table_name__temp . '` RENAME `' . $table_name . '`;') ) {
                return array('error' => 'RENAME TABLE: RANAME FAILS: ');
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
    public static function dataTablesClearUnusedCountriesDataFromMainTable($db)
    {
        // Clean common table from unused countries
        // Get all personal country tables
        $res = $db->fetchAll('SHOW TABLES LIKE "%spbc_firewall__personal_countries%"');

        // Get all countries for all blogs
        $sql = array();
        foreach ( $res as $tbl ) {
            $sql[] = '(SELECT country_code FROM ' . current($tbl) . ')';
        }
        $res = $db->fetchAll(implode(' UNION ', $sql));

        // Delete all IP/mask for every other countries not in the list
        $in[] = "'0'";
        foreach ( $res as $country_code ) {
            $in[] = "'" . current($country_code) . "'";
        }

        $delete_sql_v4 = "DELETE FROM "
                      . SPBC_TBL_FIREWALL_DATA_V4 . "
                      WHERE country_code NOT IN (" . implode(',', $in) . ")";
        $delete_sql_v6 = "DELETE FROM "
                      . SPBC_TBL_FIREWALL_DATA_V6 . "
                      WHERE country_code NOT IN (" . implode(',', $in) . ")";
        if ( $db->execute($delete_sql_v4) === false || $db->execute($delete_sql_v6) === false ) {
            return array('error' => 'CLEAR TABLE: CLEAR FAILS');
        }

        return true;
    }

    public static function privateRecordsAdd(DB $db, $metadata)
    {
        $added_count = 0;
        $updated_count = 0;
        $ignored_count = 0;
        $id_chunk = '';


        foreach ( $metadata as $row ) {
            //find duplicate to use it on updating
            $has_duplicate = false;

            $duplicated_row = self::checkDuplicateItem($db, $row);

            //if the record is same - pass
            if ( isset($duplicated_row['status']) && $duplicated_row['status'] == $row['status'] ) {
                $ignored_count++;
                continue;
            }

            //if duplicate found create a chunk
            if ( isset($duplicated_row['status']) && isset($duplicated_row['id']) ) {
                $id_chunk = "id ='" . $duplicated_row['id'] . "',";
                $has_duplicate = true;
            }

            $insert_result = self::privateRecordAddDb($db, $row, $id_chunk);

            if ( $insert_result === false ) {
                throw new \RuntimeException($db->getLastError());
            }

            $added_count = $has_duplicate ? $added_count : $added_count + 1;
            $updated_count = $has_duplicate ? $updated_count + 1 : $updated_count;
        }

        return array(
            'total' => $added_count + $updated_count + $ignored_count,
            'added' => $added_count,
            'updated' => $updated_count,
            'ignored' => $ignored_count
        );
    }

    public static function privateRecordsDelete(DB $db, $metadata)
    {
        $success_count = 0;
        $ignored_count = 0;

        foreach ( $metadata as $row ) {
            if ( is_array($row['network']) ) {
                // v6
                $query = "DELETE FROM " . SPBC_TBL_FIREWALL_DATA__IPS_V6 . " WHERE 
                    network1 = '" . $row['network'][0] . "' AND
                    network2 = '" . $row['network'][1] . "' AND
                    network3 = '" . $row['network'][2] . "' AND
                    network4 = '" . $row['network'][3] . "' AND
                    mask1 = '" . $row['mask'][1] . "' AND
                    mask2 = '" . $row['mask'][2] . "' AND
                    mask3 = '" . $row['mask'][3] . "' AND
                    mask4 = '" . $row['mask'][4] . "';";
            } else {
                // v4
                $query = "DELETE FROM " . SPBC_TBL_FIREWALL_DATA__IPS_V4 . " WHERE 
                    network = '" . $row['network'] . "' AND
                    mask = '" . $row['mask'] . "';";
            }

            $db_result = $db->execute($query);
            if ( $db_result === false ) {
                throw new \Exception($db->getLastError());
            }

            $success_count = $db_result === 1 ? $success_count + 1 : $success_count;
            $ignored_count = $db_result === 0 ? $ignored_count + 1 : $ignored_count;
        }

        return array(
            'total' => $success_count + $ignored_count,
            'deleted' => $success_count,
            'ignored' => $ignored_count
        );
    }

    /**
     * @param $row array Network item to check
     *
     * @return array
     */
    private static function checkDuplicateItem($db, $row)
    {
        $output = [];

        if ( is_array($row['network']) ) {
            // v6
            $query = "SELECT id,status FROM " . SPBC_TBL_FIREWALL_DATA__IPS_V6 . " WHERE 
                                network1 = '" . $row['network'][0] . "' AND 
                                network2 = '" . $row['network'][1] . "' AND 
                                network3 = '" . $row['network'][2] . "' AND 
                                network4 = '" . $row['network'][3] . "' AND 
                                mask1 = '" . $row['mask'][1] . "' AND 
                                mask2 = '" . $row['mask'][2] . "' AND 
                                mask3 = '" . $row['mask'][3] . "' AND 
                                mask4 = '" . $row['mask'][4] . "';";
        } else {
            // v4
            $query = "SELECT id,status FROM " . SPBC_TBL_FIREWALL_DATA__IPS_V4 . " WHERE 
                                network = '" . $row['network'] . "' AND 
                                mask = '" . $row['mask'] . "';";
        }

        $db_result = $db->fetch($query);
        if ( $db_result === false ) {
            throw new \RuntimeException($db->getLastError());
        }

        if ( isset($db_result->status) ) {
            $output['status'] = $db_result->status;
        }
        if ( isset($db_result->id) ) {
            $output['id'] = $db_result->id;
        }
        return $output;
    }

    /**
     * @param $row array Network item to insert
     * @param $id_chunk string|int id for duplicated row if it provided
     *
     * @return int
     */
    private static function privateRecordAddDb($db, $row, $id_chunk)
    {
        if ( is_array($row['network']) ) {
            // v6
            $query = "INSERT INTO " . SPBC_TBL_FIREWALL_DATA__IPS_V6 . " SET
                                " . $id_chunk . "
                                network1 = '" . $row['network'][0] . "',
                                network2 = '" . $row['network'][1] . "',
                                network3 = '" . $row['network'][2] . "',
                                network4 = '" . $row['network'][3] . "',
                                mask1 = '" . $row['mask'][1] . "',
                                mask2 = '" . $row['mask'][2] . "',
                                mask3 = '" . $row['mask'][3] . "',
                                mask4 = '" . $row['mask'][4] . "',
                                status = '" . $row['status'] . "'
                                ON DUPLICATE KEY UPDATE 
                                id = id,
                                network1 = network1,
                                network2 = network2,
                                network3 = network3,
                                network4 = network4,
                                mask1 = mask1,
                                mask2 = mask2,
                                mask3 = mask3,
                                mask4 = mask4, 
                                status = '" . $row['status'] . "';";
        } else {
            // v4
            $query = "INSERT INTO " . SPBC_TBL_FIREWALL_DATA__IPS_V4 . " SET
                                " . $id_chunk . "
                                network = '" . $row['network'] . "',
                                mask = '" . $row['mask'] . "',
                                status = '" . $row['status'] . "'
                                ON DUPLICATE KEY UPDATE 
                                id = id,
                                network = network,
                                mask = mask,
                                status = '" . $row['status'] . "';";
        }

        //insertion
        return $db->execute($query);
    }
}
