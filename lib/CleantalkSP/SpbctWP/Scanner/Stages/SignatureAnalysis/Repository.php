<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\SignatureAnalysis;

use CleantalkSP\SpbctWP\Helpers\CSV;
use CleantalkSP\SpbctWP\Helpers\Helper;
use CleantalkSP\SpbctWP\Helpers\HTTP;

class Repository
{
    public static function getLatestSignatureSubmittedTime()
    {
        global $wpdb;
        $latest_signature_submitted_time = $wpdb->get_results(
            'SELECT submitted FROM '
            . SPBC_TBL_SCAN_SIGNATURES
            . ' ORDER BY submitted DESC LIMIT 1;',
            OBJECT
        );
        return !empty($latest_signature_submitted_time[0]->submitted)
            ? $latest_signature_submitted_time[0]->submitted
            : 1;
    }

    /**
     * Receive signatures from the cloud.
     *
     * @param string $latest_signature_local the time of one last updated signature, SQL DATETIME string
     *
     * @return array An array with map and values
     * @psalm-suppress InvalidLiteralArgument
     */
    public static function getSignaturesFromCloud($latest_signature_local)
    {
        // Check signatures version. File contains time of the signatures latest update.
        $version_file_url = 'https://cleantalk-security.s3.us-west-2.amazonaws.com/security_signatures/version.txt';
        $latest_signatures_cloud = HTTP::getContentFromURL($version_file_url);
        if ( ! empty($latest_signatures_cloud['error']) || ! strtotime($latest_signatures_cloud) ) {
            return array('error' => 'WRONG_VERSION_FILE');
        }

        if ( strtotime($latest_signature_local) >= strtotime($latest_signatures_cloud) ) {
            return array('error' => 'UP_TO_DATE');
        }

        $file_url = self::getSignaturesFileURL();
        if ( !$file_url ) {
            return array('error' => 'SIGNATURES_FILE_URL_RESPONSE_NOT_200');
        }

        $unparsed_csv = HTTP::getDataFromGZ($file_url);

        if ( empty($unparsed_csv['error']) ) {
            // Set map for file
            $map = strpos($file_url, '_mapped') !== false
                ? CSV::getMapFromCSV($unparsed_csv) // Map from file
                : array(
                    'id',
                    'name',
                    'body',
                    'type',
                    'attack_type',
                    'submitted',
                    'cci',
                    'waf_headers',
                    'waf_url'
                ); // Default map

            $out['map'] = $map;
            while ( $unparsed_csv ) {
                $out['values'][] = CSV::popLineFromCSVToArray($unparsed_csv, $map);
            }

            return $out;
        }

        //contains error
        return (array) $unparsed_csv;
    }

    public static function clearSignaturesTable()
    {
        global $wpdb;
        $wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_SIGNATURES . ' WHERE 1;');
    }

    public static function addSignaturesToDb($map, $signatures)
    {
        global $wpdb;
        $sql_head = 'INSERT INTO ' . SPBC_TBL_SCAN_SIGNATURES
                    . ' (' . implode(',', $map) . ')'
                    . ' VALUES ';
        $sql_data = array();
        $sql_tail = ' ON DUPLICATE KEY UPDATE '
                    . 'submitted = submitted;';
        foreach ( $signatures as $signature ) {
            /** @psalm-suppress InvalidArgument */
            $tmp = implode(
                ',',
                array_map(
                    function ($elem) {
                        return Helper::prepareParamForSQLQuery(stripslashes($elem ?: 'null'));
                    },
                    $signature
                )
            );

            $sql_data[] = "($tmp)";
        }

        $query =
            $sql_head
            . implode(',', $sql_data)
            . $sql_tail;

        return $wpdb->query($query);
    }

    public static function thereAreSignaturesInDb()
    {
        global $wpdb;
        $count_signatures = $wpdb->get_var(
            'SELECT COUNT(*) FROM '
            . SPBC_TBL_SCAN_SIGNATURES
            . ';'
        );
        return $count_signatures > 0;
    }

    public static function addSignaturesToDbOneByOne($map, $signatures)
    {
        global $wpdb;
        $sql_head = 'INSERT INTO ' . SPBC_TBL_SCAN_SIGNATURES
                    . ' (' . implode(',', $map) . ')'
                    . ' VALUES ';
        $sql_tail = ' ON DUPLICATE KEY UPDATE '
                    . 'submitted = submitted;';
        $bad_signatures = array();
        foreach ( $signatures as $signature ) {
            /** @psalm-suppress InvalidArgument */
            $tmp = implode(
                ',',
                array_map(
                    function ($elem) {
                        return Helper::prepareParamForSQLQuery(stripslashes($elem ?: 'null'));
                    },
                    $signature
                )
            );

            $sql_data = "($tmp)";

            $query =
                $sql_head
                . $sql_data
                . $sql_tail;

            $signature_added = $wpdb->query($query);

            if (!$signature_added) {
                $bad_signatures[] = $signature['id'];
            }
        }

        if ($bad_signatures) {
            return array(
                'bad_signatures' => implode(', ', $bad_signatures),
            );
        }

        return true;
    }

    /**
     * Get signatures file URL. Check which signatures source file version is available.
     * @return false|string
     */
    private static function getSignaturesFileURL()
    {
        global $spbc;
        $file_url = '';
        $file_of_v3 = 'https://cleantalk-security.s3.us-west-2.amazonaws.com/security_signatures/security_signatures_mapped_v3.csv.gz';

        //check response and select available URL
        if ( HTTP::getResponseCode($file_of_v3) === 200 ) {
            //use v3 if available
            $file_url = $file_of_v3;
        }

        if (!empty($file_url)) {
            //save to data the last URL
            $spbc->data['scanner']['last_signatures_file_url'] = $file_url;
            $spbc->save('data');
            return $file_url;
        }
        // if nothing available return false
        return false;
    }
}
