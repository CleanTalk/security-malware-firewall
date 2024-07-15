<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP;
use CleantalkSP\SpbctWP\Helpers\Data;

class Controller
{
    private static $statuses = array(
        'OK',
        'UNKNOWN',
        'MODIFIED',
        'INFECTED',
        'QUARANTINED',
        'APPROVED_BY_USER',
    );

    private static $severities = array(
        'NONE',
        'SUSPICIOUS',
        'CRITICAL',
    );

    /**
     * Merges the scan results
     *
     * @param mixed ...$results
     *
     * @return array Merged results
     */
    public static function mergeResults(...$results)
    {
        $out = array(
            'weak_spots' => null,
            'severity'   => null,
            'status'     => 'OK',
        );

        foreach ( $results as $result ) {
            foreach ( $result as $key => $item ) {
                if ( empty($item) ) {
                    continue;
                }

                switch ( $key ) {
                    case 'weak_spots':
                        if ( is_array($item) ) {
                            foreach ( $item as $severity => $line_nums ) {
                                foreach ( $line_nums as $line_num => $codes ) {
                                    foreach ( $codes as $code ) {
                                        $out['weak_spots'][$severity][$line_num][] = $code;
                                    }
                                }
                            }
                        }
                        break;

                    case 'severity':
                        $out['severity'] = array_search($item, self::$severities, true) > array_search(
                            $out['severity'],
                            self::$severities,
                            true
                        )
                            ? $item
                            : $out['severity'];
                        break;

                    case 'status':
                        $out['status'] = array_search($item, self::$statuses, true) > array_search(
                            $out['status'],
                            self::$statuses,
                            true
                        )
                            ? $item
                            : $out['status'];
                        break;
                }
            }
        }

        return $out;
    }

    /**
     * Get signatures uploaded
     *
     * @return mixed
     */
    public static function getSignatures()
    {
        return SpbctWP\DB::getInstance()->fetchAll('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);
    }

    /**
     * Get root path of the CMS
     *
     * @param bool $end_slash
     *
     * @return string
     */
    public static function getRootPath($end_slash = false)
    {
        return $end_slash ? ABSPATH : substr(ABSPATH, 0, -1);
    }

    public static function resetCheckResult()
    {
        SpbctWP\DB::getInstance()->execute('DELETE FROM ' . SPBC_TBL_SCAN_FILES);
        SpbctWP\DB::getInstance()->execute('DELETE FROM ' . SPBC_TBL_BACKUPS);
        SpbctWP\DB::getInstance()->execute('DELETE FROM ' . SPBC_TBL_BACKUPED_FILES);
        SpbctWP\DB::getInstance()->execute('DELETE FROM ' . SPBC_TBL_CURE_LOG);
        $backups_folder = SPBC_PLUGIN_DIR . DIRECTORY_SEPARATOR . 'backups';
        if (is_dir($backups_folder) && is_writable($backups_folder)) {
            Data::removeDirectoryRecursively($backups_folder);
        }
        return true;
    }
}
