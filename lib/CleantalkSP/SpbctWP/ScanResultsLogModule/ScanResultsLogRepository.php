<?php

namespace CleantalkSP\SpbctWP\ScanResultsLogModule;

use CleantalkSP\SpbctWP\DB;

class ScanResultsLogRepository
{
    /**
     * @var DB
     */
    private $db;

    public function __construct()
    {
        $this->db = DB::getInstance();
    }

    /**
     * Inset or update table
     */
    public function addScanResultsLogRow($fast_hash, $check_type, $status_of_check)
    {
        $this->db->prepare(
            'INSERT INTO ' . SPBC_TBL_SCAN_RESULTS_LOG
            . ' (fast_hash, check_type, status_of_check, checked_at) VALUES'
            . " (%s, %s, %s, %d) "
            . 'ON DUPLICATE KEY UPDATE
                    status_of_check = VALUES(`status_of_check`),
                    checked_at = VALUES(`checked_at`)',
            array($fast_hash, $check_type, $status_of_check, time())
        )->execute();
    }

    /**
     * Get rows default
     */
    public function getScanResultsLogRows()
    {
        $rows = $this->db->fetchAll(
            'SELECT r.path, l.check_type, l.status_of_check, l.checked_at
            FROM ' . SPBC_TBL_SCAN_RESULTS_LOG . ' AS l
            INNER JOIN ' . SPBC_TBL_SCAN_FILES . ' AS r
            ON l.fast_hash = r.fast_hash'
        );

        return $rows;
    }
}