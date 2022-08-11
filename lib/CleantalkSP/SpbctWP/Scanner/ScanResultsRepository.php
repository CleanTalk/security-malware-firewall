<?php

/**
 * SQL query to spbc_scan_results
 */

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP\DB;

class ScanResultsRepository
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
     * Get approved hashes
     */
    public function getApprovedRealFullHashes()
    {
        $rows = $this->db->fetchAll(
            'SELECT real_full_hash
            FROM ' . SPBC_TBL_SCAN_FILES . '
            WHERE status="APROVED"'
        );

        return $rows;
    }
}
