<?php

namespace CleantalkSP\SpbctWP\Scanner\CureLog;

use CleantalkSP\SpbctWP\DB;

class CureLog
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
     * Returns count of cured files in cure log table
     * @return int
     */
    public function getCountData()
    {
        $query = 'SELECT COUNT(*) as cnt FROM ' . SPBC_TBL_CURE_LOG;
        $result = $this->db->fetch($query);
        return (int)$result->cnt;
    }

    /**
     * Clear cure log table.
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function clearLogDataFromFailedCures()
    {
        $query = 'DELETE FROM ' . SPBC_TBL_CURE_LOG . ' WHERE cured <> 1';
        $this->db->execute($query);
    }

    /**
     * Check if there is failed cure tries
     * @return bool
     */
    public function hasFailedCureTries()
    {
        $query = 'SELECT COUNT(*) as cnt FROM ' . SPBC_TBL_CURE_LOG . ' WHERE cured = 0';
        $result = $this->db->fetch($query);
        return (bool)$result->cnt;
    }

    /**
     * Returns cure log data for scanner accordion tab
     * @return array|object
     */
    public function getDataToAccordion($offset = 0, $amount = 20)
    {
        $offset = intval($offset);
        $amount = intval($amount);
        $query = 'SELECT fast_hash, real_path, cured, cci_cured, has_backup, fail_reason, last_cure_date FROM ' . SPBC_TBL_CURE_LOG . ' LIMIT ' . $offset . ',' . $amount . ';';
        $result = $this->db->fetchAll($query, OBJECT);

        if ( empty($result) ) {
            return new \stdClass();
        }

        foreach ($result as $row) {
            if ( isset($row->cured) && $row->cured == 1 ) {
                $row->cured = 'CURED';
            } else {
                $row->cured = 'FAILED';
            }
            if ( !empty($row->last_cure_date) ) {
                $row->last_cure_date = date("M d Y H:i:s", $row->last_cure_date);
            } else {
                $row->last_cure_date = 'N/A';
            }
        }
        return $result;
    }

    /**
     * Returns cure log data for PDF report
     * @return array|object
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getDataToPDF()
    {
        $query = 'SELECT real_path, cured, cci_cured, last_cure_date 
            FROM ' . SPBC_TBL_CURE_LOG;
        $result = $this->db->fetchAll($query, ARRAY_A);

        if ( empty($result) ) {
            return array();
        }

        foreach ($result as &$row) {
            if ( isset($row['cured']) && $row['cured'] == 1 ) {
                $row['cured'] = 'CURED';
            } else {
                $row['cured'] = 'FAILED';
            }
            if ( !empty($row['last_cure_date']) ) {
                $row['last_cure_date'] = date("M d Y H:i:s", $row['last_cure_date']);
            } else {
                $row['last_cure_date']  = 'N/A';
            }
        }
        unset($row);
        return $result;
    }

    /**
     * Process cure log record.
     * @param CureLogRecord $cure_log_record
     * @return void
     */
    public function logCureResult(CureLogRecord $cure_log_record)
    {

        if (spbc_file_has_backup($cure_log_record->real_path)) {
            $cure_log_record->has_backup = 1;
        }

        $this->db->prepare(
            'INSERT INTO ' . SPBC_TBL_CURE_LOG
                . ' (`fast_hash`, `real_path`, `cured`, `cci_cured`,`has_backup`,`fail_reason`, `last_cure_date`, `scanner_start_local_date`) VALUES'
                . "(%s, %s, %d, %s, %d, %s, %d, %s)"
                . 'ON DUPLICATE KEY UPDATE
                cured = VALUES(`cured`),
                last_cure_date = VALUES(`last_cure_date`),
                fail_reason = VALUES(`fail_reason`),
                scanner_start_local_date = VALUES(`scanner_start_local_date`)',
            array($cure_log_record->fast_hash,
                $cure_log_record->real_path,
                $cure_log_record->cured,
                $cure_log_record->cci_cured,
                $cure_log_record->has_backup,
                $cure_log_record->fail_reason,
                $cure_log_record->last_cure_date,
                $cure_log_record->scanner_start_local_date,
            )
        )->execute();
    }
}
