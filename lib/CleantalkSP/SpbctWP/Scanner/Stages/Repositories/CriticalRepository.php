<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\Repositories;

class CriticalRepository extends GlobalRepository
{
    /**
     * CriticalRepository constructor.
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Checking if we need to get data from the database
     *
     * @return bool
     */
    protected function isNeedToGet()
    {
        if ($this->spbc->settings['scanner__signature_analysis']) {
            return true;
        }

        return false;
    }

    /**
     * Getting data from the database
     *
     * @return array|object|null
     */
    protected function catchResultData()
    {
        return $this->db->fetchAll(
            'SELECT full_hash, mtime, size, source_type, source, source_status, path, status, severity'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE'
            . ' severity = "CRITICAL" AND'
            . ' status <> "QUARANTINED" AND'
            . ' status <> "APPROVED_BY_USER" AND'
            . ' status <> "APPROVED_BY_CLOUD" AND'
            . ' status <> "APPROVED_BY_CT"'
        );
    }
}
