<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\Repositories;

class UnknownRepository extends GlobalRepository
{
    /**
     * UnknownRepository constructor.
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
        if ($this->spbc->settings['scanner__list_unknown']) {
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
            'SELECT full_hash, mtime, size, path, source, severity, detected_at'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE source IS NULL AND'
            . ' status <> "APPROVED_BY_USER" AND'
            . ' status <> "APPROVED_BY_CT" AND'
            . ' status <> "APPROVED_BY_CLOUD" AND'
            . ' detected_at >= ' . (time() - $this->spbc->settings['scanner__list_unknown__older_than'] * 86400) . ' AND'
            . ' path NOT LIKE "%wp-content%themes%" AND'
            . ' path NOT LIKE "%wp-content%plugins%" AND'
            . ' path NOT LIKE "%wp-content%cache%" AND'
            . ' (severity NOT IN ("CRITICAL","SUSPICIOUS") OR severity IS NULL)'
        );
    }
}
