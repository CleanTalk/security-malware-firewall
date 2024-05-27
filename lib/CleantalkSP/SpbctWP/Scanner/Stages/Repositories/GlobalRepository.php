<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\Repositories;

use CleantalkSP\SpbctWP\DB;

abstract class GlobalRepository
{
    /**
     * @var DB
     */
    protected $db;

    /**
     * @global $spbc
     */
    protected $spbc;

    /**
     * GlobalRepository constructor.
     */
    public function __construct()
    {
        global $spbc;

        $this->db = DB::getInstance();
        $this->spbc = $spbc;
    }

    /**
     * Checking if we need to get data from the database
     *
     * @return bool
     */
    abstract protected function isNeedToGet();

    /**
     * Getting data from the database
     *
     * @return array|object|null
     */
    abstract protected function catchResultData();

    /**
     * Getting result data
     *
     * @return array<array-key, mixed>|null|object
     */
    public function getResultData()
    {
        $result = [];

        if ($this->isNeedToGet()) {
            $result = $this->catchResultData();
            if (count($result)) {
                $result = $this->prepareResultData($result);
            }
        }

        return $result;
    }

    /**
     * Prepare result data
     *
     * @param array $data
     *
     * @return array
     */
    protected function prepareResultData($data)
    {
        $result = [];

        foreach ($data as $row) {
            $path = $this->spbc->is_windows ? str_replace('\\', '/', $row['path']) : $row['path'];
            $row['mtime'] = $row['mtime'] + $this->spbc->data['site_utc_offset_in_seconds'];
            $result[$path] = array_values($row);
        }

        return $result;
    }

    /**
     * Get scanner start local date
     */
    protected function getScannerStartLocalDate()
    {
        return isset($this->spbc->data['scanner']['scanner_start_local_date'])
            ? $this->spbc->data['scanner']['scanner_start_local_date']
            : current_time('Y-m-d H:i:s');
    }
}
