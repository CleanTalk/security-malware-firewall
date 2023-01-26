<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningLog;

use CleantalkSP\SpbctWP\DB;

class Repository
{
    public static function write($content)
    {
        return DB::getInstance()->prepare(
            'INSERT INTO '
            . SPBC_TBL_SCAN_RESULTS_LOG
            . ' (timestamp, content) VALUES'
            . ' (%d, %s);',
            array(time(), wp_kses($content, '<b>'))
        )->execute();
    }

    public static function getAll()
    {
        return DB::getInstance()->fetchAll(
            'SELECT timestamp, content FROM '
            . SPBC_TBL_SCAN_RESULTS_LOG
            . ' ORDER BY timestamp DESC'
        );
    }

    public static function clear()
    {
        return DB::getInstance()->execute(
            'TRUNCATE TABLE '
            . SPBC_TBL_SCAN_RESULTS_LOG
        );
    }
}
