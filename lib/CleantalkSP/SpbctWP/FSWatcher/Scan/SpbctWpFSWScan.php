<?php

namespace CleantalkSP\SpbctWP\FSWatcher\Scan;

use CleantalkSP\SpbctWP\FSWatcher\SpbctWpFSWController;
use CleantalkSP\Common\FSWatcher\Logger;

class SpbctWpFSWScan extends \CleantalkSP\Common\FSWatcher\Scan\Scan
{
    public static function run($params)
    {
        parent::setParams($params);

        $storage = SpbctWpFSWController::$storage;
        $journal = $storage::makeProcessingJournal();
        if (SpbctWpFSWController::$debug) {
            Logger::log('create processing journal ' . $journal);
        }

        self::scan();
    }

    protected static function scan()
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(self::$dir_to_watch, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        $storage = SpbctWpFSWController::$storage;
        $storage::writeJournal($iterator, self::$extensions_to_watch, self::$exclude_dirs);
    }
}
