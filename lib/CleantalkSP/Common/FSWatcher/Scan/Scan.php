<?php

namespace CleantalkSP\Common\FSWatcher\Scan;

use CleantalkSP\Common\FSWatcher\Logger;
use CleantalkSP\Common\FSWatcher\Controller;

class Scan
{
    protected static $dir_to_watch = '';
    protected static $exclude_dirs = array();
    protected static $extensions_to_watch = array('php');

    public static function run($params)
    {
        self::setParams($params);

        $storage = Controller::$storage;
        $journal = $storage::makeProcessingJournal();
        if (Controller::$debug) {
            Logger::log('create processing journal ' . $journal);
        }

        self::scan();
    }

    protected static function setParams($params)
    {
        self::$dir_to_watch = $params['dir_to_watch'];
        self::$exclude_dirs = $params['exclude_dirs'];
        self::$extensions_to_watch = $params['extensions_to_watch'];
    }

    protected static function scan()
    {
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator(self::$dir_to_watch, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        $storage = Controller::$storage;
        $storage::writeJournal($iterator, self::$extensions_to_watch, self::$exclude_dirs);
    }
}
