<?php

namespace CleantalkSP\SpbctWP\FSWatcher;

use CleantalkSP\SpbctWP\FSWatcher\Scan\SpbctWpFSWScan;
use CleantalkSP\SpbctWP\FSWatcher\Analyzer\SpbctWpFSWAnalyzer;
use CleantalkSP\Common\FSWatcher\Logger;

class SpbctWpFSWController extends \CleantalkSP\Common\FSWatcher\Controller
{
    /**
     * @var \CleantalkSP\SpbctWP\FSWatcher\Storage\SpbctWpFSWFileStorage::class
     */
    public static $storage;

    /**
     * @var \CleantalkSP\SpbctWP\FSWatcher\Repository\SpbctWpFSWFileRepository::class'
     */
    public static $repository;

    private static $status = self::STATUS_STOPPED;

    /**
     * Initialize the `$debug` property false|true
     *
     * @return void
     */
    private static function getDebugState()
    {
        if ( defined('SPBC_FSWATCHER_DEBUG') ) {
            self::$debug = (bool) SPBC_FSWATCHER_DEBUG;
            parent::$debug = self::$debug;
        }
    }

    /**
     * Scanning file system handler
     *
     * @param $params
     * @return void
     */
    protected static function run($params)
    {
        self::$status = self::STATUS_RUNNING;
        SpbctWpFSWScan::run($params);
        self::stop();
    }

    /**
     * This is the init method.
     *
     * Making initialize the `$debug` property
     *
     * Contains Ajax handler for requests:
     * 1) Comparing logs
     * 2) Scanning file system
     * 3) Automatically making ajax requests for 2)
     *
     * @param $params
     * @return void
     */
    public static function work($params)
    {
        global $spbc;
        self::getDebugState();

        if (self::$debug) {
            Logger::log('check remote call = ' . (int)SpbctWpFSWService::isRC());
        }

        SpbctWpFSWService::setStorage(isset($params['storage']) ? $params['storage'] : 'file');

        if (self::status() === self::STATUS_STOPPED && SpbctWpFSWService::isRC() && SpbctWpFSWService::isCompareRequest()) {
            if (self::$debug) {
                Logger::log('run compare file system');
            }
            $compare_result = SpbctWpFSWAnalyzer::getCompareResult();
            if (false === $compare_result) {
                Logger::log('Can not compare logs');
                echo json_encode(array('error' => 'Can not compare logs'));
            } else {
                echo json_encode($compare_result);
            }
            die();
        }

        if (self::status() === self::STATUS_STOPPED && SpbctWpFSWService::isRC() && SpbctWpFSWService::isViewFileRequest()) {
            if (self::$debug) {
                Logger::log('run view file method');
            }

            try {
                $view_file = SpbctWpFSWAnalyzer::getViewFile();
                echo json_encode(array("data" => $view_file));
            } catch (\Exception $e) {
                Logger::log('Can not view file');
                echo json_encode(array('error' => 'Can not view file. ' . $e->getMessage()));
            }
            die();
        }

        if (self::status() === self::STATUS_STOPPED && ( SpbctWpFSWService::isRC() || ( SpbctWpFSWService::isRC() && SpbctWpFSWService::isCreateSnapshotRequest() ))) {
            if (self::$debug) {
                Logger::log('run scan file system');
            }
            self::run($params);
            die(json_encode('OK'));
        }
        $min_exec_time = $spbc->settings['scanner__fs_watcher__snapshots_period'] ?: parent::EXECUTION_MIN_INTERVAL;
        if (self::status() === self::STATUS_STOPPED && SpbctWpFSWService::isMinIntervalPassed($min_exec_time)) {
            if (self::$debug) {
                Logger::log('attach js to make remote request');
            }
            ob_start(['CleantalkSP\SpbctWP\FSWatcher\SpbctWpFSWService', 'attachJS']);
        }
    }


    /**
     * Scanning file system stop trigger
     *
     * @return void
     */
    private static function stop()
    {
        self::$status = self::STATUS_STOPPED;
        SpbctWpFSWService::setAllJournalsAsCompleted();
    }

    /**
     * Checking status of the scanning process
     *
     * @return string
     */
    private static function status()
    {
        $is_exist = SpbctWpFSWService::getProcessingJournal();
        if (!is_null($is_exist)) {
            self::$status = self::STATUS_RUNNING;
        }

        return self::$status;
    }
}
