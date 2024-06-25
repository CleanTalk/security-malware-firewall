<?php

namespace CleantalkSP\Common\FSWatcher;

use CleantalkSP\Common\FSWatcher\Analyzer\Analyzer;
use CleantalkSP\Common\FSWatcher\Scan\Scan;

class Controller
{
    /**
     * @var bool
     */
    public static $debug;

    const STATUS_STOPPED = 'stopped';

    const STATUS_RUNNING = 'running';

    const EXECUTION_MIN_INTERVAL = 3600; // 1 hour

    /**
     * @var \CleantalkSP\Common\FSWatcher\Storage\FileStorage::class
     */
    public static $storage;

    /**
     * @var \CleantalkSP\Common\FSWatcher\Repository\FileRepository::class'
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
        }
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
        self::getDebugState();

        if (self::$debug) {
            Logger::setSaltValue();
            Logger::log('check remote call = ' . (int)Service::isRC());
        }

        Service::setStorage(isset($params['storage']) ? $params['storage'] : 'file');

        if (self::status() !== self::STATUS_STOPPED) {
            return;
        }

        if (!Service::isRC()) {
            if (Service::isMinIntervalPassed(self::EXECUTION_MIN_INTERVAL)) {
                if (self::$debug) {
                    Logger::log('attach js to make remote request');
                }
                ob_start(['CleantalkSP\Common\FSWatcher\Service', 'attachJS']);
            }

            return;
        }

        if (!Service::isRateLimitPass()) {
            http_response_code(403);
            die('Rate limit exceeded. Protected - Security by CleanTalk.');
        }

        if (Service::isCompareRequest()) {
            if (self::$debug) {
                Logger::log('run compare file system');
            }
            $compare_result = Analyzer::getCompareResult();
            if (false === $compare_result) {
                Logger::log('Can not compare logs');
                echo json_encode(array('error' => 'Can not compare logs'));
            } else {
                echo json_encode($compare_result);
            }
            die();
        }

        if (Service::isCreateSnapshotRequest()) {
            if (self::$debug) {
                Logger::log('run scan file system');
            }
            self::run($params);
            die(json_encode('OK'));
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
        Scan::run($params);
        self::stop();
    }

    /**
     * Scanning file system stop trigger
     *
     * @return void
     */
    private static function stop()
    {
        self::$status = self::STATUS_STOPPED;
        Service::setAllJournalsAsCompleted();
    }

    /**
     * Checking status of the scanning process
     *
     * @return string
     */
    private static function status()
    {
        $is_exist = Service::getProcessingJournal();
        if (!is_null($is_exist)) {
            self::$status = self::STATUS_RUNNING;
        }

        return self::$status;
    }
}
