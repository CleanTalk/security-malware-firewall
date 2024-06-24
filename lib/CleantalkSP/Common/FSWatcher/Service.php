<?php

namespace CleantalkSP\Common\FSWatcher;

use CleantalkSP\Common\FSWatcher\Repository\FileRepository;
use CleantalkSP\Common\FSWatcher\Storage\FileStorage;

class Service
{
    /**
     * Factory method for initializing `Controller::$storage` and `Controller::$repository`
     *
     * @param $storage
     * @return void
     *
     * @psalm-suppress InvalidPropertyAssignmentValue
     */
    public static function setStorage($storage = 'file')
    {
        switch ($storage) {
            case 'file':
            default:
                Controller::$storage = FileStorage::class;
                Controller::$repository = FileRepository::class;
                break;
            // case 'customdb':
                // Controller::$storage = CustomDBStorage::class;
                // Controller::$repository = CustomDBStorage::class;
                // break;
            // case 'db':
                // Controller::$storage = DBStorage::class;
                // Controller::$repository = DBStorage::class;
                // break;
        }
    }

    /**
     * Is scanning interval was outdated
     *
     * @param $interval
     * @return bool
     */
    public static function isMinIntervalPassed($interval)
    {
        $storage = Controller::$storage;
        $last_exec_time = $storage::getLastJournalTime();
        if (is_null($last_exec_time)) {
            return true;
        }

        return (time() - $last_exec_time) > $interval;
    }

    /**
     * Attach JS file for start ajax call
     *
     * @param $buffer string
     * @return string
     *
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public static function attachJS($buffer, $file_to_get_md5 = null)
    {
        if (empty($file_to_get_md5)) {
            $file_to_get_md5 = __FILE__;
        }
        $is_ajax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
        $is_html = preg_match('/^\s*(<!doctype|<!DOCTYPE|<html)/i', $buffer) == 1;

        if (!$is_ajax && $is_html) {
            $path = __DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'fswatcher.js';
            $addition =
                '<script type="text/javascript">var fswatcherToken = "' . md5((string)filemtime($file_to_get_md5)) . '";</script>'
                . '<script type="text/javascript">var fswatcherWebsiteUrl = "' . get_home_url() . '";</script>'
                . '<script type="text/javascript">' . file_get_contents($path) . '</script>';

            $buffer = preg_replace(
                '/<\/body>(\s|<.*>)*<\/html>\s*$/i',
                $addition . '</body></html>',
                $buffer,
                1
            );
        }

        return $buffer;
    }

    /**
     * Is ajax call is in process
     *
     * @return bool
     */
    public static function isRC()
    {
        return static::validateFsWatcherToken();
    }

    /**
     * Checking request validity: view file
     *
     * @return bool
     */
    public static function isViewFileRequest()
    {
        if (isset($_POST['fswatcher_view_file']) && $_POST['fswatcher_view_file'] == true &&
            isset($_POST['fswatcher_file_path']) && strlen($_POST['fswatcher_file_path']) > 1
        ) {
            return true;
        }

        return false;
    }

    /**
     * Checking request validity: Comparing logs
     *
     * @return bool
     */
    public static function isCompareRequest()
    {
        if (isset($_POST['fswatcher_compare']) && $_POST['fswatcher_compare'] == true &&
            isset($_POST['fswatcher__first_date']) && filter_var($_POST['fswatcher__first_date'], FILTER_VALIDATE_INT) !== false &&
            isset($_POST['fswatcher__second_date']) && filter_var($_POST['fswatcher__second_date'], FILTER_VALIDATE_INT) !== false
        ) {
            return true;
        }

        return false;
    }

    /**
     * Checking request validity: Creating Snapshot
     *
     * @return bool
     */
    public static function isCreateSnapshotRequest()
    {
        return isset($_POST['fswatcher_create_snapshot']) && $_POST['fswatcher_create_snapshot'] == true;
    }

    /**
     * Set snapshots to completed status
     *
     * @return void
     */
    public static function setAllJournalsAsCompleted()
    {
        $storage = Controller::$storage;
        $storage::setAllJournalsAsCompleted();
    }

    /**
     * Get snapshots which is in process
     *
     * @return string|null
     */
    public static function getProcessingJournal()
    {
        $storage = Controller::$storage;
        return $storage::getProcessingJournal();
    }

    /**
     * Generates token (aka nonce).
     * The $salt must be used obligatorily
     *
     * @param $salt
     *
     * @return string
     */
    public static function generateFsWatcherToken($salt = '')
    {
        return md5(filemtime(__FILE__) . $salt);
    }

    public static function validateFsWatcherToken()
    {
        return isset($_POST['fswatcher_token']) && $_POST['fswatcher_token'] === static::generateFsWatcherToken();
    }

    /**
     * Is rate limit pass
     * Must be overridden in child class
     *
     * @return bool
     */
    public static function isRateLimitPass()
    {
        return true;
    }
}
