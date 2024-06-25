<?php

namespace CleantalkSP\SpbctWP\FSWatcher;

use CleantalkSP\SpbctWP\FSWatcher\Repository\SpbctWpFSWFileRepository;
use CleantalkSP\SpbctWP\FSWatcher\Storage\SpbctWpFSWFileStorage;

class SpbctWpFSWService extends \CleantalkSP\Common\FSWatcher\Service
{
    public static function setStorage($storage = 'file')
    {
        switch ($storage) {
            case 'file':
            default:
                SpbctWpFSWController::$storage = SpbctWpFSWFileStorage::class;
                SpbctWpFSWController::$repository = SpbctWpFSWFileRepository::class;
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
        $storage = SpbctWpFSWController::$storage;
        $last_exec_time = $storage::getLastJournalTime();
        if (is_null($last_exec_time)) {
            return true;
        }

        return (time() - $last_exec_time) > $interval;
    }

    /**
     * Get snapshots which is in process
     *
     * @return string|null
     */
    public static function getProcessingJournal()
    {
        $storage = SpbctWpFSWController::$storage;
        return $storage::getProcessingJournal();
    }

    //

    /**
     * Set snapshots to completed status
     *
     * @return void
     */
    public static function setAllJournalsAsCompleted()
    {
        $storage = SpbctWpFSWController::$storage;
        $storage::setAllJournalsAsCompleted();
    }

    public static function attachJS($buffer, $file_to_get_md5 = null)
    {
        return parent::attachJS($buffer, __FILE__);
    }

    public static function generateFsWatcherToken($salt = '')
    {
        return wp_create_nonce('spbc_secret_fs_watcher_token');
    }

    public static function validateFsWatcherToken()
    {
        return isset($_POST['fswatcher_token']) && spbc_check_ajax_referer('spbc_secret_fs_watcher_token', 'fswatcher_token');
    }

    public static function isRateLimitPass()
    {
        $time = time();

        $rateLimit = get_option('spbc_rate_limit_fswatcher', [
            'limit' => 30,
            'expires_in' => $time + 60,
            'attempts' => 0,
        ]);

        if ($rateLimit['expires_in'] <= $time) {
            $rateLimit['expires_in'] = $time + 60;
            $rateLimit['attempts'] = 0;
        }

        if ($rateLimit['expires_in'] > $time) {
            $rateLimit['attempts']++;
        }

        if ($rateLimit['attempts'] >= $rateLimit['limit']) {
            return false;
        }

        update_option('spbc_rate_limit_fswatcher', $rateLimit);

        return true;
    }
}
