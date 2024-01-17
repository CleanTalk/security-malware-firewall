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

    /**
     * Is ajax call is in process
     *
     * @return bool
     */
    public static function isRC()
    {
        if (isset($_POST['fswatcher_token']) && $_POST['fswatcher_token'] == md5((string)filemtime(__FILE__))) {
            return true;
        }

        return false;
    }

    public static function attachJS($buffer, $file_to_get_md5 = null)
    {
        return parent::attachJS($buffer, __FILE__);
    }
}
