<?php

namespace CleantalkSP\SpbctWP\FSWatcher\Analyzer;

use CleantalkSP\Common\FSWatcher\Analyzer\Analyzer;
use CleantalkSP\SpbctWP\FSWatcher\SpbctWpFSWController;
use CleantalkSP\Common\FSWatcher\Logger;
use CleantalkSP\SpbctWP\FSWatcher\Storage\SpbctWpFSWFileStorage;

class SpbctWpFSWAnalyzer extends \CleantalkSP\Common\FSWatcher\Analyzer\Analyzer
{
    /**
     * @return array|false
     */
    public static function getCompareResult()
    {
        $first = filter_var($_POST['fswatcher__first_date'], FILTER_VALIDATE_INT);
        $second = filter_var($_POST['fswatcher__second_date'], FILTER_VALIDATE_INT);

        if ($first > $second) {
            $tmp = $first;
            $first = $second;
            $second = $tmp;
        }

        $storage = SpbctWpFSWController::$storage;

        $first_journal = $storage::getJournal($first);
        $second_journal = $storage::getJournal($second);

        if (!$first_journal || !$second_journal) {
            return false;
        }

        if (SpbctWpFSWController::$debug) {
            Logger::log('first journal ' . $first_journal);
            Logger::log('second journal ' . $second_journal);
        }

        return parent::compare($first_journal, $second_journal);
    }

    /**
     * @return string|false
     */
    public static function getViewFile()
    {
        $path = isset($_POST['fswatcher_file_path']) ? $_POST['fswatcher_file_path'] : false;
        $journals = isset($_POST['fswatcher_journals']) ? json_decode($_POST['fswatcher_journals']) : false;

        if (!$path || !is_file($path)) {
            throw new \Exception('File path is incorrect.');
        }

        if (!$journals || !is_array($journals)) {
            throw new \Exception('Provided journals paths are incorrect.');
        }

        $path_found_in_journal = false;

        foreach ($journals as $journal_id) {
            if (self::isFileOfFSWJournal($path, $journal_id)) {
                $path_found_in_journal = true;
                break;
            }
        }

        if (!$path_found_in_journal) {
            throw new \Exception('The file is out of FSWatcher journals.');
        }

        return esc_html__(file_get_contents($path));
    }

    /**
     * @param $path
     * @param $journal_id
     * @return bool
     */
    private static function isFileOfFSWJournal($path, $journal_id)
    {
        $storage = new SpbctWpFSWFileStorage();
        $journal_parsed = $storage->getJournal($journal_id);
        $analyzer = new Analyzer();
        $journal_parsed = $analyzer->uncompress($journal_parsed, true);
        if (strpos($journal_parsed, $path) !== false) {
            return true;
        }
        return false;
    }
}
