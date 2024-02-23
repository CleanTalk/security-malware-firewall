<?php

namespace CleantalkSP\SpbctWP\FSWatcher\Storage;

class SpbctWpFSWFileStorage extends \CleantalkSP\Common\FSWatcher\Storage\FileStorage
{
    public static function getJournalsPath()
    {
        $wp_upload_dir = wp_get_upload_dir();
        $dir_name = $wp_upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'spbc_fswatcher' . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR;
        if ( ! is_dir($dir_name)) {
            mkdir($dir_name, 0777, true);
            file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
        }
        return $dir_name;
    }

    public static function makeProcessingJournal()
    {
        global $spbc;
        $journals_path = self::getJournalsPath();
        $api_key = $spbc->settings['spbc_key'];
        $journal_name_prefix = time() . '_' . md5($api_key);
        $path = $journals_path . DIRECTORY_SEPARATOR . $journal_name_prefix . self::STATUS_PROCESSING . '.csv';

        file_put_contents($path, '');

        return $path;
    }

    /**
     * @inheritDoc
     */
    public static function getProcessingJournal()
    {
        $is_processing = glob(self::getJournalsPath() . '*' . self::STATUS_PROCESSING . '.csv');
        if ( ! empty($is_processing)) {
            return $is_processing[0];
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public static function getLastJournalTime()
    {
        $pattern = self::getJournalsPath() . '*' . self::STATUS_COMPLETED . '.csv';
        if (function_exists('gzopen')) {
            $pattern = self::getJournalsPath() . '*' . self::STATUS_COMPLETED . '.csv.gz';
        }

        $last_journal = glob($pattern);
        if ( ! empty($last_journal)) {
            $journal = $last_journal[count($last_journal) - 1];
            return (int)explode('__', basename($journal))[0];
        }

        return null;
    }

    /**
     * @inheritDoc
     */
    public static function setAllJournalsAsCompleted()
    {
        $journals = glob(self::getJournalsPath() . '*.csv');
        foreach ($journals as $journal) {
            $new_name = str_replace(self::STATUS_PROCESSING, self::STATUS_COMPLETED, $journal);
            rename($journal, $new_name);
            parent::compressJournalGZ($new_name);
        }
    }

    /**
     * @inheritDoc
     */
    public static function getAvailableJournals()
    {
        global $spbc;

        self::removeOldJournals();

        $dir = self::getJournalsPath();

        if ( ! is_dir($dir)) {
            return [];
        }

        $pattern = $dir . '*.csv';
        if (function_exists('gzopen')) {
            $pattern = $dir . '*.csv.gz';
        }

        $dates = [];
        $journals = glob($pattern);
        $api_key = $spbc->settings['spbc_key'];
        foreach ($journals as $journal) {
            if ( strpos($journal, md5($api_key)) !== false ) {
                $dates[] = (int)explode('__', basename($journal))[0];
            }
        }

        return $dates;
    }

    /**
     * @inheritDoc
     */
    public static function writeJournal($iterator, $extensions_to_watch, $exclude_dirs)
    {
        $journal = self::getProcessingJournal();

        if ( ! $journal ) {
            return;
        }

        $fp = fopen((string)$journal, 'w');
        foreach ($iterator as $path => $dir) {
            if ($dir->isDir() && !in_array($dir->getFilename(), $exclude_dirs)) {
                $iterator->next();
            } else {
                if (in_array($dir->getExtension(), $extensions_to_watch)) {
                    $mtime = @filemtime((string)$path);
                    if ( empty($mtime) ) {
                        clearstatcache($path);
                        $mtime = @filemtime((string)$path);
                        if ( empty($mtime) ) {
                            $mtime = @filectime((string)$path);
                            if ( empty($mtime) ) {
                                $mtime = time();
                            }
                        }
                    }

                    fputcsv($fp, [$path, $mtime]);
                }
            }
        }
        fclose($fp);
    }

    /**
     * @inheritDoc
     */
    public static function getJournal($journal)
    {
        global $spbc;
        $journals_path = self::getJournalsPath();
        $api_key = $spbc->settings['spbc_key'];
        $journal_full_path = $journal . '_' . md5($api_key);
        $path = $journals_path . DIRECTORY_SEPARATOR . $journal_full_path . self::STATUS_COMPLETED . '.csv';
        if (function_exists('gzopen')) {
            $path = $journals_path . DIRECTORY_SEPARATOR . $journal_full_path . self::STATUS_COMPLETED . '.csv.gz';
        }

        if ( ! file_exists($path)) {
            return null;
        }

        return $path;
    }

    public static function getAssetsPath()
    {
        return __DIR__ . '/../assets/fswatcher-logic.js';
    }

    private static function removeOldJournals()
    {
        global $spbc;

        $dir = self::getJournalsPath();

        if ( ! is_dir($dir)) {
            return;
        }

        $pattern = $dir . '*.csv';
        if (function_exists('gzopen')) {
            $pattern = $dir . '*.csv.gz';
        }

        $timeover = $spbc->key_is_ok ? time() - 3600 * 24 * 7 : time() - 3600 * 24;
        $journals = glob($pattern);
        foreach ($journals as $journal) {
            if ((int)explode('__', basename($journal))[0] < $timeover) {
                unlink($journal);
            }
        }
    }
}
