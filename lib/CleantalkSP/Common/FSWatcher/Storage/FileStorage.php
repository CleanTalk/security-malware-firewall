<?php

namespace CleantalkSP\Common\FSWatcher\Storage;

class FileStorage implements Storage
{
    const STATUS_PROCESSING = '__processing';

    const STATUS_COMPLETED = '__completed';

    /**
     * @inheritDoc
     */
    public static function makeProcessingJournal()
    {
        $journals_path = self::getJournalsPath();
        $path = $journals_path . DIRECTORY_SEPARATOR . time() . self::STATUS_PROCESSING . '.csv';

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
            self::compressJournalGZ($new_name);
        }
    }

    /**
     * @inheritDoc
     */
    public static function getAvailableJournals()
    {
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
        foreach ($journals as $journal) {
            $dates[] = (int)explode('__', basename($journal))[0];
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
        $journals_path = self::getJournalsPath();
        $path = $journals_path . DIRECTORY_SEPARATOR . $journal . self::STATUS_COMPLETED . '.csv';
        if (function_exists('gzopen')) {
            $path = $journals_path . DIRECTORY_SEPARATOR . $journal . self::STATUS_COMPLETED . '.csv.gz';
        }

        if ( ! file_exists($path)) {
            return null;
        }

        return $path;
    }

    /**
     * Get snapshots files directory
     *
     * @return string
     */
    private static function getJournalsPath()
    {
        $dir_name = __DIR__ . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR;
        if ( ! is_dir($dir_name)) {
            mkdir($dir_name);
            file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
        }

        return $dir_name;
    }

    /**
     * Archive the snapshot file
     *
     * @param $journal string
     * @return void
     */
    protected static function compressJournalGZ($journal)
    {
        if ( ! function_exists('gzopen')) {
            return;
        }

        $gz = gzopen($journal . '.gz', 'w9');
        gzwrite($gz, file_get_contents($journal));
        gzclose($gz);

        unlink($journal);
    }


    public static function getAssetsPath()
    {
        return __DIR__ . '/../assets/fswatcher-logic.js';
    }
}
