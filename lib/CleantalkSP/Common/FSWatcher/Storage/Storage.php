<?php

namespace CleantalkSP\Common\FSWatcher\Storage;

/**
 * @psalm-suppress PossiblyUnusedMethod
 */
interface Storage
{
    /**
     * Get snapshots files which is in process
     *
     * @return string|null
     */
    public static function getProcessingJournal();

    /**
     * Get the oldest timestamp of the available snapshots files
     *
     * @return int|null
     */
    public static function getLastJournalTime();

    /**
     * Creating empty snapshot file
     *
     * @return string
     */
    public static function makeProcessingJournal();

    /**
     * Set snapshots files to completed status - renaming these to `*_completed`
     *
     * @return void
     */
    public static function setAllJournalsAsCompleted();

    /**
     * Write data into snapshot file
     *
     * @return void
     */
    public static function writeJournal($iterator, $extensions_to_watch, $exclude_dirs);

    /**
     * Get all timestamps of the available snapshots files
     *
     * @return array
     */
    public static function getAvailableJournals();

    /**
     * Get journal path by journal timestamp
     *
     * @param $journal string
     * @return string|null
     */
    public static function getJournal($journal);
}
