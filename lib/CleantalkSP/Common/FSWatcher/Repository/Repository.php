<?php

namespace CleantalkSP\Common\FSWatcher\Repository;

/**
 * @psalm-suppress PossiblyUnusedMethod
 */
interface Repository
{
    /**
     * Get all timestamps of the available snapshots
     *
     * @return array
     */
    public static function getAvailableJournals();
}
