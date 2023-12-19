<?php

namespace CleantalkSP\SpbctWP\FSWatcher\Repository;

use CleantalkSP\SpbctWP\FSWatcher\SpbctWpFSWController;
use CleantalkSP\Common\FSWatcher\Repository\Repository;

/**
 * @psalm-suppress UnusedClass
 */
class SpbctWpFSWFileRepository implements Repository
{
    /**
     * @inheritDoc
     */
    public static function getAvailableJournals()
    {
        $storage = SpbctWpFSWController::$storage;
        return $storage::getAvailableJournals();
    }
}
