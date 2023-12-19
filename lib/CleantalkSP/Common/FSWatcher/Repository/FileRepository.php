<?php

namespace CleantalkSP\Common\FSWatcher\Repository;

use CleantalkSP\Common\FSWatcher\Controller;

/**
 * @psalm-suppress UnusedClass
 */
class FileRepository implements Repository
{
    /**
     * @inheritDoc
     */
    public static function getAvailableJournals()
    {
        $storage = Controller::$storage;
        return $storage::getAvailableJournals();
    }
}
