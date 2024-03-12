<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\FileInfo;

class FileInfoExtended extends FileInfo
{
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $source_type;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $source;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $version;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $status;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $checked_heuristic;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $checked_signatures;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $fast_hash;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $real_full_hash;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $difference;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $severity;
    /**
     * @var mixed|null
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $size;

    /**
     * @param array $file
     */
    public function __construct($file)
    {
        parent::__construct($file['path']);
        $this->source_type = isset($file['source_type']) ? $file['source_type'] : null;
        $this->source = isset($file['source']) ? $file['source'] : null;
        $this->version = isset($file['version']) ? $file['version'] : null;
        $this->status = isset($file['status']) ? $file['status'] : null;
        $this->checked_heuristic = isset($file['checked_heuristic']) ? $file['checked_heuristic'] : null;
        $this->checked_signatures = isset($file['checked_signatures']) ? $file['checked_signatures'] : null;
        $this->fast_hash = isset($file['fast_hash']) ? $file['fast_hash'] : null;
        $this->real_full_hash = isset($file['real_full_hash']) ? $file['real_full_hash'] : null;
        $this->weak_spots = isset($file['weak_spots']) ? $file['weak_spots'] : array();
        $this->difference = isset($file['difference']) ? $file['difference'] : null;
        $this->severity = isset($file['severity']) ? $file['severity'] : null;
        $this->size = isset($file['size']) ? $file['size'] : null;
    }
}
