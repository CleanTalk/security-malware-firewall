<?php

namespace CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures;

class FileInfo
{
    /**
     * @var string
     */
    public $path;

    /**
     * hash_file()
     * @see https://www.php.net/manual/function.hash-file.php
     * @var string
     */
    public $full_hash;

    /**
     * @var array|string array or json
     */
    public $weak_spots;

    /**
     * @param $path
     * @param $full_hash
     * @param $weak_spots
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function __construct($path, $full_hash, $weak_spots = '')
    {
        $this->path = $path;
        $this->full_hash = $full_hash;
        if ( $weak_spots ) {
            $this->weak_spots = $weak_spots;
        }
    }
}
