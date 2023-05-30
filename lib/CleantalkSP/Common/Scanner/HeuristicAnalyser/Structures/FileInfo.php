<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures;

class FileInfo
{
    /**
     * @var string
     */
    public $path;

    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $content;
    /**
     * @var array|mixed
     */
    public $weak_spots;

    /**
     * @param $path
     * @param $content
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function __construct($path = '', $content = '')
    {
        $this->path = $path;
        $this->content = $content;
    }
}
