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
     */
    public $content;
    /**
     * @var array|mixed
     */
    public $weak_spots;

    public function __construct($path = '', $content = '')
    {
        $this->path = $path;
        $this->content = $content;
    }
}
