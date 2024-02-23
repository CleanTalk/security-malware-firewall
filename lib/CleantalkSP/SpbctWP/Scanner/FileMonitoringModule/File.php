<?php

namespace CleantalkSP\SpbctWP\Scanner\FileMonitoringModule;

class File
{
    public $id = null;
    /**
     * @var mixed
     */
    public $path;
    /**
     * @var string
     */
    public $path_hash;
    /**
     * @var int
     */
    public $started_at;
    /**
     * @var false|string|null
     */
    public $content_hash;

    public function __construct($system_file_path)
    {
        $this->path = $system_file_path;
        $this->path_hash = md5($system_file_path);
        $this->started_at = time();
        $this->content_hash = file_exists($system_file_path) ? md5_file($system_file_path) : null;
    }
}
