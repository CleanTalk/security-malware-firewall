<?php

namespace CleantalkSP\SpbctWP\Scanner;

class IteratorResult
{
    /**
     * Set path of dir when the iterator reach files limit.
     * @var string
     */
    public $on_exit_dir_path = '';

    /**
     * Files offset on the dir when the iterator reach files limit.
     * @var int
     */
    public $on_exit_dir_offset = 0;

    /**
     * Already completed dirs. Cleans up on every stage iteration, the new set will be set from the database.
     * @var array
     */
    public $completed_dirs = array();

    /**
     * Has the iterator been interrupted on reach files limit.
     * @var bool
     */
    public $max_files_interrupt = false;

    /**
     * Is stage is ended.
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $is_stage_end = false;

    public function __construct()
    {
    }
}
