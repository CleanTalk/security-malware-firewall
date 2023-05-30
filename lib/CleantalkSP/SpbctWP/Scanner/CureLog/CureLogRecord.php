<?php

namespace CleantalkSP\SpbctWP\Scanner\CureLog;

use CleantalkSP\Templates\DTO;

class CureLogRecord extends DTO
{
    /**
     * @var string
     */
    public $fast_hash = '';
    /**
     * @var string
     */
    public $real_path = '';
    /**
     * @var int
     */
    public $cured = 0;
    /**
     * @var int
     */
    public $has_backup = 0;
    /**
     * @var int
     */
    public $cci_cured = 0;
    /**
     * @var string
     */
    public $fail_reason = '';
    /**
     * @var int
     */
    public $last_cure_date = 0;
    /**
     * @var string
     */
    public $scanner_start_local_date = '';

    protected $obligatory_properties = [
        'fast_hash',
        'real_path',
        'cured',
        'cci_cured',
        'fail_reason',
        'last_cure_date',
        'scanner_start_local_date'
    ];

    public function __construct($data)
    {
        parent::__construct($data);
    }
}
