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
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty //todo if we decide to save heuristic re-check fails - we should use this property
     */
    public $heuristic_rescan_result = null;

    protected $obligatory_properties = [
        'fast_hash',
        'real_path',
        'cured',
        'cci_cured',
        'fail_reason',
        'last_cure_date',
        'scanner_start_local_date',
        'heuristic_rescan_result'
    ];

    public function __construct($data)
    {
        parent::__construct($data);
    }
}
