<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\DTO;

use CleantalkSP\Templates\DTO;

class SendBackupDTO extends DTO
{
    /**
     * @var string
     */
    public $api_key = '';

    /**
     * @var string
     */
    public $repair_result = '';

    /**
     * @var string
     */
    public $repair_comment = '';

    /**
     * @var array
     */
    public $repaired_processed_files = [];

    /**
     * @var int
     */
    public $repaired_total_files_processed = 0;

    /**
     * @var int
     */
    public $backup_id = 0;

    /**
     * @var int
     */
    public $scanner_last_start_local_date = 0;

    protected $obligatory_properties = [
        'api_key',
        'repair_result',
        'repair_comment',
        'repaired_processed_files',
        'repaired_total_files_processed',
        'backup_id',
    ];
}
