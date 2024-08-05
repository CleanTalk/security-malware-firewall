<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages\DTO;

use CleantalkSP\Templates\DTO;

/**
 * @psalm-suppress PossiblyUnusedProperty
 */
class SendFilesDTO extends DTO
{
    /**
     * @var string
     */
    public $api_key = '';

    /**
     * @var int
     */
    public $service_id = 0;

    /**
     * @var int
     */
    public $list_unknown = 0;

    /**
     * @var int
     */
    public $scanner_last_start_local_date = 0;

    /**
     * @var string
     */
    public $scan_type = '';

    /**
     * @var string
     */
    public $scanner_result = '';

    /**
     * @var int
     */
    public $total_core_files = 0;

    /**
     * @var int
     */
    public $total_site_files = 0;

    /**
     * @var int
     */
    public $total_scan_files = 0;

    /**
     * @var int
     */
    public $total_site_pages = 0;

    /**
     * @var int
     */
    public $scanned_site_pages = 0;

    /**
     * @var string
     */
    public $remote_calls_check = '';

    /**
     * @var int
     */
    public $checksum_count_ct = 0;

    /**
     * @var int
     */
    public $checksum_count_user = 0;

    /**
     * @var int
     */
    public $signatures_count = 0;

    /**
     * @var int
     */
    public $signatures_found = 0;

    /**
     * @var array
     */
    public $critical = [];

    /**
     * @var array
     */
    public $suspicious = [];

    /**
     * @var array
     */
    public $unknown = [];

    /**
     * @var string
     */
    public $failed_files = '';

    /**
     * @var int
     */
    public $failed_files_rows = 0;

    /**
     * @var string
     */
    public $suspicious_files = '';

    /**
     * @var int
     */
    public $suspicious_files_rows = 0;

    protected $obligatory_properties = [
        'api_key',
        'service_id',
        'list_unknown'
    ];
}
