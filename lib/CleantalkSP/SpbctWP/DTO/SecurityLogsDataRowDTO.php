<?php

namespace CleantalkSP\SpbctWP\DTO;

use CleantalkSP\Templates\DTO;

class SecurityLogsDataRowDTO extends DTO
{
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $log_id = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $datetime = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $datetime_gmt = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $user_log = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $event = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $auth_ip = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $page_url = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $event_runtime = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $role = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $user_agent = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $browser_signature = '';

    public function __construct($data)
    {
        $this->obligatory_properties = array(
            'log_id',
            'datetime',
            'datetime_gmt',
            'user_log',
            'event',
            'auth_ip',
            'page_url',
            'event_runtime',
            'role'
        );
        parent::__construct($data);
        if ( (strlen($this->event) > 16) ) {
            throw new \Exception(__CLASS__ . ': param "view" value is more than 16 characters');
        }
    }
}
