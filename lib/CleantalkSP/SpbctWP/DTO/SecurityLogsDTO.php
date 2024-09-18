<?php

namespace CleantalkSP\SpbctWP\DTO;

use CleantalkSP\Templates\DTO;

class SecurityLogsDTO extends DTO
{
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $auth_key = '';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $method_name = 'security_logs';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $timestamp = '0';
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $data = '';
    /**
     * @var int
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $rows = 0;

    public function __construct($data)
    {
        $this->obligatory_properties = array('auth_key', 'method_name', 'timestamp', 'data', 'rows');
        parent::__construct($data);
        if ( empty($this->auth_key) ) {
            throw new \Exception(__CLASS__ . ': param "auth_key" is empty.');
        }
    }
}
