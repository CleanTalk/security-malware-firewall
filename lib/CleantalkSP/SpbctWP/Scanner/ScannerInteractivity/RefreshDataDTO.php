<?php

namespace CleantalkSP\SpbctWP\Scanner\ScannerInteractivity;

use CleantalkSP\Templates\DTO;

class RefreshDataDTO extends DTO
{
    public $do_refresh = false;
    public $control_tab = '';

    protected $obligatory_properties = array(
        'do_refresh',
        'control_tab',
    );

    /**
     * @throws \Exception
     */
    public function __construct($data)
    {
        parent::__construct($data);
    }
}
