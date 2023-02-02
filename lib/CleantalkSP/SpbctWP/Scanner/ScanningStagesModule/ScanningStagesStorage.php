<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule;

use CleantalkSP\SpbctWP\DB\DbDataConverter;

class ScanningStagesStorage
{
    /**
     * @var DbDataConverter
     */
    public $converter;

    public function __construct()
    {
        $db_converter = new DbDataConverter('spbc_scanning_stages');
        $this->converter = $db_converter;
    }

    public function getStage($class)
    {
        return $this->converter->getObject($class);
    }

    public function saveToDb()
    {
        $this->converter->saveToDb();
    }
}
