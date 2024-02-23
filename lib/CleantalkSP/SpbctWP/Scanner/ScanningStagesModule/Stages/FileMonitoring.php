<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class FileMonitoring extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $count_files = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('File Monitoring', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Count Files ', 'security-malware-firewall')
               . $this->count_files
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'count_files' => $this->count_files,
        );
    }
}
