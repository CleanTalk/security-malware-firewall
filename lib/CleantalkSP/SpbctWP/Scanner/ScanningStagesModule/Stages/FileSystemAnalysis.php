<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class FileSystemAnalysis extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $scanned_count_files = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('File System Analysis', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Scanned files ', 'security-malware-firewall')
               . $this->scanned_count_files
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'scanned_count_files' => $this->scanned_count_files
        );
    }
}
