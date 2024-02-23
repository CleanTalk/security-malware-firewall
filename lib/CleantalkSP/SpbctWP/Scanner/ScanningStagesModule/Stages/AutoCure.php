<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class AutoCure extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $count_files = 0;
    public $count_cured = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Auto Cure', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Files ', 'security-malware-firewall')
               . $this->count_files
               . '; '
               . __('Cured ', 'security-malware-firewall')
               . $this->count_cured
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
            'count_cured' => $this->count_cured
        );
    }
}
