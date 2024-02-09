<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class ScheduleSendHeuristicSuspiciousFiles extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $count_scheduled = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Schedule suspicious files sending for analysis', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Scheduled for send ', 'security-malware-firewall')
               . $this->count_scheduled
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'count_scheduled' => $this->count_scheduled
        );
    }
}
