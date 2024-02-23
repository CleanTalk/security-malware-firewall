<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class OutboundLinks extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $total = 0;
    public $founded = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Outbound links', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Total scanned posts ', 'security-malware-firewall')
               . $this->total
               . '; '
               . __('Founded outbound links ', 'security-malware-firewall')
               . $this->founded
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'total' => $this->total,
            'founded' => $this->founded
        );
    }
}
