<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class FrontendAnalysis extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $total = 0;
    public $total_site_pages = 0;
    public $success = 0;
    public $processed = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Frontend analysis', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Total site pages ', 'security-malware-firewall')
               . $this->total_site_pages
               . '; '
               . __('Total pages scanned ', 'security-malware-firewall')
               . $this->total
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
            'total_site_pages' => $this->total_site_pages,
            'success' => $this->success,
            'processed' => $this->processed
        );
    }
}
