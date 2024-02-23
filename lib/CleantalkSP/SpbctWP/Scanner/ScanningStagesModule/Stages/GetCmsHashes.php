<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class GetCmsHashes extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $expected_count_hashes = 0;
    public $added_count_hashes = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Getting CMS hashes', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Expected hashes ', 'security-malware-firewall')
               . $this->expected_count_hashes
               . '; '
               . __('Added hashes ', 'security-malware-firewall')
               . $this->added_count_hashes
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'expected_count_hashes' => $this->expected_count_hashes,
            'added_count_hashes' => $this->added_count_hashes
        );
    }
}
