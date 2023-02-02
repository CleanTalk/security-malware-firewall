<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class GetApprovedHashes extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $count_approved_hashes = 0;
    public $count_approved_hashes_in_db = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Getting approved hashes', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Approved hashes ', 'security-malware-firewall')
               . $this->count_approved_hashes
               . '; '
               . __('Approved hashes in db ', 'security-malware-firewall')
               . $this->count_approved_hashes_in_db
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'count_approved_hashes' => $this->count_approved_hashes,
            'count_approved_hashes_in_db' => $this->count_approved_hashes_in_db
        );
    }
}
