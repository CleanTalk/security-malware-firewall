<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class GetDeniedHashes extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $count_denied_hashes = 0;
    public $count_denied_hashes_in_db = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Getting denied hashes', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Denied hashes ', 'security-malware-firewall')
               . $this->count_denied_hashes
               . '; '
               . __('Denied hashes in db ', 'security-malware-firewall')
               . $this->count_denied_hashes_in_db
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'count_denied_hashes' => $this->count_denied_hashes,
            'count_denied_hashes_in_db' => $this->count_denied_hashes_in_db
        );
    }
}
