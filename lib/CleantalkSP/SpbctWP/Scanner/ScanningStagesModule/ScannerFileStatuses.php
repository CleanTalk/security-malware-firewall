<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule;

class ScannerFileStatuses
{
    /** @psalm-suppress UnusedProperty */
    private $statuses;
    /** @psalm-suppress UnusedProperty */
    private $unknown;
    /** @psalm-suppress UnusedProperty */
    private $ok;
    /** @psalm-suppress UnusedProperty */
    private $aproved;
    /** @psalm-suppress UnusedProperty */
    private $approved_by_ct;
    /** @psalm-suppress UnusedProperty */
    private $modified;
    /** @psalm-suppress UnusedProperty */
    private $infected;
    /** @psalm-suppress UnusedProperty */
    private $quarantined;

    public function __construct()
    {
        $this->unknown = 0;
        $this->ok = 0;
        $this->aproved = 0;
        $this->approved_by_ct = 0;
        $this->modified = 0;
        $this->infected = 0;
        $this->quarantined = 0;
        $this->statuses = array(
            'unknown'        => $this->unknown,
            'ok'             => $this->ok,
            'aproved'        => $this->aproved,
            'approved_by_ct' => $this->approved_by_ct,
            'modified'       => $this->modified,
            'infected'       => $this->infected,
            'quarantined'    => $this->quarantined,
        );
    }

    public function addStatus($status)
    {
        $status = strtolower($status);

        $this->statuses[$status]++;
    }

    public function getStatuses()
    {
        return $this->statuses;
    }
}
