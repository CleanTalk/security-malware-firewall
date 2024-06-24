<?php

namespace CleantalkSP\SpbctWP\FeatureRestriction;

class FeatureRestriction
{
    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $name;
    /**
     * @var bool
     */
    public $on_moderate_fail;
    /**
     * @var bool
     */
    public $on_key_fail;

    /**
     * @param string $name
     * @param bool $on_moderate_fail
     * @param bool $on_key_fail
     */
    public function __construct($name, $on_moderate_fail = false, $on_key_fail = false)
    {
        $this->name = $name;
        $this->on_moderate_fail = isset($on_moderate_fail) ? (bool) $on_moderate_fail : false;
        $this->on_key_fail = isset($on_key_fail) ? (bool) $on_key_fail : false;
    }
}
