<?php

namespace CleantalkSP\SpbctWP\Scanner\Frontend;

use CleantalkSP\Templates\DTO;

/**
 * @psalm-suppress PossiblyUnusedProperty
 */
class ModuleResult extends DTO
{
    public $type = '';

    public $line = 0;

    public $found = '';

    public $surroundings = '';

    public $comment = '';

    public $needle;

    protected $obligatory_properties = [
        'type',
        'found',
        'surroundings',
    ];
}
