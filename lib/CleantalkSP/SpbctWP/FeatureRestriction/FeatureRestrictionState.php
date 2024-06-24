<?php

namespace CleantalkSP\SpbctWP\FeatureRestriction;

/**
 * Class FeatureRestrictionState
 *
 * Represents the restriction state of a feature.
 */
class FeatureRestrictionState
{
    /**
     * @var bool
     * @psalm-suppress PossiblyUnusedProperty
     */
    public $is_active;
    /**
     * @var string
     */
    public $info_html;

    /**
     * Constructor method for the class.
     *
     * @param bool $is_active (Optional) The flag to indicate if the object is active. Defaults to true.
     * @param string $info_html (Optional) The HTML information string. Defaults to an empty string.
     * @return void
     */
    public function __construct($is_active = true, $info_html = '')
    {
        $this->is_active = isset($is_active) ? (bool) $is_active : true;
        $this->info_html = isset($info_html) ? $info_html : '';
    }

    /**
     * Sanitizes and escapes HTML output.
     *
     * This method uses the escKsesPreset() function from the Escape class
     * to sanitize and escape the given HTML output.
     *
     * @return string The sanitized and escaped HTML output.
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function sanitizedReasonOutput()
    {
        return \CleantalkSP\SpbctWP\Escape::escKsesPreset(
            $this->info_html,
            'spbc_settings__feature_restrictions',
            array(),
            array('display')
        );
    }
}
