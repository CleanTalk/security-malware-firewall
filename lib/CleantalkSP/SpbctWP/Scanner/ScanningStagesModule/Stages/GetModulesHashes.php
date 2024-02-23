<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class GetModulesHashes extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $count_plugins = 0;
    public $count_themes = 0;
    public $count_plugins_without_hashes = 0;
    public $count_themes_without_hashes = 0;

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Getting modules hashes', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Plugins ', 'security-malware-firewall')
               . $this->count_plugins
               . '; '
               . __('Themes ', 'security-malware-firewall')
               . $this->count_themes
               . '; '
               . __('Plugins without hashes ', 'security-malware-firewall')
               . $this->count_plugins_without_hashes
               . '; '
               . __('Themes without hashes ', 'security-malware-firewall')
               . $this->count_themes_without_hashes
               . '.';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'count_plugins' => $this->count_plugins,
            'count_themes' => $this->count_themes,
            'count_plugins_without_hashes' => $this->count_plugins_without_hashes,
            'count_themes_without_hashes' => $this->count_themes_without_hashes
        );
    }
}
