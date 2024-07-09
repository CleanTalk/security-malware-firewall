<?php

namespace CleantalkSP\SpbctWP\FeatureRestriction;

use CleantalkSP\SpbctWP\State;

class FeatureRestrictionService
{
    /**
     * @var FeatureRestriction[]
     */
    public $restrictions;

    /**
     * Construct service. Init all the restrictions.
     */
    public function __construct()
    {
        $this->restrictions = $this->initRestrictions();
    }

    /**
     * @return FeatureRestriction[]
     */
    public function initRestrictions()
    {
        $restrictions[] = new FeatureRestriction('firewall_log', true, true);
        $restrictions[] = new FeatureRestriction('scanner', true, true);
        $restrictions[] = new FeatureRestriction('security_log', true, true);
        $restrictions[] = new FeatureRestriction('fswatcher', true, true);
        $restrictions[] = new FeatureRestriction('critical_updates', true, true);
        $restrictions[] = new FeatureRestriction('backups', true, true);
        return $restrictions;
    }


    /**
     * Get the state of a feature for the given SPBC state and feature name.
     *
     * @param State $spbc Global SPBC State object
     * @param string $feature_name The name of the feature.
     * @return FeatureRestrictionState The state of the feature.
     * @throws \Exception If called restriction name is not registered
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function getState($spbc, $feature_name)
    {
        $result = new FeatureRestrictionState();

        $current_feature_restrictions = $this->getRestrictionByName($feature_name);

        if ( !$current_feature_restrictions) {
            throw new \Exception(__CLASS__ . ' error: Feature restriction name is not registered! ' . $feature_name);
        }

        if ( ! $spbc->key_is_ok ) {
            if ($current_feature_restrictions->on_key_fail) {
                $result->is_active = false;
                $result->info_html = FeatureRestrictionView::keyNotValid();
            }
        } elseif ( ! $spbc->moderate ) {
            if ( $current_feature_restrictions->on_moderate_fail ) {
                $result->is_active = false;
                if ( $spbc->data['key_changed'] ) {
                    // Here we need to check if the key was changed and the plugin is waiting for the sync.
                    $result->info_html = FeatureRestrictionView::waitForSync();
                } else {
                    $result->info_html = FeatureRestrictionView::renewNotice();
                }
            }
        }
        return $result;
    }


    /**
     * Get the restriction by name.
     *
     * @param string $name The name of the restriction to retrieve.
     *
     * @return FeatureRestriction|false The found restriction object if the name matches, or false if no restriction was found.
     */
    private function getRestrictionByName($name)
    {
        foreach ($this->restrictions as $restriction) {
            if ($restriction->name === $name) {
                return $restriction;
            }
        }
        return false;
    }
}
