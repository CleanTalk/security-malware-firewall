<?php

namespace CleantalkSP\SpbctWP\FSWatcher\View;

use CleantalkSP\SpbctWP\FSWatcher\SpbctWpFSWController;
use CleantalkSP\Common\FSWatcher\View\Phrases;
use CleantalkSP\SpbctWP\FSWatcher\SpbctWpFSWService;

class View extends \CleantalkSP\Common\FSWatcher\View\View
{
    public static function renderSelectors(\CleantalkSP\Common\FSWatcher\View\Phrases $phrases)
    {
        $html = '<div class="spbc_tab_fields_group">';
        $html .= '<div class="spbc_group_header">';
        $html .= '<h3>' . $phrases->getTitle() . '</h3>';
        $html .= '</div>';

        $html .= '<div style="padding: 0 0 0 10px">';
        $html .= '<p>' . self::getFSWatcherDescription($phrases) . '</p>';
        $html .= '<p>' . self::getExtendedTabDescription($phrases) . '</p>';

        $repository = SpbctWpFSWController::$storage;
        $dates = $repository::getAvailableJournals();

        $html .= self::manualSnapshotButton($phrases);

        if ( ! static::snapshotsAreReady($dates) ) {
            // Snapshots were not ready, do not render selectors
            $html .= '<p>' . $phrases->featureNotReady1() . '</p>';
            $html .= '<p>' . $phrases->featureNotReady2() . '</p>';
        }

        $display_selectors = static::snapshotsAreReady($dates) ? 'block' : 'none';
        $html .= '<div style="display:' . $display_selectors  . '">';
        $html .= '<p>' . $phrases->getCompareButtonDescription() . '</p>';
        $html .= '<div style="display: flex;flex-wrap: wrap;gap: 16px;">';

        $html .= '<div style="display: block;">';
        $html .= '<label style="display: block" for="fswatcher__first_date">' . $phrases->getFirstDateLabel() . '</label>';
        $html .= '<select name="fswatcher__first_date" id="fswatcher__first_date">';
        $html .= parent::renderSelectorOptions($dates);
        $html .= '</select>';
        $html .= '</div>';

        $html .= '<div style="display: block;">';
        $html .= '<label style="display: block" for="fswatcher__second_date">' . $phrases->getSecondDateLabel() . '</label>';
        $html .= '<select name="fswatcher__second_date" id="fswatcher__second_date">';
        $html .= parent::renderSelectorOptions($dates);
        $html .= '</select>';
        $html .= '</div>';

        $html .= '</div>';
        $html .= '</br>';
        $html .= '</br>';

        $html .= '<div>';
        $html .= '<button class="spbc-icon-exchange" id="fswatcher__compare" onclick="return false;">' . $phrases->getCompareButtonText() . '</button>';
        $html .= '<img style="display: none; margin-left: 10px; margin-top: 1px; width: 16px;" id="fsw_preloader_compare" src="../../wp-content/plugins/security-malware-firewall/images/preloader2.gif"';
        $html .= '</br>';
        $html .= '</br>';
        $html .= '</br>';
        $html .= '</div>';
        $html .= '</div>';

        $html .= '</div>';

        $html .= '<script type="text/javascript">';
        $html .= 'var fswatcherToken = "' . SpbctWpFSWService::generateFsWatcherToken() . '";';
        $html .= 'var fswatcherWebsiteUrl = "' . get_home_url() . '";';
        $html .= file_get_contents(\CleantalkSP\Common\FSWatcher\Storage\FileStorage::getAssetsPath());
        $html .= 'var fswatcherTranslations = ' . json_encode($phrases->getTranslations()) . ';';
        $html .= '</script>';
        $html .= '</div>';

        $html .= '</br>';

        $html .= parent::renderTableTemplate($phrases);

        $html .= '<div id="spbc_dialog" title="File output" style="overflow: initial;"></div>';

        return $html;
    }

    public static function getFSWatcherDescription(Phrases $phrases)
    {
        return $phrases->getDescription();
    }

    public static function getFSWatcherSnapshotsPeriodDescription(Phrases $phrases)
    {
        return $phrases->getSnapshotsPeriodDescription();
    }

    public static function getExtendedTabDescription(Phrases $phrases)
    {
        return $phrases->getExtendedTabDescription();
    }

    protected static function manualSnapshotButton(Phrases $phrases)
    {
        $html = '<div>';
        $html .= '<button class="spbc-icon-download" id="fswatcher__create_snapshot" onclick="return false;">' . $phrases->getCreateSnapshotButtonText() . '</button>';
        $html .= '<img style="display: none; margin-left: 10px; margin-top: 1px; width: 16px;" id="fsw_preloader_create" src="../../wp-content/plugins/security-malware-firewall/images/preloader2.gif"';
        $html .= '</div>';

        return $html;
    }
}
