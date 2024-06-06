<?php

namespace CleantalkSP\Common\FSWatcher\View;

use CleantalkSP\Common\FSWatcher\Controller;
use CleantalkSP\Common\FSWatcher\Logger;
use CleantalkSP\Common\FSWatcher\Service;

class View
{
    public static function getFSWatcherDescription(Phrases $phrases)
    {
        return $phrases->getDescription();
    }

    public static function renderSelectors(Phrases $phrases)
    {
        $html = '<div class="spbc_tab_fields_group">';
        $html .= '<div class="spbc_group_header">';
        $html .= '<h3>' . $phrases->getTitle() . '</h3>';
        $html .= '</div>';

        $html .= '<div style="padding: 0 0 0 10px">';
        $html .= '<p>' . self::getFSWatcherDescription($phrases) . '</p>';

        $repository = Controller::$repository;
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
        $html .= '<label style="display: block" for="fswatcher__first_date">' . $phrases->getFirstDateLabel() . '</label>';
        $html .= '<select name="fswatcher__first_date" id="fswatcher__first_date">';
        $html .= self::renderSelectorOptions($dates);
        $html .= '</select>';
        $html .= '</br>';
        $html .= '</br>';

        $html .= '<label style="display: block" for="fswatcher__second_date">' . $phrases->getSecondDateLabel() . '</label>';
        $html .= '<select name="fswatcher__second_date" id="fswatcher__second_date">';
        $html .= self::renderSelectorOptions($dates);
        $html .= '</select>';
        $html .= '</br>';
        $html .= '</br>';

        $html .= '<div>';
        $html .= '<button class="spbc-icon-exchange" id="fswatcher__compare" onclick="return false;">' . $phrases->getCompareButtonText() . '</button>';
        $html .= '</div>';
        $html .= '</br>';
        $html .= '</div>';

        $html .= '</div>';

        $html .= '<script type="text/javascript">';
        $html .= 'var fswatcherToken = "' . Service::generateFsWatcherToken() . '";';
        $html .= 'var fswatcherWebsiteUrl = "' . get_home_url() . '";';
        $html .= file_get_contents(__DIR__ . '/../assets/fswatcher-logic.js');
        $html .= '</script>';
        $html .= '</div>';

        $html .= '</br>';

        $html .= self::renderTableTemplate($phrases);

        return $html;
    }

    protected static function renderSelectorOptions($dates)
    {
        Logger::log($dates);

        $html = '';
        foreach ($dates as $date) {
            $formated_date = date('M d Y H:i:s', $date);
            $html .= '<option value="' . $date . '">' . $formated_date . '</option>';
        }

        return $html;
    }

    protected static function manualSnapshotButton(Phrases $phrases)
    {
        $html = '<div>';
        $html .= '<button class="spbc-icon-download" id="fswatcher__create_snapshot" onclick="return false;">' . $phrases->getCreateSnapshotButtonText() . '</button>';
        $html .= '</div>';

        return $html;
    }

    protected static function renderTableTemplate(Phrases $phrases)
    {
        $html = '<div class="ui-accordion" id="spbc--fs-watcher-table-div">';
        $html .= '<p class="spbc_short_text_field" id="spbc--fs-watcher-table-handling-selects-info" style="display: none"></p>';
        $html .= '<table class="wp-list-table widefat fixed striped">';

        $html .= '<thead>';
        $html .=    '<tr>';
        $html .=        '<th>';
        $html .=        $phrases->getTableHeadPath();
        $html .=        '</th>';
        $html .=        '<th>';
        $html .=        $phrases->getTableHeadEvent();
        $html .=        '</th>';
        $html .=        '<th>';
        $html .=        $phrases->getTableHeadChangeOn();
        $html .=        '</th>';
        $html .=    '</tr>';
        $html .= '</thead>';

        $html .= '<tbody id="spbc-table-fs_watcher-comparison">';
        $html .=    '<tr id="spbc-tr-default-comparison-result">';
        $html .=        '<td colspan="3">';
        $html .=        $phrases->getTableNoLogs();
        $html .=        '</td>';
        $html .=    '</tr>';
        $html .= '</tbody>';

        $html .= '</table>';
        $html .= '</div>';

        return $html;
    }

    protected static function snapshotsAreReady($dates)
    {
        return is_array($dates) && count($dates) > 1;
    }
}
