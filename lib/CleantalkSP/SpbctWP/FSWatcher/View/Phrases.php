<?php

namespace CleantalkSP\SpbctWP\FSWatcher\View;

class Phrases extends \CleantalkSP\Common\FSWatcher\View\Phrases
{
    public function getTitle()
    {
        return __('File System Watcher', 'security-malware-firewall');
    }
    public function getDescription()
    {
        global $spbc;

        $desc_days = $spbc->key_is_ok ? __('7 days.', 'security-malware-firewall') : __('1 day.', 'security-malware-firewall');

        return __('This feature runs filesystem snapshots on selected period and allows
        you to control which of your site files has been changed between selected dates. Snapshots are stored for ' . $desc_days, 'security-malware-firewall');
    }

    public function getExtendedTabDescription()
    {
        global $spbc;
        $link = '<a href="' . $spbc->settings_link . '&spbc_tab=settings_general#spbc_setting_scanner__fs_watcher">' . __('File System Watcher', 'security-malware-firewall') . '</a>';
        $phrase = sprintf(__('Snapshots frequency can be managed in the plugin settings: %s', 'security-malware-firewall'), $link);
        $phrase .= '&nbsp;';
        $phrase .= __('Also, you can run snapshot immediately by clicking the button below and refreshing this page after.', 'security-malware-firewall');
        return $phrase;
    }

    public function getSnapshotsPeriodDescription()
    {
        return __('Select how often the snapshots will be collected.', 'security-malware-firewall');
    }

    public function featureNotReady1()
    {
        return __('Snapshots were not ready.', 'security-malware-firewall');
    }
    public function featureNotReady2()
    {
        return __('Please wait while FS Journal will be ready to work.', 'security-malware-firewall');
    }
    public function getCompareButtonText()
    {
        return __('Compare', 'security-malware-firewall');
    }
    public function getCompareButtonDescription()
    {
        return __('To run comparison select dates which you want to compare and click the "Compare" button.', 'security-malware-firewall');
    }
    public function getCreateSnapshotButtonText()
    {
        return __('Create File System snapshot', 'security-malware-firewall');
    }
    public function getFirstDateLabel()
    {
        return __('First date', 'security-malware-firewall');
    }
    public function getSecondDateLabel()
    {
        return __('Second date', 'security-malware-firewall');
    }

    public function getTableHeadPath()
    {
        return __('Path', 'security-malware-firewall');
    }

    public function getTableHeadEvent()
    {
        return __('Event', 'security-malware-firewall');
    }

    public function getTableHeadChangeOn()
    {
        return __('Changed on date', 'security-malware-firewall');
    }

    public function getTableNoLogs()
    {
        return __('No logs compared yet.', 'security-malware-firewall');
    }

    public function getTranslations()
    {
        return [
            'fs_err_parse_json' => __('File System watcher JSON parse error: see console for details.', 'security-malware-firewall'),
            'fs_err_valid_result' => __('Please contact', 'security-malware-firewall'),
            'fs_err_resp_obj' => __('Response is invalid.', 'security-malware-firewall'),
            'fs_err_property' => __('Response has no required properties.', 'security-malware-firewall'),
            'fs_modal' => __('Content of', 'security-malware-firewall'),
            'fs_no_changes' => __('No changes detected on selected dates', 'security-malware-firewall'),
            'fs_comparing' => __('Comparing log', 'security-malware-firewall'),
            'fs_with' => __('with log', 'security-malware-firewall'),
            'fs_total' => __('total count of different files', 'security-malware-firewall'),
        ];
    }
}
