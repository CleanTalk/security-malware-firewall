<?php

namespace CleantalkSP\SpbctWP\FeatureRestriction;

use CleantalkSP\SpbctWP\LinkConstructor;

class FeatureRestrictionView
{
    /**
     * Returns a formatted string indicating that the plugin does not work until the access key is entered in the general settings
     *
     * @return string A formatted HTML string
     */
    public static function keyNotValid()
    {
        return '<div style="margin: 10px auto; text-align: center;"><h3 style="margin: 5px; display: inline-block;">'
            . __('Plugin does not work until you enter the Access key in ', 'security-malware-firewall')
            . '<a href="/wp-admin/options-general.php?page=spbc&spbc_tab=settings_general">'
            . __('General settings', 'security-malware-firewall')
            . '</a>.</h3></div>';
    }

    /**
     * Wait for synchronization to complete.
     *
     * This method displays a message asking the user to wait a few seconds while the account data is being pulled from the cloud.
     *
     * @return string The HTML markup for the message.
     */
    public static function waitForSync()
    {
        return '<div style="margin-top: 10px;">'
            . '<h3 style="margin: 5px; display: inline-block;">' . __('Please give us a few seconds to pull account data from the cloud.', 'security-malware-firewall') . '</h3>' .
            '</div>';
    }

    /**
     * Display a renewal notice.
     *
     * This method generates an HTML markup for a renewal notice.
     *
     * @return string The HTML markup for the renewal notice.
     */
    public static function renewNotice()
    {
        global $spbc;
        $renew_text = __('Renew your license, unlock all Security features and join to 30k+ WordPress users who trust CleanTalk!', 'security-malware-firewall');
        $button_text = __('Renew Security license', 'security-malware-firewall');
        $link_tag = linkConstructor::buildRenewalLinkATag(
            $spbc->user_token,
            sprintf('<input type="button" class="button button-primary" value="%s"/>', $button_text),
            4,
            'renew_notice_service_restricted'
        );
        $features_list_template = '<ul style="
                    list-style: none;
                    display: flex;
                    flex-wrap: wrap;
                    align-content: center;
                    flex-direction: column;
                    text-align: left;
                    ">
                        <li class="spbc-icon-ok">%s</li>
                        <li class="spbc-icon-ok">%s</li>
                        <li class="spbc-icon-ok">%s</li>
                        <li class="spbc-icon-ok">%s</li>
                        <li class="spbc-icon-ok">%s</li>
                        <li class="spbc-icon-ok">%s</li>
                        <li class="spbc-icon-ok">%s</li>
                    </ul>
            ';
        $features_list_template = sprintf(
            $features_list_template,
            __('Daily, background Malware scans. Immediate notifications.', 'security-malware-firewall'),
            __('Security FireWall by IPs, Subnets, Countries.', 'security-malware-firewall'),
            __('Web Application FireWall.', 'security-malware-firewall'),
            __('Brute Force protection & User Actions Log (Audit).', 'security-malware-firewall'),
            __('Weekly security report', 'security-malware-firewall'),
            __('Site Security logs up to 45 days.', 'security-malware-firewall'),
            __('Tech Support 24/7.', 'security-malware-firewall')
        );
        $notice_template = '
                <div style="text-align: center">
                    <div style="margin-top: 20px; margin-bottom: 20px; ">
                        <h3 style="margin: 5px; ">%s</h3>
                    </div>
                    <div style="margin-top: 20px; margin-bottom: 20px; ">
                        %s
                    </div>                
                    <div>
                        %s
                    </div>
                </div>
            ';
        return sprintf(
            $notice_template,
            $renew_text,
            $link_tag,
            $features_list_template
        );
    }
}
