<?php

namespace CleantalkSP\SpbctWP\Views;

use CleantalkSP\SpbctWP\VulnerabilityAlarm\VulnerabilityAlarmView;
use CleantalkSP\Variables\Server;

class Settings
{
    public static function tabs()
    {
        global $spbc;

        $display_debug = in_array(Server::getDomain(), array(
                'lc',
                'loc',
                'lh',
                'wordpress'
            )) || $spbc->debug || $spbc->show_debug;

        $data = [
            "criticalCount" => $spbc->key_is_ok ? $spbc->data['display_scanner_warnings']['critical'] : "",
            "vulnerabilitiesCount" => $spbc->key_is_ok ? VulnerabilityAlarmView::getCountOfCurrnetlyVulnerableModules() : "",
            "keyIsOk" => $spbc->key_is_ok,
            "displayDebug" => $display_debug,
            "isWPMSMainSite" => is_main_site(),
            "isSecFWEnabled" => $spbc->settings['secfw__enabled'],
            "isFsWatcherEnabled" => $spbc->settings['scanner__fs_watcher'],
            "isVulnerabilityCheckEnabled" => $spbc->settings['vulnerability_check__enable_cron'],
        ];

        echo '<div id="spbct-page-tabs--react" data-data=\'' . json_encode($data) . '\'></div>';
    }

    public static function page($id_element = false)
    {
        global $spbc;

        if (is_network_admin()) {
            self::earlyOutput();
            return;
        }
        $class_element = '';
        $id_react_element_default = 'spbct-page--react';

        $id_react_element_mob_about_ct = 'spbct-page-mob-about-ct--react';
        $class_element_mob_about_ct = 'spbc_page_mob_info__about_block';

        switch ($id_element) {
            case 'mob_about_ct':
                $id_element = $id_react_element_mob_about_ct;
                $class_element = $class_element_mob_about_ct;
                break;

            default:
                $id_element = $id_react_element_default;
                break;
        }

        self::checkPhpVersion();
        self::checkMemoryLimit();

        $spbct_page_data = [
            // left corner section
            'brandname' => $spbc->data["wl_brandname"],
            'adminsOnlineCount' => self::getAdminsOnline(),
            'nextScanLaunchTime' => spbc_get_next_scan_launch_time_text(),

            // right corner section
            'supportLink' => self::getSupportLink(),
            'homepage' => self::generatePreNamedHref(
                $spbc->data["wl_url"],
                __('Plugin Homepage', 'security-malware-firewall')
            ),
            'gdprComplianceLink' => self::getGDPRComplianceEventLink(),
            'gdprModalWindow' => self::getGDPRModalWindow(),
            'twoFactorAuth' => self::get2FADialog(),
            //todo We should not use the brand name to tell this is registered trademark. We are not sure.
            'trademark' => $spbc->data["wl_brandname"] . __(' is a registered trademark. All rights reserved.', 'security-malware-firewall'),
            'feedback' => self::getFeedbackRequest(),
            'premium' => self::getPremiumLink(),
            'malwareCleaning' => self::generatePreNamedHref(
                'https://l.cleantalk.org/website-malware-removal',
                __('Malware cleaning', 'security-malware-firewall')
            ),
            // buttons
            'goToCleanTalkLink' => esc_html(self::goToCleantalkLink()),
            'goToCleanTalkText' => __('Security Dashboard', 'security-malware-firewall'),
            'support2Link' => esc_html(self::support2Link()),
            'support2Text' => __('Support', 'security-malware-firewall'),
            'sync' => spbc_api_key__is_correct() ? __('Synchronize with Cloud', 'security-malware-firewall') : '',
            'syncProgress' => __('Synchronizing with Сloud', 'security-malware-firewall'),
            'syncUrl' => SPBC_PATH . "/images/preloader2.gif",
            'syncUrlProgress' => SPBC_PATH . "/images/yes.png",

            // errors
            'spbcErrors' => spbc_settings__error__output(),
        ];
        echo '<div id="' . $id_element . '" data-data=\'' . json_encode($spbct_page_data) . '\' class="' . $class_element . '"></div>';
    }

    private static function getAdminsOnline()
    {
        global $spbc;
        $authorized_admins = spbc_get_authorized_admins(true);
        $admin_names_online = !empty($authorized_admins)
            ? implode(',', $authorized_admins)
            : 'n/a';
        $caption = __('Admins_online', 'security-malware-firewall');
        $out = sprintf(
            '<a href="options-general.php?page=spbc&spbc_tab=security_log">%s</a>
                    <span style="padding-left: 2px">%d</span>
                    <i class="spbc-icon-help-circled" title="%s"></i>',
            $caption,
            $spbc->counter__admins_online,
            $admin_names_online
        );
        return $out;
    }

    private static function getPremiumLink()
    {
        return spbc_badge__get_premium(false, true);
    }

    private static function getSupportLink()
    {
        global $spbc;

        $support_link = '<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall/">wordpress.org</a>.';
        if ($spbc->data["wl_mode_enabled"]) {
            $support_link = '<a target="_blank" href="' . $spbc->data["wl_support_url"] . '">' . $spbc->data["wl_brandname"] . '</a>.';
        }

        $html = '<span>%s&nbsp%s</span>';
        $html = sprintf(
            $html,
            __('Tech support of ' . $spbc->data["wl_brandname"], 'security-malware-firewall'),
            $support_link
        );
        return $html;
    }

    private static function generatePreNamedHref($url, $name_before_href)
    {
        return sprintf(
            '<span>%s&nbsp<a href="%s" target="_blank">%s</a></span>',
            $name_before_href,
            $url,
            $url
        );
    }

    private static function earlyOutput()
    {
        $link = get_site_option('siteurl') . 'wp-admin/options-general.php?page=spbc';
        $msg = sprintf("<h2>" . __("Please, enter the %splugin settings%s in main site dashboard.", 'security-malware-firewall') . "</h2>", "<a href='$link'>", "</a>");

        $spbct_page_data = [
            'isNetworkAdminDashboard' => true,
            'networkAdminDashboardMsg' => esc_html($msg),
        ];

        echo '<div id="spbct-page--react" data-data=\'' . json_encode($spbct_page_data) . '\'></div>';
    }

    private static function getFeedbackRequest()
    {
        global $spbc;

        $feedback_link = '';
        if (!$spbc->data["wl_mode_enabled"]) {
            $feedback_link = sprintf(
                __('Do you like CleanTalk? %sPost your feedback here%s%s.', 'security-malware-firewall'),
                '<a href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/#new-post" target="_blank">',
                '<i class="spbc-icon-link-ext"></i>',
                '</a>'
            );
        }

        return $feedback_link;
    }

    private static function getGDPRComplianceEventLink()
    {
        return '<span>' . __('Open', 'security-malware-firewall') . '&nbsp</span><span id="spbc_gdpr_open_modal" style="text-decoration: underline;">'
            . __('GDPR compliance', 'security-malware-firewall')
            . '</span>';
    }

    private static function getGDPRModalWindow()
    {
        return '<div id="gdpr_dialog" class="spbc_hide" style="padding: 0 15px;">' . spbc_show_GDPR_text() . '</div>';
    }

    private static function get2FADialog()
    {
        $user = wp_get_current_user();
        if (isset($user->ID) && $user->ID > 0) {
            $email = $user->user_email;
        } else {
            $email = spbc_get_admin_email();
        }

        return '<div id="confirmation-code" class="spbc_hide" style="padding: 0 15px;">'
            . '<p>' . sprintf(
                esc_html__('Check %s inbox for the confirmation code.', 'cleantalk'),
                $email
            ) . '</p>'
            . '<i>' . esc_html__('The code is valid for 10 minutes. If you want to change the status in this period, the new code won\'t be sent, please, use the code you\'ve already received.', 'security-malware-firewall') . '</i><br><br>'
            . '<input name="spbct-confirmation-code" type="text" />'
            . '&nbsp;&nbsp;<button type="button" id="confirmation-code--resend" class="button button-primary">Resend</button>'
            . '</div>';
    }

    private static function goToCleantalkLink()
    {
        global $spbc;

        $link = '';

        if ($spbc->key_is_ok && !$spbc->data["wl_mode_enabled"]) {
            $link = "https://cleantalk.org/my?user_token=" . $spbc->user_token . "&cp_mode=security";
        }

        return $link;
    }

    private static function support2Link()
    {
        global $spbc;

        $link = '';

        if ($spbc->key_is_ok && !$spbc->data["wl_mode_enabled"]) {
            $link = $spbc->data["wl_support_url"];
        }

        return $link;
    }

    private static function checkPhpVersion()
    {
        global $spbc;

        if (is_admin() && version_compare(phpversion(), '5.4.0', '<')) {
            $spbc->error_add('php_version', '');
        } else {
            $spbc->error_delete('php_version');
        }
    }

    private static function checkMemoryLimit()
    {
        global $spbc;

        $m_limit = ini_get('memory_limit');

        if (is_string($m_limit) && $m_limit !== "-1") {
            $prefix = strtolower(substr($m_limit, - 1, 1));
            $number = substr($m_limit, 0, - 1);
            switch ($prefix) {
                case 'k':
                    $m_limit = (int)$number * 1000;
                    break;
                case 'm':
                    $m_limit = (int)$number * 1000000;
                    break;
                case 'g':
                    $m_limit = (int)$number * 1000000000;
                    break;
            }

            if ($m_limit - memory_get_usage(true) < 25 * 1024 * 1024) {
                $spbc->error_add('memory_limit_low', '');
            } else {
                $spbc->error_delete('memory_limit_low');
            }
        }
    }
}
