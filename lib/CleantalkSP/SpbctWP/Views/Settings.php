<?php

namespace CleantalkSP\SpbctWP\Views;

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
            "keyIsOk" => $spbc->key_is_ok,
            "displayDebug" => $display_debug,
            "isWPMSMainSite" => is_main_site(),
        ];

        echo '<div id="spbct-page-tabs--react" data-data=\'' . json_encode($data) . '\'></div>';
    }

    public static function page()
    {
        global $spbc;

        if (is_network_admin()) {
            self::earlyOutput();
            return;
        }

        self::checkPhpVersion();
        self::checkMemoryLimit();

        $spbct_page_data = [
            // left corner section
            'brandname' => $spbc->data["wl_brandname"],
            'adminsOnlineCount' => self::getAdminsOnline(),
            'nextScanLaunchTime' => spbc_get_next_scan_launch_time_text(),

            // right corner section
            'supportLink' => self::supportLink(),
            'supportOf' => __('Tech support of ' . $spbc->data["wl_brandname"], 'cleantalk'),
            'homepage' => self::homepage(),
            'gdprCompliance' => self::gdprCompliance(),
            'gdprDialog' => '<div id="gdpr_dialog" class="spbc_hide" style="padding: 0 15px;">' . spbc_show_GDPR_text() . '</div>',
            'twoFactorAuth' => self::get2FADialog(),
            'trademark' => $spbc->data["wl_brandname"] . __(' is a registered trademark. All rights reserved.', 'cleantalk'),
            'feedback' => self::feedback(),
            'premium' => self::getPremiumLink(),

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
        echo '<div id="spbct-page--react" data-data=\'' . json_encode($spbct_page_data) . '\'></div>';
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
        global $spbc;

        $link = '';

        if ($spbc->data['license_trial'] == 1 && ! empty($spbc->user_token) && ! $spbc->data["wl_mode_enabled"] ) {
            $url = $spbc->data["wl_mode_enabled"] ? $spbc->data["wl_support_url"] : 'https://cleantalk.org/my/bill/security?user_token=' . $spbc->user_token;
            $link = __('Make it right!', 'cleantalk')
            . sprintf(
                __(' %sGet premium%s', 'cleantalk'),
                '<a href="' . $url . '" target="_blank">',
                '</a>'
            );
        }

        return $link;
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

    private static function supportLink()
    {
        global $spbc;

        $support_link = '<a target="_blank" href="https://wordpress.org/support/plugin/security-malware-firewall/">wordpress.org</a>.';
        if ($spbc->data["wl_mode_enabled"]) {
            $support_link = '<a target="_blank" href="' . $spbc->data["wl_support_url"] . '">' . $spbc->data["wl_brandname"] . '</a>.';
        }

        return $support_link;
    }

    private static function feedback()
    {
        global $spbc;

        $feedback_link = '';
        if (!$spbc->data["wl_mode_enabled"]) {
            $feedback_link = sprintf(
                __('Do you like CleanTalk? %sPost your feedback here%s%s.', 'cleantalk'),
                '<a href="https://wordpress.org/support/plugin/security-malware-firewall/reviews/#new-post" target="_blank">',
                '<i class="spbc-icon-link-ext"></i>',
                '</a>'
            );
        }

        return $feedback_link;
    }

    private static function homepage()
    {
        global $spbc;

        return __('Plugin Homepage at', 'cleantalk')
            . ' <a href="' . $spbc->data["wl_url"]
            . '" target="_blank">' . $spbc->data["wl_url"] . '</a>.<br/>';
    }

    private static function gdprCompliance()
    {
        return '<span id="spbc_gdpr_open_modal" style="text-decoration: underline;">'
            . __('GDPR compliance', 'cleantalk')
            . '</span><br/>';
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
            . '<i>' . esc_html__('The code is valid for 10 minutes. If you want to change the status in this period, the new code won\'t be sent, please, use the code you\'ve already received.', 'cleantalk') . '</i><br><br>'
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
