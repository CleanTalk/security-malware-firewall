<?php

namespace CleantalkSP\SpbctWP;

class LinkConstructor extends \CleantalkSP\Common\LinkConstructor
{
    //todo search unhadled links via comment //HANLDE LINK

    /**
     * @var string
     */
    public static $utm_campaign = 'spbct_links';

    /**
     * @var array[]
     * UTM (Urchin Tracking Module) presets for various link types within the plugin.
     *
     * This associative array defines a set of UTM parameters for different contexts where links are used within the plugin.
     * These contexts include settings within the admin panel, public-facing pages, emails, and renewal notices. Each entry
     * specifies the UTM parameters to be appended to URLs to track the source, medium, and content of traffic for analytical purposes.
     *
     * The presets would be categorized into:
     * - Settings: Links related to plugin settings accessible from the admin panel.
     * - Public pages: Links intended for public-facing pages, such as referral links or comment page links.
     * - Emails: Links that are sent out in emails, typically for notifications or promotions.
     * - Renewal links: Links specifically designed for license renewal notices, displayed in various parts of the admin panel.
     *
     * Each preset is an associative array with the following keys:
     * - utm_id: (string) A unique identifier for the campaign, not used in the current presets.
     * - utm_term: (string) Not used in the current presets.
     * - utm_source: (string) The source of the traffic, such as 'admin_panel' or 'newsletter'.
     * - utm_medium: (string) The medium through which the message was conveyed, like 'email' or 'banner'.
     * - utm_content: (string) A description of the content of the link, which helps in identifying the specific link clicked.
     * @see \Cleantalk\Common\LinkConstructor::$utm_presets
     */
    public static $utm_presets = array(
        /*
         * Settings
         */

        /*
         * Public pages
         */

        /*
         * Emails
         */

        /*
         * Renewal links
         */
        'renew_notice_trial' => array( //site-wide renew banner in the admin dashboard on license ended
            'utm_id' => '',
            'utm_term' => '',
            'utm_source' => 'admin_panel',
            'utm_medium' => 'banner',
            'utm_content' => 'renew_notice_trial',
        ),
        'renew_notice_renew' => array( //site-wide renew banner in the admin dashboard on license is close to end
            'utm_id' => '',
            'utm_term' => '',
            'utm_source' => 'admin_panel',
            'utm_medium' => 'banner',
            'utm_content' => 'renew_notice_renew',
        ),
        'renew_notice_service_restricted' => array( // the link for all security settings tabs if service is restricted
            'utm_id' => '',
            'utm_term' => '',
            'utm_source' => 'admin_panel',
            'utm_medium' => 'settings_tabs_notice',
            'utm_content' => 'renew_notice_service_restricted',
        ),
        'renew_plugins_listing' => array( //the renewal link for the SPBCT on the installed plugins list
            'utm_id' => '',
            'utm_term' => '',
            'utm_source' => 'admin_panel',
            'utm_medium' => 'badge',
            'utm_content' => 'renew_plugins_listing',
        ),
        'renew_admin_bar_cross_link_apbct' => array( //cross-link to renew anti-spam in admin bar if detected so - probably never works
            'utm_id' => '',
            'utm_term' => '',
            'utm_source' => 'admin_panel',
            'utm_medium' => 'admin_bar',
            'utm_content' => 'renew_admin_bar_cross_link_apbct',
        ),
        'renew_admin_bar_spbct' => array( // renew link on the product name in the admin bar
            'utm_id' => '',
            'utm_term' => '',
            'utm_source' => 'admin_panel',
            'utm_medium' => 'admin_bar',
            'utm_content' => 'renew_admin_bar',
        ),
    );

    public static function buildCleanTalkLink($utm_preset, $uri = '', $get_params = array(), $domain = 'https://cleantalk.org')
    {
        return parent::buildCleanTalkLink($utm_preset, $uri, $get_params, $domain);
    }

    public static function buildRenewalLinkATag($user_token, $link_inner_html, $product_id, $utm_preset)
    {
        return parent::buildRenewalLinkATag($user_token, $link_inner_html, $product_id, $utm_preset);
    }
}
