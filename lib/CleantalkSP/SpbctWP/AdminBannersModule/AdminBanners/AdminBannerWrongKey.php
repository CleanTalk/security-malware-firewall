<?php

namespace CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners;

use CleantalkSP\SpbctWP\AdminBannersModule\AdminBannersHandler;
use CleantalkSP\SpbctWP\Variables\Cookie;

class AdminBannerWrongKey extends AdminBannerAbstract
{
    /**
     * Simple Banner Name, most be unique
     */
    const NAME = 'wrong_key';

    /**
     * @var AdminBannersHandler
     */
    private $banners_handler;

    /**
     * @var string
     */
    private $current_screen_id;


    public function __construct(AdminBannersHandler $banners_handler)
    {
        $this->banners_handler = $banners_handler;
        $this->current_screen_id = $this->getCurrentScreenId();
    }

    /**
     * do I need to show a banner?
     *
     * @return bool
     */
    protected function needToShow()
    {
        if (
            ! $this->banners_handler->spbc->key_is_ok &&
            $this->current_screen_id !== 'settings_page_spbc' &&
            $this->current_screen_id !== 'settings_page_spbc-network' &&
            ! Cookie::get('spbc_close_wrong_key_banner')
        ) {
            return true;
        }

        return false;
    }

    /**
     * Print HTML of banner
     */
    protected function display()
    {
        echo '<div class="spbc-notice error um-admin-notice notice" style="position: relative;">';

        if ( is_network_admin() ) {
            printf(
                '<h3><u>' . $this->banners_handler->getPluginSettingsLink() . '</u>: ' . __(
                    'Access key is not valid. Enter into %splugin settings%s in the main site dashboard to get access key.',
                    'security-malware-firewall'
                ) . '</h3>',
                '<a href="' . get_site_option('siteurl') . 'wp-admin/options-general.php?page=spbc">',
                '</a>'
            );
        } else {
            printf(
                '<h3><u>' . $this->banners_handler->getPluginSettingsLink() . '</u>: ' . __(
                    'Access key is not valid. Enter into %splugin settings%s to get access key.',
                    'security-malware-firewall'
                ) . '</h3>',
                '<a href="options-general.php?page=spbc">',
                '</a>'
            );
        }

        if ( $this->banners_handler->spbc->were_updated ) {
            printf(
                '<h3>' . __(
                    'Why do you need an access key? Please, learn more %shere%s.',
                    'security-malware-firewall'
                ) . '</h3>',
                '<a href="https://wordpress.org/support/topic/why-do-you-need-an-access-key-updated/">',
                '</a>'
            );
        }

        echo '
            <button 
                onclick="this.parentNode.remove(); spbc_setCookie(\'spbc_close_wrong_key_banner\', \'1\', 3600);" 
                type="button" 
                class="notice-dismiss">
                    <span class="screen-reader-text">' . __('Dismiss this notice.', 'security-malware-firewall') . '</span>
            </button>';
        echo '</div>';
    }
}
