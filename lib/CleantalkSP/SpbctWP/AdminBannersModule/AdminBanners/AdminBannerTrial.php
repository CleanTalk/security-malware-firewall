<?php

namespace CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners;

use CleantalkSP\SpbctWP\AdminBannersModule\AdminBannersHandler;
use CleantalkSP\Variables\Get;

class AdminBannerTrial extends AdminBannerAbstract
{
    /**
     * Hiding time in days
     */
    const HIDING_TIME = 14;

    /**
     * Simple Banner Name, most be unique
     */
    const NAME = 'trial';

    /**
     * Data for template
     *
     * @var array $template_data
     */
    private $template_data;

    /**
     * @var AdminBannersHandler
     */
    private $banners_handler;

    /**
     * Is the current page is a spbc plugin settings page
     *
     * @var bool
     */
    private $is_settings_page;

    public function __construct(AdminBannersHandler $banners_handler)
    {
        global $spbc;

        $this->banners_handler   = $banners_handler;
        $this->banner_id         = $this->prefix . $this::NAME . '_' . $this->banners_handler->getUserId();

        $this->template_data = array(
            'button' => '<input type="button" class="button button-primary" value="'
                        . esc_html__('UPGRADE', 'security-malware-firewall')
                        . '" />',
            'link' => $spbc->data["wl_mode_enabled"] ? $spbc->data["wl_support_url"] :
                'https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token='
                    . $banners_handler->getUserToken(),
            'plugin_settings_link' => $this->banners_handler->getPluginSettingsLink(),
            'title' => esc_html__(
                'Trial period is now over, please upgrade to premium version to keep your site secure and safe!',
                'security-malware-firewall'
            ),
            'subtitle' => esc_html__('Account status updates every hour or click Settings -> ' . $spbc->data["wl_brandname"] . ' -> Synchronize with Cloud.', 'security-malware-firewall'),
        );
        $this->is_settings_page = Get::get('page') === 'spbc';
    }

    /**
     * do I need to show a banner?
     *
     * @return bool
     */
    protected function needToShow()
    {
        if (
            $this->banners_handler->spbc->notice_show &&
            $this->banners_handler->spbc->notice_trial &&
            (! $this->isDismissed() || $this->is_settings_page)
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
        $data = $this->template_data;
        $is_dismissible_text = $this->is_settings_page ? '' : 'is-dismissible';
        $div_head =  '<div class="spbc-notice error um-admin-notice notice '
            . $is_dismissible_text
            . '" id="'
            . $this->banner_id
            . '" style="position: relative;">';
        echo $div_head;
        ?>
            <h3>
                <u>
                    <?php echo $data['plugin_settings_link']; ?>
                </u>:
                    <?php echo $data['title']; ?>
            </h3>
            <h4 style="color: gray;">
                <?php echo $data['subtitle']; ?>
            </h4>
            <p>
                <a target="_blank" style="vertical-align: super;" href="<?php echo $data['link']; ?>">
                    <?php echo $data['button']; ?>
                </a>
            </p>
        <?php
        echo '</div>';
    }
}
