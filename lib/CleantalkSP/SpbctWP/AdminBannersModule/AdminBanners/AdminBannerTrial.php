<?php

namespace CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners;

use CleantalkSP\Common\Helpers\Helper;
use CleantalkSP\SpbctWP\AdminBannersModule\AdminBannersHandler;

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

    public function __construct(AdminBannersHandler $banners_handler)
    {
        $this->banners_handler   = $banners_handler;
        $this->banner_id         = $this->prefix . $this::NAME . '_' . $this->banners_handler->getUserId();

        $this->template_data = array(
            'button' => '<input type="button" class="button button-primary" value="'
                        . esc_html__('UPGRADE', 'security-malware-firewall')
                        . '" />',
            'link' => 'https://cleantalk.org/my/bill/security?cp_mode=security&utm_source=wp-backend&utm_medium=cpc&utm_campaign=WP%%20backend%%20trial_security&user_token='
                      . $banners_handler->getUserToken(),
            'plugin_settings_link' => $this->banners_handler->getPluginSettingsLink(),
            'title' => esc_html__(
                'Trial period is now over, please upgrade to premium version to keep your site secure and safe!',
                'security-malware-firewall'
            ),
            'subtitle' => esc_html__('Account status updates every minute.', 'security-malware-firewall'),
        );
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
            ! $this->isDismissed()
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
        ?>
        <div class="error um-admin-notice notice is-dismissible" id="<?php
        echo $this->banner_id; ?>" style="position: relative;">
            <h3><u><?php
                    echo $data['plugin_settings_link']; ?></u>: <?php
                echo $data['title']; ?></h3>
            <h4 style="color: gray;"><?php
                echo $data['subtitle']; ?></h4>
            <p>
                <a target="_blank" style="vertical-align: super;" href="<?php
                echo $data['link']; ?>">
                    <?php
                    echo $data['button']; ?>
                </a>
            </p>
        </div>
        <?php
    }
}
