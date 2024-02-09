<?php

namespace CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners;

use CleantalkSP\Common\Helpers\Helper;
use CleantalkSP\SpbctWP\AdminBannersModule\AdminBannersHandler;

class AdminBannerReview extends AdminBannerAbstract
{
    /**
     * Hiding time in days
     */
    const HIDING_TIME = 10000;

    /**
     * Simple Banner Name, most be unique
     */
    const NAME = 'review';

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
     * @param AdminBannersHandler $banners_handler
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public function __construct(AdminBannersHandler $banners_handler)
    {
        $this->banners_handler = $banners_handler;
        $this->banner_id       = $this->prefix . $this::NAME . '_' . $this->banners_handler->getUserId();

        $this->template_data = array(
            'button'   => '<input type="button" class="button button-primary" value="'
                        . esc_html__('SHARE', 'security-malware-firewall')
                        . '" />',
            'link'     => 'https://wordpress.org/support/plugin/security-malware-firewall/reviews/?filter=5',
            'title'    => esc_html__('Share your positive energy with us – give us a 5-star rating on WordPress.', 'security-malware-firewall'),
            'subtitle' => esc_html__('Security & Malware scan by CleanTalk', 'security-malware-firewall'),
            'already_posted' => '<a href="#" class="spbct-notice-dismiss-link" onclick="return false;">'
                                . __('Already posted the review', 'cleantalk-spam-protect')
                                . '</a>'
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
            $this->banners_handler->spbc->notice_review &&
            ! $this->isDismissed() &&
            current_user_can('administrator')
        ) {
            $this->banners_handler->spbc->error_delete_all('save');

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
        $already_posted = isset($data['already_posted']) ? $data['already_posted'] : '';
        ?>
        <div
            class="spbc-notice um-admin-notice notice notice-success is-dismissible"
            id="<?php echo $this->banner_id; ?>"
            style="position: relative;padding-bottom: 1em;"
        >
            <h3><?php echo $data['title']; ?></h3>
            <h4 style="color: gray;"><?php echo $data['subtitle']; ?></h4>
            <a target="_blank" style="vertical-align: super;" href="<?php echo $data['link']; ?>"><?php echo $data['button']; ?></a>
            <?php echo $already_posted; ?>
        </div>
        <?php
    }
}
