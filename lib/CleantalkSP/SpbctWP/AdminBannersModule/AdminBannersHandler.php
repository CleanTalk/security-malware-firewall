<?php

namespace CleantalkSP\SpbctWP\AdminBannersModule;

use CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners\AdminBannerRenew;
use CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners\AdminBannerReview;
use CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners\AdminBannerTrial;
use CleantalkSP\SpbctWP\AdminBannersModule\AdminBanners\AdminBannerWrongKey;
use CleantalkSP\SpbctWP\Sanitize;
use CleantalkSP\SpbctWP\State;
use CleantalkSP\Variables\Post;

/**
 * Description
 */
class AdminBannersHandler
{
    /**
     * @type State
     * @var object $spbc
     */
    public $spbc;

    /**
     * @var string $user_token
     */
    private $user_token;

    /**
     * @var int $user_id
     */
    private $user_id;

    /**
     * @var array $banners_register
     */
    private $banners_register;

    /**
     * @var string
     */
    private $plugin_settings_link;

    public function __construct(State $spbc)
    {
        $this->spbc                 = $spbc;
        $this->user_token           = $this->spbc->user_token ? '&user_token=' . $this->spbc->user_token : '';
        $this->user_id              = get_current_user_id();
        $this->plugin_settings_link = '<a href="'
                                      . (is_network_admin() ? 'settings.php' : 'options-general.php') .
                                      '?page=spbc">'
                                      . $spbc->data["wl_brandname"] .
                                      '</a>';

        // The register of banners
        $this->banners_register = array(
            AdminBannerTrial::class,
            AdminBannerRenew::class,
            AdminBannerWrongKey::class,
            AdminBannerReview::class,
        );
    }

    /**
     * Launches an array of admin banners to display.
     * Prepare common data for banners.
     */
    public function handle()
    {
        add_action('admin_notices', function () {
            foreach ( $this->banners_register as $banner_class ) {
                $banner = new $banner_class($this);
                $banner->show();
            }
        });
        add_action('network_admin_notices', function () {
            foreach ( $this->banners_register as $banner_class ) {
                $banner = new $banner_class($this);
                $banner->show();
            }
        });
        add_action('wp_ajax_spbc_dismiss_banner', array($this, 'dismissBanner'));
        add_filter('cleantalk_admin_bar__parent_node__after', array($this, 'addAttentionMark'), 20, 1);
    }

    public function getUserId()
    {
        return $this->user_id;
    }

    public function getUserToken()
    {
        return $this->user_token;
    }

    public function getPluginSettingsLink()
    {
        return $this->plugin_settings_link;
    }

    public function dismissBanner()
    {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');

        $banner_id = Post::get('banner_id');

        if ( ! $banner_id ) {
            wp_send_json_error(esc_html__('Wrong request.', 'security-malware-firewall'));
        }

        $banner_id    = Sanitize::cleanTextField($banner_id);
        $current_date = current_time('Y-m-d');

        if ( update_option($banner_id, $current_date) ) {
            wp_send_json_success();
        } else {
            wp_send_json_error(esc_html__('Notice status not updated.', 'cleantalk-spam-protect'));
        }
    }

    public function addAttentionMark($after)
    {
        if ( $this->spbc->notice_show ) {
            return $after . '<i class="spbc-icon-attention-alt"></i>';
        }

        return $after;
    }
}
