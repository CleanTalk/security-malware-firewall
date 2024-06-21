<?php

use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Firewall;
use CleantalkSP\SpbctWP\Firewall\BFP;
use CleantalkSP\SpbctWP\Firewall\FW;
use CleantalkSP\SpbctWP\Firewall\TC;
use CleantalkSP\SpbctWP\Firewall\WAF;
use CleantalkSP\SpbctWP\Firewall\WafBlocker;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\SpbctWP\Variables\Cookie;
use CleantalkSP\SpbctWP\RenameLoginPage;

function spbc_firewall__check()
{
    global $spbc;

    $firewall = new Firewall();

    $secfw_enabled_on_main_site = false;
    if (!is_main_site() && $spbc->network_settings['ms__work_mode'] == 2) {
        $spbc_settings_main_site = get_blog_option(1, 'spbc_settings');
        if ($spbc_settings_main_site['secfw__enabled']) {
            $secfw_enabled_on_main_site = true;
        }
    }

    if ( (int) $spbc->settings['secfw__enabled'] || $secfw_enabled_on_main_site ) {
        $firewall->loadFwModule(
            new FW(
                array(
                    'data_table__personal_countries' => SPBC_TBL_FIREWALL_DATA__COUNTRIES,
                    'log_table'                      => SPBC_TBL_FIREWALL_LOG,
                    'state'                          => $spbc,
                    'api_key'                        => $spbc->api_key,
                )
            )
        );
    }

    spbc_firewall_check_waf($firewall);

    //todo This rewrite could break permalinks, need to implement new logic
    if ( class_exists('Poppyz_Core') ) { //fix poppyz plugin early start conflict
        $GLOBALS['wp_rewrite'] = new WP_Rewrite(); // Fix for early load WP_Rewrite
    }

    $login_url = wp_login_url();
    if ( $spbc->settings['login_page_rename__enabled'] ) {
        //todo This rewrite could break permalinks, need to implement new logic
        $GLOBALS['wp_rewrite'] = new WP_Rewrite(); // Fix for early load WP_Rewrite
        $login_url = RenameLoginPage::getURL($spbc->settings['login_page_rename__name']);
    }

    $firewall->loadFwModule(
        new BFP(
            array(
            'api_key'       => $spbc->api_key,
            'state'         => $spbc,
            'is_login_page' => strpos(trim(Server::getURL(), '/'), trim($login_url, '/')) === 0,
            'is_logged_in'  => Cookie::get('spbc_is_logged_in') === md5($spbc->data['salt'] . get_option('home')),
            'bf_limit'      => $spbc->settings['bfp__allowed_wrong_auths'],
            'block_period'  => $spbc->settings['bfp__block_period__5_fails'],
            'count_period'  => $spbc->settings['bfp__count_interval'], // Counting login attempts in this interval
            )
        )
    );

    if ( $spbc->settings['traffic_control__enabled'] && ! is_admin() ) {
        $firewall->loadFwModule(
            new TC(
                array(
                'data_table'   => SPBC_TBL_FIREWALL_DATA,
                'log_table'    => SPBC_TBL_TC_LOG,
                'state'        => $spbc,
                'api_key'      => $spbc->api_key,
                'is_logged_in' => Cookie::get('spbc_is_logged_in') === md5($spbc->data['salt'] . get_option('home')),
                'store_interval' => $spbc->settings['traffic_control__autoblock_timeframe'],
                'tc_limit'     => $spbc->settings['traffic_control__autoblock_amount'],
                'block_period' => $spbc->settings['traffic_control__autoblock_period'],
                )
            )
        );
    }

    $firewall->run();
}

function spbc_firewall_check_admin_area()
{
    if (spbc_user_is_admin()) {
        return;
    }

    // Flow for non-admin users
    $firewall = new Firewall();

    spbc_firewall_check_waf($firewall);

    $firewall->run();
}

function spbc_firewall_check_waf($firewall)
{
    global $spbc;

    if ( $spbc->settings['waf__enabled'] ) {
        $waf_params = [
            'api_key'                           => $spbc->api_key,
            'log_table'                         => SPBC_TBL_TC_LOG,
            'state'                             => $spbc,
            'waf__xss_check'                    => $spbc->settings['waf__xss_check'],
            'waf__sql_check'                    => $spbc->settings['waf__sql_check'],
            'waf__exploit_check'                => $spbc->settings['waf__exploit_check']
        ];
        if ( $spbc->settings['waf_blocker__enabled'] ) {
            $waf_blocker_params = [
                'is_logged_in' => Cookie::get('spbc_is_logged_in') === md5($spbc->data['salt'] . get_option('home')),
                'db' => DB::getInstance(),
                'ip_array' => $firewall->ip_array
            ];
            $waf_blocker = new WafBlocker($waf_blocker_params);
            $waf_params['waf_blocker'] = $waf_blocker;
            $firewall->loadFwModule($waf_blocker);
        }
        $firewall->loadFwModule(new WAF($waf_params));
    }
}

/**
 * Wrapper to call UploadChecker logic.
 * @return void
 */
function spbc_upload_checker__check()
{
    global $spbc;
    if ( $spbc->settings['upload_checker__file_check'] && !empty($_FILES) ) {
        $upload_checker = new Firewall\UploadChecker(array(
            'upload_checker__do_check_wordpress_modules' => $spbc->settings['upload_checker__do_check_wordpress_modules'],
            'api_key'                    => $spbc->api_key,
        ));
        $firewall = new Firewall();
        $firewall->loadFwModule($upload_checker);
        $firewall->run();
    }
}

/**
 * Check if the firewall should be skipped
 * @return bool
 */
function spbc_firewall_skip_check()
{
    global $spbc, $apbct;

    // General skip
    if ( $spbc->fw_stats['is_on_maintenance']
        || ! $spbc->feature_restrictions->getState($spbc, 'firewall_log')->is_active
        || ! isset($spbc->fw_stats['last_updated'], $spbc->fw_stats['entries'])  // Plugin's FW base is updated
        || CleantalkSP\SpbctWP\Firewall::isException()
        || defined('DOING_AJAX')  // Pass AJAX
        || spbc_wp_doing_cron()           // Pass WP cron tasks
        || \CleantalkSP\Variables\Server::inUri('/favicon.ico')  // Exclude favicon.ico requests from the check
        || spbc_mailpoet_doing_cron()
        || ! empty($_FILES) // Or file downloads
    ) {
        return true;
    }

    // By cookie
    if ( ! empty($_GET['access']) ) {
        $apbct_settings = get_option('cleantalk_settings');
        $apbct_key      = ! empty($apbct_settings['apikey']) ? $apbct_settings['apikey'] : false;
        if ( ( $_GET['access'] === $spbc->settings['spbc_key'] || ( $apbct_key !== false && $_GET['access'] === $apbct_key ) ) ) {
            Cookie::set('spbc_firewall_pass_key', md5($_SERVER['REMOTE_ADDR'] . $spbc->settings['spbc_key']), time() + 1200, '/');
            Cookie::set('ct_sfw_pass_key', md5($_SERVER['REMOTE_ADDR'] . $apbct_key), time() + 1200, '/');

            return true;
        }
    }

    // Turn off the SpamFireWall if Remote Call is in progress
    if ( ( ! empty($apbct) && $apbct->rc_running ) || $spbc->rc_running ) {
        return true;
    }

    // Pass the check if cookie is set.
    $ip_set = IP::get();
    $ip_set = empty($ip_set) ? [] : $ip_set;
    $ip_set = is_array($ip_set) ? $ip_set : [$ip_set];
    foreach ( $ip_set as $spbc_cur_ip ) {
        if ( Cookie::get('spbc_firewall_pass_key') == md5($spbc_cur_ip . $spbc->settings['spbc_key']) ) {
            return true;
        }
    }

    return false;
}
