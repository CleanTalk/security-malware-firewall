<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;
use WP;

class RenameLoginPage extends \CleantalkSP\Security\RenameLoginPage
{
    /**
     * Determines if the website is using permalink URL structure
     * @var bool
     */
    private $using_permalink;

    /**
     * Flag to determs that we on login page
     * @var bool
     */
    private $on_wp_login = false;

    public function __construct($login_slug, $redirect_slug)
    {

        parent::__construct($login_slug, $redirect_slug);

        $this->using_permalink = (bool)get_option('permalink_structure', false);
        $this->login_url = self::getURL($login_slug);
        $this->redirect_url = self::getURL($redirect_slug);

        // Prevents redirecting like
        // login -> wp-login.php
        // admin -> wp-admin
        remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);

        // Change "wp-login.php" to correct link in registration email
        add_filter('site_option_welcome_email', array($this, 'welcomeEmail'));

        // Common workflow
        // Hooks goes in the load order
        add_action('plugins_loaded', array($this, 'pluginsLoaded'), 1);
        add_action('wp_loaded', array($this, 'wpLoaded'), 1);

        add_filter('wp_redirect', array($this, 'wpRedirect'), 10, 2);
        add_filter('site_url', array($this, 'siteUrl'), 10, 4);
        add_filter('network_site_url', array($this, 'networkSiteUrl'), 10, 3);
    }

    /**
     * Returns correct URL depends on URL structure in WordPress
     *
     * @param $slug
     *
     * @return string
     */
    public static function getURL($slug)
    {

        $using_permalink = (bool)get_option('permalink_structure', false);

        // Get correct URLs
        return !$using_permalink
            ? home_url() . '/' . '?' . $slug
            : home_url() . '/' . $slug . (self::isUsingTrailingSlash() ? '/' : '');
    }

    /**
     * Check if we on old login page -> redirect
     * If we on a new one waiting for wp-Loaded to redirect
     */
    public function pluginsLoaded()
    {

        global $pagenow;

        if ( !is_multisite() &&
            ($this->isOnPage('wp-signup') || $this->isOnPage('wp-activate'))
        ) {
            wp_die(__('This feature is not enabled.', 'security-malware-firewall'));
        }

        // Is on the new login URI
        // Goes first because new login URL could be equal to wp-login.php
        if ( $this->isOnPage($this->login_slug) ) {
            $pagenow = 'wp-login.php';
            $this->on_wp_login = true;
            // Is on the wp-register or on wp-login
        } elseif (
            !is_admin() &&
            ($this->isOnPage('wp-login.php') || $this->isOnPage('wp-register'))
        ) {
            $pagenow = 'index.php';
            wp_safe_redirect($this->redirect_url);
            die();
        }
    }

    /**
     * Attaching wp-login.php if on a new login page
     * @psalm-suppress UnusedVariable
     */
    public function wpLoaded()
    {

        global $pagenow;

        if ( !Post::get('post_password') || Get::get('action') !== 'postpass' ) {
            // Prevent redirecting from /wp-admin/ to login_url
            if (
                !defined('DOING_AJAX') &&
                is_admin() &&
                !is_user_logged_in() &&
                !$this->isOnPage('admin-post.php') &&
                !$this->isOnPage('wp-admin/options.php')
            ) {
                wp_safe_redirect($this->redirect_url);
                die();
            }

            // Redirect from wp-login.php to login_url with all parameters
            if ( $pagenow === 'wp-login.php' && $this->using_permalink && !$this->isOnPage($this->login_slug) ) {
                wp_safe_redirect(
                    $this->trailSlash($this->login_url)
                    . (Server::get('QUERY_STRING') ? '?' . $_SERVER['QUERY_STRING'] : '')
                );
                die();
            }

            if ( $this->on_wp_login ) {
                // Fix "Undefined variable" warnings in php >= 8
                $user_login = '';
                $error = '';

                require_once ABSPATH . 'wp-login.php';
                die();
            }
        }
    }

    /**
     * Checks if we on the $page now
     *
     * @param $page
     *
     * @return bool
     */
    private function isOnPage($page)
    {
        return $this->trailSlash($this->request['path']) === $this->trailSlash(home_url($page, 'relative')) ||
            // Using isset( $_GET[ $page ]) instead of Get::get( $page )
            // because last one returns false if no value provided
            // for ( ?some&some1 ) Get::get( 'some' ) === '' as long as for Get::get( 'something' )
            (!$this->using_permalink && isset($_GET[$page]));
    }

    /**
     * Checks if current permalink structure using trailing slash
     *
     * @return bool
     * @todo to helper
     *
     */
    public static function isUsingTrailingSlash()
    {
        return (substr(get_option('permalink_structure'), -1, 1) === '/');
    }

    /**
     * Add or trim trailing slash depends on current setting
     *
     * @param $url
     *
     * @return string
     */
    private function trailSlash($url)
    {
        return self::isUsingTrailingSlash() ? trailingslashit($url) : untrailingslashit($url);
    }

    /**
     * Filter for wp site_url
     * Using this->filter_wp_login_php() to filter and change login URL
     *
     * @param $url
     * @param $path
     * @param $scheme
     * @param $blog_id
     * @psalm-suppress PossiblyUnusedReturnValue
     * @psalm-suppress PossiblyUnusedParam
     * @return string
     */
    public function siteUrl($url, $path, $scheme, $blog_id)
    {
        return $this->filterWpLoginPhp($url, $scheme);
    }

    /**
     * Filter for wp network_site_url
     * Using this->filter_wp_login_php() to filter and change login URL
     *
     * @param $url
     * @param $path
     * @param $scheme
     *
     * @return string
     * @psalm-suppress PossiblyUnusedParam
     * @psalm-suppress PossiblyUnusedReturnValue
     */

    public function networkSiteUrl($url, $path, $scheme)
    {
        return $this->filterWpLoginPhp($url, $scheme);
    }

    /**
     * Filter for wp wp_redirect
     * Using this->filter_wp_login_php() to filter and change login URL
     *
     * @param $location
     * @param $status
     * @psalm-suppress PossiblyUnusedParam
     * @psalm-suppress PossiblyUnusedReturnValue
     * @return string
     */
    public function wpRedirect($location, $status)
    {
        // If on wordpress.com ¯\_(ツ)_/¯
        return strpos($location, 'https://wordpress.com/wp-login.php') !== false
            ? $location
            : $this->filterWpLoginPhp($location);
    }

    /**
     * Filtering URL
     * Change wp-login.php to new login URL
     * Passing wp-login.php for some cases
     *
     * @param $url
     * @param null $scheme
     *
     * @return string
     * @psalm-suppress PossiblyUnusedParam
     */
    public function filterWpLoginPhp($url, $scheme = null)
    {

        if ( strpos($url, 'wp-login.php') !== false   // Ignoring if doesn't contains 'wp-login.php'
            // Not a single thought about it
//            strpos( $url, 'wp-login.php?action=postpass' ) === false &&  // Also ignoring
//            strpos( wp_get_referer(), 'wp-login.php' ) !== false // Referer must be 'wp-login.php'
        ) {
            $parsed_url = parse_url($url);

            if ( isset($parsed_url['query']) ) {
                parse_str($parsed_url['query'], $args);
                $args_to_modify = array(
                    'login',
                    'logout'
                );
                foreach ( $args_to_modify as $arg_to_modify ) {
                    if ( isset($args[$arg_to_modify]) ) {
                        $args[$arg_to_modify] = rawurlencode($args[$arg_to_modify]);
                    }
                }
                $url = add_query_arg($args, $this->login_url);
            } else {
                $url = $this->login_url;
            }
        }

        return $url;
    }

    /**
     * Change wp-login.php to correct link in registration email
     *
     * @param $value
     *
     * @return string|string[]
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function welcomeEmail($value)
    {
        return str_replace('wp-login.php', trailingslashit($this->login_slug), $value);
    }

    /**
     * Returns forbidden slugs in WordPress
     *
     * @return array
     */
    public static function getForbiddenSlugs()
    {
        $wp = new WP();

        return array_merge($wp->public_query_vars, $wp->private_query_vars);
    }
}
