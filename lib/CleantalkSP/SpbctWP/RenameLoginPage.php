<?php


namespace CleantalkSP\SpbctWP;


use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Server;

class RenameLoginPage extends \CleantalkSP\Security\RenameLoginPage{
	
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
	
	public function __construct( $login_slug, $redirect_slug ){
		
		parent::__construct( $login_slug, $redirect_slug );
        
        $this->using_permalink = (bool) get_option( 'permalink_structure', false );
        $this->login_url       = self::getURL( $login_slug );
        $this->redirect_url    = self::getURL( $redirect_slug );
		
		// Prevents redirecting like
        // login -> wp-login.php
        // admin -> wp-admin
		remove_action('template_redirect', 'wp_redirect_admin_locations', 1000);
		
		// Change "wp-login.php" to correct link in registration email
		add_filter( 'site_option_welcome_email', array( $this, 'welcome_email' ) );
		
		// Common workflow
		// Hooks goes in the load order
		add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ), 1 );
		add_action( 'wp_loaded', array( $this, 'wp_loaded' ), 1 );
        
        add_filter( 'wp_redirect', array( $this, 'wp_redirect' ), 10, 2 );
        add_filter( 'site_url', array( $this, 'site_url' ), 10, 4 );
        add_filter( 'network_site_url', array( $this, 'network_site_url' ), 10, 3 );
		
	}
	
    /**
     * Returns correct URL depends on URL structure in WordPress
     *
     * @param $slug
     *
     * @return string
     */
    public static function getURL( $slug ){
        
        $using_permalink = (bool) get_option( 'permalink_structure', false );
        
        // Get correct URLs
        return ! $using_permalink
            ? home_url() . '/' . '?' . $slug
            : home_url() . '/' . $slug . ( self::isUsingTrailingSlash() ? '/' : '' );
        
    }
    
    /**
     * Check if we on old login page -> redirect
     * If we on a new one waiting for wp-Loaded to redirect
     */
    public function plugins_loaded(){
		
		global $pagenow;
		
		if ( ! is_multisite() &&
		     ( $this->isOnPage( 'wp-signup' ) || $this->isOnPage( 'wp-activate' ) )
           ) {
			wp_die( __( 'This feature is not enabled.', 'security-malware-firewall' ) );
		}

		// Is on the new login URI
		// Goes first because new login URL could be equal to wp-login.php
		if( $this->isOnPage( $this->login_slug ) ){
			$pagenow = 'wp-login.php';
			$this->on_wp_login = true;
		// Is on the wp-register or on wp-login
		}elseif(
			! is_admin() &&
			( $this->isOnPage( 'wp-login.php' ) || $this->isOnPage( 'wp-register' ) )
		){
			$pagenow = 'index.php';
			wp_safe_redirect( $this->redirect_url );
			die();
		}
	}
    
    /**
     * Attaching wp-login.php if on a new login page
     */
	public function wp_loaded(){
		
		global $pagenow;

		if ( ! Post::get( 'post_password' ) || Get::get('action') !== 'postpass' ) {

			// Prevent redirecting from /wp-admin/ to login_url
			if(
				is_admin() &&
				! is_user_logged_in() &&
				! defined( 'DOING_AJAX' ) &&
				! $this->isOnPage( 'admin-post.php' ) &&
				! $this->isOnPage( 'wp-admin/options.php' )
			) {
				wp_safe_redirect( $this->redirect_url );
				die();
			}

			// Redirect from wp-login.php to login_url with all parameters
            if( $pagenow === 'wp-login.php' && $this->using_permalink && ! $this->isOnPage( $this->login_slug )){
                wp_safe_redirect(
                    $this->trailSlash( $this->login_url )
                    . ( Server::get( 'QUERY_STRING' ) ? '?' . $_SERVER['QUERY_STRING'] : '' )
                );
                die();
            }
            
            if( $this->on_wp_login ){
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
	private function isOnPage( $page ){
		return $this->trailSlash( $this->request['path'] ) === $this->trailSlash( home_url( $page, 'relative' ) ) ||
               // Using isset( $_GET[ $page ]) instead of Get::get( $page )
               // because last one returns false if no value provided
               // for ( ?some&some1 ) Get::get( 'some' ) === '' as long as for Get::get( 'something' )
		       ( ! $this->using_permalink && isset( $_GET[ $page ]) );
	}
	
	/**
     * Checks if current permalink structure using trailing slash
	 *
	 * @todo to helper
	 *
	 * @return bool
	 */
	public static function isUsingTrailingSlash() {
		return ( '/' === substr( get_option( 'permalink_structure' ), - 1, 1 ) );
	}
	
	/**
	 * Add or trim trailing slash depends on current setting
	 *
	 * @param $url
	 *
	 * @return string
	 */
	private function trailSlash( $url ){
		return self::isUsingTrailingSlash() ? trailingslashit( $url ) : untrailingslashit( $url );
	}
    
    /**
     * Filter for wp site_url
     * Using this->filter_wp_login_php() to filter and change login URL
     *
     * @param $url
     * @param $path
     * @param $scheme
     * @param $blog_id
     *
     * @return string
     */
    public function site_url( $url, $path, $scheme, $blog_id ){
        return $this->filter_wp_login_php( $url, $scheme );
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
     */
    
    public function network_site_url( $url, $path, $scheme ){
        return $this->filter_wp_login_php( $url, $scheme );
    }
    
    /**
     * Filter for wp wp_redirect
     * Using this->filter_wp_login_php() to filter and change login URL
     *
     * @param $location
     * @param $status
     *
     * @return string
     */
    public function wp_redirect( $location, $status ){
        // If on wordpress.com ¯\_(ツ)_/¯
        return strpos( $location, 'https://wordpress.com/wp-login.php' ) !== false
            ? $location
            : $this->filter_wp_login_php( $location );
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
     */
    public function filter_wp_login_php( $url, $scheme = null ){
        
        if(
            strpos( $url, 'wp-login.php' ) !== false   // Ignoring if doesn't contains 'wp-login.php'
            // Not a single thought about it
//            strpos( $url, 'wp-login.php?action=postpass' ) === false &&  // Also ignoring
//            strpos( wp_get_referer(), 'wp-login.php' ) !== false // Referer must be 'wp-login.php'
        ){
            
            $parsed_url = parse_url( $url );

            if( isset( $parsed_url['query'] ) ){
                parse_str( $parsed_url['query'], $args );
                if( isset( $args['login'] ) ){
                    $args['login'] = rawurlencode( $args['login'] );
                }
                $url = add_query_arg( $args, $this->login_url );
            }else{
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
	 */
	public function welcome_email( $value ) {
		return str_replace( 'wp-login.php', trailingslashit( $this->login_slug ), $value );
	}
    
    /**
     * Returns forbidden slugs in WordPress
     *
     * @return array
     */
    public static function getForbiddenSlugs() {
        $wp = new \WP;
        
        return array_merge( $wp->public_query_vars, $wp->private_query_vars );
    }
    
}