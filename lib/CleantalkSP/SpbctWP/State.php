<?php

namespace CleantalkSP\SpbctWP;

/*
 * 
 * CleanTalk Security State class
 * 
 * @package Security Plugin by CleanTalk
 * @subpackage State
 * @Version 2.0
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 *
 */

/**
 * @property mixed data
 * @property mixed settings
 * @property mixed network_settings
 * @property mixed network_data
 * @property mixed errors
 * @property mixed fw_stats
// * @property mixed fw_stats

 */
class State extends \CleantalkSP\Common\State
{
	public $settings__elements = array();
	
	public $default_settings = array(

		// Key
		'spbc_key'                          => '',

		// Authentication
		'2fa__enable'                       => 0,
		'2fa__roles'                        => array('administrator'),
		'bfp__allowed_wrong_auths'          => 5,
		'bfp__delay__1_fails'               => 3,    // Delay to sleep after 1 wrong auth
		'bfp__delay__5_fails'               => 10,   // Delay to sleep after 5 wrong auths
		'bfp__block_period__5_fails'        => 3600, // By default ban IP for brute force for one hour
		'bfp__count_interval'               => 900,  // Counting login attempts in this interval
		'login_page_rename__enabled'        => 0,
		'login_page_rename__name'           => 'login',
		'login_page_rename__redirect'       => '',
        'there_was_signature_treatment'     => 0,
		
        // Firewall
        'fw__custom_message'          => '',   // Hidden
        'fw__append_standard_message' => true, // Hidden
        
		// Traffic Control
		'traffic_control__enabled'          => 1,
		'traffic_control__autoblock_amount' => 1000,
		'traffic_control__autoblock_period' => 3600,
		
		// Scanner
		'scanner__auto_start'		       => 1,
		'scanner__auto_start_manual'       => 0,
		'scanner__auto_start_manual_time'  => '09:00',
		'scanner__auto_start_manual_tz'    => 0, // In hours
		'scanner__outbound_links'		   => 0,
		'scanner__outbound_links_mirrors'  => '',
        'scanner__important_files_listing' => 0,
		'scanner__heuristic_analysis'	   => 0,
		'scanner__signature_analysis'      => 1,
		'scanner__auto_cure'               => 1,
		'scanner__dir_exclusions'          => '',
		'scanner__list_unknown'            => 0,
        'scanner__list_unknown__older_than' => 1, // day
        
        // Frontend scanner
		'scanner__frontend_analysis'       => 1,
		'scanner__frontend_analysis__csrf' => 0,
		'scanner__frontend_analysis__domains_exclusions' => "twitter.com\nyoutube.com\nyoutube-nocookie.com\nimg.youtube.com\nmail.ru\nok.ru\nvk.com\nrutube.ru\ndailymotion.com\nyandex.ru\nflikr.com\nfacebook.com\nvimeo.com\nmetacafe.com\nyahoo.com\nmailchimp.com\ngoogletagmanager.com\ngoogle.com\n",
		
		// Web Application Firewall
		'waf__enabled'                      => 1,
		'waf__xss_check'                    => 1,
		'waf__sql_check'                    => 1,
		'waf__file_check'                   => 1,
        'waf__file_check__uploaded_plugins' => 0,
		'waf__exploit_check'                => 1,

		// Data processing
		'data__set_cookies'                 => 1,
		'data__set_cookies__alt_sessions_type' => 1,
		'data__additional_headers'          => 1,

		// Misc
		'misc__prevent_logins_collecting'   => 0,
		'misc__backend_logs_enable'         => 1,
		'misc__forbid_to_show_in_iframes'   => 1,
		'misc__show_link_in_login_form'     => 1,
		'misc__complete_deactivation'       => 0,

		// Monitoring
        'monitoring__users' => 1,
		
		// WP
		'wp__use_builtin_http_api'          => 1,
		'wp__disable_xmlrpc'                => 0,
		'wp__disable_rest_api_for_non_authenticated' => 0,
        
        // Admin bar
        'admin_bar__show' => 1,
        'admin_bar__users_online_counter' => 1,
        'admin_bar__brute_force_counter' => 1,
        'admin_bar__firewall_counter' => 1,

	);
	public $default_data = array(
		
		'key_changed'              => false,
		'plugin_version'           => SPBC_VERSION,
		'user_token'               => '',
		'key_is_ok'                => false,
		'moderate'                 => false,
		'logs_last_sent'           => null,
		'last_sent_events_count'   => null,
		'notice_show'              => null,
		'notice_renew'             => false,
		'notice_trial'             => false,
		'service_id'               => '',
		'license_trial'            => 0,
		'account_name_ob'          => '',
		'salt'                     => '',
        'extra_package'            => [
            'backend_logs' => 0,
        ],
		'scanner'                  => array(
			'last_signature_update' => null,
			'last_wp_version'      => null,
			'cron' => array(
				'state'         => 'get_hashes',
				'total_scanned' => 0,
				'offset'        => 0,
			),
			'cured' => array(),
			'last_backup' => 0,
            'last_scan' => 0,
		),
		'errors' => array(
			'cron' => array(
				
			),
		),
		'last_php_log_sent' => 0,
		'2fa_keys'          => array(),
		'current_settings_template_id'   => null,  // Loaded settings template id
		'current_settings_template_name' => null,  // Loaded settings template name
        'ms__key_tries' => 0,
	);
	
	public $default_network_settings = array(
        'spbc_key'           => '',
        'ms__hoster_api_key' => '',
        'ms__work_mode'       => 1,
    );
    
    public $default_network_data = array(
        'key_is_ok'  => false,
        'user_token' => '',
        'service_id' => '',
        'moderate'   => 0,
    );
	
	public $default_remote_calls = array(
		
	// Common
		'check_website'          => array( 'last_call' => 0, 'cooldown' => 0 ),
		'close_renew_banner'     => array( 'last_call' => 0, ),
		'update_plugin'          => array( 'last_call' => 0, ),
		'drop_security_firewall' => array( 'last_call' => 0, ),
		'update_settings'        => array( 'last_call' => 0, ),
	    'cron_update_task'       => array( 'last_call' => 0, ),
	    'perform_service_get'    => array( 'last_call' => 0, ),
	
	// Firewall
		'update_security_firewall'         => array( 'last_call' => 0, 'cooldown' => 300 ),
		'update_security_firewall__worker' => array( 'last_call' => 0, 'cooldown' => 0 ),
	
	// Inner
		'download__quarantine_file' => array('last_call' => 0, 'cooldown' => 3),
		
	// Backups
		'backup_signatures_files' => array('last_call' => 0,),
		'rollback_repair'         => array('last_call' => 0,),
		
	// Scanner
		'scanner_signatures_update'        => array('last_call' => 0,),
		'scanner_clear_hashes'             => array('last_call' => 0,),
		
		'scanner__controller'              => array('last_call' => 0, 'cooldown' => 1),
		'scanner__get_remote_hashes'       => array('last_call' => 0,),
		'scanner__count_hashes_plug'       => array('last_call' => 0,),
		'scanner__get_remote_hashes__plug' => array('last_call' => 0,),
		'scanner__clear_table'             => array('last_call' => 0,),
		'scanner__count_files'             => array('last_call' => 0,),
		'scanner__scan'                    => array('last_call' => 0,),
		'scanner__count_files__by_status'  => array('last_call' => 0,),
		'scanner__scan_heuristic'          => array('last_call' => 0,),
		'scanner__scan_signatures'         => array('last_call' => 0,),
		'scanner__count_cure'              => array('last_call' => 0,),
		'scanner__cure'                    => array('last_call' => 0,),
		'scanner__links_count'             => array('last_call' => 0,),
		'scanner__links_scan'              => array('last_call' => 0,),
		'scanner__frontend_scan'           => array('last_call' => 0,),
		'scanner__check_listing'           => array('last_call' => 0,),
        'scanner__check_file'              => array('last_call' => 0, 'cooldown' => 0),
        'scanner__check_file__heuristic'   => array('last_call' => 0, 'cooldown' => 0),
        'scanner__check_file__signature'   => array('last_call' => 0, 'cooldown' => 0),
    
    // Debug
		'debug' => array('last_call' => 0,),
  
	);
	
	public $default_errors = array();
	
	public $default_fw_stats = array(
		'entries'            => 0,
		'last_send_count'    => null,
		'firewall_last_send' => null,
		
		'updating'             => false,
		'updating_folder'      => 'fw_files',
		'update_percent'       => 0,
		'updating_id'          => null,
		'updating_last_start' => 0,
        
        'is_on_maintenance' => false,
	);

    public $default_scanner_listing = array(
        'accessible_urls' => array(),
    );
	
    /**
     * Additional action with options
     * Set something depending on something
     *
     * Adding some dynamic properties
     *
     * Read code for details
     *
     * @return void
     */
    protected function init(){
    
        /* Changes in settings depending from different circumstances */
    
        // Data
        // Set salt if it's empty
        $this->data['salt'] = empty( $this->data['salt'] )
            ? str_pad( mt_rand( 0, mt_getrandmax() ), 6, '0' ) . str_pad( mt_rand( 0, mt_getrandmax() ), 6, '0' )
            : $this->data['salt'];
    
        // @todo why?
        $this->data['last_php_log_sent'] = empty( $this->data['last_php_log_sent'] )
            ? time()
            : $this->data['last_php_log_sent'];
    
        // @todo why?
        /*
         * It's all about first start
         * Looks like we saving it because we need it somewhere in the DB
         */
        if( $this->getOption( 'spbc_data' ) ){
            $this->save( 'data' );
        }
    
        // @todo WTF 2?
        // Get fw_stats from wp_options of the main blog
        if( ! $this->is_mainsite ){
            $initial_blog = get_current_blog_id();
            switch_to_blog( get_main_site_id() );
            $fw_stats = get_option( 'spbc_fw_stats' );
            switch_to_blog( $initial_blog );
            if( $fw_stats ){
                $this->fw_stats = new \ArrayObject( $fw_stats );
            }
        }
    
        /* Adding some dynamic properties */
        
        // Standalone or main site
        $this->api_key = $this->settings['spbc_key'];
        $this->settings_link = is_network_admin() ? 'settings.php?page=spbc' : 'options-general.php?page=spbc';
        $this->dashboard_link = 'https://cleantalk.org/my/' . ( $this->user_token ? '?user_token=' . $this->user_token : '' );
        $this->notice_show  = $this->notice_show || $this->errors;
        $this->is_windows = $this->is_windows();
        
        
        $this->scaner_enabled = true;
        $this->fw_enabled     = true;
        
        // Network
        if( ! $this->is_mainsite ){
            
            // Custom key allowed
            if( $this->ms__work_mode != 2 ){
        
                $this->scaner_enabled = false;
        
            // Mutual key
            }elseif( $this->ms__work_mode == 2 ){
        
                $this->api_key        = $this->network_settings['spbc_key'];
                $this->key_is_ok      = $this->network_data['key_is_ok'];
                $this->user_token     = $this->network_data['user_token'];
                $this->service_id     = $this->network_data['service_id'];
                $this->moderate       = $this->network_data['moderate'];
                $this->notice_show    = false;
                $this->scaner_enabled = false;
                $this->fw_enabled     = false;
            }
        }
    }
    
    /**
     * Wrapper for CMS
     * Getting the option from the database
     *
     * @param $option_name
     *
     * @return bool|mixed|void
     */
    protected function getOption( $option_name ){
        return strpos( $option_name, 'network' ) !== false
            ? get_site_option( $this->option_prefix . '_' . $option_name )
            : get_option( $this->option_prefix . '_' . $option_name );
    }
    
    /**
     * @param string $option_name
     * @param bool $use_perfix
     * @param bool $autoload
     *
     * @return bool
     */
	public function save($option_name, $use_perfix = true, $autoload = true)
	{
	    if( strpos( $option_name, 'network' ) !== false ){
	        
            return update_site_option(
                $this->option_prefix . '_' . $option_name,
                (array)$this->$option_name
            );
        }
        
        return update_option(
            $use_perfix ? $this->option_prefix . '_' . $option_name : $option_name,
            (array) $this->$option_name,
            $autoload
        );
    }
    
	public function deleteOption($option_name, $use_prefix = false)
	{
		if($this->__isset($option_name)){
			$this->__unset($option_name);
			delete_option( ($use_prefix ? $this->option_prefix.'_' : '') . $option_name);
		}		
	}
    
    /**
     * Generates new State when switching to a new blog
     * Useful for Multisite builds
     *
     * @using add_action( 'switch_blog', array( '\CleantalkSP\SpbctWP\State', 'resetState'), 2, 10 );
     */
    public static function resetState(){
	    
	    global $spbc, $spbc_old;
    
        $spbc_old = $spbc;
        
        $spbc = new self(
            'spbc',
            array(
                'settings',
                'data',
                'remote_calls',
                'debug',
                'installing',
                'errors',
                'fw_stats'
            ),
            is_multisite(),
            is_main_site()
        );
        
        return $spbc;
    }
    
    public static function restoreState(){
        
        global $spbc, $spbc_old;
        
        $spbc = $spbc_old;
    
        unset( $spbc_old );
    }
    
}
