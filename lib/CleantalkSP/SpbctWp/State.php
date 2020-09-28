<?php

namespace CleantalkSP\SpbctWp;

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

class State
{
	public $doing_cron = false;
	public $option_prefix = '';
	public $settings__elements     = array();
	public $settings__tabs_heading = array();
	public $storage = array();
	public $def_settings = array(
		
		// authentication
		'2fa_enable'                       => 0,
		'2fa_roles'                        => array('administrator'),
		'block_timer__1_fails'             => 3,     //@deprecated
		'block_timer__5_fails'             => 3600,  //By defauld ban bruteforce IP for the one hour
		
		// Key
		'spbc_key'                         => '',
		'custom_key'                       => 0,
		
		// Traffic Control
		'traffic_control_enabled'          => 1,
		'traffic_control_autoblock_amount' => 1000,
		'traffic_control_autoblock_period'   => 3600,
		
		// Scanner
		'scanner_auto_start'		       => 1,
		'scanner_auto_start_manual'		   => 0,
		'scanner_auto_start_manual_time'   => null,
		'scanner_outbound_links'		   => 0,
		'scanner_outbound_links_mirrors'   => '',
		'scanner_heuristic_analysis'	   => 1,
		'scanner_signature_analysis'       => 1,
		'scanner_auto_cure'                => 1,
		'scanner_frontend_analysis'        => 1,
		'scanner_dir_exclusions'           => '',
		
		// Web Application Firewall
		'waf_enabled'                      => 1,
		'waf_xss_check'                    => 1,
		'waf_sql_check'                    => 1,
		'waf_file_check'                   => 1,
		'waf_exploit_check'                => 1,
		
		// Misc
		'backend_logs_enable'              => 1,
		'set_cookies'                      => 1,
		'forbid_to_show_in_iframes'        => 1,
		'show_link_in_login_form'          => 1,
		'additional_headers'               => 1,
		'use_buitin_http_api'              => 1,
		'complete_deactivation'            => 0,
	);
	public $def_data = array(
		
		// Firewall
		'firewall_updating_id'         => null,
		'firewall_updating_last_start' => 0,
		'firewall_entries'             => null,
		'last_firewall_send'           => null,
		'last_firewall_send_count'     => null,
		'last_firewall_updated'        => null,
		
		'plugin_version'           => SPBC_VERSION,
		'user_token'               => '',
		'key_is_ok'                => false,
		'moderate'                 => false,
		'logs_last_sent'           => null,
		'last_sent_events_count'   => null,
		'notice_show'              => null,
		'notice_renew'             => false,
		'notice_trial'             => false,
		'notice_were_updated'      => false,
		'service_id'               => '',
		'license_trial'            => 0,
		'account_name_ob'          => '',
		'salt'                     => '',
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
		),
		'cron' => array(
			'running' => false,
		),
		'errors' => array(
			'cron' => array(
				
			),
		),
		'last_php_log_sent' => 0,
		'2fa_keys'          => array(),
	);
	public $def_network_settings = array(
		'allow_custom_key'   => false,
		'allow_cleantalk_cp' => false,
		'key_is_ok'          => false,
		'spbc_key'           => '',
		'user_token'         => '',
		'service_id'         => '',
		'moderate'           => 0,
		'waf_enabled'        => 1,
		'waf_xss_check'      => 1,
		'waf_sql_check'      => 1,
		'waf_file_check'     => 1,
		'waf_exploit_check'  => 1,
	);
	
	public $def_remote_calls = array(
		
	// Common
		'check_website'          => array( 'last_call' => 0, 'cooldown' => 0 ),
		'close_renew_banner'     => array( 'last_call' => 0, ),
		'update_plugin'          => array( 'last_call' => 0, ),
		'drop_security_firewall' => array( 'last_call' => 0, ),
		'update_settings'        => array( 'last_call' => 0, ),
	
	// Firewall
		'update_security_firewall'             => array( 'last_call' => 0, 'cooldown' => 300 ),
		'update_security_firewall__write_base' => array( 'last_call' => 0, 'cooldown' => 0 ),
	
	// Inner
		'download__quarantine_file' => array('last_call' => 0, 'cooldown' => 3),
		
	// Backups
		'backup_signatures_files' => array('last_call' => 0,),
		'rollback_repair'         => array('last_call' => 0,),
		
	// Scanner
		'scanner_signatures_update'        => array('last_call' => 0,),
		'scanner_clear_hashes'             => array('last_call' => 0,),
		
		'scanner__controller'              => array('last_call' => 0, 'cooldown' => 3),
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
	);
	
	public $def_errors = array();
	
	public function __construct($option_prefix, $options = array('settings'), $wpms = false)
	{
		$this->option_prefix = $option_prefix;
		
		if($wpms){
			$option = get_site_option($this->option_prefix.'_network_settings');			
			$option = is_array($option) ? $option : $this->def_network_settings;
			$this->network_settings = new \ArrayObject($option);
		}
		
		foreach($options as $option_name){
			
			$option = get_option($this->option_prefix.'_'.$option_name);
			
			// Default options
			if($this->option_prefix.'_'.$option_name === 'spbc_settings'){
				$option = is_array($option) ? array_merge($this->def_settings, $option) : $this->def_settings;
				if(!is_main_site()) $option['backend_logs_enable'] = 0;
			}
			
			// Default data
			if($this->option_prefix.'_'.$option_name === 'spbc_data'){
				$option = is_array($option) ? array_merge($this->def_data,     $option) : $this->def_data;
				if(empty($option['salt'])) $option['salt'] = str_pad(rand(0, getrandmax()), 6, '0').str_pad(rand(0, getrandmax()), 6, '0');
				if(empty($option['last_php_log_sent'])) $option['last_php_log_sent'] = time();
			}
			
			// Default errors
			if($this->option_prefix.'_'.$option_name === 'spbc_errors'){
				$option = is_array($option) ? array_merge($this->def_errors, $option) : $this->def_errors;
			}
			
			// Default remote calls
			if($this->option_prefix.'_'.$option_name === 'spbc_remote_calls'){
				$option = is_array($option) ? array_merge($this->def_remote_calls, $option) : $this->def_remote_calls;
			}
			
			$this->$option_name = is_array($option) ? new \ArrayObject($option) : $option;
			
		}
	}
	
	private function getOption($option_name)
	{
		$option = get_option('spbc_'.$option_name);
		$this->$option_name = gettype($option) === 'array'
			? new \ArrayObject($option)
			: $option;
	}
	
	/**
	 * @param string $option_name
	 * @param bool $use_perfix
	 * @param bool $autoload
	 */
	public function save($option_name, $use_perfix = true, $autoload = true)
	{
		update_option(
			$use_perfix ? $this->option_prefix.'_'.$option_name : $option_name,
			(array)$this->$option_name,
			$autoload
		);
	}
	
	public function saveSettings()
	{
		update_option($this->option_prefix.'_settings', $this->settings);
	}
	
	public function saveData()
	{		
		update_option($this->option_prefix.'_data', $this->data);
	}
	
	public function saveNetworkSettings()
	{
		update_site_option(
			$this->option_prefix.'_network_settings',
			(array)$this->network_settings
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
	 * Prepares an adds an error to the plugin's data
	 *
	 * @param string type
	 * @param mixed array || string
	 * @returns null
	 */
	public function error_add($type, $error, $major_type = null, $set_time = true)
	{
		$error = is_array($error)
			? $error['error']
			: $error;
		
		// Exceptions
		if( ($type == 'send_logs'          && $error == 'NO_LOGS_TO_SEND') ||
			($type == 'send_firewall_logs' && $error == 'NO_LOGS_TO_SEND') ||
			$error == 'LOG_FILE_NOT_EXISTS'
		)
			return;
		
		$error = array(
			'error'      => $error,
			'error_time' => $set_time ? current_time('timestamp') : null,
		);
		
		if(!empty($major_type)){
			$this->errors[$major_type][$type] = $error;
		}else{
			$this->errors[$type] = $error;
		}
		
		$this->save('errors');
	}
	
	/**
	 * Set or deletes an error depends of the first bool parameter
	 *
	 * @param $add_error
	 * @param $error
	 * @param $type
	 * @param null $major_type
	 * @param bool $set_time
	 * @param bool $save_flag
	 */
	public function error_toggle($add_error, $type, $error, $major_type = null, $set_time = true, $save_flag = true ){
		if( $add_error )
			$this->error_add( $type, $error, $major_type, $set_time );
		else
			$this->error_delete( $type, $save_flag, $major_type );
	}
	
	/**
	 * Deletes an error from the plugin's data
	 *
	 * @param string $type
	 * @param bool   $save_flag
	 * @param string $major_type
	 *
	 * @return void
	 */
	public function error_delete($type, $save_flag = false, $major_type = null)
	{
		if(is_string($type))
			$type = explode(' ', $type);
		
		foreach($type as $val){
			if($major_type){
				if(isset($this->errors[$major_type][$val]))
					unset($this->errors[$major_type][$val]);
			}else{
				if(isset($this->errors[$val]))
					unset($this->errors[$val]);
			}
		}
		
		// Save if flag is set and there are changes
		if($save_flag)
			$this->save('errors');
	}
	
	/**
	 * Deletes all errors from the plugin's data
	 *
	 * @param bool $save_flag
	 *
	 * @return void
	 */
	public function error_delete_all($save_flag = false)
	{
		$this->errors = new \ArrayObject($this->def_errors);
		if($save_flag)
			$this->save('errors');
	}
	
	public function __set($name, $value) 
    {
        $this->storage[$name] = $value;
    }

    public function __get($name) 
    {
        if (array_key_exists($name, $this->storage)){
            return $this->storage[$name];
        }else{
			$this->getOption($name);
			return $this->storage[$name];
		}
	
		// return !empty($this->storage[$name]) ? $this->storage[$name] : null;
    }
	
    public function __isset($name) 
    {
        return isset($this->storage[$name]);
    }
	
    public function __unset($name) 
    {
        unset($this->storage[$name]);
    }
	
	public function __call($name, $arguments)
	{
        error_log ("Calling method '$name' with arguments: " . implode(', ', $arguments). "\n");
    }
	
    public static function __callStatic($name, $arguments)
	{
        error_log("Calling static method '$name' with arguments: " . implode(', ', $arguments). "\n");
    }
}
