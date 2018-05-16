<?php

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

class SpbcState
{	
	public $option_prefix = '';
	public $storage = array();
	public $def_settings = array(
		'spbc_key'                         => '',
		'traffic_control_enabled'          => true,
		'traffic_control_autoblock_amount' => 1000,
		'show_link_in_login_form'          => true,
		'set_cookies'                      => true,
		'complete_deactivation'            => false,
		'scan_outbound_links'			   => false,
		'heuristic_analysis'			   => false,
		'scan_outbound_links_mirrors'      => '',
	);
	public $def_data = array(
		'plugin_version'           => SPBC_VERSION,
		'user_token'               => '',
		'key_is_ok'                => false,
		'moderate'                 => false,
		'logs_last_sent'           => null,
		'last_sent_events_count'   => null,
		'last_firewall_updated'    => null,
		'firewall_entries'         => null,
		'last_firewall_send'       => null,
		'last_firewall_send_count' => null,
		'notice_show'              => null,
		'notice_renew'             => false,
		'notice_trial'             => false,
		'notice_were_updated'      => false,
		'service_id'               => '',
		'license_trial'            => 0,
		'scanner'                  => array(
			'last_wp_version'      => null,
			'cron' => array(
				'state'         => 'get_hashes',
				'total_scanned' => 0,
				'offset'        => 0,
			),
		),
		'cron' => array(
			'running' => false,
		),
		'errors' => array(
			'cron' => array(
				
			),
		),
	);
	public $def_network_settings = array(
		'allow_custom_key'   => false,
		'allow_cleantalk_cp' => false,
		'key_is_ok'          => false,
		'spbc_key'           => '',
		'user_token'         => '',
		'service_id'         => '',
	);
	
	public function __construct($option_prefix, $options = array('settings'), $wpms = false)
	{
		$this->option_prefix = $option_prefix;
		
		if($wpms){
			$option = get_site_option($this->option_prefix.'_network_settings');			
			$option = is_array($option) ? $option : $this->def_network_settings;
			$this->network_settings = new ArrayObject($option);
		}
		
		foreach($options as $option_name){
			
			$option = get_option($this->option_prefix.'_'.$option_name);
			
			// Setting default options
			if($this->option_prefix.'_'.$option_name === 'spbc_settings'){
				$option = is_array($option) ? array_merge($this->def_settings, $option) : $this->def_settings;
			}
			
			if($this->option_prefix.'_'.$option_name === 'spbc_data'){
				$option = is_array($option) ? array_merge($this->def_data,     $option) : $this->def_data;
			}
			
			$this->$option_name = is_array($option) ? new ArrayObject($option) : $option;
		}
	}
	
	private function getOption($option_name)
	{
		$option = get_option($option_name);
		
		if($option === false)
			$this->$option_name = false;
		elseif(gettype($option) === 'array')
			$this->$option_name = new ArrayObject($option);
		else
			$this->$option_name = $option;
	}
	
	public function save($option_name, $use_perfix = true)
	{	
		$option_name_to_save = $use_perfix ? $this->option_prefix.'_'.$option_name : $option_name;
		$arr = array();
		foreach($this->$option_name as $key => $value){
			$arr[$key] = $value;
		}
		update_option($option_name_to_save, $arr);
	}
	
	public function saveSettings()
	{
		update_option($this->option_prefix.'_settins', $this->settings);
	}
	
	public function saveData()
	{		
		update_option($this->option_prefix.'_data', $this->data);
	}
	
	public function saveNetworkSettings()
	{		
		update_site_option($this->option_prefix.'_network_settings', $this->network_settings);
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
			? $error['error_string']
			: $error;
		
		// Exceptions
		if( ($type == 'send_logs'          && $error == 'NO_LOGS_TO_SEND') ||
			($type == 'send_firewall_logs' && $error == 'NO_LOGS_TO_SEND')
		)
			return;
		
		$error = array(
			'error_string' => $error,
			'error_time'   => $set_time ? current_time('timestamp') : null,
		);
		
		if(!empty($major_type)){
			$this->data['errors'][$major_type][$type] = $error;
		}else{
			$this->data['errors'][$type] = $error;			
		}
		
		$this->save('data');
	}
	
	/**
	 * Deletes an error from the plugin's data
	 *
	 * @param mixed (array of strings || string 'elem1 elem2...' || string 'elem') type
	 * @param delay saving
	 * @returns null
	 */
	public function error_delete($type, $save_flag = false, $major_type = null)
	{
		if(is_string($type))
			$type = explode(' ', $type);
		
		foreach($type as $val){
			if($major_type){
				if(isset($this->data['errors'][$major_type][$val]))
					unset($this->data['errors'][$major_type][$val]);
			}else{
				if(isset($this->data['errors'][$val]))
					unset($this->data['errors'][$val]);
			}
		}
		
		// Save if flag is set and there are changes
		if($save_flag)
			$this->save('data');
	}
	
	/**
	 * Deletes all errors from the plugin's data
	 *
	 * @param delay saving
	 * @returns null
	 */
	public function error_delete_all($save_flag = false)
	{
		if(isset($this->data['errors']))
			unset($this->data['errors']);
		
		if($save_flag)
			$this->save('data');
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
