<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\SpbctWP\Cron as SpbcCron;
use CleantalkSP\Variables\Request;
use CleantalkSP\Variables\Get;
use CleantalkSP\SpbctWP\Scanner\Controller;

class RemoteCalls extends \CleantalkSP\Common\RemoteCalls {
    
    public function __construct( &$state ){

        $this->state = $state;
        $this->class_name = __CLASS__;

    }
    
    /**
     * Hook before performing remote call action
     * Breaks the execution on few conditions
     *
     * @return bool|null
     */
    protected static function filter_before_action(){
    
        // Stop execution if plugin is deactivated
        if( get_option( 'spbc_deactivation_in_process' ) !== false ){ // Continue if plugin is active
            delete_option( 'spbc_deactivation_in_process' );
            
            return true;
        }
    
        // Delay before perform action
        if( Request::get( 'delay' ) ){
            
            // Do not make remote call because the website is in maintenance mode
            if( wp_is_maintenance_mode() ){
                return true;
            }
            
            sleep( Request::get( 'delay' ) );
            
            $params = Get::get( 'delay' ) ? $_GET : $_POST;
            unset( $params['delay'] );
            
            return static::performToHost(
                Request::get( 'spbc_remote_action' ),
                $params,
                array( 'async' ),
                false
            );
        }
        
        return false;
    }
    
    /**
     * Performs remote call to the current website
     *
     * @param string $host
     * @param string $rc_action
     * @param string $plugin_name
     * @param string $api_key
     * @param array  $params
     * @param array  $patterns
     * @param bool   $do_check Shows whether perform check before main remote call
     *
     * @return bool|string[]
     */
    public static function perform( $host, $rc_action, $plugin_name, $api_key, $params, $patterns = array(), $do_check = true )
    {
        // Do not make remote call because the website is in maintenance mode
        if( function_exists('wp_is_maintenance_mode') && wp_is_maintenance_mode() ){
            return true;
        }
        
        return parent::perform($host, $rc_action, $plugin_name, $api_key, $params, $patterns, $do_check);
    }
    
	public static function performToHost($rc_action, $params = array(), $patterns = array(), $do_check = true)
    {
        global $spbc;
        
        return self::perform(
            get_option( 'home' ), // <- Because of this ='(
            $rc_action,
            'spbc',
            $spbc->api_key,
            $params,
            $patterns,
            $do_check
        );
    }
	
    public static function action__check_website(){
        die('OK');
    }
    
    public static function action__close_renew_banner() {
		global $spbc;
		$spbc->data['notice_show'] = 0;
		$spbc->save('data');
		// Updating cron task
		SpbcCron::updateTask('access_key_notices', 'spbc_access_key_notices', 86400);
		die('OK');
	}
    
    public static function action__update_security_firewall() {
		global $spbc;
		$result = spbc_security_firewall_update__init();
		$spbc->error_toggle( ! empty( $result['error'] ), 'firewall_update', $result);
        die( empty( $result['error'] ) ? 'OK' : 'FAIL ' . json_encode( array( 'error' => $result['error'] ) ) );
	}
	
    public static function action__update_security_firewall__worker() {
    
		$result = spbc_security_firewall_update__worker();
        
        die( empty( $result['error'] ) ? 'OK' : 'FAIL ' . json_encode( array( 'error' => $result['error'] ) ) );
	}
    
    public static function action__drop_security_firewall() {
		$result = spbc_security_firewall_drop();
		die(empty($result['error']) ? 'OK' : 'FAIL '.json_encode(array('error' => $result['error'])));
	}
    
    public static function action__download__quarantine_file() {
		$result = spbc_scanner_file_download(true, Request::get('file_id'));
		if(empty($result['error'])){
			header('Content-Type: application/octet-stream');
			header('Content-Disposition: attachment; filename='.$result['file_name']);
		}
		die(empty($result['error'])
			? $result['file_content']
			: 'FAIL '.json_encode(array('error' => $result['error'])));
	}
    
    /**
     * The 'update_settings' remote call handler
     *
     * Handles different types of setting values:
     *  string
     *  array types separated by commas
     */
    public static function action__update_settings() {
    
		global $spbc;
		
		foreach($spbc->default_settings as $setting => $value){
			if( Request::get( $setting ) ){
       
			    $var = Request::get( $setting );
				$type = gettype($spbc->settings[$setting]);
				
				switch( $type ){
                    case 'string':
					    $var = preg_replace(array('/=/', '/`/'), '', $var);
					    break;
                    case 'array':
                        $var = explode( ',', $var );
                        break;
                }
                
                settype($var, $type);
				$spbc->settings[ $setting ] = $var;
			}
		}
		
		$spbc->save('settings');
		
		die('OK');
	}
    
    /**
     * The 'Cron::updateTask' remote call handler
     *
     */
    public static function action__cron_update_task() {
    
        $update_result = false;
        
        if( Request::get( 'task' ) && Request::get( 'handler' ) && Request::get( 'period' ) && Request::get( 'first_call' ) ){
            
            $update_result = Cron::updateTask(
                Request::get( 'task' ),
                Request::get( 'handler' ),
                (int)Request::get( 'period' ),
                (int)Request::get( 'first_call' )
            );
        }
        
        die( $update_result ? 'OK' : 'FAIL ');
    }
    
    public static function action__rollback_repair() {
		$result = spbc_rollback(Request::get('backup_id'));
		die(empty($result['error'])
			? 'OK'
			: 'FAIL '.json_encode(array('error' => $result['error'])));
	}
    
    public static function action__scanner_clear_hashes() {
		$result = true;
		switch(Request::get('type')){
			case 'plugins':            delete_option(SPBC_PLUGINS);                             break;
			case 'themes':             delete_option(SPBC_THEMES);                              break;
			case 'plugins_and_themes': delete_option(SPBC_THEMES); delete_option(SPBC_PLUGINS); break;
			case 'all':
			default:                   $result = spbc_scanner_clear();                          break;
		}
		die(empty($result['error'])
			? 'OK'
			: 'FAIL '.json_encode(array('error' => 'COULDNT_CLEAR_ALL_DB_ERROR')));
	}
    
    public static function action__scanner_signatures_update() {
		$result = spbc_scanner__signatures_update();
		die(empty($result['error'])
			? 'OK' . ' ' . (!empty($result['success']) ? $result['success'] : '')
			: 'FAIL '.json_encode(array('error' => $result['error'])));
	}
    
    public static function action__scanner__controller() {
		return spbc_scanner__controller();
	}
    
    public static function action__scanner__check_file__signature()
    {
        $file_infos = json_decode(Get::get('file_infos') ?: false, true);
        if( ! $file_infos ){
            die('FAIL ' . json_encode(array('error' => 'INVALID_JSON')));
        }
	
        $result = array();
        foreach( $file_infos as $file_info ){
            $result[ $file_info['path'] ] = Controller::scanFileForSignatures($file_info);
        }
    
        die( json_encode($result) );
    }

    public static function action__scanner__check_file__heuristic()
    {
        $file_infos = json_decode(Get::get('file_infos') ?: false, true);
        if( ! $file_infos ){
            die('FAIL ' . json_encode(array('error' => 'INVALID_JSON')));
        }
    
        $result = array();
        foreach( $file_infos as $file_info ){
            $result[ $file_info['path'] ] = Controller::scanFileForHeuristic($file_info);
        }
    
        die( json_encode($result) );
    }
    
    public static function action__scanner__check_file(){
        
        $file_infos = Get::get('file_infos');
        if( ! $file_infos || ! is_array( $file_infos ) ){
            die( json_encode( array( 'error' => 'INVALID_FILE_INFOS' ) ) );
        }
        
        $results = array();
        foreach( $file_infos as $file_info ){
            $results[ $file_info['path'] ] = Controller::scanFile($file_info);
        }
        
        die( json_encode( $results ) );
    }
    
    public static function action__perform_service_get()
    {
        $result_service_get = spbct_perform_service_get();
        
        die( ! empty($result_service_get['error'])
            ? 'FAIL ' . json_encode($result_service_get)
            : 'OK'
        );
    }
    
    public static function action__debug(){
        
        global $spbc, $wpdb;
	
	    $out['fw_data_base_size'] = $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA) +
	                                $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA__IPS);
        $out['settings'] = $spbc->settings;
        $out['fw_stats'] = $spbc->fw_stats;
        $out['data']     = $spbc->data;
        $out['cron']     = $spbc->cron;
        $out['errors']   = $spbc->errors;
        $out['debug']    = $spbc->debug;
        $out['queue']    = get_option( 'spbc_fw_update_queue' );
        $out['servers_connection'] = spbc_test_connection();
        $out['plugins'] = $spbc->plugins;
        $out['themes'] = $spbc->themes;
        $out['transactions'] = $wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_name LIKE 'spbc_transaction__%'");
        
        if( SPBC_WPMS ){
            $out['network_settings'] = $spbc->network_settings;
            $out['network_data'] = $spbc->network_data;
        }
        
        if( \CleantalkSP\Variables\Request::equal('out', 'json' ) ){
            die( json_encode( $out ) );
        }
        array_walk( $out, function(&$val, $_key){
            $val = (array) $val;
        });
        
        array_walk_recursive( $out, function(&$val, $_key){
            if( is_int( $val ) && preg_match( '@^\d{9,11}$@', (string) $val ) ){
                $val = date( 'Y-m-d H:i:s', $val );
            }
        });
        
        $out = print_r($out, true);
        $out = str_replace("\n", "<br>", $out);
        $out = preg_replace("/[^\S]{4}/", "&nbsp;&nbsp;&nbsp;&nbsp;", $out);
        
        die( $out );
        
    }
    
}
