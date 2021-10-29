<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\SpbctWP\Firewall\FW;
use CleantalkSP\SpbctWP\Helper;
use CleantalkSP\SpbctWP\Cron as SpbcCron;
use CleantalkSP\Variables\Request;
use CleantalkSP\Variables\Get;

class RemoteCalls extends \CleantalkSP\Common\RemoteCalls {
    
    public function __construct( &$state ){

        $this->state = $state;
        $this->class_name = __CLASS__;

    }
    
    /**
     * @return null
     */
    protected static function filter_before_action(){
    
        // Stop execution if plugin is deactivated
        if( get_option( 'spbc_deactivation_in_process' ) !== false ){ // Continue if plugin is active
            delete_option( 'spbc_deactivation_in_process' );
            
            return 'FAIL ' . json_encode( array( 'error' => 'PLUGIN_DEACTIVATION_IN_PROCESS' ) );
        }
    
        // Delay before perform action;
        if( Request::get( 'delay' ) ){
            
            sleep( Request::get( 'delay' ) );
            
            $params = Get::get( 'delay' ) ? $_GET : $_POST;
            unset( $params['delay'] );
        
            return Helper::http__request__rc_to_host(
                Request::get( 'spbc_remote_action' ),
                $params,
                array( 'async' ),
                false
            );
        }
        
        return null;
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
    
    public static function action__update_plugin() {
		add_action('template_redirect', 'spbc_update', 1);
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
    
    public static function action__backup_signatures_files() {
		$result = spbc_backup__files_with_signatures();
		die(empty($result['error'])
			? 'OK'
			: 'FAIL '.json_encode(array('error' => $result['error'])));
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
			case 'all':                $result = spbc_scanner_clear();                          break;
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
    
    public static function action__scanner__get_remote_hashes() {
		spbc_scanner_get_remote_hashes();
	}
    
    public static function action__scanner__count_hashes_plug() {
		spbc_scanner_count_hashes_plug();
	}
    
    public static function action__scanner__get_remote_hashes__plug() {
		spbc_scanner_get_remote_hashes__plug();
	}
    
    public static function action__scanner__get_remote_hashes__approved() {
		spbc_scanner_get_remote_hashes__approved();
	}
    
    public static function action__scanner__clear_table() {
		spbc_scanner_clear_table();
	}
    
    public static function action__scanner__count_files() {
		spbc_scanner_count_files();
	}
    
    public static function action__scanner__scan() {
		spbc_scanner_scan();
	}
    
    public static function action__scanner__count_files__by_status() {
		spbc_scanner_count_files__by_status();
	}
    
    public static function action__scanner__scan_heuristic() {
		spbc_scanner_scan_signatures();
	}
	
	public static function action__scanner__scan_signatures() {
		spbc_scanner_scan_signatures();
	}
    
    public static function action__scanner__backup_sigantures() {
		spbc_backup__files_with_signatures();
	}
    
    public static function action__scanner__count_cure() {
		spbc_scanner_count_cure();
	}
    
    public static function action__scanner__cure() {
		spbc_scanner_cure();
	}
    
    public static function action__scanner__links_count() {
		spbc_scanner_links_count();
	}
    
    public static function action__scanner__links_scan() {
		spbc_scanner_links_scan();
	}
    
    public static function action__scanner__frontend_scan() {
		spbc_scanner_frontend__scan();
	}
    
    public static function action__scanner__check_listing() {
        spbc_scanner_check_listing();
    }
    
    public static function action_scanner__send_results() {
		spbc_scanner_send_results();
	}
    
    public static function action__debug(){
        
        global $spbc, $wpdb;
    
        $out['sfw_data_base_size'] = $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA) +
                                     $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA__IPS);
        $out['settings'] = $spbc->settings;
        $out['fw_stats'] = $spbc->fw_stats;
        $out['data']     = $spbc->data;
        $out['cron']     = $spbc->cron;
        $out['errors']   = $spbc->errors;
        $out['queue']    = get_option( 'spbc_fw_update_queue' );
        $out['servers_connection'] = spbc_test_connection();
        $out['plugins'] = $spbc->plugins;
        $out['themes'] = $spbc->themes;
        
        if( APBCT_WPMS ){
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
