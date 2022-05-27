<?php

namespace CleantalkSP\Updater;

use CleantalkSP\SpbctWP\Cron;
use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\Variables\Cookie;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Helpers\Data;

class UpdaterScripts
{
    public static function updateTo_1_9_0(){
        
        //Adding send logs cron hook if not exists
        if ( !wp_next_scheduled('spbc_send_logs_hook') )
            wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_logs_hook');
        // Update Security FireWall cron hook
        if ( !wp_next_scheduled('spbc_security_firewall_update_hook') )
            wp_schedule_event(time() + 1800, 'hourly', 'spbc_security_firewall_update_hook');
        // Send logs cron hook
        if ( !wp_next_scheduled('spbc_send_firewall_logs_hook') )
            wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_firewall_logs_hook');
        
        return;
    }
    
    public static function updateTo_1_10_0(){
        
        wp_clear_scheduled_hook('spbc_send_logs_hourly_hook');
        wp_clear_scheduled_hook('spbc_send_daily_report');
        wp_clear_scheduled_hook('spbc_send_daily_report_hook');
        wp_clear_scheduled_hook('spbc_security_firewall_update_hourly_hook');
        wp_clear_scheduled_hook('spbc_send_firewall_logs_hourly_hook');
        
        wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_logs_hook');
        wp_schedule_event(time() + 43200, 'daily', 'spbc_send_report_hook');
        wp_schedule_event(time() + 43200, 'daily', 'spbc_security_firewall_update_hook');
        wp_schedule_event(time() + 1800, 'hourly', 'spbc_send_firewall_logs_hook');
        wp_schedule_event(time() + 1800, 'hourly', 'spbc_access_key_notices_hook');
    }
    
    public static function updateTo_1_19_0(){
        
        wp_clear_scheduled_hook('spbc_send_logs_hook');
        wp_clear_scheduled_hook('spbc_send_report_hook');
        wp_clear_scheduled_hook('spbc_security_firewall_update_hook');
        wp_clear_scheduled_hook('spbc_send_firewall_logs_hook');
        wp_clear_scheduled_hook('spbc_access_key_notices_hook');
        
        // Self cron system
        Cron::addTask('send_logs',           'spbc_send_logs',                3600, time() + 1800);
        Cron::addTask('send_report',         'spbc_send_daily_report',        86400, time() + 43200);
        Cron::addTask('firewall_update',     'spbc_security_firewall_update__init', 86400, time() + 43200);
        Cron::addTask('send_firewall_logs',  'spbc_send_firewall_logs',       3600, time() + 1800);
        Cron::addTask('access_key_notices',  'spbc_access_key_notices',       3600, time() + 3500);
    }
    
    public static function updateTo_1_20_0(){
        
        wp_clear_scheduled_hook('spbc_access_key_notices_hook');
        
    }
    
    public static function updateTo_1_21_0(){
        global $spbc;
        // Clearing errors because format changed
        $spbc->data['errors'] = array();
        
    }
    
    public static function updateTo_1_22_0(){
        global $spbc;
        // Adding service ID and refreshing other account params
        if(!empty($spbc->settings['spbc_key'])){
            $result = API::method__notice_paid_till($spbc->settings['spbc_key'], preg_replace('/http[s]?:\/\//', '', get_option( 'home' ), 1), 'security');
            if(empty($result['error'])){
                $spbc->data['notice_show']	= $result['show_notice'];
                $spbc->data['notice_renew'] = $result['renew'];
                $spbc->data['notice_trial'] = $result['trial'];
                $spbc->data['service_id']   = $result['service_id'];
                if(SPBC_WPMS && is_main_site()){
                    $spbc->network_settings['service_id'] = $result['service_id'];
                    $spbc->save('network_settings');
                }
            }
        }
    }
    
    public static function updateTo_2_0_0(){
        // Scanner's cron
        Cron::addTask('perform_scan_wrapper', 'spbc_perform_scan_wrapper', 86400, time() + 86400);
        // Drop existing table and create scanner's table
    }
    
    public static function updateTo_2_1_0(){
        global $spbc;
        unset($spbc->data['errors']);
        $spbc->save('data');
    }
    
    public static function updateTo_2_6_2(){
        Cron::updateTask('send_logs',            'spbc_send_logs',                3600, time() + 1800);
        Cron::updateTask('send_report',          'spbc_send_daily_report',        86400, time() + 43200);
        Cron::updateTask('firewall_update',      'spbc_security_firewall_update__init', 86400, time() + 43200);
        Cron::updateTask('send_firewall_logs',   'spbc_send_firewall_logs',       3600, time() + 1800);
        Cron::updateTask('access_key_notices',   'spbc_access_key_notices',       3600, time() + 3500);
        Cron::updateTask('perform_scan_wrapper', 'spbc_perform_scan_wrapper',     86400, time() + 43200);
    }
    
    public static function updateTo_2_8_0(){
        
        global $spbc;
        
        // Preparing for IPv6
        if(isset($spbc->data['cdn']) && $spbc->data['cdn'])                           unset($spbc->data['cdn']);
        if(isset($spbc->data['private_networks']) && $spbc->data['private_networks']) unset($spbc->data['private_networks']);
        
        unset($spbc->data['scanner']['last_wp_version']);
        Cron::removeTask('scanner_scan_deep_core');
        Cron::removeTask('scanner_scan_deep_plugin');
    }
    
    public static function updateTo_2_13_0(){
        update_option('spbc_plugins', array(), 'no');
        update_option('spbc_themes', array(), 'no');
    }
    
    public static function updateTo_2_14_0(){
        global $spbc;
        $spbc->data['cron']['running']  = false;
    }
    
    public static function updateTo_2_15_0(){
        global $spbc;
        $spbc->data['cron']['running'] = false;
        spbc_mu_plugin__install();
    }
    
    public static function updateTo_2_16_0(){
        global $spbc;
        $spbc->data['cron']['running'] = false;
        spbc_mu_plugin__uninstall();
        spbc_mu_plugin__install();
    }
    
    public static function updateTo_2_17_0(){
        global $spbc;
        $spbc->data['cron']['running'] = false;
    }
    
    public static function updateTo_2_22_0(){
        
        global $wpdb, $spbc, $wp_version;
        
        // Set source_type = null for custom files
        $wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "` SET source_type = NULL
		WHERE source_type = 'CORE' && real_full_hash IS NULL;");
        
        // Set source = wordpress and version for core files
        $wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "`
		SET source = 'wordpress',
			version = '$wp_version'
		WHERE source_type = 'CORE' && real_full_hash IS NOT NULL;");
        
        // Updating version and source of plugins
        if($spbc->plugins === false)
            $spbc->plugins = array();
        
        foreach($spbc->plugins as $name => $version){
            $wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "`
                SET source = '$name',
                    version = '$version'
                WHERE path LIKE '%$name%' && real_full_hash IS NOT NULL;");
        }
        
        // Updating version and source of themes
        if($spbc->themes === false)
            $spbc->themes = array();
        
        foreach($spbc->themes as $name => $version){
            $wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "`
                SET source_type = 'THEME',
                    source = '$name',
                    version = '$version'
                WHERE path LIKE '%$name%' && real_full_hash IS NOT NULL;");
        }
        $wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "`
		SET checked = 'YES_HEURISTIC'
		WHERE checked = 'YES' AND real_full_hash <> full_hash;");
        
        // Cron fix
        $spbc->data['cron']['running'] = false;
        
        Cron::addTask('scanner_update_signatures', 'spbc_scanner__signatures_update', 86400, time() + 20);
        $spbc->error_delete('scan_modified', 'and_save_data');
        
    }
    
    public static function updateTo_2_24_0(){
        global $wpdb;
        
        $wpdb->query("UPDATE `" . SPBC_TBL_SCAN_FILES . "`
		SET weak_spots = NULL,
			checked = 'NO'
		WHERE weak_spots IS NOT NULL;");
    
    }
    
    public static function updateTo_2_25_0(){
        
        global $spbc;
        
        $spbc->data['last_php_log_sent'] = 0;
        $spbc->save('data');
        
        Cron::addTask('send_php_logs', 'spbc_PHP_logs__send', 3600, time() + 300);
        
    }
    
    public static function updateTo_2_25_1(){
        
        global $spbc;
        
        $spbc->data['last_php_log_sent'] = time();
        $spbc->save('data');
        
    }
    
    public static function updateTo_2_26_1(){
        
        if(file_exists(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php'))
            unlink(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php');
        
        spbc_mu_plugin__install();
    }
    
    public static function updateTo_2_27(){
        
        if(file_exists(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php'))
            unlink(WPMU_PLUGIN_DIR . '/security-malware-firewall-mu.php');
        if(file_exists(WPMU_PLUGIN_DIR . '/0security-malware-firewall-mu.php'))
            unlink(WPMU_PLUGIN_DIR . '/0security-malware-firewall-mu.php');
        
        spbc_mu_plugin__install();
    }
    
    public static function updateTo_2_28_0(){
        Cookie::set( 'spbc_is_logged_in', '0', time()-30, '/' );
    }
    
    public static function updateTo_2_30_0(){
        if(!is_dir(SPBC_PLUGIN_DIR.'backups'))
            mkdir(SPBC_PLUGIN_DIR.'backups');
    }
    
    public static function updateTo_2_31_0(){
        global $spbc;
        Cron::removeTask('perform_scan_wrapper');
        Cron::removeTask('perform_scan_wrapper_act');
        
        $hour_minutes       = $spbc->settings['scanner__auto_start_manual_time']
            ? explode( ':', $spbc->settings['scanner__auto_start_manual_time'] )
            : explode( ':', date('H:i') );
        $scanner_start_time = mktime( (int) $hour_minutes[0], (int) $hour_minutes[1] ) - $spbc->settings['scanner__auto_start_manual_tz'] * 3600 + 3600;
        
        Cron::addTask( 'scanner__launch', 'spbc_scanner__launch', 86400, $scanner_start_time );
        
        // Deletting all errors
        if(isset($spbc->data['errors']))
            unset($spbc->data['errors']);
    }
    
    public static function updateTo_2_37_0(){
        global $spbc;
        $spbc->error_delete( 'allow_url_fopen', true );
    }
    
    public static function updateTo_2_42_0() {
        
        if( SPBC_WPMS ) {
            
            global $spbc;
            $spbc->network_settings['waf__enabled']       = $spbc->default_network_settings['waf__enabled'];
            $spbc->network_settings['waf__xss_check']     = $spbc->default_network_settings['waf__xss_check'];
            $spbc->network_settings['waf__sql_check']     = $spbc->default_network_settings['waf__sql_check'];
            $spbc->network_settings['waf__file_check']    = $spbc->default_network_settings['waf__file_check'];
            $spbc->network_settings['waf__exploit_check'] = $spbc->default_network_settings['waf__exploit_check'];
            
            $spbc->save('network_settings');
            
        }
        
    }
    
    
    
    public static function updateTo_2_47_1() {
        spbc_mu_plugin__install();
    }
    
    public static function updateTo_2_48_0() {
        
        global $wpdb;
        
        if( SPBC_WPMS ) {
            
            $initial_blog = get_current_blog_id();
            $blogs        = array_keys( $wpdb->get_results( 'SELECT blog_id FROM ' . $wpdb->blogs, OBJECT_K ) );
            
            foreach ( $blogs as $blog ) {
                
                set_time_limit( 30 );
                
                switch_to_blog( $blog );
                
                // Getting key
                $net_settings = get_site_option( 'spbc_network_settings' );
                $settings     = $net_settings['allow_custom_key']
                    ? get_option( 'spbc_settings' )
                    : $net_settings;
                
                // Update plugin status
                if ( ! empty( $settings['spbc_key'] ) ) {
                    
                    //Clearing all errors
                    delete_option( 'spbc_errors' );
                    
                    // Checking account status
                    $result = API::method__notice_paid_till(
                        $settings['spbc_key'],
                        preg_replace( '/http[s]?:\/\//', '', get_option( 'home' ), 1 ), // Site URL
                        'security'
                    );
                    
                    $data = get_option( 'spbc_data', array() );
                    $data['key_is_ok'] = false;
                    
                    // Passed without errors
                    if ( empty( $result['error'] ) ) {
                        
                        // Key is valid
                        if ( $result['valid'] ) {
                            
                            $data['key_is_ok']        = true;
                            $data['user_token']       = isset( $result['user_token'] ) ? $result['user_token'] : '';
                            $data['notice_show']      = $result['show_notice'];
                            $data['notice_renew']     = $result['renew'];
                            $data['notice_trial']     = $result['trial'];
                            $data['auto_update_app']  = isset( $result['show_auto_update_notice'] ) ? $result['show_auto_update_notice'] : 0;
                            $data['service_id']       = $result['service_id'];
                            $data['moderate']         = $result['moderate'];
                            $data['auto_update_app '] = isset( $result['auto_update_app'] ) ? $result['auto_update_app'] : 0;
                            $data['license_trial']    = isset( $result['license_trial'] ) ? $result['license_trial'] : 0;
                            $data['account_name_ob']  = isset( $result['account_name_ob'] ) ? $result['account_name_ob'] : '';
                            
                        }
                    }
                    
                    update_option( 'spbc_data', $data );
                    
                }
                
            }
            
            switch_to_blog( $initial_blog );
            
        }
    }
    
    
    public static function updateTo_2_49_2() {
        global $spbc;
        $spbc->settings['block_delay__5_fails'] = 3600;
        $spbc->save('settings');
    }
    
    public static function updateTo_2_55_0() {
        
        global $spbc;
        $spbc->remote_calls['update_security_firewall'] = array( 'last_call' => 0, 'cooldown' => 300 );
        $spbc->remote_calls['update_security_firewall__write_base'] = array( 'last_call' => 0, 'cooldown' => 0 );
        $spbc->save('remote_calls', true, false );
    }
    
    public static function updateTo_2_60_0() {
        
        global $spbc, $wpdb;
        
        $spbc->settings['scanner__auto_start_manual_time'] = ! preg_match( '@\d{2}:\d{2}@', $spbc->settings['scanner__auto_start_manual_time'] )
            ? $spbc->settings['scanner__auto_start_manual_time'] = '09:00'
            : $spbc->settings['scanner__auto_start_manual_time'];
    }
    
    public static function updateTo_2_62_0(){
        
        global $spbc;
        
        $spbc->settings['bfp__allowed_wrong_auths'] = 5;
        $spbc->settings['bfp__delay__1_fails'] = 3;
        $spbc->settings['bfp__delay__5_fails'] = 10;
        $spbc->settings['bfp__block_period__5_fails'] = isset( $spbc->settings['block_timer__5_fails'] )
            ? $spbc->settings['block_timer__5_fails']
            : 3600;
        $spbc->settings['bfp__count_interval'] = 900;
        $spbc->save('settings');
        
        // Updating cron tasks
        $tasks = get_option( SPBC_CRON );
        if( $tasks ){
            foreach( $tasks as &$task ){
                $task['params']     = isset( $task['params'] )     ? $task['params']     : array();
                $task['last_call']  = isset( $task['last_call'] )  ? $task['last_call']  : 0;
                $task['processing'] = isset( $task['processing'] ) ? $task['processing'] : false;
            }
        }
        update_option( SPBC_CRON, $tasks );
    }
    
    public static function updateTo_2_63_0(){
        
        // Updating cron tasks
        $tasks = get_option( SPBC_CRON );
        if( isset( $tasks['firewall_update'] ) ){
            $tasks['firewall_update']['next_call'] += rand( 0, 3600 );
        }
        update_option( SPBC_CRON, $tasks );
        
        delete_option( 'spbc_deactivation_in_process' );
        
    }
    
    public static function updateTo_2_64_0() {
        
        global $spbc, $wpdb;
        
        // Old setting name => New setting name
        $keys_map = array(
            '2fa_enable'                       => '2fa__enable',
            '2fa_roles'                        => '2fa__roles',
            'bfp_allowed_wrong_auths'          => 'bfp__allowed_wrong_auths',
            'bfp_delay__1_fails'               => 'bfp__delay__1_fails',
            'bfp_delay__5_fails'               => 'bfp__delay__5_fails',
            'bfp_block_period__5_fails'        => 'bfp__block_period__5_fails',
            'bfp_count_interval'               => 'bfp__count_interval',
            'custom_key'                       => 'misc__custom_key',
            'traffic_control_enabled'          => 'traffic_control__enabled',
            'traffic_control_autoblock_amount' => 'traffic_control__autoblock_amount',
            'traffic_control_autoblock_period' => 'traffic_control__autoblock_period',
            'scanner_auto_start'		       => 'scanner__auto_start',
            'scanner_auto_start_manual'		   => 'scanner__auto_start_manual',
            'scanner_auto_start_manual_time'   => 'scanner__auto_start_manual_time',
            'scanner_auto_start_manual_tz'     => 'scanner__auto_start_manual_tz',
            'scanner_outbound_links'		   => 'scanner__outbound_links',
            'scanner_outbound_links_mirrors'   => 'scanner__outbound_links_mirrors',
            'scanner_heuristic_analysis'	   => 'scanner__heuristic_analysis',
            'scanner_signature_analysis'       => 'scanner__signature_analysis',
            'scanner_auto_cure'                => 'scanner__auto_cure',
            'scanner_frontend_analysis'        => 'scanner__frontend_analysis',
            'scanner_dir_exclusions'           => 'scanner__dir_exclusions',
            'waf_enabled'                      => 'waf__enabled',
            'waf_xss_check'                    => 'waf__xss_check',
            'waf_sql_check'                    => 'waf__sql_check',
            'waf_file_check'                   => 'waf__file_check',
            'waf_exploit_check'                => 'waf__exploit_check',
            'backend_logs_enable'                    => 'misc__backend_logs_enable',
            'set_cookies'                            => 'data__set_cookies',
            'disable_xmlrpc'                         => 'wp__disable_xmlrpc',
            'disable_rest_api_for_non_authenticated' => 'wp__disable_rest_api_for_non_authenticated',
            'forbid_to_show_in_iframes'              => 'misc__forbid_to_show_in_iframes',
            'show_link_in_login_form'                => 'misc__show_link_in_login_form',
            'additional_headers'                     => 'data__additional_headers',
            'use_buitin_http_api'                    => 'wp__use_builtin_http_api',
            'complete_deactivation'                  => 'misc__complete_deactivation',
        );
        
        if( is_multisite() ){
            
            $initial_blog  = get_current_blog_id();
            $blogs = array_keys( $wpdb->get_results( 'SELECT blog_id FROM '. $wpdb->blogs, OBJECT_K ) );
            foreach ( $blogs as $blog ) {
                switch_to_blog( $blog );
                
                $settings = get_option( 'spbc_settings' );
                
                if( $settings ) {
                    // replacing old key to new keys
                    foreach( $settings as $key => $value ){
                        if( array_key_exists( $key, $keys_map ) ) {
                            $_settings[$keys_map[$key]] = $value;
                        } else {
                            $_settings[$key] = $value;
                        }
                    }
                    update_option( 'spbc_settings', $_settings );
                }
                
            }
            switch_to_blog( $initial_blog );
            
        } else {
            
            $spbc->data['current_settings_template_id'] = null;
            $spbc->data['current_settings_template_name'] = null;
            $spbc->save('data');
            
            $settings = (array) $spbc->settings;
            
            if( $settings ) {
                // replacing old key to new keys
                foreach( $settings as $key => $value ){
                    if( array_key_exists( $key, $keys_map ) ) {
                        $_settings[$keys_map[$key]] = $value;
                    } else {
                        $_settings[$key] = $value;
                    }
                }
                
                $spbc->settings = $_settings;
                $spbc->save('settings');
            }
            
        }
        
    }
    
    public static function updateTo_2_65_0(){
        
        global $wpdb, $spbc;
        
        // Perform all sqls for each blog
        if ( SPBC_WPMS ){
            
            // Get all blogs
            $initial_blog = get_current_blog_id();
            $blogs        = array_keys( $wpdb->get_results( 'SELECT blog_id FROM ' . $wpdb->blogs, OBJECT_K ) );
            
            foreach ( $blogs as $blog ) {
                
                switch_to_blog( $blog );
                $spbc->settings['admin_bar__show'] = 1;
                $spbc->settings['admin_bar__users_online_counter'] = 1;
                $spbc->settings['admin_bar__brute_force_counter'] = 1;
                $spbc->settings['admin_bar__firewall_counter'] = 1;
                $spbc->settings['monitoring__users'] = 1;
                $spbc->save('settings');
            }
            switch_to_blog( $initial_blog );
            
        }else{
            $spbc->settings['admin_bar__show'] = 1;
            $spbc->settings['admin_bar__users_online_counter'] = 1;
            $spbc->settings['admin_bar__brute_force_counter'] = 1;
            $spbc->settings['admin_bar__firewall_counter'] = 1;
            $spbc->settings['monitoring__users'] = 1;
            $spbc->save('settings');
        }
        
    }
    
    public static function updateTo_2_66_0(){
        
        global $spbc;
        
        unset( $spbc->remote_calls['update_security_firewall__write_base'] );
        $spbc->remote_calls['update_security_firewall__worker'] = array( 'last_call' => 0, 'cooldown' => 1 );
        $spbc->remote_calls['debug']                            = array( 'last_call' => 0, 'cooldown' => 1 );
        $spbc->save( 'remote_calls', true, false );
        
        Cron::updateTask('firewall_update',      'spbc_security_firewall_update__init', 86400 );
    }
    
    public static function updateTo_2_66_1(){
        $task = Cron::getTask( 'firewall_update' );
        Cron::updateTask(
            'firewall_update',
            'spbc_security_firewall_update__init',
            isset( $task['period'] ) ? $task['period'] : time() + 42300,
            isset( $task['next_call'] ) ? $task['next_call'] : time() + 42300
        );
    }
    
    public static function updateTo_2_66_2(){
        global $spbc;
        $spbc->error_delete( 'firewall_update', 'save_data', 'cron');
    }
    
    public static function updateTo_2_72_0(){
        
        global $spbc;
        
        $spbc->data['scanner']['last_scan'] = isset( $spbc->data['scanner']['last_scan'] ) ? $spbc->data['scanner']['last_scan'] : 0;
        $spbc->data['ms__key_tries'] = 0;
        $spbc->save( 'data' );
        
        if( $spbc->is_multisite ){
            $spbc->network_settings = array_merge( (array) $spbc->network_settings, $spbc->default_network_settings );
            $spbc->network_data     = array_merge( (array) $spbc->network_data,     $spbc->default_network_data );
            $spbc->save('network_settings');
            $spbc->save('network_data');
        }
    }
    
    public static function updateTo_2_72_2(){
        global $spbc;
        
        $spbc->fw_stats['is_on_maintenance'] = false;
        $spbc->save( 'fw_stats', true, false );
    }
    
    public static function updateTo_2_73_0(){
        
        global $spbc;
        
        Data::remove(\CleantalkSP\Variables\Server::get('DOCUMENT_ROOT' ) . '/fw_filesindex.php' );
        Data::remove(\CleantalkSP\Variables\Server::get('DOCUMENT_ROOT' ) . '/fw_files' );
        Data::remove(SPBC_PLUGIN_DIR . '/fw_files' );
        
        // Adding possible missing params to tasks
        $cron_option = get_option( 'spbc_cron' );
        if( $cron_option ){
            foreach( $cron_option as $task => &$details ){
                $details['processing'] = isset( $details['processing'] ) ? $details['processing'] : false;
                $details['last_call']  = isset( $details['last_call'] ) ? $details['last_call'] : 0;
            }
        }
        update_option( 'spbc_cron', $cron_option);
        
        // New setting "List unknown files"
        $spbc->settings['scanner__list_unknown'] = 0;
        $spbc->save('settings');
        
        // Deleting useless data
        if( isset($spbc->data['cron']) ){
            unset( $spbc->data['cron'] );
            $spbc->save( 'data' );
        }
    }
    
    public static function updateTo_2_74_0(){
        
        global $spbc;
        
        Data::remove(\CleantalkSP\Variables\Server::get('DOCUMENT_ROOT' ) . '/fw_filesindex.php' );
        Data::remove(\CleantalkSP\Variables\Server::get('DOCUMENT_ROOT' ) . '/fw_files' );
        Data::remove(SPBC_PLUGIN_DIR . '/fw_files' );
        
        // Adding possible missing params to tasks
        $cron_option = get_option( 'spbc_cron' );
        if( $cron_option ){
            foreach( $cron_option as $task => &$details ){
                $details['processing'] = isset( $details['processing'] ) ? $details['processing'] : false;
                $details['last_call']  = isset( $details['last_call'] ) ? $details['last_call'] : 0;
            }
            unset( $details );
        }
        update_option( 'spbc_cron', $cron_option);
        
        // Deleting useless data
        if( isset($spbc->data['cron']) ){
            unset( $spbc->data['cron'] );
            $spbc->save( 'data' );
        }
        
        // Updating hidden option
        $spbc->settings['monitoring__users'] = 1;
        $spbc->save('settings');
    }
    
    public static function updateTo_2_75_0(){
        global $spbc;
        
        // Clear these options because new format was implemented
        $spbc->plugings = array();
        $spbc->save('plugins', true, false);
        $spbc->themes   = array();
        $spbc->save('themes', true, false);
        
        // New listing files
        $spbc->settings['scanner__important_files_listing'] = 0;
        $spbc->save('settings');
        
        $spbc->scanner_listing = array( 'accessible_urls' => array(), );
        $spbc->save('scanner_listing', true, false );
        
        $spbc->remote_calls['scanner__check_listing']= array('last_call' => 0,);
        $spbc->save('remote_calls', true, false );
        
        // New domain exceptions
        $spbc->settings['scanner__frontend_analysis__domains_exclusions'] = implode(
            "\n",
            array(
                'googletagmanager.com',
                'google.com',
                'twitter.com',
                'youtube.com',
                'youtube-nocookie.com',
                'img.youtube.com',
                'rutube.ru',
                'dailymotion.com',
                'yandex.ru',
                'flikr.com',
                'facebook',
                'vimeo.com',
                'metacafe.com',
                'yahoo.com',
                'mailchimp.com',
                'mail.ru',
                'ok.ru',
                'vk.com',
            )
        );
        $spbc->save('settings');
    }
    
    public static function updateTo_2_76_0(){
        global $spbc;
        $spbc->settings['scanner__list_unknown__older_than'] = 1;
        $spbc->save('settings');
    }

    public static function updateTo_2_80_0(){
        global $spbc;
        
        // New setting
        $spbc->settings['waf__file_check__uploaded_plugins'] = 0;
        $spbc->save('settings');
        
        // New remote calls
        $spbc->remote_calls['scanner__check_file']            = array('last_call' => 0, 'cooldown' => 0);
        $spbc->remote_calls['scanner__check_file__heuristic'] = array('last_call' => 0, 'cooldown' => 0);
        $spbc->remote_calls['scanner__check_file__signature'] = array('last_call' => 0, 'cooldown' => 0);
        $spbc->save('remote_calls', true, false );
    }
    
    public static function updateTo_2_82_0(){

        global $spbc;
      
        // Default parameter there_was_signature_treatment
        $spbc->settings['there_was_signature_treatment'] = 0;
        $spbc->save('settings');
    	
    	// START OF cleaning from heuristic results
    	$heuristic_marked_files = DB::getInstance()->fetch_all(
    		'SELECT weak_spots, checked, status, severity, fast_hash'
			. ' FROM ' . SPBC_TBL_SCAN_FILES
		    . ' WHERE '
		        . ' STATUS NOT IN ("APROVED","APPROVED_BY_CT","QUARANTINED") AND'
		        . '    weak_spots LIKE "%DANGER%"'
		        . ' OR weak_spots LIKE "%DANGER%"'
		        . ' OR weak_spots LIKE "%SUSPICIOUS%";'
	    );
    	
    	if( empty($heuristic_marked_files) ){
    	    return;
        }
    	
    	foreach( $heuristic_marked_files as &$file ){
    	
    		// Processing weak_spots
    		$file['weak_spots'] = json_decode( $file['weak_spots'], true );
    		unset(
    			$file['weak_spots']['CRITICAL'],
			    $file['weak_spots']['DANGER'],
			    $file['weak_spots']['SUSPICIOUS']
		    );
    		$file['weak_spots'] = ! empty( $file['weak_spots'] )
				? json_encode( $file['weak_spots'] )
				: 'NULL';
    	
    		// Processing checked
    		$file['checked'] = $file['checked'] === 'YES' || $file['checked'] === 'YES_SIGNATURE'
			   ? 'YES_SIGNATURE'
			   : 'NO';
    	
    		// Processing status
    		$file['status'] = $file['weak_spots'] !== 'NULL'
			    ? $file['status']
			    : 'OK';
    	
    		// Processing severity
    		$file['severity'] = $file['weak_spots'] !== 'NULL'
			    ? $file['severity']
			    : 'NULL';
    	
    		$file = '(\'' . implode( "','", $file ) . '\')';
    		$file = str_replace('\'NULL\'', 'NULL', $file);
	    }
    	unset($file);
    	
        DB::getInstance()->execute(
            'INSERT INTO ' . SPBC_TBL_SCAN_FILES
				. ' (weak_spots, checked, status, severity, fast_hash)'
	            . ' VALUES ' . implode( ',', $heuristic_marked_files )
	        . ' ON DUPLICATE KEY UPDATE'
		        . ' weak_spots = VALUES(weak_spots),'
		        . ' checked = VALUES(checked),'
		        . ' status = VALUES(status),'
		        . ' severity = VALUES(severity);'
	    );
    	// END OF cleaning from heuristic results
    }
    
    
    public static function updateTo_2_86_0(){
        global $spbc;
        
        $spbc->data['backup_for_heuristic_setting']    = $spbc->settings['scanner__heuristic_analysis'];
        $spbc->settings['scanner__heuristic_analysis'] = 0;
        $spbc->save('settings');
        $spbc->save('data');
    }
    
    public static function updateTo_2_86_1()
    {
        global $spbc;
        
        if( isset($spbc->data['backup_for_heuristic_setting']) ){
            $spbc->settings['scanner__heuristic_analysis'] = $spbc->data['backup_for_heuristic_setting'];
            unset($spbc->data['backup_for_heuristic_setting']);
            $spbc->save('settings');
            $spbc->save('data');
        }
    }

    /**
     * Update to 2.87. Runs SPBC_TBL_SCAN_FILES table alteration to move "checked" column condition
     * to the brand new columns "checked_heuristic" and "checked_signatures"
     */
    public static function updateTo_2_87_0()
    {
        global $spbc;
        
        // Adding info about extra package
        $spbc->data['extra_package']['backend_logs'] = 1;
        
        // New settings for custom block message
        $spbc->data['fw__custom_message']          = '';
        $spbc->data['fw__append_standard_message'] = true;
        
        // Adding new remote call 'perform_service_get'
        $spbc->remote_calls['perform_service_get'] = array('last_call' => 0,);
        // Firewall
        $spbc->save('remote_calls');
        $spbc->save('settings');
        $spbc->save('data');
  
        // extracting fo files needs to update
        $scanned_files = DB::getInstance()->fetch_all(
            'SELECT full_hash, checked'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE '
            . ' checked <> \'NO\''
        );

        if ( empty($scanned_files) ) {
            return;
        }

        $hashes_to_update = array();
        foreach ( $scanned_files as $file ) {
            $hashes_to_update[$file['checked']][] = $file['full_hash'];
        }

        $signs_of_file_checked_status = array(
            "YES" => array('\'1\'', '\'1\''),
            "YES_SIGNATURE" => array('\'1\'', '\'0\''),
            "YES_HEURISTIC" => array('\'0\'', '\'1\''),
        );

        foreach ( $signs_of_file_checked_status as $status => $signs ) {
            if ( !empty($hashes_to_update[$status]) ) {
                $hashes_to_update[$status] = '\'' . implode("','", $hashes_to_update[$status]) . '\'';
                $queries[] = 'UPDATE ' . SPBC_TBL_SCAN_FILES
                    . ' SET'
                    . ' checked_signatures=' . $signs[0] . ','
                    . ' checked_heuristic=' . $signs[1]
                    . ' WHERE full_hash IN (' . $hashes_to_update[$status] . ')';
            }
        }

        if ( !empty($queries) ) {
            foreach ( $queries as $query ) {
                if ( $query !== '\'\'' ) {
                    DB::getInstance()->execute($query);
                }
            }
        }

        $unhandled_files = DB::getInstance()->fetch_all(
            'SELECT full_hash, checked'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE '
            . ' checked <> \'NO\' AND checked_signatures = \'0\' AND checked_heuristic = \'0\''
        );

        if ( empty($unhandled_files) ) {
            $delete_row_query__checked =
                'ALTER TABLE ' . SPBC_TBL_SCAN_FILES
                . ' DROP COLUMN checked';
            DB::getInstance()->execute($delete_row_query__checked);
        }

        // END OF cleaning from heuristic results
    }
}