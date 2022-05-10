<?php

namespace CleantalkSP\SpbctWP\Variables;

use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Helpers\IP;

class AltSessions{
    
    /**
     * Sessions life time
     */
    const SESSION__LIVE_TIME = 86400;
    
    /**
     * The chance to run cleanup (for each request) from old entries in percents
     */
    const SESSION__CHANCE_TO_CLEAN = 10;
    
    public static $sessions_already_cleaned = false;
    
    public static function getID()
    {
        $id = Ip::get( 'real' )
            . Server::get( 'HTTP_USER_AGENT' )
            . Server::get( 'HTTP_ACCEPT_LANGUAGE' );
        return hash('sha256', $id);
    }
    
    /**
     * Write alternative cookie to database
     *
     * @param $name
     * @param $value
     *
     * @return bool
     */
    public static function set($name, $value)
    {
        self::cleanFromOld();
        
        // Bad incoming data
        if( ! $name || ! $value ){
            return false;
        }
        
        global $wpdb;
        
        $session_id = self::getID();
        
        $q = $wpdb->prepare(
            'INSERT INTO '. SPBC_TBL_SESSIONS .'
				(id, name, value, last_update)
				VALUES (%s, %s, %s, %s)
			ON DUPLICATE KEY UPDATE
				value = %s,
				last_update = %s',
            $session_id, $name, $value, date('Y-m-d H:i:s'), $value, date('Y-m-d H:i:s')
        );
        
        return (bool) $wpdb->query(
            $q
        );
        
    }
    
    public static function setFromRemote( $request = null )
    {
        if( ! $request ){
            $cookies_to_set = (array) \CleantalkSP\Variables\Post::get( 'cookies' );
        }else{
            $cookies_to_set = $request->get_param( 'cookies' );
        }
        
        foreach( $cookies_to_set as $cookie_to_set ){
            Cookie::set( $cookie_to_set[0], $cookie_to_set[1] );
        }
        
        wp_send_json( array( 'success' => true ) );
    }
    
    public static function get( $name )
    {
        self::cleanFromOld();
        
        // Bad incoming data
        if( ! $name ){
            return;
        }
        
        global $wpdb;
        
        $session_id = self::getID();
        $result = $wpdb->get_row(
            $wpdb->prepare(
                'SELECT value
				FROM `'. SPBC_TBL_SESSIONS .'`
				WHERE id = %s AND name = %s;',
                $session_id, $name
            ),
            ARRAY_A
        );
        
        return isset( $result['value'] ) ? $result['value'] : '';
    }
    
    public static function getFromRemote( $request = null )
    {
        $value = Cookie::get( $request
            ? $request->get_param( 'cookies' )
            : \CleantalkSP\Variables\Post::get( 'name' )
        );
    
        wp_send_json( array( 'success' => true, 'value' => $value ) );
    }
    
    public static function cleanFromOld()
    {
        if( ! self::$sessions_already_cleaned && rand(0, 100) < self::SESSION__CHANCE_TO_CLEAN ){
            
            global $wpdb;
            self::$sessions_already_cleaned = true;
            
            $wpdb->query(
                'DELETE
				FROM `'. SPBC_TBL_SESSIONS .'`
				WHERE last_update < NOW() - INTERVAL '. self::SESSION__LIVE_TIME .' SECOND
				LIMIT 100000;'
            );
        }
    }
    
    public static function wipe( $full_clear = true )
    {
        global $wpdb;
        return $wpdb->query(
            'TRUNCATE TABLE '. SPBC_TBL_SESSIONS .';'
        );
    }
    
}