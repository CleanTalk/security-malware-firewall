<?php


namespace CleantalkSP\Monitoring;


use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Helpers\IP;

class User {

    public static function record(){
    
        global $wpdb;
        
        $current_user = wp_get_current_user();
        if( $current_user && $current_user->ID ) {
            
            $user_id = $current_user->ID;
            $user_login = $current_user->user_login;
            $last_activity = time();
            $page = substr( Server::get( 'REQUEST_URI' ), 0, 500 );
            $ip = IP::get();
            $role = isset( $current_user->roles[0] )
	            ? $current_user->roles[0]
	            : null ;
            $user_agent = substr( strip_tags( Server::get( 'HTTP_USER_AGENT' ) ), 0, 1000 );
            
            // Inserting / updating user
            $wpdb->replace(
                SPBC_TBL_MONITORING_USERS,
                compact( 'user_id', 'user_login', 'last_activity', 'page', 'ip', 'role', 'user_agent' )
            );
    
            // Cleaning form offline users
            $wpdb->query( $wpdb->prepare( 'DELETE FROM ' . SPBC_TBL_MONITORING_USERS . ' WHERE last_activity < %s', time() - 60 * 8 ) );
        }
        
    }
    
    public static function getUsersOnline(){
        global $wpdb;
        return $wpdb->get_col( 'SELECT user_login FROM ' . SPBC_TBL_MONITORING_USERS );
    }
    
    public static function countUsersOnline(){
        return count( self::getUsersOnline() );
    }
    
}