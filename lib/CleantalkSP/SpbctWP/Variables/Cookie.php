<?php


namespace CleantalkSP\SpbctWP\Variables;

use CleantalkSP\SpbctWP\Helpers\Data;

class Cookie extends \CleantalkSP\Variables\Cookie {
    
    public static function get( $name, $default = '', $cast_to = null, $raw = false ){
    
        global $spbc;
        
        // Getting by alternative way if enabled
        if( $spbc->settings['data__set_cookies'] == 2 ){
            $value = AltSessions::get( $name );
    
        // The old way
        }else{
    
            if( function_exists( 'filter_input' ) ){
                $value = filter_input( INPUT_COOKIE, $name );
            }
    
            if( empty( $value ) ){
                $value = isset( $_COOKIE[ $name ] ) ? $_COOKIE[ $name ] : '';
            }
    
        }
        
        // Decoding by default
        if( ! $raw  ){
            $value = Data::isJSON($value ) ? json_decode($value, true ) : $value; // JSON decode
            if( ! is_null( $cast_to ) ){
                settype( $value, $cast_to );
                $value = $cast_to === 'array' && $value === array('') ? array() : $value;
            }
        }
        
        return ! $value ? $default : $value;
    }
    
    /**
     * Universal method to add cookies.
     *
     * Using Alternative Sessions or native cookies depends on settings.
     *
     * Automatically convert non-scalar values to JSON string.
     *
     * @param string $name
     * @param int|string|array $value
     * @param int    $expires
     * @param string $path
     * @param string $domain
     * @param bool   $secure
     * @param bool   $httponly
     * @param string $samesite
     *
     * @return bool
     */
    public static function set ($name, $value = '', $expires = 0, $path = '', $domain = '', $secure = null, $httponly = false, $samesite = 'Lax' ) {
        
        global $spbc;
    
        // Convert to JSON if array or object
        if( ! is_scalar( $value ) ){
            $value = json_encode( $value );
        }
        
        if( $spbc->settings['data__set_cookies'] == 0 && ! is_admin() ){
            return false;

        }elseif( $spbc->settings['data__set_cookies'] == 2 ){
            return AltSessions::set( $name, $value );
            
        }else/*( $spbc->settings['data__set_cookies'] == 1 )*/{
            return parent::set( $name, $value, $expires, $path, $domain, $secure, $httponly, $samesite );
        }
    
    }
    
}