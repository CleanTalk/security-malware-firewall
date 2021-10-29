<?php

namespace CleantalkSP\Variables;

/**
 * Class Server
 * Wrapper to safely get $_SERVER variables
 *
 * @usage \CleantalkSP\Variables\Server::get( $name );
 *
 * @package \CleantalkSP\Variables
 */
class Server extends ServerVariables {

	public static $instance;
	
	/**
	 * Gets given $_SERVER variable and save it to memory
	 *
	 * @param string $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->server
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		$name = strtoupper( $name );
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_SERVER, $name );
		
		if( empty( $value ) )
			$value = isset( $_SERVER[ $name ] ) ? $_SERVER[ $name ]	: '';
		
		// Convert to upper case for REQUEST_METHOD
		if( in_array( $name, array( 'REQUEST_METHOD' ), true ) )
			$value = strtoupper( $value );
        
        // Convert to lower case for HTTPS
        if( in_array( $name, array( 'HTTPS' ), true ) )
            $value = strtolower( $value );
		
		// Convert HTML chars for HTTP_USER_AGENT, HTTP_USER_AGENT, SERVER_NAME
		if( in_array( $name, array( 'HTTP_USER_AGENT', 'HTTP_USER_AGENT', 'SERVER_NAME' ) ) )
			$value = htmlspecialchars( $value );
		
		// Remember for thurther calls
		static::getInstance()->remember_variable( $name, $value );
		
		return $value;
	}
	
	/**
	 * Checks if $_SERVER['REQUEST_URI'] contains string
	 *
	 * @param string $needle
	 *
	 * @return bool
	 */
	public static function in_uri( $needle ){
		return self::has_string( 'REQUEST_URI', $needle );
	}
	
	public static function in_host( $needle ){
		return self::has_string( 'HTTP_HOST', $needle );
	}
	
	public static function get_domain(){
		preg_match( '@\S+\.(\S+)\/?$@', self::get( 'HTTP_HOST' ), $matches );
		return isset( $matches[1] ) ? $matches[1] : false;
	}
	
	public static function getHomeURL( $scheme = null ){
		return ( self::isSSL() ? 'https' : self::get( 'REQUEST_SCHEME' ) ) . '://' . self::get( 'HTTP_HOST' ) . '/';
	}
	
	/**
	 * Checks if $_SERVER['REQUEST_URI'] contains string
	 *
	 * @param string $needle needle
	 *
	 * @return bool
	 */
	public static function in_referer( $needle ){
		return self::has_string( 'HTTP_REFERER', $needle );
	}
	
	/**
	 * Checks if $_SERVER['REQUEST_URI'] contains string
	 *
	 * @return bool
	 */
	public static function is_post(){
		return self::get( 'REQUEST_METHOD' ) === 'POST';
	}
    
    /**
     * Determines if SSL is used.
     *
     * @return bool True if SSL, otherwise false.
     */
    public static function isSSL() {
        if(
            self::get( 'HTTPS' ) === 'on' ||
            self::get( 'HTTPS' ) === '1' ||
            self::get( 'SERVER_PORT' ) == '443'
        ){
            return true;
        }
        
        return false;
    }
    public static function isGet(){
        return self::get( 'REQUEST_METHOD' ) === 'GET';
    }
    
    public static function getURL(){
        return substr( self::getHomeURL(), 0, -1) . self::get( 'REQUEST_URI');
    }
}
