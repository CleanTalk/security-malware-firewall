<?php

namespace CleantalkSP\Variables;

/**
 * Class Get
 * Safety handler for $_GET
 *
 * @usage \CleantalkSP\Variables\Get::get( $name );
 *
 * @package \CleantalkSP\Variables
 */
class Get extends ServerVariables{
	
	public static $instance;
	
	/**
	 * Gets given $_GET variable and save it to memory
	 *
	 * @param string $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_GET, $name );
		
		if( empty( $value ) )
			$value = isset( $_GET[ $name ] ) ? $_GET[ $name ]	: '';
		
		// Remember for further calls
		static::getInstance()->remember_variable( $name, $value );
		
		return $value;
	}
}