<?php

namespace CleantalkSP\Variables;

/**
 * Class Request
 * Safety handler for $_REQUEST
 *
 * @usage \CleantalkSP\Variables\Request::get( $name );
 *
 * @package \CleantalkSP\Variables
 */
class Request extends ServerVariables{
	
	public static $instance;
	
	/**
	 * Gets given $_REQUEST variable and save it to memory
	 * @param $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		$value = isset( $_REQUEST[ $name ] ) ? $_REQUEST[ $name ]	: '';
		
		// Remember for further calls
		static::getInstance()->remember_variable( $name, $value );
		
		return $value;
	}
}