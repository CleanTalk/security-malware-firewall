<?php

namespace CleantalkSP\Variables;

/**
 * Class Post
 * Safety handler for $_POST
 *
 * @usage \CleantalkSP\Variables\Post::get( $name );
 *
 * @package \CleantalkSP\Variables
 */
class Post extends ServerVariables{
	
	public static $instance;
	
	/**
	 * Gets given $_POST variable and save it to memory
	 * @param $name
	 *
	 * @return mixed|string
	 */
	protected function get_variable( $name ){
		
		// Return from memory. From $this->variables
		if(isset(static::$instance->variables[$name]))
			return static::$instance->variables[$name];
		
		if( function_exists( 'filter_input' ) )
			$value = filter_input( INPUT_POST, $name );
		
		if( empty( $value ) )
			$value = isset( $_POST[ $name ] ) ? $_POST[ $name ]	: '';
		
		// Remember for further calls
		static::getInstance()->remember_variable( $name, $value );
		
		return $value;
	}
}