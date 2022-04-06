<?php

namespace CleantalkSP\Variables;

use CleantalkSP\SpbctWP\Sanitize;
use CleantalkSP\SpbctWP\Validate;

/**
 * Class ServerVariables
 * Safety handler for ${_SOMETHING}
 *
 * @depends \CleantalkSP\Common\Singleton
 *
 * @usage \CleantalkSP\Variables\{SOMETHING}::get( $name );
 *
 * @package \CleantalkSP\Variables
 */
abstract class ServerVariables{
	
	use \CleantalkSP\Templates\Singleton;
	
	/**
	 * @var array Contains saved variables
	 */
	public $variables = [];
 
	/**
	 * Gets given ${_SOMETHING} variable and seva it to memory
	 * @param $name
	 *
	 * @return mixed|string
	 */
	abstract protected function get_variable( $name );
	
    /**
     * Gets variable from ${_SOMETHING}
     *
     * @param string      $name Variable name
     *
     * @param null|string $validation_filter Filter name to run validation
     * @param null|string $sanitize_filter   Filter name to run sanitizing
     *
     * @return string
     */
	public static function get( $name, $validation_filter = null, $sanitize_filter = null )
	{
		$self     = static::getInstance();
		$variable = $self->recallVariable($name);

	    if( $variable === null ){
	    	$variable = $self->get_variable( $name );
			$self->remember_variable($name, $variable);
	    }

	    // Validate variable
	    if( $validation_filter && ! Validate::validate($variable, $validation_filter) ) {
            return false;
        }

        if( $sanitize_filter ) {
            $variable = Sanitize::sanitize($variable, $sanitize_filter);
        }

		return $variable;
	}
	
	/**
	 * Save variable to $this->variables[]
	 *
	 * @param string $name
	 * @param string $value
	 */
	protected function remember_variable( $name, $value ){
		$this->variables[$name] = $value;
	}
	
	/**
	 * Get stored variable to $this->variables[]
	 *
	 * @param string $name
	 *
	 * @return string|array|null
	 */
	protected function recallVariable( $name )
	{
		return isset( $this->variables[ $name ] )
			? $this->variables[ $name ]
			: null;
	}
	
	/**
	 * Checks if variable contains given string
	 *
	 * @param string $var    Haystack to search in
	 * @param string $string Needle to search
	 *
	 * @return bool|int
	 */
	static function has_string( $var, $string ){
		return stripos( self::get( $var ), $string ) !== false;
	}
	
	/**
	 * Checks if variable equal to $param
	 *
	 * @param string $var   Variable to compare
	 * @param string $param Param to compare
	 *
	 * @return bool|int
	 */
	static function equal( $var, $param ){
		return self::get( $var ) == $param;
	}
}