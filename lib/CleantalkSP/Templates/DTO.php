<?php


namespace CleantalkSP\Templates;

/**
 * Class DTO
 *
 * Data Transfer Object
 *
 * @since   2.83
 * @version 1.0.0
 * @package CleantalkSP\Templates
 */
class DTO
{
	public function __construct($params = array())
	{
		foreach( $params as $param_name => $param ){
			if( property_exists(static::class, $param_name) ){
				$type = gettype($this->$param_name);
				$this->$param_name = $param;
				settype($this->$param_name, $type);
			}
		}
	}

}