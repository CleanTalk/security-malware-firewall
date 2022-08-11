<?php

namespace CleantalkSP\Templates;

/**
 * Class DTO
 *
 * Data Transfer Object
 *
 * @since   2.83
 * @version 1.1.0
 * @package CleantalkSP\Templates
 * @psalm-suppress UnusedClass
 */
class DTO
{
    protected $obligatory_properties = [];

    public function __construct($params = array())
    {
        if ( ! $this->isObligatoryParamsPresented($params) ) {
            throw new \Exception('No go!');
        }

        foreach ( $params as $param_name => $param ) {
            if ( property_exists(static::class, $param_name) ) {
                $type = gettype($this->$param_name);
                $this->$param_name = $param;
                settype($this->$param_name, $type);
            }
        }
    }

    /**
     * @param $params
     *
     * @return bool
     * @since 1.1.0
     *
     */
    private function isObligatoryParamsPresented($params)
    {
        return empty($this->obligatory_properties) ||
               count(array_intersect($this->obligatory_properties, array_keys($params))) === count(
                   $this->obligatory_properties
               );
    }
}
