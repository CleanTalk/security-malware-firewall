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
class Get extends ServerVariables
{
    /**
     * Gets given $_GET variable and save it to memory
     *
     * @param string $name
     *
     * @return mixed|string
     */
    protected function getVariable($name)
    {

        if ( function_exists('filter_input') ) {
            $value = filter_input(INPUT_GET, $name);
        }

        if ( empty($value) ) {
            $value = isset($_GET[$name]) ? $_GET[$name] : '';
        }

        return $value;
    }
}
