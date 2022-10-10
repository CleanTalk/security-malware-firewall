<?php

namespace CleantalkSP\Variables;

/**
 * Class Request
 * Safety handler for $_REQUEST
 *
 * @usage \CleantalkSP\Variables\Request::get( $name );
 *
 * @package \CleantalkSP\Variables
 * @psalm-suppress UnusedClass
 */
class Request extends ServerVariables
{
    /**
     * Gets given $_REQUEST variable and save it to memory
     *
     * @param $name
     *
     * @return mixed|string
     */
    protected function getVariable($name)
    {

        if ( function_exists('filter_input') ) {
            $value = filter_input(INPUT_POST, $name);
        }

        if ( empty($value) ) {
            $value = isset($_REQUEST[$name]) ? $_REQUEST[$name] : '';
        }

        return $value;
    }
}
