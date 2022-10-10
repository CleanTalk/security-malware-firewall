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
class Post extends ServerVariables
{
    /**
     * Gets given $_POST variable and save it to memory
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
            $value = isset($_POST[$name]) ? $_POST[$name] : '';
        }

        return $value;
    }
}
