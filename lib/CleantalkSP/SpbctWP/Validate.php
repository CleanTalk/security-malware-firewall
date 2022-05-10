<?php

namespace CleantalkSP\SpbctWP;

class Validate extends \CleantalkSP\Common\Validate
{
    /**
     * Validate email
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isEmail( $variable )
    {
        return (bool)is_email($variable);
    }
    
    /**
     * Validate file path
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isValidFilePath( $variable )
    {
        return (bool)validate_file($variable);
    }
}