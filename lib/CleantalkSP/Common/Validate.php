<?php

namespace CleantalkSP\Common;

class Validate
{
    /**
     * Runs validation for input parameter
     *
     * Now contains filters: hash
     *
     * @param mixed|mixed[] $variable    Input to validate
     * @param string        $filter_name Validation filter name
     *
     * @return bool
     */
    public static function validate($variable, $filter_name)
    {
        // If array is passed, recursively validate every element of it
        if( ! is_scalar($variable) ){
            $out = true;
            foreach( $variable as $value ){
                $out &= self::validate($value, $filter_name);
            }
            return $out;
        }
        
        switch( $filter_name ){
            case 'hash':
                return self::isHash($variable);
            case 'int':
                return self::isInt($variable);
            case 'float':
                return self::isFloat($variable);
            case 'word':
                return self::isWord($variable);
            case 'text':
                return self::isText($variable);
        }

        return false;
    }
    
    /**
     * validate hash string
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isHash($variable)
    {
        return preg_match('#^[a-zA-Z0-9]{8,128}$#', $variable) === 1;
    }
    
    /**
     * Validate int
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isInt($variable)
    {
        return preg_match('#^\d+$#', $variable) === 1;
    }
    
    /**
     * Validate float
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isFloat($variable)
    {
        return preg_match('#^[\d.]+\d+$#', $variable) === 1;
    }
    
    /**
     * Validate word
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isWord($variable)
    {
        return preg_match('#^[a-zA-Z0-9_.\-,]+$#', $variable) === 1;
    }
    
        /**
     * Validate word
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isText($variable)
    {
        return preg_match('#^[\w\s0-9.\-,]*$#', $variable) === 1;
    }
    
    /**
     * Validate email
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isEmail($variable)
    {
        return preg_match('#^\S+?@\S+?\.\S+$#', $variable) === 1;
    }
    
    /**
     * Validate file path (not exists)
     *
     * @param string $variable
     *
     * @return bool
     */
    public static function isValidFilePath($variable)
    {
        // TODO
    }
}