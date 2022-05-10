<?php

namespace CleantalkSP\Common;

class Sanitize
{
    /**
     * Runs sanitizing process for input
     *
     * Now contains no filters: xss, url
     *
     * @param mixed|mixed[] $variable    Input to sanitize
     * @param string        $filter_name Sanitizing filter name
     *
     * @return string
     */
    public static function sanitize($variable, $filter_name)
    {
        // If array is passed, recursively sanitize every element of it
        if( ! is_scalar($variable) ){
            $out = true;
            foreach( $variable as &$value ){
                $value = self::sanitize($value, $filter_name);
            }
            return $out;
        }
        
        switch( $filter_name ){
            case 'xss':
                return self::cleanXss($variable);
            case 'url':
                return self::cleanUrl($variable);
            case 'word':
                return self::cleanWord($variable);
            case 'int':
                return self::cleanInt($variable);
        }

        return $variable;
    }

    /**
	 * Simple method: clean xss
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanXss($variable)
    {
        $variable_filtered = preg_replace( '#[\'"].*?>.*?<#i', '', $variable );
        return $variable === $variable_filtered
            ? htmlspecialchars($variable_filtered)
            : static::cleanXss($variable_filtered);
    }

    /**
	 * Simple method: clean url
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanUrl($variable)
    {
        return preg_replace( '#[^a-zA-Z0-9$\-_.+!*\'(),{}|\\^~\[\]`<>\#%";\/?:@&=.]#i', '', $variable );
    }

    /**
	 * Simple method: clean word
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanWord($variable)
    {
        return preg_replace( '#[^a-zA-Z0-9_.\-,]#', '', $variable );
    }

    /**
	 * Simple method: clean int
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanInt($variable)
    {
        return preg_replace( '#[^0-9.,]#', '', $variable );
    }
    
    /**
     * Simple method: clean email
     *
     * @param $variable
     *
     * @return string
     */
    public static function cleanEmail($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean file name
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanFileName($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean hex color
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanHexColor($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean hex color no hash
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanHexColorNoHash($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean html class
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanHtmlClass($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean key
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanKey($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean meta
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanMeta($meta_key, $meta_value, $object_type)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean mime type
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanMimeType($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean option
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanOption($option, $value)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean sql order by
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanSqlOrderBy($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean text field
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanTextField($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean textarea field
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanTextareaField($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean title
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanTitle($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean title for query
     *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanTitleForQuery($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean title with dashes
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanTitleWithDashes($variable)
    {
        // TODO
    }
    
    /**
	 * Simple method: clean user
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanUser($variable)
    {
        // TODO
    }
}