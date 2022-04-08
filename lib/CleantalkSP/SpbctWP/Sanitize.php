<?php

namespace CleantalkSP\SpbctWP;

class Sanitize extends \CleantalkSP\Common\Sanitize
{
    /**
	 * Simple method: clean url
	 *
	 * @param $variable
	 *
	 * @return string
	 */
    public static function cleanUrl($variable)
    {
        return sanitize_url($variable);
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
        return sanitize_email($variable);
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
        return sanitize_file_name($variable);
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
        return sanitize_hex_color($variable);
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
        return sanitize_hex_color_no_hash($variable);
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
        return sanitize_html_class($variable);
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
        return sanitize_key($variable);
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
        return sanitize_meta($meta_key, $meta_value, $object_type);
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
        return sanitize_mime_type($variable);
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
        return sanitize_option($option, $value);
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
        return sanitize_sql_orderby($variable);
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
        return sanitize_text_field($variable);
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
        return sanitize_textarea_field($variable);
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
        return sanitize_title($variable);
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
        return sanitize_title_for_query($variable);
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
        return sanitize_title_with_dashes($variable);
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
        return sanitize_user($variable);
    }
}