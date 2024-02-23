<?php

namespace CleantalkSP\Common;

class Sanitize
{
    /**
     * Runs sanitizing process for input
     *
     * Now contains no filters: xss, url
     *
     * @param mixed|array $variable    Input to sanitize
     * @param string        $filter_name Sanitizing filter name
     *
     * @return string|false
     */
    public static function sanitize($variable, $filter_name)
    {
        // If array is passed, recursively sanitize every element of it
        if (! is_scalar($variable)) {
            foreach ($variable as &$value) {
                $value = self::sanitize($value, $filter_name);
            }
            return false;
        }

        switch ($filter_name) {
            case 'xss':
                return self::cleanXss($variable);
            case 'url':
                return self::cleanUrl($variable);
            case 'word':
                return self::cleanWord($variable);
            case 'int':
                return self::cleanInt($variable);
        }

        return (string)$variable;
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
        $variable_filtered = preg_replace('#[\'"].*?>.*?<#i', '', $variable);
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
        return preg_replace('#[^a-zA-Z0-9$\-_.+!*\'(),{}|\\^~\[\]`<>\#%";\/?:@&=.]#i', '', $variable);
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
        return preg_replace('#[^a-zA-Z0-9_.\-,]#', '', $variable);
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
        return preg_replace('#[^0-9.,]#', '', $variable);
    }

    /**
     * Simple method: clean email
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanEmail($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean file name
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanFileName($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean hex color
     *
     * @param $variable
     *
     * @return string|void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanHexColor($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean hex color no hash
     *
     * @param $variable
     *
     * @return string|void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanHexColorNoHash($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean html class
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanHtmlClass($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean key
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanKey($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean meta
     *
     * @param $_meta_key
     * @param $_meta_value
     * @param $_object_type
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanMeta($_meta_key, $_meta_value, $_object_type)
    {
        return '';
    }

    /**
     * Simple method: clean mime type
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanMimeType($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean option
     *
     * @param $_option
     * @param $_value
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanOption($_option, $_value)
    {
        return '';
    }

    /**
     * Simple method: clean sql order by
     *
     * @param $variable
     *
     * @return string|false
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanSqlOrderBy($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean text field
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanTextField($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean textarea field
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanTextareaField($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean title
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanTitle($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean title for query
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanTitleForQuery($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean title with dashes
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanTitleWithDashes($variable)
    {
        return $variable;
    }

    /**
     * Simple method: clean user
     *
     * @param $variable
     *
     * @return string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function cleanUser($variable)
    {
        return $variable;
    }
}
