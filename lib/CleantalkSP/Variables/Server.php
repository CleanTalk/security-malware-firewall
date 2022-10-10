<?php

namespace CleantalkSP\Variables;

/**
 * Class Server
 * Wrapper to safely get $_SERVER variables
 *
 * @usage \CleantalkSP\Variables\Server::get( $name );
 *
 * @package \CleantalkSP\Variables
 */
class Server extends ServerVariables
{
    /**
     * Gets given $_SERVER variable and save it to memory
     *
     * @param string $name
     *
     * @return mixed|string
     */
    protected function getVariable($name)
    {

        $name = strtoupper($name);

        if ( function_exists('filter_input') ) {
            $value = filter_input(INPUT_SERVER, $name);
        }

        if ( empty($value) ) {
            $value = isset($_SERVER[$name]) ? $_SERVER[$name] : '';
        }

        // Convert to upper case for REQUEST_METHOD
        if ( in_array($name, array('REQUEST_METHOD'), true) ) {
            $value = strtoupper($value);
        }

        // Convert to lower case for HTTPS
        if ( in_array($name, array('HTTPS'), true) ) {
            $value = strtolower($value);
        }

        // Convert HTML chars for HTTP_USER_AGENT, HTTP_USER_AGENT, SERVER_NAME
        if ( in_array($name, array('HTTP_USER_AGENT', 'HTTP_USER_AGENT', 'SERVER_NAME')) ) {
            $value = htmlspecialchars($value);
        }

        return $value;
    }

    /**
     * Checks if $_SERVER['REQUEST_URI'] contains string
     *
     * @param string $needle
     *
     * @return bool
     */
    public static function inUri($needle)
    {
        return self::hasString('REQUEST_URI', $needle);
    }

    /**
     * Checks if $_SERVER['HTTP_HOST'] contains string
     * @param $needle
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function inHost($needle)
    {
        return self::hasString('HTTP_HOST', $needle);
    }

    public static function getDomain()
    {
        preg_match('@\S+\.(\S+)\/?$@', self::get('HTTP_HOST'), $matches);

        return isset($matches[1]) ? $matches[1] : false;
    }

    public static function getHomeURL()
    {
        return (self::isSSL() ? 'https' : self::get('REQUEST_SCHEME')) . '://' . self::get('HTTP_HOST') . '/';
    }

    /**
     * Checks if $_SERVER['HTTP_REFERER'] contains string
     *
     * @param string $needle needle
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function inReferer($needle)
    {
        return self::hasString('HTTP_REFERER', $needle);
    }

    /**
     * Checking if the request is on POST method
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function isPost()
    {
        return self::get('REQUEST_METHOD') === 'POST';
    }

    /**
     * Determines if SSL is used.
     *
     * @return bool True if SSL, otherwise false.
     */
    public static function isSSL()
    {
        if (
            self::get('HTTPS') === 'on' ||
            self::get('HTTPS') === '1' ||
            self::get('SERVER_PORT') == '443'
        ) {
            return true;
        }

        return false;
    }

    /**
     * Checking if the request is on GET method
     *
     * @return bool
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function isGet()
    {
        return self::get('REQUEST_METHOD') === 'GET';
    }

    public static function getURL()
    {
        return substr(self::getHomeURL(), 0, - 1) . self::get('REQUEST_URI');
    }
}
