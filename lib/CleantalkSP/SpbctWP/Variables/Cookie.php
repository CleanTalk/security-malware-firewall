<?php

namespace CleantalkSP\SpbctWP\Variables;

use CleantalkSP\Variables\Server;
use CleantalkSP\SpbctWP\Helpers\Data;
use CleantalkSP\SpbctWP\Sanitize;
use CleantalkSP\SpbctWP\Validate;

class Cookie extends \CleantalkSP\Variables\Cookie
{
    public static function get($name, $validation_filter = null, $sanitize_filter = null)
    {
        global $spbc;

        // Getting by alternative way if enabled
        if ( $spbc->settings['data__set_cookies'] == 2 ) {
            $value = AltSessions::get($name);
            // The old way
        } else {
            if ( function_exists('filter_input') ) {
                $value = filter_input(INPUT_COOKIE, $name);
            }

            if ( empty($value) ) {
                $value = isset($_COOKIE[$name]) ? $_COOKIE[$name] : '';
            }

            // Validate variable
            if ( $validation_filter && ! Validate::validate($value, $validation_filter) ) {
                return false;
            }

            if ( $sanitize_filter ) {
                $value = Sanitize::sanitize($value, $sanitize_filter);
            }

            // Remember for further calls
            static::getInstance()->rememberVariable($name, $value);
        }

        // Decoding
        $value = Data::isJSON($value) ? json_decode($value, true) : $value; // JSON decode

        return $value;
    }

    /**
     * Universal method to add cookies.
     *
     * Using Alternative Sessions or native cookies depends on settings.
     *
     * Automatically convert non-scalar values to JSON string.
     *
     * @param string $name
     * @param int|string|array $value
     * @param int $expires
     * @param string $path
     * @param string $domain
     * @param bool $secure
     * @param bool $httponly
     * @param string $samesite
     *
     * @return bool
     */
    public static function set(
        $name,
        $value = '',
        $expires = 0,
        $path = '',
        $domain = '',
        $secure = null,
        $httponly = false,
        $samesite = 'Lax'
    ) {
        global $spbc;

        $secure = ! is_null($secure) ? $secure : Server::get('HTTPS') || Server::get('SERVER_PORT') == 443;

        // Convert to JSON if array or object
        if ( ! is_scalar($value) ) {
            $value = json_encode($value);
        }

        if ( $spbc->settings['data__set_cookies'] == 0 && ! is_admin() ) {
            return false;
        }

        if ( $spbc->settings['data__set_cookies'] == 2 ) {
            return AltSessions::set($name, (string) $value);
        }

        return parent::set($name, (string) $value, $expires, $path, $domain, $secure, $httponly, $samesite);
    }
}
