<?php

namespace CleantalkSP\Variables;

/**
 * Class Cookie
 * Safety handler for $_COOKIE
 *
 * @usage \CleantalkSP\Variables\Cookie::get( $name );
 *
 * @package \CleantalkSP\Variables
 * @psalm-suppress UnusedClass
 */
class Cookie extends ServerVariables
{
    /**
     * Gets given $_COOKIE variable and save it to memory
     *
     * @param string $name
     * @param bool $do_decode Should we decode the cookie?
     *
     * @return mixed|string
     */
    protected function getVariable($name, $do_decode = true)
    {

        if ( function_exists('filter_input') ) {
            $value = filter_input(INPUT_COOKIE, $name);
        }

        if ( empty($value) ) {
            $value = isset($_COOKIE[$name]) ? $_COOKIE[$name] : '';
        }

        return $value;
    }

    /**
     * Universal method to adding cookies
     * Wrapper for setcookie() Conisdering PHP version
     *
     * @see https://www.php.net/manual/ru/function.setcookie.php
     *
     * @param string $name Cookie name
     * @param string $value Cookie value
     * @param int $expires Expiration timestamp. 0 - expiration with session
     * @param string $path
     * @param string $domain
     * @param bool $secure
     * @param bool $httponly
     * @param string $samesite
     *
     * @return bool
     */
    public static function set($name, $value = '', $expires = 0, $path = '', $domain = '', $secure = null, $httponly = false, $samesite = 'Lax')
    {

        $secure = ! is_null($secure) ? $secure : Server::get('HTTPS') !== 'off' || Server::get('SERVER_PORT') == 443;

        // For PHP 7.3+ and above
        if ( version_compare(phpversion(), '7.3.0', '>=') ) {
            $params = array(
                'expires'  => $expires,
                'path'     => $path,
                'domain'   => $domain,
                'secure'   => $secure,
                'httponly' => $httponly,
            );

            if ( $samesite ) {
                $params['samesite'] = $samesite;
            }

            /** @psalm-suppress InvalidArgument */
            $out = setcookie($name, $value, $params);

            // For PHP 5.6 - 7.2
        } else {
            $out = setcookie($name, $value, $expires, $path, $domain, $secure, $httponly);
        }

        return $out;
    }
}
