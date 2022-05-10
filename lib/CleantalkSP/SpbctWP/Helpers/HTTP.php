<?php

namespace CleantalkSP\SpbctWP\Helpers;


/**
 * CleanTalk Security Helper class
 *
 * @depends       \CleantalkSP\Common\Helper
 *
 * @package       Security Plugin by CleanTalk
 * @subpackage    Helper
 * @Version       2.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/security-malware-firewall
 */

class HTTP extends \CleantalkSP\Common\Helpers\HTTP
{
    /**
     * Sort CleanTalks API servers by response time
     * Wrapper for self::sortHostsByResponseTime()
     *
     * @return array
     */
    public static function getCleantalksAPIServersOrderedByResponseTime()
    {
        return static::sortHostsByResponseTime(
            // Get only apix*.cleantalk.org domains from cleantalk servers
            array_filter(
                IP::$cleantalks_servers,
                static function ($key){
                    return (bool)preg_match('/^apix\d\.cleantalk\.org$/', $key);
                },
                ARRAY_FILTER_USE_KEY
            )
        );
    }
    
    /**
     * Sort CleanTalks moderate servers by response time
     * Wrapper for self::sortHostsByResponseTime()
     *
     * @return array
     */
    public static function getCleantalksModerateServersOrderedByResponseTime()
    {
        return static::sortHostsByResponseTime(
            // Get only moderate*.cleantalk.org domains from cleantalk servers
            array_filter(
                IP::$cleantalks_servers,
                static function ($key){
                    return (bool)preg_match('/^moderate\d\.cleantalk\.org$/', $key);
                },
                ARRAY_FILTER_USE_KEY
            )
        );
    }
}
