<?php

namespace CleantalkSP\SpbctWP\Helpers;

class IP extends \CleantalkSP\Common\Helpers\IP
{
    /**
     * Known headers collection array( (id=>(slug,name), id=>(slug,name), ...).
     * @var array[]
     */
    public static $known_headers_collection = array(
        2 => array('slug' => 'remote_addr', 'name' => 'Remote Addr'),
        3 => array('slug' => 'x_forwarded_for', 'name' => 'X-Forwarded-For'),
        4 => array('slug' => 'x_real_ip', 'name' => 'X-Real-Ip'),
        5 => array('slug' => 'incapsula', 'name' => 'Incap-Client-Ip'),
        6 => array('slug' => 'ico_x_forwarded_for', 'name' => 'Ico-X-Forwarded-For'),
        7 => array('slug' => 'stackpath', 'name' => 'X-Sp-Forwarded-Ip'),
        8 => array('slug' => 'x_forwarded_by', 'name' => 'X-Client-Ip'),
        9 => array('slug' => 'sucury', 'name' => 'X-Sucuri-Clientip'),
        10 => array('slug' => 'ezoic', 'name' => 'X-Middleton-Ip'),
        11 => array('slug' => 'gtranslate', 'name' => 'X-Gt-Viewer-Ip'),
        12 => array('slug' => 'cloud_flare', 'name' => 'Cf-Connecting-Ip'),
        13 => array('slug' => 'ovh', 'name' => 'Remote-Ip'),
    );

    public static function get($ip_type_to_get = 'real', $headers = array(), $recursion = false)
    {
        global $spbc;

        $current_setting = (int)$spbc->settings['secfw__get_ip'];

        if ( $current_setting !== 1 && $current_setting !== 0) {
            $ip_type_to_get = self::$known_headers_collection[$current_setting]['slug'];
        }

        $ip_found = parent::get($ip_type_to_get, $headers, $recursion);

        //if not ip found in selected headers, return automatic search result ('real' state)
        if ( empty($ip_found) ) {
            $ip_found = parent::get('real', $headers, $recursion);
        }

        return $ip_found;
    }

    /**
     * Returns list of known CDN headers names.
     * @return string[]
     */
    public static function getKnownCDNHeadersNames()
    {
        $result = array_map(function ($cdn_record_data) {
            return $cdn_record_data['name'];
        }, self::$known_headers_collection);
        return $result;
    }

    /**
     * Returns header ID by slug.
     * @param string $slug
     * @return string|null
     */
    public static function getHeaderIDbySlug($slug = '')
    {
        foreach (self::$known_headers_collection as $header_id => $header_data) {
            if ( $header_data['slug'] === $slug ) {
                return (string)$header_id;
            }
        }
        return null;
    }

    public static function getHeaderSlugByName($name = '')
    {
        foreach (self::$known_headers_collection as $_header_id => $header_data) {
            if ( strtolower($header_data['name']) === strtolower($name) ) {
                return (string)($header_data['slug']);
            }
        }
        return '';
    }

    /**
     * Returns array of localized strings for long option description.
     * @return array
     */
    public static function getOptionLongDescriptionArray()
    {
        return array(
            'title' => __('Get IP from additional headers', 'security-malware-firewall'),
            'desc' => __('If the source header is selected, the plugin will search IP address in this header. If nothing found there, the plugin will run automatic search for every known possible IP sources.', 'security-malware-firewall'),
        );
    }
}
