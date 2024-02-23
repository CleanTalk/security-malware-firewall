<?php

namespace CleantalkSP\SpbctWP\HTTP;

use CleantalkSP\Common\Helpers\HTTP;
use CleantalkSP\SpbctWP\Helpers\IP;
use CleantalkSP\SpbctWP\RemoteCalls;
use CleantalkSP\SpbctWP\State;

class CDNHeadersChecker
{
    /**
     * @var array
     * <ul>
     * <li>'time' => time()</li>
     * <li>'found_cdn_headers' => $found_headers</li>
     * <li>'setting_changed_to' => $new_header_id</li>
     * </ul>
     */
    private static $current_cdn_check_result = array();

    /**
     * How much records we need to keep.
     * @var int
     */
    private static $limit_of_cdn_records_to_keep = 10;

    /**
     * Main CDN headers self check logic.
     * @return array 'found_headers' => null,
     * 'setting_changed_to' => null,
     * 'error' => null
     */
    public static function check()
    {
        global $spbc;
        $result = array(
            'found_headers' => null,
            'setting_changed_to' => null,
            'error' => null
        );
        try {
            $provided_headers = array();
            foreach (HTTP::getHTTPHeaders() as $header => $value) {
                if (!empty($value) && IP::validate($value)) {
                    $provided_headers[] = $header;
                }
            }
            $known_cdn_headers = IP::getKnownCDNHeadersNames();
            $found_headers_slugs = self::findKnownCDNHeaderSlugs($provided_headers, $known_cdn_headers);
            $result['found_headers'] = $found_headers_slugs;
            $new_spbc_setting_header_id = self::getNewHeaderIdForSettings($spbc->settings['secfw__get_ip'], $found_headers_slugs);
            if ( $new_spbc_setting_header_id ) {
                $result['setting_changed_to'] = $new_spbc_setting_header_id;
                self::applyIPGetHeadersSettings($spbc, $new_spbc_setting_header_id);
            }
            self::updateStoredCDNHeadersData($found_headers_slugs, $new_spbc_setting_header_id);
        } catch (\Exception $e) {
            $result['error'] = $e->getMessage();
        }
        return $result;
    }

    public static function sendCDNCheckerRequest()
    {
        return RemoteCalls::performToHost(
            'cdn_check',
            array(),
            array('async', 'get')
        );
    }

    /**
     * Filter provided headers strings array to find known CDN headers slugs.
     * @param string[] $provided_headers provided headers strings array
     * @param string[] $known_cdn_headers known CDN headers
     * @return array matches
     */
    public static function findKnownCDNHeaderSlugs($provided_headers, $known_cdn_headers)
    {
        $slugs = array();
        foreach ($provided_headers as $provided_header) {
            $provided_header = strtolower($provided_header);
            foreach ($known_cdn_headers as $known_header) {
                $known_header = strtolower($known_header);
                if ( stripos($provided_header, $known_header) !== false ) {
                    $slugs[] = IP::getHeaderSlugByName($known_header);
                    break;
                }
            }
        }
        return $slugs;
    }

    /**
     * Save stored data to state->data.
     * @return void
     */
    private static function saveStoredCDNHeadersData()
    {
        global $spbc;
        $spbc->data['allowed_cdn_headers_data'] = serialize(self::$current_cdn_check_result);
        $spbc->save('data');
    }

    /**
     * Return stored data from state->data.
     * @return array
     */
    public static function loadStoredCDNHeadersData()
    {
        global $spbc;
        $stored_cdn_headers_data = isset($spbc->data['allowed_cdn_headers_data']) && is_string($spbc->data['allowed_cdn_headers_data'])
            ? $spbc->data['allowed_cdn_headers_data']
            : '';
        $result = unserialize($stored_cdn_headers_data);
        return is_array($result) ? $result : array();
    }

    /**
     * Update stored data to state->data.
     * @param string[] $found_headers newly found headers
     * @param string $new_spbc_setting_header_id if checker found a new CDN header and changed the setting, write it to the data
     * @return void
     */
    public static function updateStoredCDNHeadersData($found_headers, $new_spbc_setting_header_id = null)
    {
        $new_spbc_setting_header_id = !empty($new_spbc_setting_header_id) ? $new_spbc_setting_header_id : null;

        //shift stored data to limit
        self::$current_cdn_check_result = self::loadStoredCDNHeadersData();
        if ( count(self::$current_cdn_check_result) >= self::$limit_of_cdn_records_to_keep ) {
            array_shift(self::$current_cdn_check_result);
        }

        //add new item to the common results
        self::$current_cdn_check_result[] = array(
            'time' => time(),
            'found_cdn_headers' => $found_headers,
            'setting_changed_to' => $new_spbc_setting_header_id,
        );

        self::saveStoredCDNHeadersData();
    }

    /**
     * Returns the new CDN header ID. If nothing found and current settings is not 2, then returns '2' (remote_addr).
     * Returns null otherwise.
     * @param string $current_get_ip_state
     * @param string[] $found_headers_array
     * @return string|null
     */
    public static function getNewHeaderIdForSettings($current_get_ip_state, $found_headers_array)
    {
        $work_header = self::getWorkHeaderSlug($found_headers_array);
        $new_header_id = null;
        if ( !$work_header ) {
            //set remote addr (2) as source if nothing found
            if ( !isset($current_get_ip_state) || $current_get_ip_state !== '2' ) {
                $new_header_id = '2';
            }
        } else {
            $new_header_id = IP::getHeaderIDbySlug($work_header);
        }

        //if current statement is the same, return null
        if ($new_header_id == $current_get_ip_state) {
            $new_header_id = null;
        }

        return $new_header_id;
    }

    /**
     * Set the new secfw__get_ip state from header ID.
     * @param State $spbc SPBC State Obj.
     * @param string $new_header_id New header ID.
     * @return void
     */
    public static function applyIPGetHeadersSettings(State $spbc, $new_header_id = '1')
    {
        $spbc->data['secfw__get_ip__last_auto_set'] = serialize(array(
            'time' => time(),
            'header_id' => $new_header_id,
            'setting_name' => IP::$known_headers_collection[$new_header_id]['name'],
            'header_slug' => IP::$known_headers_collection[$new_header_id]['slug'],
        ));
        $spbc->save('data');

        $spbc->settings['secfw__get_ip'] = !is_null($new_header_id) ? (string)$new_header_id : $spbc->settings['secfw__get_ip'];
        $spbc->save('settings');
    }

    /**
     * Returns HTML code to draw CDN checker results block.
     * @return string
     */
    public static function getSummaryBlockHTML()
    {
        global $spbc;

        //collect data
        $stored_checks_data = self::loadStoredCDNHeadersData();

        //build layout template rows
        $rows = '';
        foreach ($stored_checks_data as $check) {
            $__headers_text = !empty($check['found_cdn_headers'])
                ? __('Found headers:', 'security_malware_firewall') . ' ' . implode(',', $check['found_cdn_headers'])
                : __('No known CDN headers found', 'security_malware_firewall');
            $__time_text = date('Y-m-d h:i:s', (int)($check['time']));
            $__new_setting_state_text = !empty($check['setting_changed_to'])
                ? __('Set new source to ', 'security_malware_firewall') . '<b>' . IP::$known_headers_collection[$check['setting_changed_to']]['slug'] . '</b>'
                : 'No changes';
            $rows .= '
            <tr>
                <td class="wp-tab-panel">
                ' . $__time_text . '
                </td>
                <td class="wp-tab-panel">
                ' . $__headers_text . '
                </td>
                <td class="wp-tab-panel">
                ' . $__new_setting_state_text . '
                </td>
            </tr>
            ';
        }

        //build text locales
        $__header = __('Automatic HTTP Headers Detection results (click to show)', 'security_malware_firewall');
        $__check_result_h = __('Check result', 'security_malware_firewall');
        $__check_time_h = __('Check time', 'security_malware_firewall');
        $__source_changes = __('Source changes', 'security_malware_firewall');
        $current_ip_source_id = $spbc->settings['secfw__get_ip'] != 0 && $spbc->settings['secfw__get_ip'] != 1
            ? $spbc->settings['secfw__get_ip']
            : 2;
        $__header_slug_text = !empty($current_ip_source_id)
            ? '<b>' . IP::$known_headers_collection[$current_ip_source_id]['name'] . '</b>'
            : __('unknown statement', 'security_malware_firewall');
        $__current_source = __("Current IP source is set to", 'security_malware_firewall') . ' ' . $__header_slug_text;

        //build template
        $html = '
        <div>
            <a href="#" onclick="spbcSummaryShowCDNCheckerTable()">
            ' . $__header . '
            </a>
            <table id="spbc_stats_cdn_checker_table" class="wp-tab-panel" style="display: none; width: max-content">
                <tbody>
                    <tr>
                        <th class="wp-tab-panel">
                        ' . $__check_time_h . '
                        </th>
                        <th class="wp-tab-panel">
                        ' . $__check_result_h . '
                        </th>
                        <th class="wp-tab-panel">
                        ' . $__source_changes . '
                        </th>
                    </tr>
                    ' . $rows . '
                    <tr>
                        <td colspan="3">
                        </td>
                    </tr>
                    <tr style="text-align: center">
                        <td class="wp-tab-panel" colspan="3">
                        ' . $__current_source . '
                        </td>
                    </tr>
                </tbody>
            </table>
        </div>';

        return $html;
    }

    /**
     * Returns localized text for option description.
     * @return string|null
     */
    public static function getOptionDescriptionText()
    {
        return __('If enabled, the plugin will detect IP source via self-call. Stats can be seen on the "Summary" tab', 'security-malware-firewall');
    }

    /**
     * Get work header slug from slugs array. If no CDN signs found, return first of another headers. If nothing found returns null.
     * @param $found_headers_slugs
     * @return string|null
     */
    public static function getWorkHeaderSlug($found_headers_slugs)
    {
        //this list of slugs is used to found exact cdn
        $cdn_slugs_ruleset = array(
            'incapsula',
            'ico_x_forwarded_for',
            'stackpath',
            'sucury',
            'ezoic',
            'gtranslate',
            'cloud_flare',
            'ovh',
        );

        //find unique sign of cdn, get first found if several
        $match = array_intersect($cdn_slugs_ruleset, $found_headers_slugs);
        if (!empty($match)) {
            return (string)array_values($match)[0];
        }

        return !empty($found_headers_slugs[0]) ? $found_headers_slugs[0] : null;
    }
}
