<?php

use CleantalkSP\SpbctWP\Scanner;
use CleantalkSP\Variables\Post;

// Returns country part for emails
function spbc_report_country_part($ips_c, $ip = null)
{
    if (isset($ips_c[ $ip ]['country_code'])) {
        $country_code = strtolower($ips_c[ $ip ]['country_code']);
        $country_name = (isset($ips_c[ $ip ]['country_name']) ? $ips_c[ $ip ]['country_name'] : '-');

        $country_part = sprintf(
            '<img src="https://cleantalk.org/images/flags/%s.png" alt="%s" />&nbsp;%s',
            $country_code,
            $country_code,
            $country_name
        );
    } else {
        $country_part = '-';
    }

    return $country_part;
}

function spbc_report_tc_requests_per($ip = null)
{
    global $wpdb;

    if (is_null($ip)) {
        return '-';
    }

    $c = $wpdb->get_results(
        'SELECT entries FROM ' . SPBC_TBL_TC_LOG
        . ' WHERE ip = "' . $ip . '"'
        . ' ORDER BY interval_start DESC'
        . ' LIMIT 1',
        ARRAY_A
    );

    if (isset($c[0]) && isset($c[0]['entries'])) {
        return (string)$c[0]['entries'];
    }

    return '-';
}

function spbc_get_root_path($end_slash = false)
{
    return $end_slash ? ABSPATH : substr(ABSPATH, 0, - 1);
}

//* Write $message to the plugin's debug option
function spbc_log($message, $func = null, $params = array())
{
    sleep(1);

    global $spbc;

    $time_Ms = (int) substr(microtime(), 2, 6);

    $key = date('Y-m-d H:i:s') . ':' . $time_Ms . ' ACTION ' . current_action() . ' FUNCTION ' . $func;

    if ($message) {
        $spbc->debug[ $key ] = $message;
    }
    if (in_array('cron', $params)) {
        $spbc->debug[ $key ]['cron'] = $spbc->cron;
    }
    if (in_array('data', $params)) {
        $spbc->debug[ $key ]['data'] = $spbc->data;
    }
    if (in_array('to_date', $params)) {
        $spbc->debug[ $key ]['settings'] = $spbc->settings;
    }

    $spbc->save('debug');
}

function spbc_search_page_errors($string_page)
{
    return
        empty($string_page)
        || strpos($string_page, 'PHP Notice') !== false
        || strpos($string_page, 'PHP Warning') !== false
        || strpos($string_page, 'Fatal error') !== false
        || strpos($string_page, 'Parse error') !== false
        || stripos($string_page, 'internal server error') !== false
        || stripos($string_page, 'has been a critical error on this website') !== false;
}

/**
 * @param $module_type
 *
 * @return string|void
 */
function spbc_get_module_folder_by_type($module_type)
{
    if ($module_type === 'plugins') {
        return WP_PLUGIN_DIR;
    }

    if ($module_type === 'themes') {
        return get_theme_root();
    }
}

function spbc_get_modules_by_type($module_type)
{
    $output      = array();
    $modules_dir = spbc_get_module_folder_by_type($module_type);

    foreach (glob($modules_dir . '/*') as $module_dir) {
        if (is_dir($module_dir)) {
            foreach (glob($module_dir . '/*') as $module_file) {
                if ( ! is_file($module_file) || ($module_type === 'themes' && strpos($module_file, 'style.css') === false)) {
                    continue;
                }
                $module_type_simple = substr($module_type, 0, -1);
                $module = get_file_data($module_file, array('Name' => "$module_type_simple name", 'Version' => 'Version',));
                if ( ! empty($module['Version']) && ! empty($module['Name'])) {
                    if ($module_type === 'plugins') {
                        $module[ $module_type ] = substr($module_file, strlen(WP_PLUGIN_DIR) + 1);
                        $output[ preg_replace('/^(.*)(\/|\\\\).*/', '$1', substr($module_file, strlen(WP_PLUGIN_DIR) + 1)) ] = $module;
                    }
                    if ($module_type === 'themes') {
                        $module[ $module_type ] = substr($module_file, strlen(get_theme_root()) + 1, - (strlen('/style.css')));
                        $output[ substr($module_file, strlen(get_theme_root()) + 1, - (strlen('/style.css'))) ] = $module;
                    }
                }
            }
        }
    }

    return $output;
}

/**
 * Defines the source and its params depending on a file path
 *
 * @param string $file_path relative (WP root) path to the file
 *
 * @return array Keys in the array are 'slug', 'name, type', 'version'
 */
function spbc_get_source_info_of($file_path)
{
    $absolute_file_path = spbc_get_root_path() . $file_path;
    global $wp_version;

    if (strpos($absolute_file_path, WP_PLUGIN_DIR) !== false) {
        $source_dir = explode(DIRECTORY_SEPARATOR, pathinfo(substr($absolute_file_path, strlen(WP_PLUGIN_DIR)), PATHINFO_DIRNAME))[0];
        if ($source_dir) {
            foreach (glob($source_dir . '/*') as $plugin_file) {
                $source_info = get_file_data($plugin_file, array('Name' => null, 'Version' => null));
                if (isset($source_info['Version'], $source_info['Name'])) {
                    $source_info = array(
                        'source_type' => 'PLUGIN',
                        'source'      => $source_dir,
                        'name'        => $source_info['Name'],
                        'version'     => $source_info['Version'],
                    );
                }
            }
        }
    } elseif (strpos($absolute_file_path, get_theme_root()) !== false) {
        $source_dir       = explode(DIRECTORY_SEPARATOR, pathinfo(substr($absolute_file_path, strlen(get_theme_root())), PATHINFO_DIRNAME))[0];
        $source_info_file = $source_dir . DIRECTORY_SEPARATOR . 'style.css';
        if ($source_dir && file_exists($source_info_file)) {
            $source_info = get_file_data($source_info_file, array('Name' => null, 'Version' => null));
            if (isset($source_info['Version'], $source_info['Name'])) {
                $source_info = array(
                    'source_type' => 'THEME',
                    'source'      => $source_dir,
                    'name'        => $source_info['Name'],
                    'version'     => $source_info['Version'],
                );
            }
        }
    } else {
        $result = Scanner\Helper::getHashesForCMS('wordpress', $wp_version);
        if (empty($result['error'])) {
            foreach ($result['checksums'] as $path => $_real_full_hash) {
                if ($file_path === $path) {
                    $source_info = array(
                        'source_type' => 'CORE',
                        'source'      => 'wordpress',
                        'name'        => 'WordPress',
                        'version'     => $wp_version,
                    );
                }
            }
        }
    }

    return isset($source_info) ? $source_info : array();
}

/**
 * Checks if the current user has role
 *
 * @param array $roles
 * @param int|bool|string|WP_User $user User ID to check
 *
 * @return boolean Does the user has this role|roles
 */
function spbc_is_user_role_in($roles, $user = false)
{
    if (is_numeric($user) && function_exists('get_userdata')) {
        $user = get_userdata((int)$user);
    }
    if (is_string($user) && function_exists('get_user_by')) {
        $user = get_user_by('login', $user);
    }
    if ( ! $user && function_exists('wp_get_current_user')) {
        $user = wp_get_current_user();
    }

    if (empty($user->ID)) {
        return false;
    }

    foreach ((array) $roles as $role) {
        if (isset($user->caps[ strtolower($role) ]) || in_array(strtolower($role), $user->roles)) {
            return true;
        }
    }

    return false;
}

/**
 * Does ey has correct symbols? Checks against regexp ^[a-z\d]{3,30}$
 *
 * @param string api_key
 *
 * @return bool
 */
function spbc_api_key__is_correct($api_key = null)
{
    global $spbc;
    $api_key = $api_key !== null
        ? $api_key
        : $spbc->api_key;

    return $api_key && preg_match('/^[a-z\d]{3,30}$/', $api_key);
}

/**
 * Copies wp_timezone_string() function accessible only from WP 5.3
 *
 * ***
 *
 * Retrieves the timezone from site settings as a string.
 *
 * Uses the `timezone_string` option to get a proper timezone if available,
 * otherwise falls back to an offset.
 *
 * @return string PHP timezone string or a ±HH:MM offset.
 * @since 5.3.0
 *
 */
function spbc_wp_timezone_string()
{
    $timezone_string = get_option('timezone_string');

    if ($timezone_string) {
        return $timezone_string;
    }

    $offset  = (float) get_option('gmt_offset');
    $hours   = (int) $offset;
    $minutes = ($offset - $hours);

    $sign     = ($offset < 0) ? '-' : '+';
    $abs_hour = abs($hours);
    $abs_mins = abs($minutes * 60);

    return sprintf('%s%02d:%02d', $sign, $abs_hour, $abs_mins);
}

/**
 * Checks if the string is ASCII
 *
 * @param $string
 *
 * @return bool
 */
function spbc_check_ascii($string)
{
    if (function_exists('mb_check_encoding')) {
        if (mb_check_encoding($string, 'ASCII')) {
            return true;
        }
    } elseif ( ! preg_match('/[^\x00-\x7F]/', $string)) {
        return true;
    }

    return false;
}

/**
 * @param $file
 * @param bool $as_acronym
 *
 * @return int|string|null
 */
function spbc_PHP_logs__detect_EOL_type($file, $as_acronym = true)
{
    $eol_type = null;

    if ( file_exists($file) && is_readable($file) && filesize($file) ) {
        $fd = @fopen($file, 'r');

        if ( $fd ) {
            $string  = fgets($fd);

            $acronym_data = array(
                'CRLF' => "\r\n",
                'LF'   => "\n",
                'CR'   => "\r",
            );

            $symbol_data = array(
                "\r\n",
                "\n",
                "\r",
            );

            $eols = $as_acronym ? $acronym_data : $symbol_data;

            $cur_cnt = 0;
            foreach ( $eols as $acronym => $eol ) {
                $count = substr_count($string, $eol);
                if ( $count > $cur_cnt ) {
                    $cur_cnt  = $count;
                    $eol_type = $as_acronym ? $acronym : $eol;
                }
            }
        }
    }

    return $eol_type;
}

/**
 * Wrapper for trusted text to use in wp_footer hook. Echoing spbc_generate_trusted_text_html().
 */
function spbc_hook__wp_footer_trusted_text()
{
    $apbct_trusted_footer_flag = get_option('cleantalk_settings');
    if ( isset($apbct_trusted_footer_flag['trusted_and_affiliate__footer'])
        && $apbct_trusted_footer_flag['trusted_and_affiliate__footer'] == '1' ) {
        $apbct_trusted_footer_flag = true;
    } else {
        $apbct_trusted_footer_flag = false;
    }
    if ( spbc_is_plugin_active('cleantalk-spam-protect/cleantalk.php')
        && $apbct_trusted_footer_flag ) {
        if (function_exists('apbct_hook__wp_footer_trusted_text')) {
            /** @psalm-suppress UndefinedFunction */
            remove_action('wp_footer', 'apbct_hook__wp_footer_trusted_text', 999);
        }
        echo spbc_generate_trusted_text_html('div', true);
    } else {
        echo spbc_generate_trusted_text_html();
    }
}

/**
 * Wrapper of spbc_generate_trusted_text_html('span') to use in shortcode
 * @return string
 */
function spbc_trusted_text_shortcode_handler()
{
    return spbc_generate_trusted_text_html('span');
}

/**
 * Generates an HTML block with trusted text.
 * @param string $type Block type
 * @param bool $add_apbct_link if should add APBCT affiliate link to the block
 * @return string
 */
function spbc_generate_trusted_text_html($type = 'div', $add_apbct_link = false)
{
    $trusted_text = '';
    $apbct_text = '';
    $css_class = 'spbc-trusted-text--' . $type;

    $cleantalk_tag_with_ref_link = spbc_generate_affiliate_link();

    if ( $add_apbct_link ) {
        $query_data['product_name'] = 'antispam';
        $apbct_tag_with_ref_link = '<a href="https://cleantalk.org/register?'
            . http_build_query($query_data)
            . '" target="_blank" rel="nofollow">'
            . 'CleanTalk Anti-Spam'
            . '</a>';
        $apbct_text = ' and ' . $apbct_tag_with_ref_link;
    }

    if ( $type === 'div' ) {
        $trusted_text = '<div class="' . $css_class . '">'
            . '<p>'
            . __('Protected by ', 'security-malware-firewall')
            . $cleantalk_tag_with_ref_link . $apbct_text
            . '</p>'
            . '</div>';
    }

    if ( strpos($type, 'label') !== false ) {
        $trusted_text = '<label for="hidden_trusted_text" type="hidden" class="' . $css_class . '">'
            . __('Protected by ', 'security-malware-firewall')
            . $cleantalk_tag_with_ref_link
            . '</label>'
            . '<input type="hidden" name="hidden_trusted_text" id="hidden_trusted_text">';
    }
    if ( $type === 'span' ) {
        $trusted_text = '<span class="' . $css_class . '">'
            . __('Protected by ', 'security-malware-firewall')
            . $cleantalk_tag_with_ref_link
            . '</span>';
    }

    return $trusted_text;
}

/**
 * Attach CSS to public pages.
 */
function spbc_attach_public_css()
{
    wp_enqueue_style('spbc-public', SPBC_PATH . '/css/spbc-public.min.css', array(), SPBC_VERSION, 'all');
}

/**
 * Generate the affiliate link for next usages. If PID setting is active, adds pid=user_id to GET parameters.
 * @return string
 */
function spbc_generate_affiliate_link()
{
    global $spbc;
    $query_data = array(
        'product_name'  => 'security',
    );

    if ( $spbc->settings['spbc_trusted_and_affiliate__add_id'] === '1'
        && !empty($spbc->data['user_id']) ) {
        $query_data['pid'] = $spbc->data['user_id'];
    }

    return '<a href="https://cleantalk.org/register?'
        . http_build_query($query_data)
        . '" target="_blank" rel="nofollow">'
        . $spbc->data["wl_brandname"]
        . '</a>';
}

/**
 * Returns custom data for background scanner launch. Use state settings if no settings provided
 * @param bool $first_start optional, if is used on activation
 * @param array $settings optional, from settings validate
 * @return array period, start_time
 */
function spbc_get_custom_scanner_launch_data($first_start = false, $settings = array())
{
    global $spbc;

    $period = $first_start ? 43200 : 86400;

    $settings = empty($settings) ? $spbc->settings : $settings;
    $period = $settings['scanner__auto_start__set_period'] ?: $period;

    $timezone = $settings['scanner__auto_start_manual_tz'] ?: (int) Post::get('user_timezone');

    $hour_minutes = $settings['scanner__auto_start_manual_time']
        ? explode(':', $settings['scanner__auto_start_manual_time'])
        : explode(':', (string)current_time('H:i'));
    $start_time = mktime((int)$hour_minutes[0], (int)$hour_minutes[1]) - $timezone * 3600 + $period;

    return array(
        'period' => $period,
        'start_time' => $start_time
    );
}
