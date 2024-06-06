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

function spbc_report_tc_requests_per($ip = null, $status = null)
{
    global $wpdb, $spbc;

    if (is_null($ip) || is_null($status)) {
        return '-';
    }

    $log_type = 0;
    if (strpos($status, 'BFP')) {
        $log_type = 1;
    }
    if (strpos($status, 'WAF')) {
        $log_type = 2;
    }

    $c = $wpdb->get_results(
        'SELECT entries FROM ' . SPBC_TBL_TC_LOG
        . ' WHERE ip = "' . $ip . '"'
        . ' AND log_type = ' . $log_type
        . ' ORDER BY block_end_on DESC'
        . ' LIMIT 1',
        ARRAY_A
    );

    if (isset($c[0]) && isset($c[0]['entries'])) {
        $entries = (int)$c[0]['entries'];
        // @TODO this condition need to prevent anomalies on Firewall tab in admin panel, refactor it
        if ($entries > $spbc->settings['traffic_control__autoblock_amount']) {
            $entries = $spbc->settings['traffic_control__autoblock_amount'];
        }

        return (string)$entries;
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
    if ( is_numeric($user) && function_exists('get_userdata') ) {
        $user = ! get_userdata((int)$user) ? $user : get_userdata((int)$user);
    }
    if ( is_string($user) && function_exists('get_user_by') ) {
        $user = get_user_by('login', $user);
    }
    if ( ! $user && function_exists('wp_get_current_user')) {
        $user = wp_get_current_user();
    }

    if (empty($user->ID)) {
        return false;
    }

    foreach ((array) $roles as $role) {
        $role_slug = spbc_get_role_slug_by_role_name($role);
        if (isset($user->caps[$role_slug]) || in_array($role_slug, $user->roles)) {
            return true;
        }
    }

    return false;
}

/**
 * @param string $role_name
 *
 * @return string
 */
function spbc_get_role_slug_by_role_name($role_name)
{
    $wp_roles = new WP_Roles();
    $role_slug = '';

    if ( ! is_array($wp_roles->roles) ) {
        return $role_slug;
    }

    foreach ( $wp_roles->roles as $role_slug => $role_details ) {
        if ( isset($role_details['name']) && $role_details['name'] === $role_name ) {
            return $role_slug;
        }
    }
    return $role_slug;
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

    return  sprintf('%s %s%02d:%02d', date('e'), $sign, $abs_hour, $abs_mins);
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

    $timezone = $settings['scanner__auto_start_manual_tz'] ?: (int) Post::get('spbc_settings[scanner__auto_start_manual_tz]');

    $hour_minutes = $settings['scanner__auto_start_manual_time']
        ? explode(':', $settings['scanner__auto_start_manual_time'])
        : explode(':', (string)current_time('H:i'));
    $start_time = mktime((int)$hour_minutes[0], (int)$hour_minutes[1]) - $timezone * 3600 + $period;

    // Hard fix - increments one more $period if the $start_time calculated in the past
    if ( time() > $start_time ) {
        $start_time += $period;
    }

    return array(
        'period' => $period,
        'start_time' => $start_time
    );
}

/**
 * Enqueue JS scripts, css and localization for widget.
 * @return void
 */
function spbc_widget_scripts_init()
{
    global $spbc;
    wp_enqueue_script(
        'spbc-widget-chart-js',
        SPBC_PATH . '/js/lib/chart/spbc-dashboard-widget--chartjs.min.js',
        array('jquery'),
        SPBC_VERSION,
        false
    );
    wp_enqueue_script(
        'spbc-widget-dashboard',
        SPBC_PATH . '/js/spbc-dashboard-widget.min.js',
        array('spbc-widget-chart-js'),
        SPBC_VERSION,
        false
    );
    wp_enqueue_style(
        'spbc_admin_css_widget_dashboard',
        SPBC_PATH . '/css/spbc-dashboard-widget.min.css',
        array(),
        SPBC_VERSION,
        'all'
    );

    $brief_data = isset($spbc->data['brief_data']) ? $spbc->data['brief_data'] : array();
    $bfp_data = !empty($brief_data['bfp_data']) ? $brief_data['bfp_data'] : array();
    $fw_data = !empty($brief_data['bfp_data']) ? $brief_data['fw_data'] : array();

    sort($bfp_data);
    sort($fw_data);

    wp_localize_script('spbc-widget-dashboard', 'spbcDashboardWidget', array(
        'data_bfp' => $bfp_data,
        'data_fw' => $fw_data,
    ));
}

/**
 * Set brief data for widget to the State.
 * @return void
 */
function spbc_set_brief_data()
{
    global $spbc;

    // prepare vars
    $current_fw_data = $spbc->data['brief_data']['fw_data']
        ? $spbc->data['brief_data']['fw_data']
        : array();
    $current_bfp_data = $spbc->data['brief_data']['bfp_data']
        ? $spbc->data['brief_data']['bfp_data']
        : array();
    $logs_scanned_ts = $spbc->data['brief_data']['logs_scanned_ts']
        ? $spbc->data['brief_data']['logs_scanned_ts']
        : array(
            'fw' => 0,
            'bfp' => 0,
        );
    $current_last_actions = $spbc->data['brief_data']['last_actions']
        ? $spbc->data['brief_data']['last_actions']
        : array();

    $out_last_actions = spbc_update_brief_data_last_actions($current_last_actions);
    $out_firewalls_data = spbc_get_brief_data_for_firewalls($current_fw_data, $current_bfp_data, $logs_scanned_ts);

    //save data to state
    $spbc->data['brief_data']['last_actions'] = $out_last_actions;
    $spbc->data['brief_data']['bfp_data'] = $out_firewalls_data['bfp_data'];
    $spbc->data['brief_data']['fw_data'] = $out_firewalls_data['fw_data'];
    $spbc->data['brief_data']['total_count'] = $out_firewalls_data['total_count'];
    $spbc->data['brief_data']['logs_scanned_ts'] = $out_firewalls_data['logs_scanned_ts'];
    $spbc->data['brief_data']['brief_last_updated'] = time();
    $spbc->save('data');
}

/**
 * Update widget brief data for last actions
 * @param array $current_last_actions before updated
 * @return array updated last action
 */
function spbc_update_brief_data_last_actions($current_last_actions)
{
    global $spbc;
    /**
     * Collect last actions
     */

    $last_actions_already_gained_ids = [];
    $actions_limit = SPBC_BRIEF_DATA_ACTIONS_LIMIT;
    $db = \CleantalkSP\SpbctWP\DB::getInstance();


    foreach ($current_last_actions as $_action => &$value) {
        if (!empty($value['id'])) {
            // skip already gained
            $last_actions_already_gained_ids[] = $value['id'];
            // reformat already gained actions
            $action = spbc_parse_action_from_admin_page_uri($value['action_url']);
            $value['action_event'] = $action['action_event'];
        }
    }

    $last_actions_already_gained_ids = !empty($last_actions_already_gained_ids)
        ? '(\'' . implode('\',\'', $last_actions_already_gained_ids) . '\')'
        : '(\'\')';

    // do query
    $last_actions_query = 'SELECT id, datetime AS date, auth_ip AS ip, user_login AS login, page AS action_url' .
        ' FROM ' . SPBC_TBL_SECURITY_LOG .
        // looks for urls that have action
        ' WHERE (
            (page LIKE \'%action=%\' AND page not like \'%action=delete&user%\' AND page not like \'%meta-box-loader%\')
            OR page LIKE \'%delete\_count=%\'
            OR page LIKE \'%users\.php%update=add%\'
            )' .
        // exclude already gained
        ' AND id NOT IN ' . $last_actions_already_gained_ids .
        // limit up to param
        ' ORDER BY timestamp_gmt DESC LIMIT ' . ($actions_limit);

    $result = $db->fetchAll($last_actions_query);
    if (false !== $result) {
        foreach ($result as $_action => &$data) {
            // parse url to user-friendly string
            $action = spbc_parse_action_from_admin_page_uri($data['action_url']);
            $data['action_event'] = $action['action_event'];
            // collect parsed
            $current_last_actions[] = $data;
        }
    }

    usort($current_last_actions, function ($a, $b) {
        return strtotime($b["date"]) - strtotime($a["date"]);
    });

    $diff = count($current_last_actions) - $actions_limit;

    if ($diff > 0) {
        array_splice($current_last_actions, -1 * $diff);
    }


    return $current_last_actions;
}

/**
 * Update widget brief data Firewall records.
 * @param array $current_fw_data current firewall blocks data excluding BFP
 * @param array $current_bfp_data current BFP blocks data
 * @param array $logs_scanned_ts array of timestamps when the appropriate data scanned for changes last time,
 * ['fw' => 0,'bfp' => 0]
 * @return array array(
 * 'fw_data' => [],
 * 'bfp_data' => [],
 * 'total_count',
 * 'logs_scanned_ts' => ['fw' => 0,'bfp' => 0] ,
 * );
 */
function spbc_get_brief_data_for_firewalls($current_fw_data, $current_bfp_data, $logs_scanned_ts)
{
    $days_limit = SPBC_BRIEF_DATA_DAYS_LIMIT;

    $db = \CleantalkSP\SpbctWP\DB::getInstance();

    $out_data = array(
        'fw_data' => [],
        'bfp_data' => [],
        'logs_scanned_ts' => $logs_scanned_ts,
    );

    // clear data older than days limit
    $formatted_fw_data = spbc_brief_clear_and_reformat_records($current_fw_data, $days_limit);
    $formatted_bfp_data = spbc_brief_clear_and_reformat_records($current_bfp_data, $days_limit);

    // get new records of all types
    $new_log_data = array();
    $fw_data_query = 'SELECT entry_timestamp as ts, status' .
        ' FROM ' . SPBC_TBL_FIREWALL_LOG
        // exclude too old
        . ' WHERE entry_timestamp > ' . ((current_datetime()->getTimestamp()) - ($days_limit * 3600 * 24)) . ' AND'
        // looks for just denied records
        . ' ('
        . ' (status LIKE "%DENY_%" AND status <> \'DENY_BY_BFP\' AND entry_timestamp > ' . $logs_scanned_ts['fw'] . ')'
        . ' OR (status = \'DENY_BY_BFP\' AND entry_timestamp > ' . $logs_scanned_ts['bfp'] . ')'
        . ' )'
        . ' ORDER BY entry_timestamp LIMIT 10000';

    $result = $db->fetchAll($fw_data_query);
    if (false !== $result) {
        $new_log_data = $result;
    }

    // collect old counters by type from chart-ready data
    $new_fw_data = array();
    $new_bfp_data = array();

    foreach ($formatted_fw_data as $_data => $value) {
        $new_fw_data[$value[0]] = array('day' => $value[0], 'count' => $value[1]);
    }

    foreach ($formatted_bfp_data as $_data => $value) {
        $new_bfp_data[$value[0]] = array('day' => $value[0], 'count' => $value[1]);
    }

    $out_data['logs_scanned_ts']['bfp'] = !empty($new_bfp_data) ? time() : $out_data['logs_scanned_ts']['bfp'];
    $out_data['logs_scanned_ts']['fw'] = !empty($new_fw_data) ? time() : $out_data['logs_scanned_ts']['fw'];

    // collect new events counters by type
    foreach ($new_log_data as $_entry => $value) {
        // skip wrong records
        if (!isset($value['status'], $value['ts'])) {
            continue;
        }

        $day = date('Y-m-d', (int)$value['ts']);

        if ($value['status'] === 'DENY_BY_BFP') {
            $count = in_array($day, array_keys($new_bfp_data)) ? $new_bfp_data[$day]['count'] + 1 : 1;
            $new_bfp_data[$day] = array('day' => $day,
                'count' => $count);
        } else {
            $count = in_array($day, array_keys($new_fw_data)) ? $new_fw_data[$day]['count'] + 1 : 1;
            $new_fw_data[$day] = array('day' => $day,
                'count' => $count);
        }
    }

    // convert arrays to use in chart data
    if ( !empty($new_fw_data) ) {
        foreach ($new_fw_data as $_date => $value) {
            if (isset($value['day'], $value['count'])) {
                $out_data['fw_data'][] = array($value['day'], $value['count']);
            }
        }
    }
    if ( !empty($new_bfp_data) ) {
        foreach ($new_bfp_data as $_date => $value) {
            if (isset($value['day'], $value['count'])) {
                $out_data['bfp_data'][] = array($value['day'], $value['count']);
            }
        }
    }

    // count total blocks
    $count = 0;
    foreach (array($out_data['bfp_data'], $out_data['fw_data']) as $current_set) {
        foreach ($current_set as $entry) {
            if (!empty($entry[1])) {
                $count += (int)$entry[1];
            }
        }
    }
    $out_data['total_count'] = $count;

    return $out_data;
}

/**
 * Parse URL to find human-readable description.
 * @param string $url - requested URL
 * @param string $post_id - a WordPress post ID, default null
 * @return array ['action_event' => '', 'add_time' => bool, 'post_id' => null, 'page_action' => null, 'plugin_name' => null]
 */
function spbc_parse_action_from_admin_page_uri($url, $post_id = null)
{
    $parsed_url = parse_url($url);
    $parsed_query = [];
    $plugin_name = '';
    if ( isset($parsed_url['query']) ) {
        parse_str($parsed_url['query'], $parsed_query);
    }
    if ( isset($parsed_query['plugin']) ) {
        if (is_callable('get_plugin_data')) {
            $plugin_name = get_plugin_data(WP_PLUGIN_DIR . '/' . $parsed_query['plugin'])['Name'];
        }
        if (empty($plugin_name)) {
            $plugin_name = explode('/', $parsed_query['plugin'])[0];
        }
    }
    $out = array(
        'action_event' => 'Action of empty URL',
        'add_time' => true,
        'post_id' => null,
        'page_action' => null,
        'plugin_name' => null,
    );
    if (!is_null($url)) {
        switch ($url) {
            case ('/wp-admin/edit.php' == $url
                || '/wp-admin/network/edit.php' == $url
                ? true
                : false):
                $out['action_event'] = 'viewing_posts_list';
                break;
            case ('/wp-admin/edit.php?post_type=page' == $url
                || '/wp-admin/network/edit.php?post_type=page' == $url
                ? true
                : false):
                $out['action_event'] = 'viewing_pages_list';
                break;
            case (preg_match('#/wp-admin/post.php\?post=[\d\w]+&action=edit#', $url)
                || preg_match('#/wp-admin/network/post.php\?post=[\d\w]+&action=edit#', $url)
                ? true
                : false):
                $post_id = is_null($post_id) && isset($parsed_query['post']) ? (int)$parsed_query['post'] : null;
                $page_action = '';
                if (strpos($url, 'message=6') !== false) {
                    $page_action = ': ' . __('publish', 'security-malware-firewall');
                }
                if (strpos($url, 'message=3') !== false) {
                    $page_action = ': ' . __('field remove', 'security-malware-firewall');
                }
                if (strpos($url, 'message=2') !== false) {
                    $page_action = ': ' . __('field add', 'security-malware-firewall');
                }
                if (strpos($url, 'message=4') !== false || strpos($url, 'message=1') !== false) {
                    $page_action = ': ' . __('update', 'security-malware-firewall');
                }
                if (strpos($url, 'message=7') !== false) {
                    $page_action = ': ' . __('save', 'security-malware-firewall');
                }
                if (strpos($url, 'message=10') !== false) {
                    $page_action = ': ' . __('draft update', 'security-malware-firewall');
                }
                if ( is_int($post_id) ) {
                    $out['action_event'] = 'editing_post_id';
                    $out['post_id'] = $post_id;
                    $out['page_action'] = $page_action;
                } else {
                    $out['action_event'] = 'editing_post';
                }
                break;
            case (preg_match('#/wp-admin/plugins.php\?.*action=activate#', $url)
                || preg_match('#/wp-admin/network/plugins.php\?.*action=activate#', $url)
                ? true
                : false):
                $out['action_event'] = 'activate_plugin_name';
                $out['plugin_name'] = $plugin_name;
                $out['add_time'] = false;
                break;
            case (preg_match('#/wp-admin/plugins.php\?.*action=deactivate#', $url)
                || preg_match('#/wp-admin/network/plugins.php\?.*action=deactivate#', $url)
                ? true
                : false):
                $out['action_event'] = 'deactivate_plugin_name';
                $out['plugin_name'] = $plugin_name;
                $out['add_time'] = false;
                break;
            case (preg_match('#/wp-admin/update.php\?.*action=upload-plugin#', $url)
            || preg_match('#/wp-admin/network/update.php\?.*action=upload-plugin#', $url)
                ? true
                : false):
                $out['action_event'] = 'uploading_plugin';
                $out['add_time'] = false;
                break;
            case (preg_match('#/wp-admin/users.php\?.*update=add#', $url)
            || preg_match('#/wp-admin/network/users.php\?.*update=add#', $url)
                ? true
                : false):
                $out['action_event'] = 'adding_user';
                $out['add_time'] = false;
                break;
            case (preg_match('#/wp-admin/users.php\?.*delete_count#', $url)
            || preg_match('#/wp-admin/network/users.php\?.*delete_count#', $url)
                ? true
                : false):
                $out['action_event'] = 'deleting_user';
                $out['add_time'] = false;
                break;
            default:
                preg_match_all('/\/wp-admin\/(.+\.php)\?(action=.+?)&/', $url, $matches);
                $file = !empty($matches[1]) && !empty($matches[1][0]) ? $matches[1][0] : '';
                $the_action = !empty($matches[2]) && !empty($matches[2][0]) ? $matches[2][0] : '';
                $out['action_event'] = !empty($file) && !empty($the_action) ? $file . '...' . $the_action : 'view';
                $out['add_time'] = false;
        }
    }
    return $out;
}

/**
 * Prepare days set for last days limit. Clear old records by days limit.
 * @param $current_block_data
 * @param $days_limit
 * @return array
 */
function spbc_brief_clear_and_reformat_records($current_block_data, $days_limit)
{
    //preset last $days_limit days set
    $last_days_predicted = array();
    $day_length = 3600 * 24;
    $current_day_ts = DateTime::createFromFormat('Y-m-d', date('Y-m-d'))->getTimestamp();
    foreach (range(0, $days_limit - 1) as $number) {
        $date_for_set = date('Y-m-d', ($current_day_ts - $day_length * $number));
        $last_days_predicted[$date_for_set] = 0;
    }
    // now it looks like ['2023-08-09' => '15',...+last 6 days set]

    // clear old Firewall records, if record date is not in preset - skip it
    foreach ($current_block_data as $entry ) {
        if (!empty($entry[0]) && !empty($entry[1])) {
            if (in_array($entry[0], array_keys($last_days_predicted))) {
                $last_days_predicted[$entry[0]] = $entry[1];
            }
        }
    }

    // reformatting to [[%day,%count]]
    $out = [];
    foreach ($last_days_predicted as $key => $value) {
        $out[] = array($key, $value);
    }
    return $out;
}
