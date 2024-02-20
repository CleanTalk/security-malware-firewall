<?php

namespace CleantalkSP\SpbctWP;

use CleantalkSP\SpbctWP\Cron as SpbcCron;
use CleantalkSP\SpbctWP\Scanner\ScanningLog\Repository;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Request;
use CleantalkSP\Variables\Get;
use CleantalkSP\SpbctWP\Scanner\Controller;

class RemoteCalls extends \CleantalkSP\Common\RemoteCalls
{
    public function __construct(&$state)
    {
        $this->without_token = self::checkWithoutToken();
        $this->state = $state;
        $this->class_name = __CLASS__;
    }

    /**
     * Hook before performing remote call action
     * Breaks the execution on few conditions
     *
     * @return bool|string[]
     */
    protected static function filter_before_action() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        // Stop execution if plugin is deactivated
        if ( get_option('spbc_deactivation_in_process') !== false ) { // Continue if plugin is active
            delete_option('spbc_deactivation_in_process');
            return true;
        }

        // Delay before perform action
        if ( Request::get('delay') ) {
            // Do not make remote call because the website is in maintenance mode
            if ( wp_is_maintenance_mode() ) {
                return true;
            }

            sleep((int)Request::get('delay'));

            $params = Get::get('delay') ? $_GET : $_POST;
            unset($params['delay']);

            return static::performToHost(
                Request::get('spbc_remote_action'),
                $params,
                array('async'),
                false
            );
        }

        return false;
    }

    /**
     * Performs remote call to the current website
     *
     * @param string $host
     * @param string $rc_action
     * @param string $plugin_name
     * @param string $api_key
     * @param array $params
     * @param array $patterns
     * @param bool $do_check Shows whether perform check before main remote call
     *
     * @return bool|string[]
     */
    public static function perform($host, $rc_action, $plugin_name, $api_key, $params, $patterns = array(), $do_check = true)
    {
        // Do not make remote call because the website is in maintenance mode
        if ( function_exists('wp_is_maintenance_mode') && wp_is_maintenance_mode() ) {
            return true;
        }

        return parent::perform($host, $rc_action, $plugin_name, $api_key, $params, $patterns, $do_check);
    }

    /**
     * @param $rc_action
     * @param array $params
     * @param array $patterns
     * @param bool $do_check
     * @return bool|string[]
     * @psalm-suppress NullArgument
     */
    public static function performToHost($rc_action, $params = array(), $patterns = array(), $do_check = true)
    {
        global $spbc;

        $patterns = array_merge(array('no_cache'), $patterns);

        $home_url = is_multisite() ? get_blog_option(null, 'home') : get_option('home');

        return self::perform(
            $home_url, // <- Because of this ='(
            $rc_action,
            'spbc',
            $spbc->api_key,
            $params,
            $patterns,
            $do_check
        );
    }

    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__check_website() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        die('OK');
    }

    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__close_renew_banner() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;
        $spbc->data['notice_show'] = 0;
        $spbc->save('data');
        // Updating cron task
        SpbcCron::updateTask('access_key_notices', 'spbc_access_key_notices', 86400);
        die('OK');
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__update_security_firewall() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;
        $result = spbc_security_firewall_update__init();
        $spbc->error_toggle(!empty($result['error']), 'firewall_update', $result);
        die(empty($result['error']) ? 'OK' : 'FAIL ' . json_encode(array('error' => $result['error'])));
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__update_security_firewall__worker() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {

        $result = spbc_security_firewall_update__worker();

        die(empty($result['error']) ? 'OK' : 'FAIL ' . json_encode(array('error' => $result['error'])));
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__drop_security_firewall() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $result = spbc_security_firewall_drop();
        die(empty($result['error']) ? 'OK' : 'FAIL ' . json_encode(array('error' => $result['error'])));
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__download__quarantine_file() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $result = spbc_scanner_file_download(true, Request::get('file_id'));
        if ( empty($result['error']) ) {
            header('Content-Type: application/octet-stream');
            header('Content-Disposition: attachment; filename=' . $result['file_name']);
        }
        die(empty($result['error'])
            ? $result['file_content']
            : 'FAIL ' . json_encode(array('error' => $result['error'])));
    }

    /**
     * The 'update_settings' remote call handler
     *
     * Handles different types of setting values:
     *  string
     *  array types separated by commas
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__update_settings() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        if ( ! headers_sent() ) {
            header('Content-Type: application/json');
        }

        global $spbc;

        // Try to get setting from JSON
        $incoming_settings = json_decode(Request::get('settings'), true);

        // Try to get setting from STRING
        if ( ! $incoming_settings ) {
            foreach ( $spbc->default_settings as $setting_name => $_setting_value ) {
                if ( Request::get($setting_name) !== '' ) {
                    $incoming_settings[$setting_name] = Request::get($setting_name);
                }
            }
        }

        if ( ! $incoming_settings ) {
            wp_send_json(['error' => 'No settings provided']);
        }

        $result = [];
        foreach ( $spbc->default_settings as $setting_name => $_setting_value ) {
            if ( $setting_name === 'spbc_key' ) {
                continue;
            }
            if ( isset($incoming_settings[$setting_name]) ) {
                $var = $incoming_settings[$setting_name];
                $type = gettype($spbc->settings[$setting_name]);

                settype($var, $type);
                $spbc->settings[$setting_name] = $var;
                $result[$setting_name] = true;
            } else {
                $result[$setting_name] = false;
            }
        }

        $spbc->save('settings');

        wp_send_json(['success' => $result]);
    }

    /**
     * The 'Cron::updateTask' remote call handler
     *
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__cron_update_task() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {

        $update_result = false;

        if ( Request::get('task') && Request::get('handler') && Request::get('period') && Request::get('first_call') ) {
            $update_result = Cron::updateTask(
                Request::get('task'),
                Request::get('handler'),
                (int)Request::get('period'),
                (int)Request::get('first_call')
            );
        }

        die($update_result ? 'OK' : 'FAIL ');
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__rollback_repair() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $result = spbc_rollback(Request::get('backup_id'));
        die(empty($result['error'])
            ? 'OK'
            : 'FAIL ' . json_encode(array('error' => $result['error'])));
    }

    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__scanner__controller() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        return spbc_scanner__controller();
    }

    /**
     * RC handler for \CleantalkSP\SpbctWP\Scanner\DirectoryScan::scanInMultipleThreads()
     *
     * @psalm-suppress PossiblyUnusedMethod
     * @psalm-suppress UnusedVariable
     */
    public static function action__scanner__check_dir() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $file_infos = Get::get('file_infos');
        if ( ! is_array($file_infos) || ! $file_infos ) {
            wp_send_json(array('error' => 'INVALID_FILE_INFOS'));
            return;
        }

        $results = array();
        foreach ( $file_infos as $file_info ) {
            $dir_scan = new \CleantalkSP\SpbctWP\Scanner\DirectoryScan(
                '',
                Scanner\Controller::getRootPath(),
                array(
                    'output_file_details' => array('path', 'full_hash'),
                )
            );
            $dir_scan->setFiles([$file_info]);
            $results[] = $dir_scan->scan();
        }

        wp_send_json($results);
    }

    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__perform_service_get() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $result_service_get = spbct_perform_service_get();

        die(
            !empty($result_service_get['error'])
            ? 'FAIL ' . json_encode($result_service_get)
            : 'OK'
        );
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__debug() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {

        global $spbc, $wpdb;
        //todo: this call wdb error
//        $out['fw_data_base_size'] = $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA) +
//            $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA__IPS);
        $out['settings'] = $spbc->settings;
        $out['fw_stats'] = $spbc->fw_stats;
        $out['data'] = $spbc->data;
        foreach (Repository::getAll() as $record) {
            if (!empty($record['content']) && is_string($record['content']) && !empty($record['timestamp']) && strpos($record['content'], 'OK') === false) {
                $logs[date('Y-m-d H:i:s', $record['timestamp'])] = ': ' . $record['content'];
            }
        }
        $out['last_scan_log'] = array_reverse($logs);
        $out['cron'] = $spbc->cron;
        $out['errors'] = $spbc->errors;
        $out['debug'] = $spbc->debug;
        $out['queue'] = get_option('spbc_fw_update_queue');
        $out['servers_connection'] = Get::get('do_test_connection') ? spbc_test_connection() : 'skipped, add &do_test_connection to run this';
        $out['plugins'] = $spbc->plugins;
        $out['themes'] = $spbc->themes;
        $out['transactions'] = $wpdb->get_results("SELECT * FROM {$wpdb->options} WHERE option_name LIKE 'spbc_transaction__%'");

        if ( SPBC_WPMS ) {
            $out['network_settings'] = $spbc->network_settings;
            $out['network_data'] = $spbc->network_data;
        }

        if ( \CleantalkSP\Variables\Request::equal('out', 'json') ) {
            wp_send_json($out);
        }
        array_walk($out, function (&$val, $_key) {
            $val = (array)$val;
        });

        array_walk_recursive($out, function (&$val, $_key) {
            if ( is_int($val) && preg_match('@^\d{9,11}$@', (string)$val) ) {
                $val = date('Y-m-d H:i:s', $val);
            }
        });

        $out = print_r($out, true);
        $out = str_replace("\n", "<br>", $out);
        $out = preg_replace("/[^\S]{4}/", "&nbsp;&nbsp;&nbsp;&nbsp;", $out);

        die($out);
    }
    /**
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__post_api_key() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $key = trim(Request::get('api_key'));
        if ( !spbc_api_key__is_correct($key) ) {
            wp_send_json(['FAIL' => ['error' => 'Api key is incorrect']]);
        }

        $template_id = Request::get('apply_template_id');
        if ( !empty($template_id) ) {
            $templates = CleantalkSettingsTemplates::get_options_template($key);
            if ( !empty($templates) ) {
                foreach ( $templates as $template ) {
                    if ( $template['template_id'] == $template_id && !empty($template['options_site']) ) {
                        $template_name = $template['template_id'];
                        $settings = $template['options_site'];
                        $settings = array_replace((array)$spbc->settings, json_decode($settings, true));

                        require_once SPBC_PLUGIN_DIR . 'inc/spbc-settings.php';
                        $settings = \spbc_sanitize_settings($settings);

                        $spbc->settings = $settings;
                        $spbc->save('settings');
                        $spbc->data['current_settings_template_id'] = $template_id;
                        $spbc->data['current_settings_template_name'] = $template_name;
                        $spbc->save('data');
                        break;
                    }
                }
            }
        }

        $spbc->storage['settings']['spbc_key'] = $key;
        $spbc->api_key = $key;
        $spbc->key_is_ok = true;
        $spbc->save('settings');

        spbc_sync(true);

        wp_send_json(['OK' => ['template_id' => $template_id]]);
    }

    /**
     * SecFW send logs
     *
     * @return void
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__secfw_send_logs() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $result = spbc_send_firewall_logs();

        if ( ! empty($result['error']) ) {
            die('FAIL ' . json_encode(array('error' => $result['error'])));
        }

        die('OK');
    }

    /**
     * Provide remote call handler for private_record_add
     * @return string
     * @throws \Exception
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__private_record_add() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        return spbct_sfw_private_records_handler('add');
    }

    /**
     * Provide remote call handler for private_record_delete
     * @return string
     * @throws \Exception
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__private_record_delete() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        return spbct_sfw_private_records_handler('delete');
    }

    /**
     * Handle remote call action "run_service_template_get".
     * @return string
     * @throws \InvalidArgumentException
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__run_service_template_get() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $error_hat = 'spbc_run_service_template_get: ';

        if ( empty($spbc->api_key) ) {
            throw new \InvalidArgumentException($error_hat . 'api key not found');
        }
        /**
         * $template_id validation
         */
        $template_id = Request::get('template_id');

        if ( empty($template_id) || !is_string($template_id) ) {
            throw new \InvalidArgumentException($error_hat . 'bad param template_id');
        }

        /**
         * Run and validate API method service_template_get
         */
        $options_template_data = CleantalkSettingsTemplates::settingsTemplatesValidateApiResponse(
            $template_id,
            API::method__services_templates_get($spbc->api_key, 'security')
        );

        return CleantalkSettingsTemplates::settingsTemplatesSetOptions($template_id, $options_template_data, $spbc->api_key);
    }

    /**
     * Remote call update_pscan_statuses handler.
     * @return false|string
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__update_pscan_statuses() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        try {
            //get db
            $db = DB::getInstance();
            //check if data is provided
            if (Post::get('file_pscan_ids')) {
                //get data from json from POST
                $file_pscan_ids = json_decode(Post::get('file_pscan_ids'), true);

                //validate values
                if ( $file_pscan_ids === null ) {
                    throw new \Exception('JSON decode failed');
                }

                if ( !is_array($file_pscan_ids) ) {
                    throw new \Exception('file_pscan_ids parameter must be a JSON string contains an array');
                }

                foreach ($file_pscan_ids as $file_pscan_id) {
                    //$file_pscan_id = Sanitize::cleanWord((string)$file_pscan_id);
                    if ( !Validate::isHash($file_pscan_id) ) {
                        throw new \Exception('invalid hash format detected');
                    }
                }

                //prepare to SQL
                $file_pscan_ids = implode('","', $file_pscan_ids);
                $file_pscan_ids = '("' . $file_pscan_ids . '")';
                $query = 'SELECT fast_hash FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE pscan_file_id IN ' . $file_pscan_ids;
                $result = $db->fetchAll($query, OBJECT_K);
            } else {
                //if no post data but get paramter persists update very file
                if (Get::get('update_all')) {
                    //prepare to SQL
                    $query = 'SELECT fast_hash FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE pscan_file_id IS NOT NULL';
                    $result = $db->fetchAll($query, OBJECT_K);
                } else {
                    //no post data
                    return json_encode(array('success' => false, 'result' => 'missing file_pscan_ids param'));
                }
            }

            if (false === $result) {
                throw new \Exception('internal db error');
            }

            $fast_hashes_to_update = array_keys($result);

            $update_result = spbc_scanner_pscan_check_analysis_status(true, $fast_hashes_to_update);

            if ( !empty($update_result['error_detail']) ) {
                throw new \Exception('internal error');
            }

            return json_encode(array('success' => true, 'result' => $update_result));
        } catch (\Exception $e) {
            return json_encode(array('success' => false, 'result' => $e->getMessage()));
        }
    }

    /**
     * Remote call spbc_cdn_check handler.
     * @psalm-suppress PossiblyUnusedMethod
     */
    public static function action__cdn_check() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $result_cdn_check = spbc_cdn_checker__parse_request();

        die(
            empty($result_cdn_check['error'])
            ? 'OK ' . json_encode($result_cdn_check)
            : 'FAIL ' . json_encode($result_cdn_check['error'])
        );
    }
}
