<?php

use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\API as SpbcAPI;
use CleantalkSP\SpbctWP\Helpers\CSV;
use CleantalkSP\SpbctWP\LinkConstructor;
use CleantalkSP\SpbctWP\Scanner\CureLog\CureLog;
use CleantalkSP\SpbctWP\Scanner\FrontendScan;
use CleantalkSP\SpbctWP\Scanner\Stages\CureStage;
use CleantalkSP\SpbctWP\Scanner\Surface;
use CleantalkSP\Variables\Post;
use CleantalkSP\SpbctWP\Scanner\Links;
use CleantalkSP\SpbctWP\Scanner;
use CleantalkSP\SpbctWP\Helpers\HTTP;
use CleantalkSP\Common\Helpers\Arr;
use CleantalkSP\SpbctWP\DTO;
use CleantalkSP\Fpdf\Pdf;

/**
 * Cron wrapper function for launchBackground
 *
 * @return bool|string|string[]|void
 */
function spbc_scanner__launch()
{
    $result = \CleantalkSP\SpbctWP\Scanner\ScannerQueue::launchBackground();

    if (\CleantalkSP\SpbctWP\RemoteCalls::check()) {
        $result = empty($result['error'])
            ? 'OK'
            : 'FAIL ' . die(json_encode($result));
    }

    return $result;
}

/**
 * Cron wrapper function for controllerBackground
 *
 * @param null $transaction_id
 * @param null $stage
 * @param null $offset
 * @param null $amount
 *
 * @return bool|string|string[]
 */
function spbc_scanner__controller($transaction_id = null, $stage = null, $offset = null, $amount = null)
{
    //cron task provide a single parameter
    if (isset($transaction_id) && is_array($transaction_id)) {
        $stage = isset($transaction_id['stage']) ? $transaction_id['stage'] : null;
        $offset = isset($transaction_id['offset']) ? $transaction_id['offset'] : null;
        $amount = isset($transaction_id['amount']) ? $transaction_id['amount'] : null;
        $transaction_id = isset($transaction_id['transaction_id']) ? $transaction_id['transaction_id'] : null;
    }

    $result = \CleantalkSP\SpbctWP\Scanner\ScannerQueue::controllerBackground($transaction_id, $stage, $offset, $amount);

    if (\CleantalkSP\SpbctWP\RemoteCalls::check()) {
        $result = empty($result['error'])
            ? 'OK'
            : 'FAIL ' . die(json_encode($result));
    }

    return $result;
}

/**
 * /**
 * For debug purpose
 * Clear table from results
 *
 * @param $direct_call
 *
 * @return array|void
 */
function spbc_scanner_clear($direct_call = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc;

    $spbc->plugins = array();
    $spbc->save('plugins');

    $spbc->themes = array();
    $spbc->save('themes');

    $spbc->data['scanner'] = array(
        'last_wp_version' => null,
        'cron'            => array(
            'state'         => 'get_hashes',
            'total_scanned' => 0,
            'offset'        => 0,
        ),
    );
    $spbc->save('data');

    $out = [
        'deleted_files_entries'    => Scanner\Controller::resetCheckResult(),
        'deleted_frontend_entries' => Scanner\Frontend::resetCheckResult(),
        'deleted_links'            => Scanner\Links::resetCheckResult(),
    ];

    if ($direct_call) {
        return $out;
    }

    wp_send_json($out);
}

function spbc_scanner_count_files($direct_call = false, $path = ABSPATH)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    ini_set('max_execution_time', '120');

    $start = microtime(true);

    global $spbc;

    $path_to_scan = realpath($path);
    $root_path    = realpath(ABSPATH);
    $init_params  = array(
        'count'           => true,
        'extensions'      => 'php, html, htm, php2, php3, php4, php5, php6, php7, phtml, shtml, phar, odf',
        'files_mandatory' => array(),
        'dir_exceptions'  => array(SPBC_PLUGIN_DIR . 'quarantine')
    );
    if ( ! empty($spbc->settings['scanner__dir_exclusions'])) {
        $excluded_dirs = spbc__get_exists_directories(explode("\n", $spbc->settings['scanner__dir_exclusions']));
        $init_params['dir_exceptions'] = array_merge($init_params['dir_exceptions'], $excluded_dirs);
    }

    $scaner = new Surface($path_to_scan, $root_path, $init_params);

    $output = array(
        'total'     => $scaner->output_files_count,
        'exec_time' => microtime(true) - $start,
    );

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_links_count($direct_call = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $links_scanner = new Links(array('count' => true));

    $output = array(
        'success' => true,
        'total'   => $links_scanner->posts_total,
    );

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_links_count_found($total = true, /* Out */ $count = 0)
{
    global $wpdb;

    $sql_result = $wpdb->get_results(
        'SELECT COUNT(*) AS cnt FROM ' . SPBC_TBL_SCAN_LINKS
        . (! $total ? ' WHERE scan_id = (SELECT MAX(scan_id) FROM ' . SPBC_TBL_SCAN_LINKS . ');' : ''), // only latest scan
        ARRAY_A
    );

    if ($sql_result) {
        $count = ! $sql_result[0]['cnt'] ? 0 : $sql_result[0]['cnt'];
    }

    return $count;
}

function spbc_scanner_links_count_found__domains()
{
    global $wpdb;
    $count = $wpdb->get_results(
        'SELECT COUNT(DISTINCT domain)
				FROM ' . SPBC_TBL_SCAN_LINKS . ';',
        OBJECT_K
    );

    return $count ? key($count) : 0;
}

function spbc_scanner_links_get_scanned__domains($offset = 0, $amount = 20, $order = null, $by = null, $get_array = false)
{
    global $wpdb;
    $offset = intval($offset);
    $amount = intval($amount);
    $data   = $wpdb->get_results(
        'SELECT domain, page_url, COUNT(domain) as link_count
				FROM ' . SPBC_TBL_SCAN_LINKS . ' 
			GROUP BY domain
			' . ($order && $by ? "ORDER BY $by $order" : '') . '
			LIMIT ' . $offset . ',' . $amount . ';',
        $get_array === true ? ARRAY_A : OBJECT
    );

    return $data;
}

/**
 * Remove file from the database
 * @param int $file_id
 * @return bool
 */
function spbc_scanner_file_remove_from_log($file_id)
{
    global $wpdb;

    return $wpdb->delete(SPBC_TBL_SCAN_FILES, array('fast_hash' => $file_id));
}

/**
 * Send file to Cleantalk Cloud
 * @param int $file_id
 * @param bool $do_rescan
 * @return array
 */
function spbc_scanner_file_send_handler($file_id = null, $do_rescan = true)
{
    global $spbc, $wpdb;

    $root_path = spbc_get_root_path();

    if (!$file_id) {
        return array('error' => 'WRONG_FILE_ID');
    }

    // Getting file info.
    $sql = 'SELECT fast_hash, path, source_type, source, source_status, version, mtime, weak_spots, full_hash, real_full_hash, status, checked_signatures, checked_heuristic
        FROM ' . SPBC_TBL_SCAN_FILES . '
        WHERE fast_hash = "' . $file_id . '"
        LIMIT 1';
    $sql_result = $wpdb->get_results($sql, ARRAY_A);
    $file_info  = $sql_result[0];

    if (empty($file_info)) {
        return array('error' => 'FILE_NOT_FOUND');
    }

    if (!file_exists($root_path . $file_info['path'])) {
        $res = spbc_scanner_file_remove_from_log($file_id);
        if ($res === false) {
            return array(
                'error' => __('File not exists and must be removed from log, but something went wrong.', 'security-malware-firewall'),
                'error_type' => 'FILE_NOT_EXISTS_DB_ERROR'
            );
        }

        return array(
            'error' => __('File not exists and will be removed from log.', 'security-malware-firewall'),
            'error_type' => 'FILE_NOT_EXISTS'
        );
    }

    if (!is_readable($root_path . $file_info['path'])) {
        return array('error' => 'FILE_NOT_READABLE');
    }

    if (filesize($root_path . $file_info['path']) < 1) {
        return array('error' => 'FILE_SIZE_ZERO');
    }

    if (filesize($root_path . $file_info['path']) > 1048570) {
        return array('error' => 'FILE_SIZE_TOO_LARGE');
    }

    if ($file_info['status'] === 'APPROVED_BY_CT' || $file_info['status'] === 'APPROVED_BY_CLOUD') {
        return array('error' => 'IT_IS_IMPOSIBLE_RESEND_APPROVED_FILE');
    }

    if ( $do_rescan ) {
        // Scan file before send it
        $rescan_results = spbc_scanner_rescan_single_file($file_info['path'], $file_info['full_hash'], $root_path);
        if (isset($rescan_results['error'])) {
            return array('error' => $rescan_results['error']);
        }

        $merged_result = $rescan_results['merged_result'];

        //prepare weakspots for DTO
        $file_info['weak_spots'] = $merged_result['weak_spots'];

        //update file in the table
        $wpdb->update(
            SPBC_TBL_SCAN_FILES,
            array(
                'checked_signatures' => $file_info['checked_signatures'],
                'checked_heuristic'  => $file_info['checked_heuristic'],
                'status'             => $file_info['status'] === 'MODIFIED' ? 'MODIFIED' : $merged_result['status'],
                'severity'           => $merged_result['severity'],
                'weak_spots'         => json_encode($merged_result['weak_spots']),
                'full_hash'          => md5_file($root_path . $file_info['path']),
            ),
            array('fast_hash' => $file_info['fast_hash']),
            array('%s', '%s', '%s', '%s', '%s', '%s'),
            array('%s')
        );
    }

    // Updating file_info if file source is unknown
    if ( ! isset($file_info['version'], $file_info['source'], $file_info['source_type'])) {
        $file_info_updated = spbc_get_source_info_of($file_info['path']);
        if ($file_info_updated) {
            $file_info = array_merge($file_info, $file_info_updated);
        }
    }

    // prepare file hash
    $file_info['full_hash']  = md5_file($root_path . $file_info['path']);

    // Getting file && API call
    $file_content   = file_get_contents($root_path . $file_info['path']);
    try {
        $dto = new DTO\MScanFilesDTO(
            array(
                'path_to_sfile' => $file_info['path'],
                'attached_sfile' => $file_content,
                'md5sum_sfile' => $file_info['full_hash'],
                'dangerous_code' => $file_info['weak_spots'],
                'version' => $file_info['version'],
                'source' => $file_info['source'],
                'source_type' => $file_info['source_type'],
                'source_status' => $file_info['source_status'],
                'real_hash' => $file_info['real_full_hash'],
                'client_php_version' => phpversion(),
                'auto_send_type' => 'Suspicious',
                'current_scanner_settings' => json_encode($spbc->settings),
                'plugin_heuristic_checked' => $file_info['checked_heuristic'],
                'plugin_signatures_checked' => $file_info['checked_signatures'],
            )
        );
    } catch ( \InvalidArgumentException $e ) {
        return array('error' => "File can not be send. Error: \n" . substr($e->getMessage(), 0, 100));
    }

    $api_response = SpbcAPI::method__security_pscan_files_send($spbc->settings['spbc_key'], $dto);

    if (!empty($api_response['error'])) {
        if ($api_response['error'] === 'QUEUE_FULL') {
            //do something with not queued files
            $sql_result = $wpdb->query(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET'
                . ' last_sent = ' . current_time('timestamp') . ','
                . ' pscan_pending_queue = 1'
                . ' WHERE fast_hash = "' . $file_id . '"'
            );

            if ($sql_result === false) {
                return array('error' => 'DB_COULD_NOT_UPDATE pscan_pending_queue');
            }

            //set new cron to resend unqueued files
            \CleantalkSP\SpbctWP\Cron::updateTask(
                'scanner_resend_pscan_files',
                'spbc_scanner_resend_pscan_files',
                SPBC_PSCAN_RESEND_FILES_STATUS_PERIOD,
                time() + SPBC_PSCAN_RESEND_FILES_STATUS_PERIOD
            );

            return array('success' => true, 'result' => $api_response);
        } else {
            //out API error if error is not queue_full
            return $api_response;
        }
    }

    if (!isset($api_response['file_id'])) {
        return array('error' => 'API_RESPONSE: file_id is NULL');
    }

    // Updating "last_sent"
    $sql_result = $wpdb->query(
        'UPDATE ' . SPBC_TBL_SCAN_FILES
        . ' SET'
        . ' last_sent = ' . current_time('timestamp') . ','
        . ' pscan_processing_status = "NEW",'
        . ' pscan_pending_queue = 0,'
        . ' pscan_file_id = "' . $api_response["file_id"] . '"'
        . ' WHERE fast_hash = "' . $file_id . '"'
    );

    if ($sql_result === false) {
        return array('error' => 'DB_COULDNT_UPDATE pscan_processing_status');
    }

    //set new cron to update statuses
    \CleantalkSP\SpbctWP\Cron::updateTask(
        'scanner_update_pscan_files_status',
        'spbc_scanner_update_pscan_files_status',
        SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD,
        time() + SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD
    );

    return array('success' => true, 'result' => $api_response);
}

function spbc_scanner_file_send($direct_call = false, $file_id = null, $do_rescan = true)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
        $file_id = preg_match('@[a-zA-Z0-9]{32}@', Post::get('file_id')) ? Post::get('file_id') : null;
    }

    $output = spbc_scanner_file_send_handler($file_id, $do_rescan);

    if ( !$direct_call ) {
        wp_send_json($output);
    }

    return $output;
}


/**
 * Do rescan a single file with heuristic and signatures.
 * @param $file_path
 * @param $full_hash
 * @param $root_path
 * @return array[]|string[]
 * <ul>
 * <li>array('heuristic_result' => Verdict,
 * <br>'signatures_result' => Verdict,
 * <br>'merged_result' => array(
 * <br>&nbsp&nbsp&nbsp&nbsp 'status' => '',
 * <br>&nbsp&nbsp&nbsp&nbsp 'severity' => '',
 * <br>&nbsp&nbsp&nbsp&nbsp 'weak_spots' => '')) on success
 * </li>
 * <li>array('error' => 'error_text') on failure.</li>
 * </ul>
 */
function spbc_scanner_rescan_single_file($file_path, $full_hash, $root_path)
{
    global $wpdb;

    $out = array(
        'heuristic_result' => array(),
        'signatures_result' => array(),
        'merged_result' => array(),
    );

    //Heuristic
    $heuristic_scanner = new \CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller();
    $file_to_check = new Scanner\FileInfoExtended(array('path' => $file_path));
    $result_heur = $heuristic_scanner->scanFile($file_to_check, $root_path);

    if ($result_heur->status === 'ERROR') {
        return array('error' => $result_heur->error_msg);
    }

    // Signature
    $signatures  = $wpdb->get_results('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);
    $signatures_scanner = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Controller();
    $file_to_check = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\FileInfo(
        $file_path,
        $full_hash
    );
    $result_sign = $signatures_scanner->scanFile($file_to_check, $root_path, $signatures);

    if ($result_sign->status === 'ERROR') {
        return array('error' => $result_sign->error_msg);
    }

    $out['heuristic_result'] = $result_heur;
    $out['signature_result'] = $result_sign;

    $merged_result = Arr::mergeWithSavingNumericKeysRecursive((array)$result_heur, (array)$result_sign);

    //merge weak-spots
    if ( isset($merged_result['weak_spots']) &&
        is_array($merged_result['weak_spots']) &&
        isset($merged_result['weak_spots'][0]) &&
        count($merged_result['weak_spots']) > 1 ) {
        unset($merged_result['weak_spots'][0]);
    }

    //merge status and severities
    if ($result_sign->status !== 'OK') {
        //signatures verdict is prior
        $merged_result['status'] = $result_sign->status;
        $merged_result['severity'] = $result_sign->severity;
    } elseif ($result_heur->status  !== 'OK') {
        //if no signatures found - check heuristic verict
        $merged_result['status'] = $result_heur->status;
        $merged_result['severity'] = $result_heur->severity;
    }

    $out['merged_result'] = $merged_result;

    return $out;
}

function spbc_scanner_file_delete($direct_call = false, $file_id = null)
{
    global $spbc;

    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    if ( $spbc->data['license_trial'] == 1 ) {
        wp_send_json(['error' => spbc_get_trial_restriction_notice(), 'hide_support_link' => '1']);
    }

    $time_start = microtime(true);

    global $wpdb;

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT *
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            $file_path = $file_info['status'] == 'QUARANTINED' ? $file_info['q_path'] : $root_path . $file_info['path'];

            if (file_exists($file_path)) {
                if (is_writable($file_path)) {
                    $is_file_required_result = spbc_is_file_required_in_php_ini($file_path);
                    if ( $is_file_required_result === false ) {
                        // Getting file && API call
                        $remembered_file_content = file_get_contents($file_path);
                        $response_content_before_actions = HTTP::getContentFromURL(get_option('home'));
                        $response_content_admin_before_actions = HTTP::getContentFromURL(get_option('home') . '/wp-admin');
                        $result                  = unlink($file_path);

                        if ($result) {
                            $response_content       = HTTP::getContentFromURL(get_option('home'));
                            if ( $response_content === $response_content_before_actions ) {
                                $response_content_ok = true;
                            } else {
                                if (is_string($response_content) && !spbc_search_page_errors($response_content)) {
                                    $response_content_ok = true;
                                } else {
                                    $response_content_ok = false;
                                }
                            }

                            $response_content_admin = HTTP::getContentFromURL(get_option('home') . '/wp-admin');
                            if ( $response_content_admin === $response_content_admin_before_actions ) {
                                $response_content_admin_ok = true;
                            } else {
                                if (is_string($response_content_admin) && !spbc_search_page_errors($response_content_admin)) {
                                    $response_content_admin_ok = true;
                                } else {
                                    $response_content_admin_ok = false;
                                }
                            }

                            if (
                                !$response_content_admin_ok ||
                                !$response_content_ok
                            ) {
                                $output          = array('error' => 'WEBSITE_RESPONSE_BAD');
                                $result          = file_put_contents($file_path, $remembered_file_content);
                                $output['error'] .= $result === false ? ' REVERT_FAILED' : ' REVERT_OK';
                            } else {
                                // Deleting row from DB
                                if ($wpdb->query('DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE fast_hash = "' . $file_id . '"') !== false) {
                                    $output = array('success' => true);
                                } else {
                                    $output = array('error' => 'DB_COULDNT_DELETE_ROW');
                                }
                            }
                        } else {
                            $output = array('error' => 'FILE_COULDNT_DELETE');
                        }
                        unset($remembered_file_content);
                    } else {
                        $output = $is_file_required_result === null
                            ? array('error' => 'PHP_INI_REQUIREMENTS_CHECK_FAIL')
                            : array('error' => 'FILE_IS_REQUIRED_IN_PHP_INI');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_WRITABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
        return true;
    }
}

/**
 * Cheсk if the filepath is required in php.ini settings. It could be set in "auto_prepend_file" or in "auto_append_file" keys strings.
 * @param $file_path
 * @return bool|null True if files is required, false otherwise. Null on any code fail.
 */
function spbc_is_file_required_in_php_ini($file_path)
{
    try {
        $ini_auto_prepend_file_req[] = @ini_get('auto_prepend_file');
        $ini_auto_prepend_file_req[] = @ini_get('auto_append_file');
        if (!empty($file_path) && is_string($file_path)) {
            foreach ($ini_auto_prepend_file_req as $required_string) {
                if (is_string($required_string)) {
                    if (strpos($required_string, $file_path) !== false ||
                        (!empty(basename($file_path)) && strpos($required_string, basename($file_path)) !== false)) {
                        return true;
                    }
                }
            }
        }
    } catch (\Exception $_e) {
        return null;
    }
    return false;
}

function spbc_scanner_file_approve($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc, $wpdb;

    if ( $spbc->data['license_trial'] == 1 ) {
        wp_send_json(['error' => spbc_get_trial_restriction_notice(), 'hide_support_link' => '1']);
    }

    $time_start = microtime(true);

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT path, status, severity, pscan_status, pscan_processing_status, pscan_balls, pscan_file_id
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_readable($root_path . $file_info['path'])) {
                    // Getting file && API call
                    $previous = json_encode(array(
                        'status'   => $file_info['status'],
                        'severity' => $file_info['severity'],
                        'pscan_status' => $file_info['pscan_status'],
                        'pscan_processing_status' => $file_info['pscan_processing_status'],
                        'pscan_balls' => $file_info['pscan_balls'],
                        'pscan_file_id' => $file_info['pscan_file_id'],
                    ));

                    // Updating all other statuses
                    $wpdb->update(
                        SPBC_TBL_SCAN_FILES,
                        array(
                            'status'         => 'APPROVED_BY_USER',
                            'previous_state' => $previous,
                            'pscan_pending_queue' => null,
                            'pscan_status' => null,
                            'pscan_processing_status' => null,
                            'pscan_balls' => null,
                            'pscan_file_id' => null,
                        ),
                        array('fast_hash' => $file_id),
                        array('%s', '%s', '%s'),
                        array('%s')
                    );

                    // Set severity to NULL
                    // Using strait query because WPDB doesn't support NULL values
                    $sql        = 'UPDATE ' . SPBC_TBL_SCAN_FILES . '
                        SET severity = NULL
                        WHERE fast_hash = "' . $file_id . '"';
                    $sql_result = $wpdb->query($sql, ARRAY_A);

                    if ($sql_result !== false) {
                        $output = array('success' => true);
                    } else {
                        $output = array('error' => 'DB_COULDNT_UPDATE_ROW_APPROVE');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_READABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

/**
 * Checks analysis status of passed file(s)
 *
 * @param bool $direct_call Direct call flag. Show that the function was called directly from other function, not from AJAX
 * @param string|array $file_ids_input IDs of files to check the analysis status
 * @return array|true[]
 */
function spbc_scanner_pscan_check_analysis_status($direct_call = false, $file_ids_input = '')
{
    // Check ajax nonce
    if ( !$direct_call ) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
        $file_ids_input = Post::get('file_id', 'hash') ? (string)Post::get('file_id') : '';
    }

    global $spbc, $wpdb;

    // Parse if there are more than 1 file
    $_file_ids_input = is_string($file_ids_input) ? explode(',', $file_ids_input) : $file_ids_input;

    // Prepare counters
    $counters = array(
        'queued' => 0,
        'updated' => 0,
        'failed' => 0,
        'skipped' => 0,
        'total' => count($_file_ids_input)
    );

    // Prepare out array
    $out = array('counters' => $counters);

    /*
     * Processing files start
     */
    foreach ( $_file_ids_input as $file_id ) {
        /*
         * Process a single file start
         */
        // Get file info.
        $file_info = spbc_scanner_get_file_by_id($file_id);

        // Validate file info
        try {
            $file_info = spbc_scanner_pscan_validate_file_info($file_info);
        } catch (\Exception $e) {
            $out['error_detail'][] = array(
                'error' => $e->getMessage(),
            );
            $counters['failed']++;
            continue;
        }

        try {
            $file_info = spbc_scanner_pscan_update_check_exclusions($file_info);
        } catch (\Exception $e) {
            switch ($e->getMessage()) {
                case 'skipped':
                    $counters['skipped']++;
                    break;
                case 'queued':
                    $counters['queued']++;
                    break;
            }
            continue;
        }


        // Perform API call
        $api_response = SpbcAPI::method__security_pscan_status(
            $spbc->settings['spbc_key'],
            $file_info['pscan_file_id']
        );


        // Validate API response
        try {
            $api_response = spbc_scanner_validate_pscan_status_response($api_response);
        } catch ( Exception $exception ) {
            $out['error_detail'][] = array(
                'file_path' => $file_info['path'],
                'pscan_file_id' => $file_info['pscan_file_id'],
                'fast_hash' => $file_id,
                'error' => 'API response validation failed "' . $exception->getMessage() . "\"",
            );
            continue;
        }

        if ( $api_response['processing_status'] !== 'DONE' ) {
            /*
            * If file process is not finished, update data
            */
            $update_result = $wpdb->query(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET '
                . ' pscan_pending_queue = 0, '
                . ' pscan_processing_status  = "' . $api_response['processing_status'] . '",'
                . ' pscan_estimated_execution_time  = "' . $api_response['estimated_execution_time'] . '"'
                . ' WHERE pscan_file_id = "' . $file_info['pscan_file_id'] . '"'
            );
        } else {
            if ( $api_response['file_status'] === 'SAFE' ) {
                /*
                * Do something with SAFE files
                */
                // Prepare query for good files update
                $update_query = $wpdb->prepare(
                    'UPDATE ' . SPBC_TBL_SCAN_FILES
                    . ' SET '
                    . ' pscan_processing_status  = "DONE",'
                    . ' pscan_pending_queue = 0, '
                    . ' pscan_status  = "SAFE",'
                    . ' pscan_balls  = %s,'
                    . ' status = "APPROVED_BY_CLOUD",'
                    . ' pscan_estimated_execution_time = NULL'
                    . ' WHERE pscan_file_id = %s',
                    isset($api_response['file_balls']) ? $api_response['file_balls'] : '{SAFE:0}',
                    $file_info['pscan_file_id']
                );
            } else {
                /*
                * Do something with DANGEROUS files
                */
                // Prepare query for bad files update
                $update_query = $wpdb->prepare(
                    'UPDATE ' . SPBC_TBL_SCAN_FILES
                    . ' SET '
                    . ' pscan_processing_status  = "DONE",'
                    . ' pscan_pending_queue = 0, '
                    . ' pscan_status  = %s ,'
                    . ' severity  = "CRITICAL",'
                    . ' pscan_balls  = %s,'
                    . ' status  = "DENIED_BY_CLOUD",'
                    . ' pscan_estimated_execution_time = NULL'
                    . ' WHERE pscan_file_id = %s',
                    $api_response['file_status'],
                    isset($api_response['file_balls']) ? $api_response['file_balls'] : '{DANGEROUS:0}',
                    $file_info['pscan_file_id']
                );
            }
            // Run prepared query and keep update result
            $update_result = $wpdb->query($update_query);
        }

        if ( $update_result === false ) {
            // Collect errors
            $out['error_detail'][] = array(
                'file_path' => $file_info['path'],
                'pscan_file_id' => $file_info['pscan_file_id'],
                'fast_hash' => $file_id,
                'error' => 'COULDNT_UPDATE file status',
            );
        } else {
            // All is fine, inc updated counter
            $counters['updated']++;
        }
        /*
        * Process a single file end
        */
    }

    /*
    * Processing files end
    */

    // Process errors
    if ( !empty($out['error_detail']) ) {
        $out['error'] = 'Some files where not updated.';
    }

    // Fill counters
    $out['counters'] = $counters;

    // Shift cron task
    \CleantalkSP\SpbctWP\Cron::updateTask(
        'scanner_update_pscan_files_status',
        'spbc_scanner_update_pscan_files_status',
        SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD,
        time() + SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD
    );

    // Resend queued files if available
    if ( $counters['queued'] > 0 && $spbc->settings['spbc_scanner_user_can_force_pscan_update'] ) {
        spbc_scanner_resend_pscan_files();
    }

    if (!$direct_call) {
        wp_send_json_success($out);
    }

    return $out;
}

/**
 * Validate file info collected for pscan status updating process
 * @param $file_info array|false array of file info or false if we could not collect this
 * @return array origin array of file info
 * @throws Exception
 */
function spbc_scanner_pscan_validate_file_info($file_info)
{
    // SQL query result validation
    if ( $file_info !== false ) {
        // Validate path
        $file_path = !empty($file_info['path']) ? $file_info['path'] : false;
        if (!$file_path) {
            throw new Exception('can not get file path');
        }

        // Set pscan file id to be sure that file is correctly reached from db
        $pscan_file_id = !empty($file_info['pscan_file_id']) ? $file_info['pscan_file_id'] : false;
        if ( !$pscan_file_id ) {
            throw new Exception('can not get pscan_file_id');
        }
    } else {
        throw new Exception('can not get file info');
    }
    return $file_info;
}


/**
 * Check if status updater should skip this file
 * @param $file_info
 * @return array array of file info
 * @throws Exception message contains reason for skip the file
 */
function spbc_scanner_pscan_update_check_exclusions(array $file_info)
{
    global $spbc;
    //skip quarantined files
    if (isset($file_info['status']) && $file_info['status'] === 'QUARANTINED') {
        throw new Exception('skipped');
    }

    // skip not queued files
    $pscan_pending_queue = isset($file_info['pscan_pending_queue']) && $file_info['pscan_pending_queue'] == '1';
    if ($pscan_pending_queue) {
        throw new Exception('queued');
    }

    //skip maual analysis checked
    if (empty($file_info['pscan_processing_status'])) {
        throw new Exception('skipped');
    }

    return $file_info;
}

/**
 * @param array $response API Response
 * @param bool $await_estimated_data Do await estimated data set on undone files check
 * @return mixed API Response
 * @throws Exception if validation failed
 */
function spbc_scanner_validate_pscan_status_response($response)
{
    // Check if API error
    if ( !empty($response['error']) ) {
        throw new Exception('API error: "' . $response['error'] . "\"");
    }

    // Check if processing_status is set and correct
    if ( !isset($response['processing_status']) ) {
        throw new Exception('response provided no processing status');
    }

    // Set allowed statuses
    $allowed_statuses_array = array(
        'NEW',
        'DONE',
        'ERROR',
        'IN_SCANER',
        'NEW_CLOUD',
        'IN_CLOUD',
        'IN_SANDBOX',
        'NEW_SANDBOX',
        'UNKNOWN'
    );

    // Check allowed statuses
    if ( !in_array($response['processing_status'], $allowed_statuses_array) ) {
        throw new Exception('response provided unknown processing status "' . $response['processing_status'] . "\"");
    }

    // Check precessing status
    if ( $response['processing_status'] === 'DONE' && !isset($response['file_status']) ) {
        throw new Exception('process finished, but status is unset');
    }

    if ( $response['processing_status'] === 'DONE' ) {
        // Check file_status
        if ( !in_array($response['file_status'], array('DANGEROUS', 'SAFE')) ) {
            throw new Exception('process finished, but status is unknown: "' . $response['file_status'] . "\"");
        }
    }

    //estimated time validation
    if ( $response['processing_status'] !== 'DONE' ) {
        if ( ! isset($response['estimated_execution_time'])) {
            throw new Exception('response provided no estimated scan time');
        }
        //todo remove on business decision
        //if ( ! isset($response['number_of_files'])) {
        //  throw new Exception('response provided no number of estimated files');
        //}
        //if ( ! isset($response['number_of_files_scanned'])) {
        //  throw new Exception('response provided no number of already scanned files');
        //}
    }

    return $response;
}

function spbc_scanner_file_approve__bulk($ids = array())
{
    if ( ! $ids) {
        return array('error' => 'Noting to approve');
    }

    $out = array();

    foreach ($ids as $id) {
        $result = spbc_scanner_file_approve(true, $id);

        if ( ! empty($result['error'])) {
            $file_info             = spbc_scanner_get_file_by_id($id);
            $file_path             = isset($file_info['path']) ? $file_info['path'] : 'UNKNOWN_FILE';
            $out['error']          = 'Some files where not updated.';
            $out['error_detail'][] = array(
                'file_path' => $file_path,
                'error'     => $result['error'],
            );
        }
    }

    return $out;
}

function spbc_scanner_file_disapprove__bulk($ids = array())
{
    if ( ! $ids ) {
        return array('error' => 'Nothing to disapprove');
    }

    $out = array();

    foreach ($ids as $id) {
        $result = spbc_scanner_file_disapprove(true, $id);

        if ( ! empty($result['error']) ) {
            $file_info             = spbc_scanner_get_file_by_id($id);
            $file_path             = isset($file_info['path']) ? $file_info['path'] : 'UNKNOWN_FILE';
            $out['error']          = 'Some files where not updated.';
            $out['error_detail'][] = array(
                'file_path' => $file_path,
                'error'     => $result['error'],
            );
        }
    }

    return $out;
}

function spbc_scanner_page_approve_process__bulk($action)
{
    global $wpdb;

    $action = $action === 'approve' ? '1' : '0';

    $out = array();

    $sql = 'UPDATE ' . SPBC_TBL_SCAN_FRONTEND . ' SET approved = ' . $action;
    $sql = $wpdb->prepare($sql);
    $sql_result = $wpdb->query($sql);
    if ($sql_result === false) {
        $out['error'] = 'COULDNT_UPDATE_DB';
    }

    $ids = $wpdb->get_col("SELECT page_id FROM " . SPBC_TBL_SCAN_FRONTEND);
    foreach ($ids as $id) {
        $update_meta_result = update_post_meta($id, '_spbc_frontend__approved', (int)$action);
        if ($update_meta_result === false) {
            $out['error'] = 'COULDNT_UPDATE_POST_META';
        }
    }

    return $out;
}

function spbc_scanner_file_send_for_analysis__bulk($fast_hashes_list = array())
{
    if ( ! $fast_hashes_list) {
        return array('error' => 'Record has no file id to send.');
    }

    global $wpdb;

    $sql_result = $wpdb->get_results(
        'SELECT fast_hash FROM ' . SPBC_TBL_SCAN_FILES . '
        WHERE last_sent IS NULL
        AND status NOT IN ("APPROVED_BY_USER","APPROVED_BY_CT","APPROVED_BY_CLOUD","DENIED_BY_CT")',
        ARRAY_A
    );

    $sql_result = array_map(
        function ($data) {
            return $data['fast_hash'];
        },
        $sql_result
    );

    $not_sent_files_intersection = array_values(array_intersect($fast_hashes_list, $sql_result));

    $out = array(
        'files_sent_counter' => 0
    );

    if ( ! empty($not_sent_files_intersection)) {
        foreach ($not_sent_files_intersection as $fast_hash) {
            $result = spbc_scanner_file_send(true, $fast_hash);

            if ( ! empty($result['error'])) {
                $file_info             = spbc_scanner_get_file_by_id($fast_hash);
                $file_path             = isset($file_info['path']) ? $file_info['path'] : 'UNKNOWN_FILE';
                $out['error']          = 'Some files where not updated.';
                $out['error_detail'][] = array(
                    'file_path' => $file_path,
                    'error'     => $result['error'],
                );
            }

            $out['files_sent_counter']++;
        }
    } else {
        $out['error'] = __('All the available files have been already sent.', 'security-malware-firewall');
    }

    return $out;
}

/**
 * Get SQL *WHERE* suffix for SELECT query depends on files category.
 * @param string $category Category of files category which needs to be searched for
 * @return string SQL *WHERE* suffix.
 */
function spbc_get_sql_where_addiction_for_table_of_category($category)
{
    global $spbc;
    switch ($category) {
        case 'critical':
            $res = ' WHERE status IN ("DENIED_BY_CLOUD", "DENIED_BY_CT")
            OR (
                severity = "CRITICAL"
                AND (
                    status <> "QUARANTINED" AND 
                    status <> "APPROVED_BY_USER" AND 
                    status <> "APPROVED_BY_CT" AND
                    status <> "OK"
                    )
                AND (
                    last_sent IS NULL OR 
                    pscan_status = "DANGEROUS"
                )
            )';
            break;
        case 'suspicious':
            $res = ' WHERE severity <> "CRITICAL" AND
                        last_sent IS NULL AND
                        (status = "MODIFIED" AND source_type IS NOT NULL) 
                        OR (status = "INFECTED" AND severity = "SUSPICIOUS" AND last_sent IS NULL)';
            break;
        case 'approved':
            $res = ' WHERE status = "APPROVED_BY_USER" AND source_type IS NULL';
            break;
        case 'approved_by_cloud':
            $res = ' WHERE ( status = "APPROVED_BY_CT" OR status = "APPROVED_BY_CLOUD") AND source_type IS NULL';
            break;
        case 'analysis_log':
            $res = ' WHERE last_sent IS NOT NULL';
            break;
        case 'unknown':
            $res = ' WHERE status NOT IN ("APPROVED_BY_USER","APPROVED_BY_CT","APPROVED_BY_CLOUD","DENIED_BY_CT", "ERROR") AND
						    detected_at >= ' . (time() - $spbc->settings['scanner__list_unknown__older_than'] * 86400) . ' AND
						    source IS NULL AND
						    source_type IS NULL AND
		                    path NOT LIKE "%wp-content%themes%" AND
                            path NOT LIKE "%wp-content%plugins%" AND
                            path NOT LIKE "%wp-content%cache%" AND
                            path NOT LIKE "%wp-config.php" AND
						    (severity IS NULL OR severity NOT IN ("CRITICAL", "SUSPICIOUS")) AND
						    last_sent IS NULL';
            break;
        case 'quarantined':
            $res = ' WHERE status = "QUARANTINED"';
            break;
        case 'frontend_malware':
            $res = ' WHERE approved IS NULL OR approved <> 1';
            break;
        case 'frontend_scan_results_approved':
            $res = ' WHERE approved = 1';
            break;
        case 'skipped':
            $res = ' WHERE status = "ERROR" AND error_msg IS NOT NULL AND error_msg NOT LIKE "%FILE_SIZE_ZERO%"';
            break;
        default:
            $res = '';
    }
    return $res;
}

/**
 * Get all files IDs of the category.
 * @param string $category Category of files category which needs to be searched for
 * @return array Array of IDs
 */
function spbc_scanner_get_files_by_category($category)
{
    global $wpdb;

    $ids = array();

    $query = 'SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES . spbc_get_sql_where_addiction_for_table_of_category($category);

    $res = $wpdb->get_results($query);

    foreach ($res as $tmp) {
        $ids[] = $tmp->fast_hash;
    }

    return $ids;
}

function spbc_scanner_file_disapprove($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $wpdb;

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT path, full_hash, previous_state
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info) ) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_readable($root_path . $file_info['path'])) {
                    // Getting file && API call

                    $previous = is_string($file_info['previous_state'])
                        ? json_decode($file_info['previous_state'], true)
                        : false;

                    if ( ! $previous ) {
                        // Placeholders for the approved by CT files
                        $previous['status'] = 'OK';
                        $previous['severity'] = null;
                        $previous['pscan_status'] = null;
                        $previous['pscan_processing_status'] = null;
                        $previous['pscan_balls'] = null;
                        $previous['pscan_file_id'] = null;
                    }

                    $sql_upd_result = $wpdb->update(
                        SPBC_TBL_SCAN_FILES,
                        array(
                            'status' => $previous['status'],
                            'severity' => $previous['severity'],
                            'pscan_status' => $previous['pscan_status'],
                            'pscan_processing_status' => $previous['pscan_processing_status'],
                            'pscan_balls' => $previous['pscan_balls'],
                            'pscan_file_id' => $previous['pscan_file_id'],
                        ),
                        array('fast_hash' => $file_id),
                        array('%s', '%s', '%s', '%s', '%s', '%d'),
                        array('%s')
                    );

                    if ($sql_upd_result !== false) {
                        $output = array('success' => true);
                    } else {
                        $output = array('error' => 'DB_COULDNT_UPDATE_ROW_APPROVE');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_READABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_page_view($direct_call = false, $page_url = false)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $spbc, $wpdb;

    $page_url = $direct_call
        ? $page_url
        : Post::get('page_url');

    $page_content = HTTP::getContentFromURL($page_url);

    if ( ! empty($page_content)) {
        // Getting signatures
        $check_list = array('redirects', 'dbd', 'signatures_js', 'signatures_html');
        if ($spbc->settings['scanner__frontend_analysis__csrf']) {
            $check_list[] = 'csrf';
        }

        $fe_scanner = new FrontendScan($check_list);

        $recheck_res = $fe_scanner->setHomeUrl(get_option('home'))
                                  ->setExceptUrls(CSV::parseNSV($spbc->settings['scanner__frontend_analysis__domains_exclusions']))
                                  ->setSignatures($wpdb->get_results('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES, ARRAY_A))
                                  ->setContent($page_content)
                                  ->check()
                                  ->getResult();

        if (count($recheck_res) === 0) {
            // If the malware not more present
            $page_id = $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT page_id'
                    . ' FROM ' . SPBC_TBL_SCAN_FRONTEND
                    . ' WHERE url = %s',
                    $page_url
                )
            );
            delete_post_meta($page_id, '_spbc_frontend__last_checked');
            delete_post_meta($page_id, 'spbc_frontend__last_checked');
            $wpdb->query(
                $wpdb->prepare(
                    'DELETE'
                    . ' FROM ' . SPBC_TBL_SCAN_FRONTEND
                    . ' WHERE url = %s',
                    $page_url
                )
            );

            wp_send_json([
                'success' => false,
                'content' => esc_html__('The malware found earlier no longer present. The notice about the malware will be replaced from the results list.', 'security-malware-firewall'), // Content of the modal
                'file_path' => esc_html__('The malware no longer found', 'security-malware-firewall') // Title of the modal
            ]);
        }

        $page_text = array();

        $page_url_sql = str_replace('.', '%', $page_url);

        // Getting file info.
        $sql_result = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT weak_spots'
                . ' FROM ' . SPBC_TBL_SCAN_FRONTEND
                . ' WHERE url LIKE %s'
                . ' LIMIT 1',
                $page_url_sql
            ),
            ARRAY_A
        );

        $result = $sql_result[0];

        foreach (preg_split("/((\r?\n)|(\r\n?))/", $page_content) as $line) {
            $page_text[] = htmlspecialchars($line);
        }
        $output = array(
            'success'    => true,
            'file'       => $page_text,
            'file_path'  => $page_url,
            'difference' => null,
            'weak_spots' => $result['weak_spots']
        );
    } else {
        $output = array('error' => 'FILE_TEXT_EMPTY');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    }
    $red_line             = '<span style=\"background: rgb(200,80,80);\">';
    $red_line_end         = '</span>';
    $output['weak_spots'] = str_replace('__SPBCT_RED__', $red_line, $output['weak_spots']);
    $output['weak_spots'] = str_replace('__SPBCT_RED_END__', $red_line_end, $output['weak_spots']);

    wp_send_json($output);
}

/**
 * Handler to approve or disapprove a page.
 * @param string $action Could be 'approve' or 'disapprove'
 * @return true
 * @throws Exception
 */
function spbc_scanner_page_approve_process($action)
{
    global $wpdb;

    if (!in_array($action, array('approve', 'disapprove'))) {
        throw new \Exception('APPROVE_PROCESS_MISTYPE');
    }

    $action = $action === 'approve' ? '1' : '0';

    $page_url = Post::get('page_url');
    $page_id = (int)Post::get('page_id');

    if (empty($page_url) || $page_id === 0 ) {
        throw new \Exception('PAGE_ID_OR_PAGE_URL_IS_EMPTY');
    }

    if (filter_var($page_url, FILTER_VALIDATE_URL)) {
        // Getting file info.
        $sql = 'UPDATE ' . SPBC_TBL_SCAN_FRONTEND . ' SET approved = ' . $action . ' WHERE url = %s';
        $sql = $wpdb->prepare($sql, $page_url);
        $sql_result = $wpdb->query($sql);
        if ($sql_result === false) {
            throw new \Exception('COULDNT_UPDATE_DB');
        }
        $update_meta_result = update_post_meta($page_id, '_spbc_frontend__approved', (int)$action);
        if (false === $update_meta_result) {
            throw new \Exception('COULDNT_UPDATE_POST_META');
        }
    }

    return true;
}

function spbc_scanner_file_view($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $spbc, $wpdb;

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT *
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            $file_path = $file_info['status'] == 'QUARANTINED' ? $file_info['q_path'] : $root_path . $file_info['path'];

            if (file_exists($file_path)) {
                if (is_readable($file_path)) {
                    // Getting file && API call
                    $file = file($file_path);

                    if ($file !== false && count($file)) {
                        $file_text = array();
                        for ($i = 0; isset($file[ $i ]); $i++) {
                            $file_text[ $i + 1 ] = htmlspecialchars($file[ $i ]);
                            $file_text[ $i + 1 ] = preg_replace("/[^\S]{4}/", "&nbsp;", $file_text[ $i + 1 ]);
                        }

                        if ( ! empty($file_text)) {
                            $output = array(
                                'success'    => true,
                                'file'       => $file_text,
                                'file_path'  => $file_path,
                                'difference' => $file_info['difference'],
                                'weak_spots' => $file_info['weak_spots']
                            );
                        } else {
                            $output = array('error' => 'FILE_TEXT_EMPTY');
                        }
                    } else {
                        $output = array('error' => 'FILE_EMPTY');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_READABLE');
                }
            } else {
                $output = array('error' => 'File not exists and will be removed from log through next scan.');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_file_compare($direct_call = false, $file_id = null, $_platform = 'wordpress')
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $wpdb, $wp_version;

    $_cms_version = $wp_version;
    $root_path    = spbc_get_root_path();

    $file_id = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT path, source_type, source, version, status, severity, weak_spots, difference
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_readable($root_path . $file_info['path'])) {
                    // Getting file && API call
                    $file = file($root_path . $file_info['path']);

                    if ($file !== false && count($file)) {
                        $file_text = array();
                        for ($i = 0; isset($file[ $i ]); $i++) {
                            $file_text[ $i + 1 ] = htmlspecialchars($file[ $i ]);
                            $file_text[ $i + 1 ] = preg_replace("/[^\S]{4}/", "&nbsp;", $file_text[ $i + 1 ]);
                        }
                        if ( ! empty($file_text)) {
                            $file_original = Scanner\Helper::getOriginalFile($file_info);

                            if ( $file_original && is_string($file_original) ) {
                                $file_original = explode("\n", $file_original);
                                for ($i = 0; isset($file_original[ $i ]); $i++) {
                                    $file_original_text[ $i + 1 ] = htmlspecialchars($file_original[ $i ]);
                                    $file_original_text[ $i + 1 ] = preg_replace("/[^\S]{4}/", "&nbsp;", $file_original_text[ $i + 1 ]);
                                }
                                if ( ! empty($file_original_text)) {
                                    $output = array(
                                        'success'       => true,
                                        'file'          => $file_text,
                                        'file_original' => $file_original_text,
                                        'file_path'     => $root_path . $file_info['path'],
                                        // 'weak_spots'    => $file_info['weak_spots'],
                                        'difference'    => Scanner\Helper::getDifferenceFromOriginal($root_path, $file_info, $file_original)
                                    );
                                } else {
                                    $output = array('error' => 'FILE_ORIGINAL_TEXT_EMPTY');
                                }
                            } else {
                                $output = array('error' => 'GET_FILE_REMOTE_FAILED');
                            }
                        } else {
                            $output = array('error' => 'FILE_TEXT_EMPTY');
                        }
                    } else {
                        $output = array('error' => 'FILE_EMPTY');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_READABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_file_replace($direct_call = false, $file_id = null, $_platform = 'wordpress')
{
    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $wpdb;

    $root_path = spbc_get_root_path();

    $file_id = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT path, source_type, source, version, status, severity, source_type
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_writable($root_path . $file_info['path'])) {
                    // Getting file && API call
                    $original_file = Scanner\Helper::getOriginalFile($file_info);

                    if ($original_file && !isset($original_file['error'])) {
                        $file_desc = fopen($root_path . $file_info['path'], 'w');
                        if ($file_desc && is_string($original_file)) {
                            $res_fwrite = fwrite($file_desc, $original_file);
                            if ($res_fwrite) {
                                fclose($file_desc);

                                $db_result = $wpdb->query(
                                    'DELETE FROM ' . SPBC_TBL_SCAN_FILES
                                    . ' WHERE fast_hash = "' . $file_id . '";'
                                );

                                if ($db_result) {
                                    $output = array('success' => true,);
                                } else {
                                    $output = array('error' => 'FILE_DB_DELETE_FAIL');
                                }
                            } else {
                                $output = array('error' => 'FILE_COULDNT_WRITE');
                            }
                        } else {
                            $output = array('error' => 'FILE_COULDNT_OPEN');
                        }
                    } else {
                        $output = array('error' => 'GET_FILE_FAILED');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_WRITABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    $exec_time           = round(microtime(true) - $time_start);
    $output['exec_time'] = $exec_time;

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_file_quarantine($direct_call = false, $file_id = null)
{
    global $wpdb, $spbc;

    if ( ! $direct_call ) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    if ( $spbc->data['license_trial'] == 1 ) {
        wp_send_json(['error' => spbc_get_trial_restriction_notice(), 'hide_support_link' => '1']);
    }

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT *
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_writable($root_path . $file_info['path'])) {
                    $q_path = SPBC_PLUGIN_DIR . 'quarantine/'
                              . str_replace('/', '__', str_replace('\\', '__', $file_info['path'])) . '___'
                              . md5($file_info['path'] . rand(0, 99999999)) . '.punished';

                    $dir_name = SPBC_PLUGIN_DIR . 'quarantine/';
                    if ( ! is_dir($dir_name)) {
                        mkdir($dir_name);
                        file_put_contents($dir_name . 'index.php', '<?php');
                    }
                    if (copy($root_path . $file_info['path'], $q_path)) {
                        $result = $wpdb->update(
                            SPBC_TBL_SCAN_FILES,
                            array(
                                'status'         => 'QUARANTINED',
                                'q_path'         => $q_path,
                                //should be offset to use in date()
                                'q_time'         => current_time('timestamp'),
                                'previous_state' => json_encode(array(
                                    'status' => $file_info['status'],
                                )),
                            ),
                            array('full_hash' => $file_info['full_hash'], 'fast_hash' => $file_info['fast_hash']),
                            array('%s', '%s', '%d', '%s'),
                            array('%s', '%s')
                        );
                        if ($result !== false && $result > 0) {
                            if (unlink($root_path . $file_info['path'])) {
                                $response_content       = HTTP::getContentFromURL(get_option('home'));
                                $response_content_admin = HTTP::getContentFromURL(get_option('home') . '/wp-admin/');
                                if (
                                    isset(
                                        $response_content['error'],
                                        $response_content_admin['error']
                                    ) ||
                                    spbc_search_page_errors($response_content) ||
                                    spbc_search_page_errors($response_content_admin)
                                ) {
                                    $output          = array('error' => 'WEBSITE_RESPONSE_BAD');
                                    $result          = spbc_scanner_file_quarantine__restore(true, $file_info['fast_hash']);
                                    $output['error'] .= ! empty($result['error']) ? ' REVERT_FAILED ' . $result['error'] : ' REVERT_OK';
                                } else {
                                    $output = array('success' => true,);
                                }
                            } else {
                                $output = array('error' => 'DELETE_FAILED');
                            }
                        } else {
                            $output = array('error' => 'UPDATE_TABLE_FAILED');
                        }
                    } else {
                        $output = array('error' => 'COPY_FAILED');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_WRITABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    if ($direct_call) {
        return spbc_humanize_output($output);
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_file_quarantine__restore($direct_call = false, $file_id = null)
{
    global $wpdb;

    if ( ! $direct_call) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT *
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($file_info['q_path'])) {
                if (is_writable($file_info['q_path'])) {
                    if (copy($file_info['q_path'], $root_path . $file_info['path'])) {
                        $previous = json_decode($file_info['previous_state'], true);

                        $result = $wpdb->update(
                            SPBC_TBL_SCAN_FILES,
                            array(
                                'status' => $previous['status'],
                                'q_path' => null,
                                'q_time' => null,
                            ),
                            array('fast_hash' => $file_info['fast_hash']),
                            array('%s', '%s', '%d',),
                            array('%s')
                        );
                        if ($result !== false && $result > 0) {
                            if (unlink($file_info['q_path'])) {
                                $output = array('success' => true,);
                            } else {
                                $output = array('error' => 'DELETE_FAILED');
                            }
                        } else {
                            $output = array('error' => 'UPDATE_TABLE_FAILED');
                        }
                    } else {
                        $output = array('error' => 'COPY_FAILED');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_WRITABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

function spbc_scanner_file_download($direct_call = false, $file_id = null)
{
    global $wpdb;

    $file_id = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT *
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);

        $file_info = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($file_info['q_path'])) {
                if (is_readable($file_info['q_path'])) {
                    // Getting file && API call
                    $file_path = substr($file_info['q_path'], stripos($file_info['q_path'], 'wp-content'));
                    $file_content      = HTTP::getContentFromURL(get_home_url() . '/' . $file_path);

                    if (empty($file_content['error'])) {
                        $output = array(
                            'file_name'    => preg_replace('/.*(\/|\\\\)(.*)/', '$2', $file_info['path']),
                            'file_content' => $file_content,
                        );
                    } else {
                        $output = array('error' => 'FILE_EMPTY');
                    }
                } else {
                    $output = array('error' => 'FILE_NOT_READABLE');
                }
            } else {
                $output = array('error' => 'FILE_NOT_EXISTS');
            }
        } else {
            $output = array('error' => 'FILE_NOT_FOUND');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    if ($direct_call) {
        return $output;
    } else {
        wp_send_json($output);
    }
}

/**
 * Delete file from analysis log
 */
function spbc_scanner_analysis_log_delete_from_log($direct_call = false)
{
    // Check ajax nonce
    if ( ! $direct_call ) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $wpdb;

    $file_ids = Post::get('file_ids');
    $file_ids_clean = [];

    if ( is_array($file_ids) ) {
        // Validate if the ID is hash (SQL-clear)
        $file_ids_clean = array_map(function ($_id) {
            if ( \CleantalkSP\Common\Validate::isHash($_id) ) {
                return $_id;
            }
        }, $file_ids);
    }

    $output = array('error' => false);

    if ( $file_ids_clean ) {
        $file_ids_string = '';
        foreach ( $file_ids_clean as $id ) {
            $file_ids_string .= '"' . $id . '",';
        }
        $query = "UPDATE " . SPBC_TBL_SCAN_FILES . " SET 
            last_sent = null,
            pscan_status = null,
            pscan_processing_status = null,
            pscan_pending_queue = null,
            pscan_balls = null,
            pscan_file_id = null 
            WHERE fast_hash IN (" . trim($file_ids_string, ',') . ")";
        $updated_rows = $wpdb->query($query);

        if ( ! $updated_rows) {
            $output = array('error' => 'DB_ERROR');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    if ( ! $direct_call ) {
        wp_send_json($output);
    }

    return $output;
}

/**
 * Replacing error codes by readable and translatable format.
 * We have to add new error descriptions here future.
 *
 * @param $output_array
 *
 * @return array
 */
function spbc_humanize_output($output_array)
{
    if (is_array($output_array) && array_key_exists('error', $output_array)) {
        $errors_codes = array(
            'WEBSITE_RESPONSE_BAD',
            'REVERT_OK'
        );
        $errors_texts = array(
            esc_html__('The requested action caused a website error.', 'security-malware-firewall'),
            // WEBSITE_RESPONSE_BAD
            esc_html__('The changes were reverted.', 'security-malware-firewall'),
            // REVERT_OK
        );
        foreach ($output_array as $key => $item) {
            $output_array[ $key ] = str_replace($errors_codes, $errors_texts, $item);
        }
    }

    return $output_array;
}

function spbc_scanner_get_file_by_id($file_id)
{

    global $wpdb;

    $file_info = $wpdb->get_row(
        'SELECT *
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1',
        ARRAY_A
    );

    return $file_info ?: false;
}

/**
 * Save scanner logs to pdf
 *
 * @param $direct_call
 *
 * @return array|void
 */
function spbc_scanner_save_to_pdf($direct_call = false)
{
    if ( !$direct_call ) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $pdf = new Pdf();

    $pdf->AliasNbPages();

    $pdf->AddPage();

    $pdf->drawScanCommonStatsTable();

    $pdf->Ln();

    $pdf->drawScanResultsOfScanType('heuristic_results');
    $pdf->drawScanResultsOfScanType('signature_results');

    $pdf->Ln();

    $pdf->drawFilesListByType('cure_log');

    $pdf->AddPage();

    $pdf->drawFilesListByType('critical_files');

    $pdf->AddPage();

    $pdf->drawFilesListByType('suspicious_files');

    $pdf->Output();
}

function spbc_scanner_get_pdf_file_name($direct_call = false)
{

    if ( !$direct_call ) {
        spbc_check_ajax_referer('spbc_secret_nonce', 'security');
    }

    global $spbc;
    wp_send_json_success('spbct-mscan-'
        . preg_replace('/^http(s)?:\/\//', '', site_url())
        . '-'
        . date('M-d-Y', $spbc->data['scanner']['last_scan'])
        . '.pdf');
}

function spbc_file_cure_ajax_action()
{
    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    $file_fast_hash = isset($_POST['file_fast_hash']) ? esc_sql($_POST['file_fast_hash']) : null;

    $result = spbc_cure_file($file_fast_hash);

    if (is_wp_error($result)) {
        wp_send_json_error($result->get_error_message());
    }

    wp_send_json_success($result);
}

/**
 * AJAX handler for cure action.
 * @param string $file_fast_hash
 * @return string|WP_Error
 */
function spbc_cure_file($file_fast_hash)
{
    global $wpdb;

    if (is_null($file_fast_hash)) {
        return new WP_Error(
            '422',
            esc_html__('Error: File not found.', 'security-malware-firewall')
        );
    }

    $file_data = $wpdb->get_row(
        'SELECT * '
        . ' FROM ' . SPBC_TBL_SCAN_FILES
        . ' WHERE fast_hash="' . $file_fast_hash . '";',
        ARRAY_A
    );

    if (empty($file_data)) {
        return new WP_Error(
            '422',
            esc_html__('Error: File not found in table.', 'security-malware-firewall')
        );
    }

    $cure_log = new CureLog();

    $cure_stage = new CureStage(DB::getInstance());
    $cure_log_record = $cure_stage->processCure($file_data);

    $cure_log->logCureResult($cure_log_record);

    if ( !empty($cure_log_record->fail_reason) ) {
        return new WP_Error(
            '422',
            esc_html__('Error: ' . $cure_log_record->fail_reason, 'security-malware-firewall')
        );
    }

    return esc_html__('Success!', 'security-malware-firewall');
}

function spbc_restore_file_from_backup_ajax_action()
{
    global $wpdb;

    spbc_check_ajax_referer('spbc_secret_nonce', 'security');

    $file_fast_hash = isset($_POST['file_fast_hash']) ? esc_sql($_POST['file_fast_hash']) : null;

    if (is_null($file_fast_hash)) {
        wp_send_json_error(esc_html__('Error: File not found.', 'security-malware-firewall'));
    }

    // Getting file path
    $file_path = $wpdb->get_row(
        'SELECT path '
        . ' FROM ' . SPBC_TBL_SCAN_FILES
        . ' WHERE fast_hash="' . $file_fast_hash . '";',
        ARRAY_A
    );

    if (is_null($file_path)) {
        wp_send_json_error(esc_html__('Error: File path not found.', 'security-malware-firewall'));
    }

    $file_path = $file_path['path'];
    $full_file_path = ABSPATH . ltrim($file_path, '\\');

    // Getting backup path
    $sql_prepared = $wpdb->prepare(
        'SELECT back_path '
        . ' FROM ' . SPBC_TBL_BACKUPED_FILES
        . ' WHERE real_path="%s"'
        . ' ORDER BY backup_id DESC LIMIT 1;',
        $file_path
    );
    $backup_path = $wpdb->get_row($sql_prepared, ARRAY_A);

    if (is_null($backup_path)) {
        wp_send_json_error(esc_html__('Error: Backup not found.', 'security-malware-firewall'));
    }

    $backup_path = $backup_path['back_path'];
    $full_backup_path = ABSPATH . ltrim($backup_path, '/');

    // Trying to replace backup and original file
    $backup_content = file_get_contents($full_backup_path);

    if ($backup_content === false) {
        wp_send_json_error(esc_html__('Error: File not exists or permissions denied.', 'security-malware-firewall'));
    }

    if (file_exists($full_file_path)) {
        $result = file_put_contents($full_file_path, $backup_content);

        if ($result === false) {
            wp_send_json_error(esc_html__('Error: Permissions denied.', 'security-malware-firewall'));
        }

        // Success: remove all data about backup
        try {
            $backup_deleted = unlink($full_backup_path);

            if ($backup_deleted === false) {
                wp_send_json_error(esc_html__('Error: Permissions denied.', 'security-malware-firewall'));
            }

            // Remove from backup
            $sql_prepared = $wpdb->prepare(
                'DELETE '
                . ' FROM ' . SPBC_TBL_BACKUPED_FILES
                . ' WHERE real_path="%s";',
                $file_path
            );
            $delete = $wpdb->query($sql_prepared);

            if (is_null($delete)) {
                wp_send_json_error(esc_html__('Error: Something is wrong.', 'security-malware-firewall'));
            }

            // Remove from cure log
            $sql_prepared = $wpdb->prepare(
                'DELETE '
                . ' FROM ' . SPBC_TBL_CURE_LOG
                . ' WHERE real_path="%s";',
                $file_path
            );
            $delete = $wpdb->query($sql_prepared);

            if (is_null($delete)) {
                wp_send_json_error(esc_html__('Error: Something is wrong.', 'security-malware-firewall'));
            }
        } catch (\Exception $e) {
            wp_send_json_error(esc_html__('Error: Something is wrong.', 'security-malware-firewall'));
        }
    } else {
        wp_send_json_error(esc_html__('Error: Original file not exists.', 'security-malware-firewall'));
    }

    wp_send_json_success(esc_html__('Success!', 'security-malware-firewall'));
}

/**
 * @param $paths array
 *
 * @return array
 */
function spbc__get_exists_directories($paths)
{
    $exists_dirs = array();

    foreach ($paths as $path) {
        if (is_dir(ABSPATH . $path)) {
            $exists_dirs[] = $path;
        }
    }

    return $exists_dirs;
}

function spbc_get_trial_restriction_notice()
{
    global $spbc;

    $html = '<h2>' . esc_html__('Just one step before remove malware', 'security-malware-firewall') . '</h2>';
    $html .= esc_html__('Please upgrade your account to premium Security license to Cure, Approve, Remove and Quarantine viruses and malware. As well as using 1600+ viruses signatures by now.', 'security-malware-firewall');
    $html .= linkConstructor::buildRenewalLinkATag(
        $spbc->user_token,
        '<button class="button button-primary">' . esc_html__('UPGRADE', 'security-malware-firewall') . '<i class="spbc-icon-link-ext"></i></button>',
        4,
        'trial_restriction_notice_upgrade_button'
    );
    return $html;
}

/**
 * Get JSON string of accordion row actions that do not need to be confirmed.
 * @return string
 */
function spbc_get_no_confirm_row_actions()
{
    global $spbc;
    // by defaults
    $actions = array (
        'defaults' => array(
            'copy_file_info',
            'check_analysis_status',
        ),
        'restricted' => array(),
    );
    // if license is trial
    if ($spbc->data['license_trial']) {
        $actions['restricted'][] = 'delete';
        $actions['restricted'][] = 'quarantine';
        $actions['restricted'][] = 'approve';
    }

    $actions['any'] = array_merge($actions['restricted'], $actions['defaults']);

    $actions = json_encode($actions);
    return is_string($actions) ? $actions : '{[]}';
}
