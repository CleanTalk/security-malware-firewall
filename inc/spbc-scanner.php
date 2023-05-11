<?php

use CleantalkSP\SpbctWP\Helper as SpbcHelper;
use CleantalkSP\SpbctWP\API as SpbcAPI;
use CleantalkSP\SpbctWP\Helpers\CSV;
use CleantalkSP\SpbctWP\Scanner\FrontendScan;
use CleantalkSP\Variables\Get;
use CleantalkSP\Variables\Post;
use CleantalkSP\Variables\Request;
use CleantalkSP\SpbctWP\Scanner\Cure;
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
        'extensions'      => 'php, html, htm',
        'files_mandatory' => array(),
        'dir_exceptions'  => array(SPBC_PLUGIN_DIR . 'quarantine')
    );
    if ( ! empty($spbc->settings['scanner__dir_exclusions'])) {
        $init_params['dir_exceptions'] = array_merge($init_params['dir_exceptions'], explode("\n", $spbc->settings['scanner__dir_exclusions']));
    }

    $scaner = new Scanner\Surface($path_to_scan, $root_path, $init_params);

    $output = array(
        'total'     => $scaner->files_count,
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
        'SELECT COUNT(link_id) AS cnt FROM ' . SPBC_TBL_SCAN_LINKS,
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
        'SELECT domain, spam_active, page_url, COUNT(domain) as link_count
				FROM ' . SPBC_TBL_SCAN_LINKS . ' 
			GROUP BY domain
			' . ($order && $by ? "ORDER BY $by $order" : '') . '
			LIMIT ' . $offset . ',' . $amount . ';',
        $get_array === true ? ARRAY_A : OBJECT
    );

    return $data;
}

function spbc_scanner_file_send($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
        $file_id = preg_match('@[a-zA-Z0-9]{32}@', Post::get('file_id')) ? Post::get('file_id') : null;
    }

    global $spbc, $wpdb;

    $root_path = spbc_get_root_path();

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT fast_hash, path, source_type, source, source_status, version, mtime, weak_spots, full_hash, real_full_hash, status, checked_signatures, checked_heuristic
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ($file_info['status'] === 'APPROVED_BY_CT' || $file_info['status'] === 'APPROVED_BY_CLOUD') {
            $output = array('error' => 'IT_IS_IMPOSIBLE_RESEND_APPROVED_FILE');
            if ( !$direct_call ) {
                wp_send_json($output);
            }
            return $output;
        }

        // Scan file before send it
        // Heuristic
        $result_heur = Scanner\Controller::scanFileForHeuristic($file_info, $root_path);
        if ( ! empty($result_heur['error'])) {
            $output = array('error' => 'RESCANNING_FAILED');
            if ( !$direct_call ) {
                wp_send_json($output);
            }
            return $output;
        }
        // Signature
        $signatures  = $wpdb->get_results('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES, ARRAY_A);
        $result_sign = Scanner\Controller::scanFileForSignatures($file_info, $root_path, $signatures);
        if ( ! empty($result_sign['error'])) {
            $output = array('error' => 'RESCANNING_FAILED');
            if ( !$direct_call ) {
                wp_send_json($output);
            }
            return $output;
        }

        $api_response = Arr::mergeWithSavingNumericKeysRecursive($result_sign, $result_heur);

        $wpdb->update(
            SPBC_TBL_SCAN_FILES,
            array(
                'checked_signatures' => $file_info['checked_signatures'],
                'checked_heuristic'  => $file_info['checked_heuristic'],
                'status'             => $file_info['status'] === 'MODIFIED' ? 'MODIFIED' : $api_response['status'],
                'severity'           => $api_response['severity'],
                'weak_spots'         => json_encode($api_response['weak_spots']),
                'full_hash'          => md5_file($root_path . $file_info['path']),
            ),
            array('fast_hash' => $file_info['fast_hash']),
            array('%s', '%s', '%s', '%s', '%s', '%s'),
            array('%s')
        );
        $file_info['weak_spots'] = $api_response['weak_spots'];
        $file_info['full_hash']  = md5_file($root_path . $file_info['path']);

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_readable($root_path . $file_info['path'])) {
                    if (filesize($root_path . $file_info['path']) > 0) {
                        if (filesize($root_path . $file_info['path']) < 1048570) {
                            // Updating file_info if file source is unknown
                            if ( ! isset($file_info['version'], $file_info['source'], $file_info['source_type'])) {
                                $file_info_updated = spbc_get_source_info_of($file_info['path']);
                                if ($file_info_updated) {
                                    $file_info = array_merge($file_info, $file_info_updated);
                                }
                            }

                            // Getting file && API call
                            $file   = file_get_contents($root_path . $file_info['path']);

                            try {
                                $dto = new DTO\MScanFilesDTO(
                                    array(
                                        'path_to_sfile' => $file_info['path'],
                                        'attached_sfile' => $file,
                                        'md5sum_sfile' => $file_info['full_hash'],
                                        'dangerous_code' => $file_info['weak_spots'],
                                        'version' => $file_info['version'],
                                        'source' => $file_info['source'],
                                        'source_type' => $file_info['source_type'],
                                        'source_status' => $file_info['source_status'],
                                        'real_hash' => $file_info['real_full_hash'],
                                    )
                                );
                            } catch ( \InvalidArgumentException $e ) {
                                return array('error' => "File can not be send. Error: \n" . substr($e->getMessage(), 0, 100));
                            }

                            $api_response = SpbcAPI::method__security_pscan_files_send($spbc->settings['spbc_key'], $dto);

                            if (empty($api_response['error'])) {
                                if ($api_response['file_id']) {
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
                                    if ($sql_result !== false) {
                                        $output = array('success' => true, 'result' => $api_response);
                                        //set new cron to update statuses
                                        \CleantalkSP\SpbctWP\Cron::updateTask(
                                            'scanner_update_pscan_files_status',
                                            'spbc_scanner_update_pscan_files_status',
                                            SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD,
                                            time() + SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD
                                        );
                                    //error on fail
                                    } else {
                                        $output = array('error' => 'DB_COULDNT_UPDATE pscan_processing_status');
                                    }
                                } else {
                                    $output = array('error' => 'API_RESPONSE: file_id is NULL');
                                }
                            } else {
                                if ($api_response['error'] === 'QUEUE_FULL') {
                                    //do something with not queued files
                                    $sql_result = $wpdb->query(
                                        'UPDATE ' . SPBC_TBL_SCAN_FILES
                                        . ' SET'
                                        . ' last_sent = ' . current_time('timestamp') . ','
                                        . ' pscan_pending_queue = 1'
                                        . ' WHERE fast_hash = "' . $file_id . '"'
                                    );
                                    if ($sql_result !== false) {
                                        $output = array('success' => true, 'result' => $api_response);
                                        //set new cron to resend unqueued files
                                        \CleantalkSP\SpbctWP\Cron::updateTask('scanner_resend_pscan_files', 'spbc_scanner_resend_pscan_files', SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD, time() + SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD);
                                    //error on fail
                                    } else {
                                        $output = array('error' => 'DB_COULD_NOT_UPDATE pscan_pending_queue');
                                    }
                                } else {
                                    //out API error if error is not queue_full
                                    $output = $api_response;
                                }
                            }
                        } else {
                            $output = array('error' => 'FILE_SIZE_TO_LARGE');
                        }
                    } else {
                        $output = array('error' => 'FILE_SIZE_ZERO');
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

    if ( !$direct_call ) {
        wp_send_json($output);
    }

    return $output;
}

function spbc_scanner_file_delete($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
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
                    // Getting file && API call
                    $remembered_file_content = file_get_contents($file_path);
                    $result                  = unlink($file_path);
                    if ($result) {
                        $response_content       = HTTP::getContentFromURL(get_option('home'));
                        $response_content_admin = HTTP::getContentFromURL(get_option('home') . '/wp-admin/');
                        $response_code          = HTTP::getResponseCode(get_option('home'));
                        $response_code_admin    = HTTP::getResponseCode(get_option('home') . '/wp-admin/');
                        if (
                            isset(
                                $response_content['error'],
                                $response_content_admin['error'],
                                $response_code['error'],
                                $response_code_admin['error']
                            ) ||
                            (is_string($response_code) && preg_match('/5\d\d/', $response_code)) ||
                            (is_string($response_code_admin) && preg_match('/5\d\d/', $response_code_admin)) ||
                            spbc_search_page_errors($response_content) ||
                            spbc_search_page_errors($response_content_admin)
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

function spbc_scanner_file_approve($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $spbc, $wpdb;

    $root_path = spbc_get_root_path();
    $file_id   = $direct_call
        ? $file_id
        : Post::get('file_id', 'hash');

    if ($file_id) {
        // Getting file info.
        $sql        = 'SELECT path, full_hash, status, severity
			FROM ' . SPBC_TBL_SCAN_FILES . '
			WHERE fast_hash = "' . $file_id . '"
			LIMIT 1';
        $sql_result = $wpdb->get_results($sql, ARRAY_A);
        $file_info  = $sql_result[0];

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_readable($root_path . $file_info['path'])) {
                    // Getting file && API call
                    $md5 = md5_file($root_path . $file_info['path']);

                    if ($md5) {
                        $previous = json_encode(array('status'   => $file_info['status'],
                                                      'severity' => $file_info['severity']
                        ));

                        // Updating all other statuses
                        $wpdb->update(
                            SPBC_TBL_SCAN_FILES,
                            array(
                                'status'         => 'APROVED',
                                'real_full_hash' => $md5,
                                'previous_state' => $previous,
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
                        $output = array('error' => 'FILE_COULDNT_MD5');
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
        check_ajax_referer('spbc_secret_nonce', 'security');
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
            // Set old processing status to compare with next
            $old_processing_status = !empty($file_info['pscan_processing_status']) ? $file_info['pscan_processing_status'] : null;
            // Update processing status
            if ( $api_response['processing_status'] !== $old_processing_status ) {
                // Keep update result
                $update_result = $wpdb->query(
                    'UPDATE ' . SPBC_TBL_SCAN_FILES
                    . ' SET '
                    . ' pscan_pending_queue = 0, '
                    . ' pscan_processing_status  = "' . $api_response['processing_status'] . '"'
                    . ' WHERE pscan_file_id = "' . $file_info['pscan_file_id'] . '"'
                );
            } else {
                // Status have not been changed, however status process is succesfull
                $update_result = true;
            }
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
                    . ' status = "APPROVED_BY_CLOUD" '
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
                    . ' pscan_status  = %s ,'
                    . ' pscan_balls  = %s,'
                    . ' status  = "DENIED_BY_CLOUD"'
                    . ' WHERE pscan_file_id = %s',
                    $api_response['file_status'],
                    $api_response['file_balls'],
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
    if (!empty($file_info['analysis_status'])) {
        throw new Exception('skipped');
    }

    //skip already checked
    if (isset($file_info['pscan_processing_status']) &&
        $file_info['pscan_processing_status'] === 'DONE' &&
        $spbc->settings['spbc_scanner_user_can_force_pscan_update'] !== true
    ) {
        throw new Exception('skipped');
    }

    return $file_info;
}

/**
 * @param array $response API Response
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
        if ( $response['file_status'] === 'DANGEROUS' ) {
            // Check balls set on DANGEROUS file_status
            if ( !isset($response['file_balls']) ) {
                throw new Exception('process finished, but points in unset');
            }
        }
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
    if ( ! $ids) {
        return array('error' => 'Noting to disapprove');
    }

    $out = array();

    foreach ($ids as $id) {
        $result = spbc_scanner_file_disapprove(true, $id);

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

function spbc_scanner_file_send_for_analysis__bulk($fast_hashes_list = array())
{
    if ( ! $fast_hashes_list) {
        return array('error' => 'Record has no file id to send.');
    }

    global $wpdb;

    $sql_result = $wpdb->get_results(
        'SELECT fast_hash FROM ' . SPBC_TBL_SCAN_FILES . '
        WHERE last_sent IS NULL
        AND status NOT IN ("OK","APROVED","APPROVED_BY_CT","APPROVED_BY_CLOUD")',
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
        $out['error'] = 'All the files have been already sent.';
    }

    return $out;
}

function spbc_scanner_get_files_by_category($status)
{
    global $wpdb;

    $ids = array();

    switch ($status) {
        case 'critical':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES . ' WHERE severity = "CRITICAL" AND status <> "QUARANTINED"');
            break;
        case 'suspicious':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES . ' WHERE status = "MODIFIED" AND severity <> "CRITICAL"');
            break;
        case 'unknown':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES . ' WHERE status <> "APROVED" AND source IS NULL AND path NOT LIKE "%wp-content%themes%" AND path NOT LIKE "%wp-content%plugins%" AND (severity <> "CRITICAL" OR severity IS NULL)');
            break;
        case 'approved':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES . ' WHERE status = "APROVED"');
            break;
        case 'analysis_log':
            $res = $wpdb->get_results('SELECT fast_hash from ' . SPBC_TBL_SCAN_FILES . '  WHERE last_sent IS NOT NULL');
            break;
    }

    foreach ($res as $tmp) {
        $ids[] = $tmp->fast_hash;
    }

    return $ids;
}

function spbc_scanner_file_disapprove($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
    }

    $time_start = microtime(true);

    global $spbc, $wpdb;

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

        if ( ! empty($file_info)) {
            if (file_exists($root_path . $file_info['path'])) {
                if (is_readable($root_path . $file_info['path'])) {
                    // Getting file && API call
                    $md5 = md5_file($root_path . $file_info['path']);

                    if ($md5) {
                        $previous = json_decode($file_info['previous_state'], true);

                        $wpdb->update(
                            SPBC_TBL_SCAN_FILES,
                            array(
                                'status'         => $previous['status'],
                                'severity'       => $previous['severity'],
                                'real_full_hash' => $md5,
                            ),
                            array('fast_hash' => $file_id),
                            array('%s', '%s', '%s'),
                            array('%s')
                        );

                        if ($sql_result !== false) {
                            $output = array('success' => true);
                        } else {
                            $output = array('error' => 'DB_COULDNT_UPDATE_ROW_APPROVE');
                        }
                    } else {
                        $output = array('error' => 'FILE_COULDNT_MD5');
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
        check_ajax_referer('spbc_secret_nonce', 'security');
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

        // Getting file info.
        $sql_result = $wpdb->get_results(
            $wpdb->prepare(
                'SELECT weak_spots'
                . ' FROM ' . SPBC_TBL_SCAN_FRONTEND
                . ' WHERE url = %s'
                . ' LIMIT 1',
                $page_url
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

function spbc_scanner_page_approve()
{
    global $wpdb;

    check_ajax_referer('spbc_secret_nonce', 'security');

    $page_url = Post::get('page_url');
    $page_id  = (int) Post::get('page_id');

    if ($page_url && filter_var($page_url, FILTER_VALIDATE_URL)) {
        // Getting file info.
        $sql = 'UPDATE ' . SPBC_TBL_SCAN_FRONTEND . ' SET approved = 1 WHERE url = %s';
        $sql = $wpdb->prepare($sql, $page_url);
        $wpdb->query($sql);
        update_post_meta($page_id, '_spbc_frontend__approved', 1);
    }
}

function spbc_scanner_file_view($direct_call = false, $file_id = null)
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
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

function spbc_scanner_file_compare($direct_call = false, $file_id = null, $_platform = 'wordpress')
{
    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
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
        check_ajax_referer('spbc_secret_nonce', 'security');
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

    if ( ! $direct_call) {
        check_ajax_referer('spbc_secret_nonce', 'security');
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
                    if ( ! is_dir(SPBC_PLUGIN_DIR . 'quarantine/')) {
                        mkdir(SPBC_PLUGIN_DIR . 'quarantine/');
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
                            array('full_hash' => $file_info['full_hash']),
                            array('%s', '%s', '%d', '%s'),
                            array('%s')
                        );
                        if ($result !== false && $result > 0) {
                            if (unlink($root_path . $file_info['path'])) {
                                $response_content       = HTTP::getContentFromURL(get_option('home'));
                                $response_content_admin = HTTP::getContentFromURL(get_option('home') . '/wp-admin/');
                                $response_code          = HTTP::getResponseCode(get_option('home'));
                                $response_code_admin    = HTTP::getResponseCode(get_option('home') . '/wp-admin/');
                                if (
                                    isset(
                                        $response_content['error'],
                                        $response_content_admin['error'],
                                        $response_code['error'],
                                        $response_code_admin['error']
                                    ) ||
                                    (is_string($response_code) && preg_match('/5\d\d/', $response_code)) ||
                                    (is_string($response_code_admin) && preg_match('/5\d\d/', $response_code_admin)) ||
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
        check_ajax_referer('spbc_secret_nonce', 'security');
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
                    $file      = HTTP::getContentFromURL(get_home_url() . '/' . $file_path);

                    if ($file !== false) {
                        $output = array(
                            'file_name'    => preg_replace('/.*(\/|\\\\)(.*)/', '$2', $file_info['path']),
                            'file_content' => $file,
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
function spbc_scanner_analysis_log_delete_from_log()
{
    check_ajax_referer('spbc_secret_nonce', 'security');

    global $wpdb;

    $file_id = Post::get('file_id', 'hash');

    $output = array('error' => false);

    if ($file_id) {
        $updated_rows = $wpdb->update(
            SPBC_TBL_SCAN_FILES,
            array(
                'last_sent' => null,
                'pscan_status' => null,
                'pscan_processing_status' => null,
                'pscan_pending_queue' => null,
                'pscan_balls' => null,
                'pscan_file_id' => null,
            ),
            array(
                'fast_hash' => $file_id
            )
        );

        if ( ! $updated_rows) {
            $output = array('error' => 'DB_ERROR');
        }
    } else {
        $output = array('error' => 'WRONG_FILE_ID');
    }

    wp_send_json($output);
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

    $pdf->AddPage();

    $pdf->drawFilesListByType('critical_files');

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
