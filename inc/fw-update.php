<?php

use CleantalkSP\Common\DNS;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Firewall\FW;
use CleantalkSP\SpbctWP\Cron;
use CleantalkSP\SpbctWP\Queue;
use CleantalkSP\Variables\Request;
use CleantalkSP\SpbctWP\RemoteCalls;
use CleantalkSP\SpbctWP\Helpers\Data;

/**
 * Called by update_security_firewall remote call
 * Starts the Security Firewall update and could use a delay before start
 *
 * @param int $delay
 *
 * @return bool|string|string[]|array[]
 * @throws Exception
 * @psalm-suppress NullArgument
 */
function spbc_security_firewall_update__init($delay = null)
{
    global $spbc;

    sleep((int)$delay);

    // Prevent start an update if update is already running and started less than 2 minutes ago
    if (
        $spbc->fw_stats['updating_id'] &&
        spbc_security_firewall_update__is_in_progress() &&
        time() - $spbc->fw_stats['updating_last_start'] < 120
    ) {
        return true;
    }

    if ( ! $spbc->api_key ) {
        return array( 'error' => 'FW UPDATE INIT: KEY_EMPTY' );
    }

    if ( ! $spbc->key_is_ok ) {
        return array( 'error' => 'FW UPDATE INIT: KEY_IS_NOT_VALID' );
    }

    // Delete temporary tables
    FW::dataTablesDeleteTemporary(DB::getInstance(), array(
        SPBC_TBL_FIREWALL_DATA,
        SPBC_TBL_FIREWALL_DATA__IPS,
        SPBC_TBL_FIREWALL_DATA__COUNTRIES,
    ));

    $wp_upload_dir = wp_upload_dir();
    $spbc->fw_stats['updating_folder'] = $wp_upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'fw_files_for_blog_' . get_current_blog_id() . DIRECTORY_SEPARATOR;

    // Set a new update ID and an update time start
    $spbc->fw_stats['update_percent'] = 5;
    $spbc->fw_stats['calls']          = 0;
    $spbc->fw_stats['updating_id']    = md5((string) mt_rand(0, 100000));
    $spbc->fw_stats['updating_last_start'] = time();
    $spbc->save('fw_stats', true, false);

    // Delete update errors
    $spbc->error_delete('firewall_update', true);
    $spbc->error_delete('firewall_update', 'save_data', 'cron');

    $prepare_dir__result = spbc_security_firewall_update__prepare_upd_dir();
    $home_url = is_multisite() ? get_blog_option(null, 'home') : get_option('home');
    $test_rc_result = RemoteCalls::performTest(
        $home_url,
        array(
            'spbc_remote_call_token'  => md5($spbc->api_key),
            'spbc_remote_call_action' => 'update_security_firewall__worker',
            'plugin_name'             => 'security',
        )
    );

    // Make a direct update if folder creation or test RC fail
    if ( ! empty($prepare_dir__result['error']) || ! empty($test_rc_result['error'])) {
        return spbc_security_firewall_update_direct();
    }

    $queue = new Queue('fw_update', 'update_security_firewall__worker');
    $queue->clearQueue();
    $queue->addStage('spbc_security_firewall_update__get_multifiles');

    Cron::addTask('fw_update_checker', 'spbc_security_firewall_update__checker', 5, time() + 30);

    $result = RemoteCalls::performToHost(
        'update_security_firewall__worker',
        array( 'updating_id' => $spbc->fw_stats['updating_id'], ),
        array( 'async' )
    );

    return ( ! empty($result['error']) && $queue->isQueueFinished() ) ? $result : true;
}

/**
 * Updating Security FireWall data
 *
 * @param bool $checker_work flag indicates that the function were called by checker cron task
 *
 * @return array|bool|array[]|string[]
 */
function spbc_security_firewall_update__worker($checker_work = null)
{
    global $spbc;

    if ( ! $spbc->key_is_ok ) {
        return array( 'error' => 'KEY_IS_NOT_VALID' );
    }

    // Check if the update performs right now. Blocks remote calls with different ID
    // This was done to make sure that we won't have multiple updates at a time

    if ( ! $checker_work ) {
        if (
            Request::equal('updating_id', '')
            || ! Request::equal('updating_id', $spbc->fw_stats['updating_id'])
        ) {
            return array( 'error' => 'FW UPDATE WORKER: WRONG_UPDATE_ID' );
        }
    }

    $spbc->fw_stats['calls']++;
    $spbc->save('fw_stats', true, false);

    if ( $spbc->fw_stats['calls'] > 600 ) {
        $spbc->error_add('firewall_update', 'WORKER_CALL_LIMIT_EXCEEDED');
        $spbc->save('errors');
        return array( 'error' => 'WORKER_CALL_LIMIT_EXCEEDED' );
    }

    // Queue is already empty. Exit.
    $queue = new Queue('fw_update', 'update_security_firewall__worker');
    if ( $queue->isQueueFinished() ) {
        return true;
    }

    $result = $queue->executeStage();

    if ( $result === null ) {
        // The stage is in progress, will try to wait up to 5 seconds to its complete
        for ( $i = 0; $i < 5; $i++ ) {
            sleep(1);
            $queue->refreshQueue();
            if ( ! $queue->isQueueInProgress() ) {
                // The stage executed, break waiting and continue sfw_update__worker process
                break;
            }
            if ( $i >= 4 ) {
                // The stage still not executed, exit from sfw_update__worker
                return true;
            }
        }
    }

    if ( isset($result['error']) ) {
        $spbc->error_add('firewall_update', $result['error']);
        $spbc->save('errors');

        return array('error' => $result['error']);
    }

    if ( $queue->isQueueFinished() ) {
        $queue->queue['finished'] = time();
        $queue->saveQueue();

        if ( array_column($queue->queue['stages'], 'error') ) {
            $spbc->error_add('firewall_update', current(array_column($queue->queue['stages'], 'error')));
        }

        return true;
    }

    // This is the repeat stage request, do not generate any new RC
    if ( stripos(Request::get('stage'), 'Repeat') !== false ) {
        return true;
    }

    $result = RemoteCalls::performToHost(
        'update_security_firewall__worker',
        array( 'updating_id' => $spbc->fw_stats['updating_id'] ),
        array( 'async' )
    );

    return ! empty($result['error']) && $queue->isQueueFinished() ? $result : true;
}

/**
 * Get updating multifiles hashes.
 * @param array $result Optional. firewallUpdateGetMultifiles result, if empty the function
 * will run new firewallUpdateGetMultifiles to get result.
 * @return array of hashes
 */
function spbc_security_firewall_update_get_update_files_hashes($result = array())
{
    global $spbc;
    $file_hashes = array();

    if ( empty($result) ) {
        $result = FW::firewallUpdateGetMultifiles($spbc->api_key);
    }
    // Create array with urls
    if ( empty($result['error']) && isset($result['file_urls']) ) {
        foreach ( $result['file_urls'] as $file_url_info ) {
            $file_hashes[] = isset($file_url_info[1]) ? $file_url_info[1] : '';
        }
    }

    return $file_hashes;
}

/**
 * @return array[]|string[]
 */
function spbc_security_firewall_update__get_multifiles()
{

    global $spbc;

    if ( $spbc->key_is_ok ) {
        $result = FW::firewallUpdateGetMultifiles($spbc->api_key);

        if ( empty($result['error']) ) {
            $tries_for_download_again         = 3 + (int)(count($result['file_urls']) / 20);
            $spbc->fw_stats['files_count']    = count($result['file_urls']);
            $spbc->fw_stats['update_percent'] = 10;
            $file_urls = array();

            $spbc->save('fw_stats', true, false);

            // Create array with urls
            foreach ($result['file_urls'] as $file_url_info) {
                $file_urls[] = isset($file_url_info[0]) ? $file_url_info[0] : '';
            }

            // Save info about urls and hashes
            $spbc->data['secfw_data_files_info'] = spbc_security_firewall_update_get_update_files_hashes($result);
            $spbc->save('data');

            return array(
                'next_stage' => array(
                    'name'    => 'spbc_security_firewall_update__download_files',
                    'args'    => $file_urls,
                    'accepted_tries' => $tries_for_download_again
                )
            );
        }

        return array('error' => 'GET MULTIFILE: ' . $result['error']);
    }

    return array('error' => 'FW UPDATE PREPARE: KEY_IS_NOT_VALID');
}

function spbc_security_firewall_update__download_files($urls)
{

    global $spbc;

    sleep(3);

    // Split URLs
    $urls_to_download_next_time = array_slice($urls, 20);
    $urls_to_download_right_now    = array_slice($urls, 0, 20);

    $http    = new CleantalkSP\Common\HTTP\Request();
    $results = $http
        ->setUrl($urls_to_download_right_now)
        ->setPresets('get')
        ->addCallback(
            static function ($content, $url) use ($spbc) {
                if ( is_dir($spbc->fw_stats['updating_folder']) && is_writable($spbc->fw_stats['updating_folder'])) {
                    return file_put_contents($spbc->fw_stats['updating_folder'] . Data::getFilenameFromUrl($url), $content)
                        ? 'success'
                        : 'error';
                }

                return $content;
            }
        )
        ->request();

    if ( is_scalar($results) ) {
        return [ 'error' => 'UNKNOWN ERROR: ' . substr((string)$results, 300) ];
    }

    if ( ! empty($results['error']) ) {
        return $results;
    }

    $download_again = array();
    $results        = array_values($results);

    for ( $i = 0, $iMax = count($results); $i < $iMax; $i++ ) {
        if ( $results[$i] === 'error' ) {
            $download_again[] = $urls[$i];
        }
    }

    $download_again = array_merge($download_again, $urls_to_download_next_time);

    if ( count($download_again) !== 0 ) {
        return array(
            'error' => 'Files download not completed.',
            'update_args' => array(
                'args'    => $download_again
            )
        );
    }

    $spbc->fw_stats['update_percent'] = 10;
    $spbc->save('fw_stats', true, false);

    return array(
        'next_stage' => array(
            'name'    => 'spbc_security_firewall_update__prepare'
        )
    );
}

function spbc_security_firewall_update__prepare()
{

    global $spbc;

    if ( ! $spbc->key_is_ok ) {
        return array( 'error' => 'FW UPDATE PREPARE: KEY_IS_NOT_VALID' );
    }

    global $wpdb;
    // Make sure that the table exists. Creating it if not.
    $db_tables_creator = new \CleantalkSP\SpbctWP\DB\TablesCreator();
    $db_tables_creator->createTable($wpdb->base_prefix . 'spbc_firewall_data');
    $db_tables_creator->createTable($wpdb->prefix . 'spbc_firewall__personal_ips');
    $db_tables_creator->createTable($wpdb->prefix . 'spbc_firewall__personal_countries');

    // Update only personal tables for daughter blogs
    $result = FW::dataTablesCreateTemporaryTablesForTables(
        DB::getInstance(),
        array(
            SPBC_TBL_FIREWALL_DATA,
            SPBC_TBL_FIREWALL_DATA__IPS,
            SPBC_TBL_FIREWALL_DATA__COUNTRIES
        )
    );

    if ( ! empty($result['error']) ) {
        return $result;
    }

    // Copying data without country code
    $result = FW::dataTablesCopyCountiesDataFromMainTable(DB::getInstance(), SPBC_TBL_FIREWALL_DATA);
    if ( ! empty($result['error']) ) {
        return $result;
    }

    $spbc->fw_stats['update_percent'] = 15;
    $spbc->save('fw_stats', true, false);

    return array(
        'next_stage' => array(
            'name'    => 'spbc_security_firewall_update__process_files',
        )
    );
}

function spbc_security_firewall_update__process_files()
{

    global $spbc;

    $files = glob($spbc->fw_stats['updating_folder'] . '/*csv.gz');

    if ( count($files) ) {
        $result = spbc_security_firewall_update__process_file(reset($files));

        if ( ! empty($result['error']) ) {
            return $result;
        }

        if ( file_exists(reset($files))) {
            unlink(reset($files));
        }

        $spbc->fw_stats['update_percent'] = 15 + round(65 * (($spbc->fw_stats['files_count'] - count($files)) / $spbc->fw_stats['files_count']), 2);
        $spbc->save('fw_stats', true, false);

        return array(
            'next_stage' => array(
                'name'    => 'spbc_security_firewall_update__process_files',
            )
        );
    }

    return array(
        'next_stage' => array(
            'name'    => 'spbc_security_firewall_update__process_exclusions',
        )
    );
}


/**
 * @param $path
 *
 * @return array|bool|int|mixed|string
 * @throws Exception
 */
function spbc_security_firewall_update__process_file($path)
{
    global $spbc;

    $current_file_content = file_get_contents($path);
    if ( $current_file_content ) {
        $current_file_hash = md5($current_file_content);

        //if hashes comparison failed
        if ( !in_array($current_file_hash, $spbc->data['secfw_data_files_info']) ) {
            //run new hashes getting
            $updated_hashes_list = spbc_security_firewall_update_get_update_files_hashes();

            if ( !in_array($current_file_hash, $updated_hashes_list) ) {
                //still has no success, warn the user, probably something with cloud data
                return array('error' => 'PROCESS FILE: ' . 'unexpected file contents: ' . $path . ' hash:' . $current_file_hash);
            } else {
                //try to save new hashes for next call
                $spbc->data['secfw_data_files_info'] = $updated_hashes_list;
                $spbc->save('data');
            }
        }
    }

    $result = FW::updateWriteToDb(
        DB::getInstance(),
        SPBC_TBL_FIREWALL_DATA . '_temp', // Write to the main table for daughter blogs
        SPBC_TBL_FIREWALL_DATA__IPS . '_temp',
        SPBC_TBL_FIREWALL_DATA__COUNTRIES . '_temp',
        $path
    );

    return empty($result['error'])
        ? $result
        : array( 'error' => 'PROCESS FILE: ' . $result['error']);
}

/**
 * @return array
 * @throws Exception
 */
function spbc_security_firewall_update__process_exclusions()
{

    global $spbc;

    $result = FW::updateWriteToDbExclusions(
        DB::getInstance(),
        SPBC_TBL_FIREWALL_DATA__IPS . '_temp',
        SPBC_TBL_FIREWALL_DATA . '_temp'
    );

    if ( ! empty($result['error']) ) {
        return array( 'error' => 'EXCLUSIONS: ' . $result['error'] );
    }

    $spbc->fw_stats['update_percent'] = 90;
    $spbc->save('fw_stats', true, false);

    return array(
        'next_stage' => array(
            'name'           => 'spbc_security_firewall_update__end_of_update',
            'accepted_tries' => 1,
        )
    );
}

function spbc_security_firewall_update__end_of_update()
{

    global $spbc, $wpdb;

    // Put in maintenance mode
    $spbc->fw_stats['is_on_maintenance'] = true;
    $spbc->save('fw_stats', true, false);
    usleep(100000);


    //Increment firewall entries
    $tables_to_work_with = array(
        SPBC_TBL_FIREWALL_DATA,
        SPBC_TBL_FIREWALL_DATA__IPS,
        SPBC_TBL_FIREWALL_DATA__COUNTRIES
    );

    $result = FW::dataTablesDelete(DB::getInstance(), $tables_to_work_with);
    if ( empty($result['error']) ) {
        $result = FW::dataTablesMakeTemporaryPermanent(DB::getInstance(), $tables_to_work_with);
        if ( empty($result['error']) ) {
            $result = FW::dataTablesClearUnusedCountriesDataFromMainTable(DB::getInstance()); // Clear useless entries about countries in the ain table
        }
    }
    if ( ! empty($result['error']) ) {
        $spbc->fw_stats['is_on_maintenance'] = false;
        $spbc->save('fw_stats', true, false);

        return $result;
    }

    //Files array is empty update sfw stats
    $spbc->fw_stats['update_percent'] = 0;
    $spbc->fw_stats['updating_id'] = null;
    $spbc->fw_stats['updating_last_start'] = 0;
    $spbc->fw_stats['last_updated'] = current_time('timestamp');
    $spbc->fw_stats['is_on_maintenance'] = false; // Remove maintenance mode
    $spbc->fw_stats['entries'] =
        $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA) +
        $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA__IPS);

    $spbc->save('fw_stats', true, false);

    $spbc->error_delete('firewall_update', true);
    $spbc->error_delete('firewall_update', 'save_data', 'cron');

    // Get update period for server
    $update_period = DNS::getRecord('securityfirewall-ttl-txt.cleantalk.org', true, DNS_TXT);
    $update_period = isset($update_period['txt']) ? $update_period['txt'] : 0;
    $update_period = (int) $update_period > 43200 ?  (int) $update_period : 43200;
    Cron::updateTask('firewall_update', 'spbc_security_firewall_update__init', $update_period);
    Cron::removeTask('fw_update_checker');

    Data::removeDirectoryRecursively($spbc->fw_stats['updating_folder']);

    return true;
}

function spbc_security_firewall_update__is_in_progress()
{
    $queue = new Queue('fw_update', 'update_security_firewall__worker');
    return $queue->isQueueInProgress();
}

function spbc_security_firewall_update__prepare_upd_dir()
{

    global $spbc;

    $dir_name = $spbc->fw_stats['updating_folder'];

    if ( $dir_name === '' ) {
        return array('error' => 'FW dir can not be blank.');
    }

    if ( ! is_dir($dir_name) && ! mkdir($dir_name) ) {
        return ! is_writable(SPBC_PLUGIN_DIR)
            ? array( 'error' => 'Can not to make FW dir. Low permissions: ' . fileperms(SPBC_PLUGIN_DIR) )
            : array( 'error' => 'Can not to make FW dir. Unknown reason.' );
    }

    $files = glob($dir_name . '/*');
    if ( $files === false ) {
        return array( 'error' => 'Can not find FW files.' );
    }
    if ( count($files) === 0 ) {
        return (bool) file_put_contents($dir_name . 'index.php', '<?php' . PHP_EOL);
    }

    foreach ( $files as $file ) {
        if ( is_file($file) && unlink($file) === false ) {
            return array( 'error' => 'Can not delete the FW file: ' . $file );
        }
    }

    return (bool) file_put_contents($dir_name . 'index.php', '<?php');
}

function spbc_security_firewall_update__checker()
{

    global $spbc;

    $queue = new Queue('fw_update', 'update_security_firewall__worker');

    if (
        $spbc->fw_stats['updating_id'] &&
        $queue->hasUnstartedStages()
    ) {
        $result = spbc_security_firewall_update__worker(true);

        if ( ! empty($result['error']) && $queue->isQueueFinished() ) {
            $spbc->fw_stats['update_percent'] = 0;
            $spbc->fw_stats['updating_id'] = null;
            $spbc->save('fw_stats', true, false);

            Cron::removeTask('fw_update_checker');

            return $result;
        }
    }

    return true;
}

/**
 * Update security firewall in single thread
 *
 * @return bool|string[]|array[]
 * @throws Exception
 */
function spbc_security_firewall_update_direct()
{
    global $spbc;

    // get_multifiles
    $result_get_multifiles = spbc_security_firewall_update__get_multifiles();
    if ( ! empty($result_get_multifiles['error']) ) {
        return $result_get_multifiles;
    }
    $urls = $result_get_multifiles['next_stage']['args'];

    // prepare
    $result_prepare = spbc_security_firewall_update__prepare();
    if ( ! empty($result_prepare['error']) ) {
        return $result_prepare;
    }

    // process_file
    foreach ( $urls as $url ) {
        $result_process_file = spbc_security_firewall_update__process_file($url);
        if ( ! empty($result_process_file['error']) ) {
            return $result_process_file;
        }
        $spbc->fw_stats['update_percent'] = 15 + round(65 * (($spbc->fw_stats['files_count'] - count($urls)) / $spbc->fw_stats['files_count']), 2);
        $spbc->save('fw_stats', true, false);
    }

    // process_exclusions
    $result_process_exclusions = spbc_security_firewall_update__process_exclusions();
    if ( ! empty($result_process_exclusions['error']) ) {
        return $result_process_exclusions;
    }

    // end_of_update
    $result_end_of_update = spbc_security_firewall_update__end_of_update();
    if ( ! empty($result_end_of_update['error']) ) {
        return $result_end_of_update;
    }

    return $result_end_of_update;
}
