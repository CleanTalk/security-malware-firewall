<?php

use CleantalkSP\Common\DNS;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Firewall\FW;
use CleantalkSP\SpbctWP\Cron;
use CleantalkSP\SpbctWP\Helper;
use CleantalkSP\SpbctWP\Queue;
use CleantalkSP\SpbctWP\DB\SQLSchema;
use CleantalkSP\Variables\Request;

/**
 * Called by update_security_firewall remote call
 * Starts the Security Firewall update and could use a delay before start
 *
 * @param int $delay
 *
 * @return bool|string|string[]
 * @throws Exception
 */
function spbc_security_firewall_update__init( $delay = 0 ){
    
    global $spbc;
    
    sleep( $delay );
    
    // Prevent start an update if update is already running and started less than 2 minutes ago
    if(
        spbc_security_firewall_update__is_in_progress() &&
        $spbc->fw_stats['updating_id'] &&
        time() - $spbc->fw_stats['updating_last_start'] < 120
    ){
        return true;
    }
    
    if( ! $spbc->api_key ){
        return array( 'error' => 'FW UPDATE INIT: KEY_EMPTY' );
    }
    
    if( ! $spbc->key_is_ok ){
        return array( 'error' => 'FW UPDATE INIT: KEY_IS_NOT_VALID' );
    }
    
    // Delete temporary tables
    FW::data_tables__deleteTemporary( DB::getInstance(), array(
        SPBC_TBL_FIREWALL_DATA,
        SPBC_TBL_FIREWALL_DATA__IPS,
        SPBC_TBL_FIREWALL_DATA__COUNTRIES,
    ) );
    
    $spbc->fw_stats['updating_folder'] = SPBC_PLUGIN_DIR . DIRECTORY_SEPARATOR . 'fw_files_for_blog_' . get_current_blog_id() . DIRECTORY_SEPARATOR;
    
    $prepare_dir__result = spbc_security_firewall_update__prepare_upd_dir();
    if( ! empty( $prepare_dir__result['error'] ) ){
        return $prepare_dir__result;
    }
    
    // Set a new update ID and an update time start
    $spbc->fw_stats['update_percent'] = 5;
    $spbc->fw_stats['calls']          = 0;
    $spbc->fw_stats['updating_id']    = md5( mt_rand( 0, 100000 ) );
    $spbc->fw_stats['updating_last_start'] = time();
    $spbc->save( 'fw_stats' );
    
    
    // Delete update errors
    $spbc->error_delete( 'firewall_update', true );
    $spbc->error_delete( 'firewall_update', 'save_data', 'cron');
    
    Queue::clearQueue();
    $queue = new Queue();
    $queue->addStage( 'spbc_security_firewall_update__get_multifiles' );
    
    Cron::addTask('fw_update_checker', 'spbc_security_firewall_update__checker', 1 );
    
    $result = Helper::http__request__rc_to_host(
        'update_security_firewall__worker',
        array( 'updating_id' => $spbc->fw_stats['updating_id'], ),
        array( 'async' )
    );
    
    return ! empty( $result['error'] ) && $queue->isQueueFinished()
        ? $result
        : true;
}

/**
 * Updating Security FireWall data
 *
 * @param bool $checker_work flag indicates that the function were called by checker cron task
 *
 * @return array|bool
 */
function spbc_security_firewall_update__worker( $checker_work = false ){
    
    global $spbc;
    
    sleep(1);
    
    if( ! $spbc->key_is_ok ){
        return array( 'error' => 'KEY_IS_NOT_VALID' );
    }
    
    // Check if the update performs right now. Blocks remote calls with different ID
    // This was done to make sure that we won't have multiple updates at a time
    
    if( ! $checker_work ){
        if(
            Request::equal( 'updating_id', '' ) ||
            ! Request::equal( 'updating_id', $spbc->fw_stats['updating_id'] )
        ){
            return array( 'error' => 'FW UPDATE WORKER: WRONG_UPDATE_ID' );
        }
    }
    
    $spbc->fw_stats['calls']++;
    $spbc->save( 'fw_stats' );
    
    if( $spbc->fw_stats['calls'] > 600 ){
        $spbc->error_add('firewall_update', 'WORKER_CALL_LIMIT_EXCEEDED' );
        $spbc->save( 'errors' );
        return array( 'error' => 'WORKER_CALL_LIMIT_EXCEEDED' );
    }
    
    // Queue is already empty. Exit.
    $queue = new Queue();
    if( $queue->isQueueFinished() ){
        return true;
    }
    
    $result = $queue->executeStage();
    
    if( isset( $result['error'] ) ){
        
        $spbc->error_add('firewall_update', $result['error'] );
        $spbc->save( 'errors' );
        
        return $result['error'];
    }
    
    if( $queue->isQueueFinished() ) {
        
        $queue->queue['finished'] = time();
        $queue->saveQueue();
    
        if( array_column( $queue->queue['stages'], 'error') ) {
            $spbc->error_add('firewall_update', current( array_column( $queue->queue['stages'], 'error') ) );
        }
        
        return true;
    }
    
    // This is the repeat stage request, do not generate any new RC
    if( stripos( Request::get('stage'), 'Repeat' ) !== false ) {
        return true;
    }
    
    $result = Helper::http__request__rc_to_host(
        'update_security_firewall__worker',
        array( 'updating_id' => $spbc->fw_stats['updating_id'] ),
        array( 'async' )
    );
    
    return ! empty( $result['error'] ) && $queue->isQueueFinished()
        ? $result
        : true;
}

/**
 * @return array[]|string[]
 */
function spbc_security_firewall_update__get_multifiles(){
    
    global $spbc;
    
    if( $spbc->key_is_ok ){
    
        $result = FW::firewall_update__get_multifiles( $spbc->api_key );
        
        if( empty( $result['error'] ) ){
    
            $spbc->fw_stats['files_count'] = count( $result['file_urls'] );
            $spbc->fw_stats['update_percent'] = 10;
            $spbc->save( 'fw_stats' );
            
            return array(
                'next_stage' => array(
                    'name'    => 'spbc_security_firewall_update__download_files',
                    'args'    => array_values( $result['file_urls'] ),
                )
            );
            
        }else
            return array( 'error' => 'GET MULTIFILE: ' . $result['error'] );
    }else
        return array( 'error' => 'FW UPDATE PREPARE: KEY_IS_NOT_VALID' );
}

function spbc_security_firewall_update__download_files( $urls ){
    
    global $spbc;
    
    sleep(3);
    
    //Reset keys
    $urls = array_values( $urls );
    $results = Helper::http__multi_request( $urls, $spbc->fw_stats['updating_folder'] );
    
    $count_urls = count( $urls );
    $count_results = count( $results );
    
    if ( empty( $results['error'] ) && ( $count_urls === $count_results ) ) {
        $download_again = array();
        for( $i = 0; $i < $count_results; $i++ ) {
            if( $results[$i] === 'error' ) {
                $download_again[] = $urls[$i];
            }
        }
        
        if( count( $download_again ) !== 0 ) {
            return array(
                'error' => 'Files download not completed.',
                'update_args' => array(
                    'args'    => $download_again
                )
            );
        }
    
        $spbc->fw_stats['update_percent'] = 10;
        $spbc->save( 'fw_stats' );
        
        return array(
            'next_stage' => array(
                'name'    => 'spbc_security_firewall_update__prepare'
            )
        );
    }
    
    if ( ! empty( $results['error'] ) ) {
        return $results;
    }
    
    return array( 'error' => 'Files download not completed.' );
    
}

function spbc_security_firewall_update__prepare(){
    
    global $spbc;
    
    if( ! $spbc->key_is_ok ){
        return array( 'error' => 'FW UPDATE PREPARE: KEY_IS_NOT_VALID' );
    }
    
    global $wpdb;
    // Make sure that the table exists. Creating it if not.
    $db_tables_creator = new \CleantalkSP\SpbctWP\DB\TablesCreator();
    $db_tables_creator->createTable($wpdb->base_prefix . 'spbc_firewall_data');
    $db_tables_creator->createTable($wpdb->prefix . 'spbc_firewall__personal_ips');
    $db_tables_creator->createTable($wpdb->prefix . 'spbc_firewall__personal_countries');
    
    // Update only personal tables for daughter blogs
    $result = FW::data_tables__createTemporaryTablesForTables(
        DB::getInstance(),
        array(
            SPBC_TBL_FIREWALL_DATA,
            SPBC_TBL_FIREWALL_DATA__IPS,
            SPBC_TBL_FIREWALL_DATA__COUNTRIES
        )
    );
    
    if( ! empty( $result['error'] ) ){
        return $result;
    }
    
    // Copying data without country code
    $result = FW::data_tables__copyCountiesDataFromMainTable( DB::getInstance(), SPBC_TBL_FIREWALL_DATA );
    if( ! empty( $result['error'] ) ){
        return $result;
    }
    
    $spbc->fw_stats['update_percent']= 15;
    $spbc->save( 'fw_stats' );
    
    return array(
        'next_stage' => array(
            'name'    => 'spbc_security_firewall_update__process_files',
        )
    );
    
}

function spbc_security_firewall_update__process_files() {
    
    global $spbc;
    
    $files = glob( $spbc->fw_stats['updating_folder'] . '/*csv.gz' );
    
    if( count( $files ) ){
        
        $result = spbc_security_firewall_update__process_file( reset( $files ) );
        
        if( ! empty( $result['error'] ) ) {
            return $result;
        }
    
        if( file_exists(reset($files)) ){
            unlink(reset($files));
        }
    
        $spbc->fw_stats['update_percent'] = 15 + round( 65 * ( ( $spbc->fw_stats['files_count'] - count( $files ) ) / $spbc->fw_stats['files_count'] ), 2 );
        $spbc->save( 'fw_stats' );
        
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
 * @return array|bool|string|string[]
 * @throws Exception
 */
function spbc_security_firewall_update__process_file( $path ){
    
    $result = FW::update__write_to_db(
        DB::getInstance(),
        SPBC_TBL_FIREWALL_DATA . '_temp', // Write to the main table for daughter blogs
        SPBC_TBL_FIREWALL_DATA__IPS . '_temp',
        SPBC_TBL_FIREWALL_DATA__COUNTRIES . '_temp',
        $path
    );
    
    
    return empty( $result['error'] )
        ? $result
        : array( 'error' => 'PROCESS FILE: ' . $result['error'] );
}

/**
 * @return array|bool|string|string[]
 * @throws Exception
 */
function spbc_security_firewall_update__process_exclusions(){
    
    global $spbc;
    
    $result = FW::update__write_to_db__exclusions(
        DB::getInstance(),
        SPBC_TBL_FIREWALL_DATA__IPS . '_temp',
        SPBC_TBL_FIREWALL_DATA . '_temp'
    );
    
    if( ! empty( $result['error'] ) ){
        return array( 'error' => 'EXCLUSIONS: ' . $result['error'] );
    }
    
    $spbc->fw_stats['update_percent'] = 90;
    $spbc->save( 'fw_stats' );
    
    return array(
        'next_stage' => array(
            'name'           => 'spbc_security_firewall_update__end_of_update',
            'accepted_tries' => 1,
        )
    );
}

function spbc_security_firewall_update__end_of_update(){
    
    global $spbc, $wpdb;
    
    // Put in maintenance mode
    $spbc->fw_stats['is_on_maintenance'] = true;
    $spbc->save( 'fw_stats' );
    usleep( 100000 );
    
    
    //Increment firewall entries
    $tables_to_work_with = array(
        SPBC_TBL_FIREWALL_DATA,
        SPBC_TBL_FIREWALL_DATA__IPS,
        SPBC_TBL_FIREWALL_DATA__COUNTRIES
    );
    
    $result = FW::data_tables__delete( DB::getInstance(), $tables_to_work_with );
    if( empty( $result['error'] ) ){
        $result = FW::data_tables__makeTemporaryPermanent( DB::getInstance(), $tables_to_work_with );
        if( empty( $result['error'] ) ){
            $result = FW::data_tables__clearUnusedCountriesDataFromMainTable( DB::getInstance() ); // Clear useless entries about countries in the ain table
        }
    }
    if( ! empty( $result['error'] ) ){
        $spbc->fw_stats['is_on_maintenance'] = false;
        $spbc->save( 'fw_stats' );
    
        return $result;
    }
    
    //Files array is empty update sfw stats
    $spbc->fw_stats['update_percent'] = 0;
    $spbc->fw_stats['updating_id'] = null;
    $spbc->fw_stats['updating_last_start'] = 0;
    $spbc->fw_stats['last_updated'] = current_time('timestamp');
    $spbc->fw_stats['entries'] =
        $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA ) +
        $wpdb->get_var('SELECT COUNT(*) FROM ' . SPBC_TBL_FIREWALL_DATA__IPS );
    
    $spbc->save('fw_stats');
    
    $spbc->error_delete( 'firewall_update', true );
    $spbc->error_delete( 'firewall_update', 'save_data', 'cron');
    
    // Remove maintenance mode
    $spbc->fw_stats['is_on_maintenance'] = false;
    $spbc->save( 'fw_stats' );
    
    // Get update period for server
    $update_period = DNS::getRecord( 'securityfirewall-ttl-txt.cleantalk.org', true, DNS_TXT );
    $update_period = isset( $update_period['txt'] ) ? $update_period['txt'] : 0;
    $update_period = (int) $update_period > 43200 ?  (int) $update_period : 43200;
    Cron::updateTask( 'firewall_update', 'spbc_security_firewall_update__init', $update_period );
    Cron::removeTask( 'fw_update_checker' );
    
    \CleantalkSP\Common\Helper::fs__removeDirectoryRecursively( $spbc->fw_stats['updating_folder'] );
    
    return true;
}

function spbc_security_firewall_update__is_in_progress() {
    $queue = new Queue();
    return $queue->isQueueInProgress();
}

function spbc_security_firewall_update__prepare_upd_dir(){
    
    global $spbc;
    
    $dir_name = $spbc->fw_stats['updating_folder'];
	
	if( $dir_name === '' ) {
		return array( 'error' => 'FW dir can not be blank.' );
	}
	
    if( ! is_dir( $dir_name ) && ! mkdir( $dir_name ) ){
		
		return ! is_writable( SPBC_PLUGIN_DIR )
			? array( 'error' => 'Can not to make FW dir. Low permissions: ' . fileperms( SPBC_PLUGIN_DIR ) )
			: array( 'error' => 'Can not to make FW dir. Unknown reason.' );
		
	} else {
        $files = glob( $dir_name . '/*' );
        if( $files === false ){
            return array( 'error' => 'Can not find FW files.' );
        }
        if( count( $files ) === 0 ){
            return (bool) file_put_contents( $dir_name . 'index.php', '<?php' . PHP_EOL );
        }
        foreach( $files as $file ){
            if( is_file( $file ) && unlink( $file ) === false ){
                return array( 'error' => 'Can not delete the FW file: ' . $file );
            }
        }
    }
    
    return (bool) file_put_contents( $dir_name . 'index.php', '<?php' );
}

function spbc_security_firewall_update__checker(){
    
    global $spbc;
    
    $queue = new Queue();
    
    if(
        $spbc->fw_stats['updating_id'] &&
        $queue->hasUnstartedStages()
    ){
        $result = spbc_security_firewall_update__worker( true );
        
        if( ! empty( $result['error'] ) && $queue->isQueueFinished() ){
            
            $spbc->fw_stats['update_percent'] = 0;
            $spbc->fw_stats['updating_id'] = null;
            $spbc->save('fw_stats');
            
            Cron::removeTask( 'fw_update_checker' );
            
            return $result;
        }
        
    }
    
    return true;
}