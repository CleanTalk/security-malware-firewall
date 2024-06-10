<?php

namespace CleantalkSP\SpbctWP\Scanner;

use CleantalkSP\SpbctWP\Scanner\FileMonitoringModule\FileMonitoringEntry;
use CleantalkSP\SpbctWP\Scanner\CureLog\CureLog;
use CleantalkSP\SpbctWP\Scanner\CureLog\CureLogRecord;
use CleantalkSP\SpbctWP\Scanner\ScanningLog\ScanningLogFacade;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\ScannerFileStatuses;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\ScanningStagesStorage;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\AutoCure;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\ScheduleSendHeuristicSuspiciousFiles;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\FileSystemAnalysis;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\FrontendAnalysis;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\GetApprovedHashes;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\GetCmsHashes;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\GetDeniedHashes;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\GetModulesHashes;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\HeuristicAnalysis;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\OutboundLinks;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\SignatureAnalysis;
use CleantalkSP\SpbctWP\Scanner\Stages\SignatureAnalysis\SignatureAnalysisFacade;
use CleantalkSP\SpbctWP\Scanner\UnsafePermissionsModule\UnsafePermissionsHandler;
use CleantalkSP\Variables\Request;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Cron;
use CleantalkSP\SpbctWP\Transaction;
use CleantalkSP\SpbctWP\State;
use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\Helpers\HTTP;
use CleantalkSP\SpbctWP\Helpers\Helper as QueueHelper;
use CleantalkSP\SpbctWP\Helpers\CSV;
use CleantalkSP\SpbctWP\RemoteCalls;

class ScannerQueue
{
    /**
     * @var string[] List of scan stages
     */
    public static $stages = array(
        'get_cms_hashes',
        'get_modules_hashes',
        'clean_results',
        'file_system_analysis',
        'get_denied_hashes',
        'get_approved_hashes',
        'file_monitoring',
        'signature_analysis',
        'heuristic_analysis',
        'schedule_send_heuristic_suspicious_files',
        'auto_cure_backup',
        'auto_cure',
        'outbound_links',
        'frontend_analysis',
        'important_files_listing',
        'send_results',
    );

    /**
     * @var string Site root directory
     */
    private $root;

    /**
     * @var int Current action offset
     */
    private $offset;

    /**
     * @var int Amount of elements to process in current action
     */
    private $amount;

    /**
     * @var string Current scan stage
     */
    private $stage;

    /**
     * @var bool Shows if this is an end of scan
     * @psalm-suppress UnusedProperty
     */
    private $end_of_scan = false;

    /**
     * @var DB
     */
    private $db;

    /**
     * Max queue iteration size for signature analysis.
     * @var int
     */
    private static $max_queue_files_aggregated_size__signatures = 2097152;
    /**
     * Max queue iteration size for heuristic analysis.
     * @var int
     */
    private static $max_queue_files_aggregated_size__heuristic = 524288;

    public function __construct($stage = '', $offset = null, $amount = null, $root_dir = null)
    {
        global $spbc;

        @set_time_limit(120); // Increasing Script execution time

        $this->db = DB::getInstance();

        $this->stage  = isset($stage) ? $stage : Request::get('stage');
        $this->amount = isset($amount) ? (int)$amount : (int)Request::get('amount');
        $this->offset = isset($offset) ? (int)$offset : (int)Request::get('offset');
        $this->root   = $root_dir ?: realpath(ABSPATH);

        // Crunch for cure backups
        if ( isset($spbc->settings['scanner__auto_cure']) && $spbc->settings['scanner__auto_cure'] == 0) {
            unset(self::$stages['auto_cure_backup']);
        }

        // Skip send_heuristic_suspicious_files if setting is disabled
        if ( isset($spbc->settings['scanner__schedule_send_heuristic_suspicious_files']) && $spbc->settings['scanner__schedule_send_heuristic_suspicious_files'] == 0) {
            unset(self::$stages['schedule_send_heuristic_suspicious_files']);
        }
    }

    /**
     * Launches background scanning by making a remote call
     * Also set a cron task for each 30 seconds in case RC failing
     * Set a transaction 'background_scan' and pass it to RC and Cron task
     *
     * @return bool|string[]
     */
    public static function launchBackground()
    {
        global $spbc;

        $transaction_id = Transaction::get('background_scanner', 3600 * 2)->perform();

        if (
            ! $spbc->moderate ||
            ! $spbc->settings['scanner__auto_start'] ||
            ! $transaction_id
        ) {
            return true;
        }

        $params = array(
            'transaction_id' => $transaction_id,
            'stage'          => 'get_cms_hashes',
            'offset'         => 0,
        );

        //remove old task and set a new
        Cron::updateTask(
            'background_scan',
            'spbc_scanner__controller',
            30,
            time() + 30,
            $params
        );

        // Remove link for shuffle salts
        $spbc->settings['there_was_signature_treatment'] = 0;
        $spbc->save('settings');

        // Do not return the value because it could alter a scheduled scan time
        // If fails scan will run the next scheduled time
        return RemoteCalls::performToHost(
            'scanner__controller',
            $params,
            array('async', 'get')
        );
    }

    /**
     * Description here
     *
     * @param int|null $transaction_id Transaction ID passed directly
     * @param string|null $stage
     * @param int $offset
     * @param int $amount
     *
     * @return bool|string|string[]
     * @global State $spbc
     */
    public static function controllerBackground($transaction_id = null, $stage = null, $offset = null, $amount = null)
    {
        global $spbc;

        $transaction_id = $transaction_id ?: Request::get('transaction_id'); // @todo cast to int by Variables

        if ( (int)$transaction_id !== (int)Transaction::get('background_scanner')->getTID() ) {
            return true;
        }

        $self = new self($stage, $offset, $amount);
        if ( ! method_exists($self, $self->stage) ) {
            return array('error' => 'controllerBackground: UNKNOWN_METHOD: ' . $self->stage);
        }

        $result = $self->{$self->stage}();

        // Handling errors
        $spbc->error_toggle(! empty($result['error']), 'cron_scan', $result);
        if ( ! empty($result['error']) ) {
            return $result;
        }

        // Current stage is ended. Preparing for next.
        if ( $result['end'] ) {
            $self->stage = $self->getNextStage($self->stage);
        }

        // New stage is unset. End of scanning.
        if ( $self->stage === null ) {
            // End the transaction cause the scanning is finished
            Transaction::get('background_scanner')->clearTransactionTimer();
            Cron::removeTask('background_scan');

            return true;
        }

        switch ( $self->stage ) {
            case 'get_modules_hashes':
                $self->amount = 20;
                break;
            case 'frontend_analysis':
                $self->amount = (defined('SPBCT_ALLOW_CURL_SINGLE') && SPBCT_ALLOW_CURL_SINGLE) ? 2 : 20;
                break;
            case 'clean_results':
                $self->amount = 10000;
                break;
            case 'file_system_analysis':
                $self->amount = 700;
                break;
            case 'heuristic_analysis':
                $self->amount = 4;
                break;
            case 'auto_cure':
                $self->amount = 5;
                break;
            case 'signature_analysis':
            case 'outbound_links':
                $self->amount = 10;
                break;
        }

        $params = array(
            'transaction_id' => $transaction_id,
            'stage'          => $self->stage,
            'offset'         => $result['end'] ? 0 : $self->offset + $result['processed'],
            'amount'         => $self->amount,
        );

        Cron::updateTask(
            'background_scan',
            'spbc_scanner__controller',
            30,
            time() + 30,
            $params
        );

        // Need to halt the script because of cooldown for remote call 'scanner__controller' (2 seconds)
        sleep(2);


        $rc_result = RemoteCalls::performToHost(
            'scanner__controller',
            $params,
            array('async', 'get')
        );

        return $rc_result;
    }

    public function getNextStage($stage)
    {
        global $spbc;

        // Check if the passed and next state is set
        if ( ! isset(self::$stages[$stage]) && ! isset(self::$stages[(int)array_search($stage, self::$stages, true) + 1]) ) {
            return null;
        }

        $stage   = self::$stages[(int)array_search($stage, self::$stages, true) + 1];
        $setting = 'scanner__' . $stage;

        /**
         * Recursion.
         * Check if the next stage is disabled by setting
         * If so, get the next one
         */
        if ( isset($spbc->settings[$setting]) && (int)$spbc->settings[$setting] === 0 ) {
            $stage = $this->getNextStage($stage);
        }

        return $stage;
    }

    public static function controllerFront()
    {
        if ( ! spbc_check_ajax_referer('spbc_secret_nonce', 'security', false) ) {
            wp_send_json(array('error' => 'Nonce had been changed. Please, restart the scan.'));
        }

        $scanner     = new self();
        $method_name = str_replace('spbc_scanner_', '', Request::get('method'));

        $out = method_exists(__CLASS__, $method_name)
            ? $scanner->$method_name()
            : array('error' => 'UNKNOWN_ACTION');
        wp_send_json($out);
    }

    /**
     * Receive CMS hash
     *
     * @global string $wp_version
     * @global State $spbc
     *
     * @return array
     */
    public function get_cms_hashes() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc, $wp_version;

        $spbc->data['scanner']['scan_start_timestamp'] = time();
        //use wordpress native fucntion to get localized time for scanner start
        $spbc->data['scanner']['scanner_start_local_date'] = current_time('Y-m-d H:i:s');
        $spbc->save('data');

        // Clearing old data about scanning stages
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->reset();
        ScanningLogFacade::clearLog();

        if ( preg_match('/^\d*\.?\d*\.?\d*$/', $wp_version) === 1 ) {
            $stage_data_obj = $scanning_stages_storage->getStage(GetCmsHashes::class);

            if (
                ! isset($spbc->data['scanner']['last_wp_version'])
                || (isset($spbc->data['scanner']['last_wp_version']) && $spbc->data['scanner']['last_wp_version'] !== $wp_version)
                || ! $this->db->execute('SELECT path FROM ' . SPBC_TBL_SCAN_FILES . ' LIMIT 1')
            ) {
                // Getting hashes
                $result = \CleantalkSP\SpbctWP\Scanner\Helper::getHashesForCMS('wordpress', $wp_version);

                if ( empty($result['error']) ) {
                    $this->db->execute('DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE source_type = "CORE";');
                    $is_windows        = $spbc->is_windows ? true : false;
                    $data              = array();
                    $missed_cms_hashes = array();
                    $expected_count_hashes = $result['checksums_count'];

                    foreach ( $result['checksums'] as $path => $real_full_hash ) {
                        $path      = $is_windows ? str_replace('/', '\\', $path) : $path;
                        $fast_hash = md5($path);
                        $path      = addslashes($path);
                        $data[]    = sprintf(
                            '("%s","%s","%s","CORE", "wordpress", "%s", "1", "1", "OK")',
                            $fast_hash,
                            $path,
                            $real_full_hash,
                            $wp_version
                        );
                        //collect if there are still some files (fix for cron launch after WP updated)
                        $missed_cms_hash = $this->db->fetchAll(
                            'SELECT fast_hash FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE fast_hash = "' . $fast_hash . '";'
                        );
                        if ( $missed_cms_hash ) {
                            $missed_cms_hashes[] = '\'' . $missed_cms_hash[0]['fast_hash'] . '\'';
                        }
                    }
                    //if missed hashes found delete them
                    if ( ! empty($missed_cms_hashes) ) {
                        $this->db->execute(
                            'DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE fast_hash in (' . implode(
                                ',',
                                $missed_cms_hashes
                            ) . ');'
                        );
                    }

                    $sql = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES . ' (`fast_hash`, `path`, `real_full_hash`, `source_type`, `source`, `version`, `checked_heuristic`, `checked_signatures`, `status`) VALUES ';

                    $result = $this->db->execute($sql . implode(',', $data) . ';');

                    if ( $result !== false ) {
                        // save data to scanning stages log
                        $stage_data_obj->set('expected_count_hashes', $expected_count_hashes);
                        $stage_data_obj->set('added_count_hashes', $result);

                        $out = array(
                            'end'         => 1,
                            'processed'   => $result,
                            'files_count' => $result
                        );
                    } else {
                        $out['error'] = 'COULDNT_INSERT with error: ' . $this->db->getLastError();
                    }

                    $spbc->data['scanner']['last_wp_version'] = $wp_version;
                    $spbc->error_delete('get_hashes', true);
                    $spbc->save('data');
                } else {
                    $out = $result;
                }
            } else {
                // not the first scan from a client
                $sql = 'SELECT COUNT(*) AS cnt FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE source_type = "CORE";';
                $result = $this->db->fetch($sql, OBJECT);
                $stage_data_obj->set('expected_count_hashes', 0);
                $stage_data_obj->set('added_count_hashes', $result->cnt);
                $out = array('comment' => 'Already up to date.', 'end' => 1,);
            }

            $scanning_stages_storage->saveToDb();

            // Adding to log
            ScanningLogFacade::writeToLog(
                '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
            );

            // Sending data to frontend
            $out['stage_data_for_logging'] = array(
                'title' => $stage_data_obj::getTitle(),
                'description' => $stage_data_obj->getDescription()
            );
        } else {
            $out = array('error' => 'Your WordPress version is not supported');
        }

        return $out;
    }

    /**
     * Count total amount of plugins and themes
     *
     * @return array|void
     * @global State $spbc
     *
     */
    public function countModules()
    {
        global $spbc;

        $out = array(
            'total'   => 0,
            'plugins' => 0,
            'themes'  => 0,
        );

        foreach ( array('plugins', 'themes') as $modules_type ) {
            // Preparing modules to check again
            $modules = spbc_get_modules_by_type($modules_type);
            $spbc->$modules_type;
            if ( empty($spbc->$modules_type) ) {
                $spbc->$modules_type = $modules;
            }

            foreach ( array_keys($modules) as $module_slug ) {
                if ( isset($spbc->{$modules_type}[$module_slug]) ) {
                    if ( empty($spbc->{$modules_type}[$module_slug]['checked']) ) {
                        $out['total']++;
                        $out[$modules_type]++;
                    }
                    if ( ! empty($spbc->{$modules_type}[$module_slug]['should_be_checked_again']) ) {
                        $spbc->{$modules_type}[$module_slug]['checked'] = 0;
                        $out['total']++;
                        $out[$modules_type]++;
                        unset($spbc->{$modules_type}[$module_slug]['should_be_checked_again']);
                    }
                    if ( $spbc->{$modules_type}[$module_slug]['Version'] !== $modules[$module_slug] ['Version'] ) {
                        $spbc->{$modules_type}[$module_slug]['checked'] = 0;
                        $out['total']++;
                        $out[$modules_type]++;
                    }
                } else {
                    $out['total']++;
                    $out[$modules_type]++;
                }
            }
            $spbc->save($modules_type, true, false);
        }

        return $out;
    }

    /**
     * @param int $amount
     * @param int $offset
     *
     * @return array
     * @global State $spbc
     *
     * @global State $spbc
     */
    public function get_modules_hashes($amount = null, $offset = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $amount = isset($amount) ? (int)$amount : $this->amount;
        $offset = isset($offset) ? (int)$offset : $this->offset;

        $out = array('processed' => 0);

        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(GetModulesHashes::class);

        // Count modules and add it to output
        if ( $offset === 0 ) {
            $count_modules = $this->countModules();

            $stage_data_obj->set('count_plugins', count(spbc_get_modules_by_type('plugins')));
            $stage_data_obj->set('count_themes', $count_modules['themes']);

            $out = array_merge($out, $count_modules);
        }

        //return false on the hook to prevent errors from other actions bound to the hook
        add_filter('plugins_api', function ($_res) {
            return false;
        }, 9999, 1);

        foreach ( array('plugins', 'themes') as $modules_type ) {
            // Attaching API functions
            if ( $modules_type === 'plugins' ) {
                require_once(ABSPATH . 'wp-admin/includes/plugin-install.php');
            }

            if ( $modules_type === 'themes' ) {
                require_once(ABSPATH . 'wp-admin/includes/theme.php');
            }

            // Get all modules
            $modules               = spbc_get_modules_by_type($modules_type);
            $modules_type_singular = substr($modules_type, 0, -1);
            $modules_dir           = spbc_get_module_folder_by_type($modules_type);
            $is_windows            = $spbc->is_windows;

            // @todo crunch. this calls magic method __get on $spbc->plugins or $spbc->themes property.
            $spbc->$modules_type;

            // Fix for the first start
            if ( is_array($spbc->$modules_type) ) {
                $spbc->$modules_type = new \ArrayObject($spbc->$modules_type);
            }

            foreach ( $modules as $module_slug => $module ) {
                if ( $out['processed'] >= $amount ) {
                    break;
                }

                if (
                    ! empty($spbc->{$modules_type}[$module_slug]['checked']) &&
                    ! empty($spbc->{$modules_type}[$module_slug]['Version']) &&
                    $spbc->{$modules_type}[$module_slug]['Version'] === $module['Version']
                ) {
                    continue;
                }

                $spbc->{$modules_type}[$module_slug] = $module;

                $modules_entry_type = $modules_type === 'plugins' ? 'plugin_information' : 'theme_information';

                if ( $modules_entry_type === 'plugin_information' ) {
                    if (version_compare(phpversion(), '7.0.0', '>')) {
                        try {
                            $result_wp_api_modules = plugins_api(
                                $modules_entry_type,
                                array('slug' => $module_slug, 'fields' => array('Version' => true))
                            );
                        } catch (\Exception $e) {
                            error_log($e->getMessage(), 1);
                        }
                    } else {
                        $result_wp_api_modules = plugins_api(
                            $modules_entry_type,
                            array('slug' => $module_slug, 'fields' => array('Version' => true))
                        );
                    }
                } else {
                    $result_wp_api_modules = themes_api(
                        $modules_entry_type,
                        array('slug' => $module_slug, 'fields' => array('Version' => true))
                    );
                }

                if ( ! is_wp_error($result_wp_api_modules) && isset($result_wp_api_modules->version) ) {
                    // Not error, version exists
                    $source_status = (version_compare(
                        $module['Version'],
                        $result_wp_api_modules->version,
                        '>='
                    ) ? 'UP_TO_DATE' : 'OUTDATED');
                } elseif ( ! is_wp_error($result_wp_api_modules) && ! isset($result_wp_api_modules->version) ) {
                    // Not error, version NOT exists
                    $source_status = 'UNKNOWN';
                } else {
                    // Error
                    $source_status = ($result_wp_api_modules->get_error_message(
                    ) === 'Plugin not found.' ? 'NOT_IN_DIRECTORY' : 'UNKNOWN');
                }

                $out['outdated']                   = $source_status === 'OUTDATED';
                $out['checked_' . $modules_type][] = $module_slug;

                // Get Cleantalk's hash
                $result_hashes = \CleantalkSP\SpbctWP\Scanner\Helper::getHashesForModules(
                    'wordpress',
                    $modules_type_singular,
                    $module_slug,
                    $module['Version']
                );

                // Remove approved files
                $scan_results_repository = new ScanResultsRepository();
                $approved_real_full_hashes = $scan_results_repository->getApprovedRealFullHashes();

                if ($approved_real_full_hashes) {
                    foreach ($result_hashes as $key => $data) {
                        if (in_array($data[1], $approved_real_full_hashes)) {
                            unset($result_hashes[$key]);
                        }
                    }
                }

                if ( empty($result_hashes['error']) ) {
                    $this->db->execute(
                        'DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE path LIKE "%' . $module_slug . '%" AND status <> "APPROVED_BY_USER";'
                    );
                    $sql_hat    = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES . ' (`fast_hash`, `path`, `real_full_hash`, `source_type`, `source`, `source_status`, `version`, `checked_heuristic`, `checked_signatures`, `status`) VALUES ';
                    $sql_values = array();
                    foreach ( $result_hashes as $value ) {
                        $path           = '/' . substr($modules_dir . '/' . $value[0], strlen(ABSPATH));
                        $path           = $is_windows ? str_replace('/', '\\', $path) : $path;
                        $fast_hash      = md5($path);
                        $path           = addslashes($path);
                        $real_full_hash = $value[1];
                        $sql_values[]   = "('$fast_hash', '$path', '$real_full_hash', '"
                                          . strtoupper($modules_type_singular)
                                          . "', '$module_slug', '$source_status', '{$module['Version']}', '1', '1', 'OK')";
                    }
                    if ( $sql_values ) {
                        $this->db->execute($sql_hat . implode(',', $sql_values));
                    }
                } else {
                    if ($modules_type === 'plugins') {
                        $stage_data_obj->increase('count_plugins_without_hashes', 1);
                    }
                    if ($modules_type === 'themes') {
                        $stage_data_obj->increase('count_themes_without_hashes', 1);
                    }

                    // Cloud should refresh the hash for this module
                    if ( $result_hashes['error'] === 'REMOTE_FILE_NOT_FOUND_OR_VERSION_IS_NOT_SUPPORTED__PLUG' ) {
                        $to_refresh['wordpress'][$modules_type][] = array(
                            'name'    => $module_slug,
                            'version' => $module['Version'],
                        );
                    }

                    // Saving it.
                    $spbc->{$modules_type}[$module_slug]['error'] = $result_hashes['error'];
                }

                if (
                    $source_status === 'NOT_IN_DIRECTORY' ||
                    $source_status === 'UNKNOWN' ||
                    ! empty($spbc->{$modules_type}[$module_slug]['error'])
                ) {
                    $spbc->{$modules_type}[$module_slug]['should_be_checked_again'] = true;
                }

                $out['processed']++;
                $spbc->{$modules_type}[$module_slug]['checked'] = true;
            }

            $spbc->save($modules_type, true, false);
        }

        if ( ! empty($to_refresh) ) {
            $to_refresh = json_encode($to_refresh);
            API::method__request_checksums($spbc->settings['spbc_key'], $to_refresh);
        }

        $out['end'] = $out['processed'] < $amount ? 1 : 0;

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $out;
    }

    /**
     * Delete non-existing files from table (except quarantined files)
     *
     * @param int $offset
     * @param int $amount
     *
     * @return mixed
     */
    public function clean_results($offset = null, $amount = 50000) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $offset = isset($offset) ? $offset : $this->offset;
        $amount = isset($amount) ? $amount : $this->amount;

        global $spbc;

        $result = $this->db->fetchAll(
            'SELECT path, fast_hash, status'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . " LIMIT $offset, $amount;"
        );

        $to_delete = array();
        foreach ( $result as $value ) {
            if ( $value['status'] !== 'QUARANTINED' && ! file_exists($this->root . $value['path']) ) {
                $to_delete[] = $this->db->prepare('%s', $value['fast_hash'])->getQuery();
            }
        }

        $deleted = 0;
        if ( ! empty($to_delete) ) {
            $deleted = $this->db->execute(
                'DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE fast_hash IN (' . implode(',', $to_delete) . ');'
            );
        }

        // Deleting newly added exclusions
        $this->deleteFilesOfExclusionDirs($spbc->settings['scanner__dir_exclusions']);

        $out = array(
            'total'     => (int)$deleted,
            'processed' => (int)$deleted,
            'deleted'   => (int)$deleted,
            'end'       => 1,
        );

        if ( $deleted === false ) {
            $out['error'] = 'COULDNT_DELETE';
        }

        return $out;
    }

    /**
     * Count files in the tables by given 'status' and 'checked' columns
     *
     * @param string $status
     * @param string $caller
     *
     * @return array
     */
    public function countFilesByStatusAndChecked($status = '', $caller = '')
    {
        $status = stripslashes(Request::get('status')) ?: $status;
        //$checked = stripslashes( Request::get('checked') ) ?: $checked; #todo What was this for?
        if ( Request::get('checked') ) {
            error_log(
                'countFilesByStatusAndChecked: $_GET[\'checked\'] parameter found, but not handled in the method ' . var_export(
                    $_GET,
                    true
                )
            );
        }

        if ( ! preg_match('#^[A-Z,_]+$#', $status) ) {
            return array('error' => 'BAD_PARAMS', 'comment' => "status: $status");
        }

        if ( ! preg_match('#^[A-Z,_]+$#', $caller) ) {
            return array('error' => 'BAD_PARAMS', 'comment' => "caller: $caller");
        }

        $status = is_string($status) ? explode(',', $status) : $status;
        $status = '"' . implode('","', $status) . '"';

        $caller = $caller === 'SIGNATURE_ANALYSIS' ? 'checked_signatures' : 'checked_heuristic';
        $query  =
            'SELECT COUNT(fast_hash) AS cnt'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE ' . $caller . " = '0' AND status IN (" . $status . ');';// No need to validate or sanitize, already did
        $result = $this->db->fetch($query);

        return $result !== null
            ? array('total' => (int)$result->cnt)
            : array(
                'error'   => __FUNCTION__ . ' query error',
                'comment' => substr($this->db->getLastError(), 0, 1000),
            );
    }

    /**
     * @param string $path_to_scan
     *
     * @return array
     * @global State $spbc
     *
     */
    public function countFileSystem($path_to_scan = ABSPATH)
    {
        ini_set('max_execution_time', '120');

        global $spbc;

        $path_to_scan = realpath($path_to_scan);
        $init_params  = array(
            'count'           => true,
            'file_exceptions' => 'wp-config.php',
            'extensions'      => 'php, html, htm, js, php2, php3, php4, php5, php6, php7, phtml, shtml, phar, odf, [ot.]',
            'files_mandatory' => array(),
            'dir_exceptions'  => array(SPBC_PLUGIN_DIR . 'quarantine')
        );

        if ( ! empty($spbc->settings['scanner__dir_exclusions']) ) {
            $init_params['dir_exceptions'] = array_merge(
                $init_params['dir_exceptions'],
                spbc__get_exists_directories(explode("\n", $spbc->settings['scanner__dir_exclusions']))
            );
        }

        $scanner = new Surface($path_to_scan, $this->root, $init_params);

        return array(
            'total' => $scanner->files_count,
            'end'   => 1,
        );
    }

    /**
     * Scan file system for alterations
     * Save it to DB/Storage
     *
     * @param int $offset
     * @param int $amount
     * @param string $path_to_scan
     *
     * @return array|string[]
     */
    public function file_system_analysis($offset = null, $amount = null, $path_to_scan = ABSPATH) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $offset       = isset($offset) ? $offset : $this->offset;
        $amount       = isset($amount) ? $amount : $this->amount;
        $path_to_scan = realpath($path_to_scan);
        $output       = array();
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(FileSystemAnalysis::class);

        $init_params = array(
            'fast_hash'             => true,
            'full_hash'             => true,
            'offset'                => $offset,
            'amount'                => $amount,
            'extensions'            => 'php, html, htm, js, php2, php3, php4, php5, php6, php7, phtml, shtml, phar, odf, [ot.]',
            'extensions_exceptions' => '', //array('jpg', 'jpeg', 'png', 'gif', 'css', 'txt', 'zip', 'xml', 'json')
            'file_exceptions'       => 'wp-config.php',
            'files_mandatory'       => array(),
            'dir_exceptions'        => array(SPBC_PLUGIN_DIR . 'quarantine')
        );

        if ( ! empty($spbc->settings['scanner__dir_exclusions']) ) {
            $init_params['dir_exceptions'] = array_merge(
                $init_params['dir_exceptions'],
                spbc__get_exists_directories(explode("\n", $spbc->settings['scanner__dir_exclusions']))
            );
        }

        $scanner = new Surface($path_to_scan, $this->root, $init_params);

        if ( $scanner->files_count ) {
            $stage_data_obj->increase('scanned_count_files', $scanner->files_count);
            $sql_query__values           = array();
            $sql_query__values_non_ascii = array();
            //should be offset
            $detected_at                 = current_time('timestamp');
            $sql_hat                     = 'INSERT INTO ' . SPBC_TBL_SCAN_FILES
                                           . ' (`path`, `size`, `perms`, `mtime`, `fast_hash`, `full_hash`, `detected_at`, `checked_heuristic`) VALUES ';

            foreach ( $scanner->files as $_key => $file ) {
                $file['path']        = trim($this->db->prepare('%s', $file['path'])->getQuery(), '\'');
                $file['detected_at'] = $detected_at;

                //JS files exclusion
                $ext = @pathinfo($file['path'], PATHINFO_EXTENSION);
                $file['checked_heuristic'] = $ext === 'js' ? 1 : 0;
                //JS files end

                if ( ! spbc_check_ascii($file['path']) ) {
                    $sql_query__values_non_ascii[] = '(\'' . implode('\',\'', $file) . '\')';
                } else {
                    $sql_query__values[] = '(\'' . implode('\',\'', $file) . '\')';
                }
            }

            $sql_suffix = " ON DUPLICATE KEY UPDATE
			
			size        = VALUES(`size`),
			perms       = VALUES(`perms`),
			source      = source,
			source_type = source_type,
			version     = version,

			fast_hash = fast_hash,
			full_hash = VALUES(`full_hash`),
			real_full_hash = real_full_hash,
			
			checked_signatures =
				IF(real_full_hash IS NOT NULL AND real_full_hash = VALUES(`full_hash`),
					1,
					IF(mtime <> VALUES(`mtime`) OR mtime IS NULL,
						0,
						checked_signatures
					)
				),
				
			checked_heuristic =
				IF(real_full_hash IS NOT NULL AND real_full_hash = VALUES(`full_hash`),
					1,
					IF(mtime <> VALUES(`mtime`) OR mtime IS NULL,
						0,
						checked_heuristic
					)
				),
			
			status =
				IF(mtime <> VALUES(`mtime`) OR mtime IS NULL,
					IF(real_full_hash IS NULL,
						IF(checked_heuristic = 1 OR checked_signatures = 1,
							status,
							'UNKNOWN'
						),
						IF(real_full_hash = VALUES(`full_hash`),
							'OK',
							'MODIFIED'
						)
					),
					status
				),
			
			mtime     = VALUES(`mtime`),
			
			detected_at = IF(
			    detected_at IS NULL,
			    VALUES(`detected_at`),
			    detected_at
            ),
			
			severity  =
				IF(
				    (status <> 'OK' AND (checked_heuristic = 1 OR checked_signatures = 1)),
					severity,
					NULL
				),
				
			weak_spots  =
				IF(
				    (status <> 'OK' AND (checked_heuristic = 1 OR checked_signatures = 1)),
					weak_spots,
					NULL
				);";

            if ( $sql_query__values ) {
                $success = $this->db->execute($sql_hat . implode(',', $sql_query__values) . $sql_suffix);
            }
            if ( $sql_query__values_non_ascii ) {
                // @todo Resolve conflict with non ASCII symbol path names. Right now DB errors is suppressed for this cases.
                @$this->db->execute($sql_hat . implode(',', $sql_query__values_non_ascii) . $sql_suffix);
            }
        } else {
            $output = array('error' => __FUNCTION__ . ' No files to scan',);
        }

        if ( isset($success) ) {
            if ( $success === false ) {
                $output = array(
                    'error'   => __FUNCTION__ . ' DataBase write error while scanning files.',
                    'comment' => substr($this->db->getLastError(), 0, 1000),
                );
                if ( $spbc->debug ) {
                    spbc_log($this->db->getLastQuery());
                }
            } else {
                $output = array(
                    'processed'   => $scanner->files_count,
                    'files_count' => $scanner->files_count,
                    'dirs_count'  => $scanner->dirs_count,
                    'offset'      => $offset,
                    'amount'      => $amount,
                    'end'         => false
                );

                // End of stage
                if ($scanner->files_count < $amount) {
                    $output['end'] = true;

                    // Checking unsafe permissions
                    $unsafe_permissions_handler = new UnsafePermissionsHandler();
                    $unsafe_permissions_handler->handle();
                }
            }
        }

        // Count files if it's first iteration
        if ( $offset === 0 ) {
            $init_params['count'] = true;
            unset($init_params['amount'], $init_params['offset']);
            $scanner         = new Surface($path_to_scan, $this->root, $init_params);
            $output['total'] = $scanner->files_count;
        }

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $output['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $output;
    }

    /**
     * Getting remote hashes of denied files
     *
     * @return array
     */
    public function get_denied_hashes() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $result = \CleantalkSP\SpbctWP\Scanner\Helper::getHashesForFiles('wordpress', 'denied', '1.0.0');

        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(GetDeniedHashes::class);

        if ( empty($result['error']) ) {
            $spbc->data['scanner']['checksums_count_ct'] = count($result);
            $spbc->save('data');

            $where = implode('\',\'', array_column($result, 1));
            if ( ! preg_match('#^[a-zA-Z0-9\',]+$#', $where) ) {
                return array('error' => 'BAD_PARAMS');
            }

            /**
             * Set unknown status if the file was denied before, but its has does not
             * persist in the denied hashes list for now. This implemented for cases where we
             * do change hashes list on mistakenly accepted wrong verdict
             */
            $this->db->execute(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET
                checked_heuristic = 0,
                checked_signatures = 0,
                severity =  NULL,
                status = \'UNKNOWN\',
                weak_spots = \'\'
                WHERE status   =   \'DENIED_BY_CT\'
                AND full_hash NOT IN (\'' . $where . '\')
                AND status <> \'QUARANTINED\';'
            );

            /**
             * Update the db depend on current hashes list.
             */
            $updated_rows = $this->db->execute(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET
                checked_heuristic = 1,
                checked_signatures = 1,
                status   =   \'DENIED_BY_CT\',
                severity =   \'CRITICAL\',
                weak_spots = \'{"DENIED_HASH":{"1":["denied_hash"]}}\'
                WHERE full_hash IN (\'' . $where . '\')
                AND status <> \'QUARANTINED\';'
            );

            $stage_data_obj->set('count_denied_hashes', count($result));
            $stage_data_obj->set('count_denied_hashes_in_db', $updated_rows);
            $scanning_stages_storage->saveToDb();
        }

        $out = array(
            'end'       => 1,
            'processed' => empty($result['error']) ? count($result) : 0
        );

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $out;
    }

    /**
     * Getting remote hashes of approved files
     *
     * @return array
     */
    public function get_approved_hashes() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $result = \CleantalkSP\SpbctWP\Scanner\Helper::getHashesForFiles('wordpress', 'approved', '1.0.0');

        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(GetApprovedHashes::class);

        if ( empty($result['error']) ) {
            $spbc->data['scanner']['checksums_count_ct'] = count($result);
            $spbc->save('data');

            $where = implode('\',\'', array_column($result, 1));
            if ( ! preg_match('#^[a-zA-Z0-9\',]+$#', $where) ) {
                return array('error' => 'BAD_PARAMS');
            }

            /**
             * Set unknown status if the file was approved before, but its has does not
             * persist in the approved hashes list for now. This implemented for cases where we
             * do change hashes list on mistakenly accepted wrong verdict
             */
            $this->db->execute(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET
                checked_heuristic = 0,
                checked_signatures = 0,
                severity =  NULL,
                status = \'UNKNOWN\'
                WHERE status   =   \'APPROVED_BY_CT\'
                AND full_hash NOT IN (\'' . $where . '\');'
            );

            /**
             * Update the db depend on current hashes list.
             */
            $updated_rows = $this->db->execute(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET
                checked_heuristic = 1,
                checked_signatures = 1,
                status   =   \'APPROVED_BY_CT\',
                severity =   NULL
                WHERE full_hash IN (\'' . $where . '\');'
            );

            $stage_data_obj->set('count_approved_hashes', count($result));
            $stage_data_obj->set('count_approved_hashes_in_db', $updated_rows);
            $scanning_stages_storage->saveToDb();
        }

        $out = array(
            'end'       => 1,
            'processed' => empty($result['error']) ? count($result) : 0
        );

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $out;
    }

    /**
     * @param string $status
     * @param int $offset
     * @param int $amount
     *
     * @return array
     */
    public function signature_analysis($status = 'UNKNOWN,MODIFIED,OK,INFECTED,ERROR', $offset = null, $amount = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $status_raw = isset($status) ? $status : stripslashes(Request::get('status'));
        if ( ! preg_match('#^[A-Z,_]+$#', $status_raw) ) {
            return array('error' => 'BAD_PARAMS');
        }
        $offset = isset($offset) ? $offset : $this->offset;
        $amount = isset($amount) ? $amount : $this->amount;
        $status = is_string($status_raw) ? explode(',', $status_raw) : $status_raw;
        $status = '"' . implode('","', $status) . '"';
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(SignatureAnalysis::class);

        // Count total files if offset is 0
        if ( $offset === 0 ) {
            // There are no signatures in the DB
            $there_are_signatures_in_db = SignatureAnalysisFacade::thereAreSignaturesInDb();
            if (!$there_are_signatures_in_db) {
                // Adding to log
                ScanningLogFacade::writeToLog(
                    '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescriptionEmptySignaturesTable()
                );

                return array(
                    'found'     => 0,
                    'processed' => 0,
                    'end'       => 1,
                    'stage_data_for_logging' => array(
                        'title' => $stage_data_obj::getTitle(),
                        'description' => $stage_data_obj->getDescriptionEmptySignaturesTable()
                    )
                );
            }
            $spbc->data['scanner']['scanned_total'] = 0;
            $spbc->data['scanner']['signatures_found'] = []; // Clearing ids of the signatures found
            $total = $this->countFilesByStatusAndChecked($status_raw, 'SIGNATURE_ANALYSIS');
            if ( ! isset($total['total']) ) {
                error_log('countFilesByStatusAndChecked: ' . $total['error'] . ' ' . $total['comment']);
            }
            $total = $total['total'];
            $stage_data_obj->set('total_count_files_for_analysis', $total);

            if (isset($spbc->errors['scanner_update_signatures_bad_signatures'])) {
                // Adding to log
                ScanningLogFacade::writeToLog(
                    '<b>'
                    . $stage_data_obj::getTitle()
                    . '</b> '
                    . __('Some signatures were not recorded in the database: ', 'security-malware-firewall')
                    . $spbc->errors['scanner_update_signatures_bad_signatures']
                );
            }
        }

        // Get files to check for this iteration
        $files = $this->db->fetchAll(
            'SELECT path, source_type, source, version, status, checked_heuristic, checked_signatures, fast_hash, real_full_hash, full_hash, weak_spots, difference, severity, size, error_msg'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . " WHERE checked_signatures = 0 AND status IN ($status)"
            . " LIMIT 1000"
        );

        $aggregated_size = 0;
        $files_to_check  = array();
        $size_breaking_flag = false;
        foreach ( $files as $file ) {
            if ( $aggregated_size < static::$max_queue_files_aggregated_size__signatures ) {
                //even if a single file over limit to load, it will be added to files for checking anyway
                $aggregated_size  += $file['size'];
                $files_to_check[] = $file;
            } else {
                $size_breaking_flag = true;
                break;
            }
        }

        // Preparing data for log
        $processed_items = array();
        foreach ( $files_to_check as $file ) {
            $processed_items[$file['fast_hash']] = array(
                'path'   => $file['path'],
                'module' => $stage_data_obj::getTitle(),
                'status' => 0,
            );
        }

        $scanned = 0;
        $statuses = new ScannerFileStatuses();

        if ( count($files_to_check) ) {
            $root_path  = spbc_get_root_path();
            $signatures = $this->db->fetchAll('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES);

            $signatures_scanner = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Controller();

            foreach ( $files_to_check as $file ) {
                $file_to_check = new \CleantalkSP\Common\Scanner\SignaturesAnalyser\Structures\FileInfo(
                    $file['path'],
                    $file['full_hash']
                );

                $result = $signatures_scanner->scanFile($file_to_check, $root_path, $signatures);

                $processed_items[$file['fast_hash']]['status'] = ! empty($file['status']) && $file['status'] === 'MODIFIED'
                    ? 'MODIFIED'
                    : $result->status;

                $status     = ! empty($file['status']) && $file['status'] === 'MODIFIED' ? 'MODIFIED' : $result->status;
                $weak_spots = ! empty($result->weak_spots) ? json_encode($result->weak_spots) : 'NULL';
                $severity   = ! empty($file['severity']) ? $file['severity'] : $result->severity;
                $statuses->addStatus($status);

                if ( $weak_spots !== 'NULL' ) {
                    // Collect signatures triggered counts
                    if ( isset($result->weak_spots['SIGNATURES']) && is_array($result->weak_spots['SIGNATURES']) ) {
                        foreach ( $result->weak_spots['SIGNATURES'] as $signature_ids ) {
                            $signature_idx = $spbc->data['scanner']['signatures_found'];
                            foreach ( $signature_ids as $signature_id ) {
                                $signature_idx[$signature_id] = ! empty($signature_idx[$signature_id])
                                    ? (int)$signature_idx[$signature_id] + 1
                                    : 1;
                            }
                            $spbc->data['scanner']['signatures_found'] = $signature_idx;
                        }
                    }
                }

                $current_error_msg = self::handleErrorMsg($file['error_msg'], $result->error_msg, 'signature_analysis');

                $error_msg = !empty($current_error_msg)
                    ? '\'' . $current_error_msg . '\''
                    : 'NULL';

                $result_db = $this->db->execute(
                    'UPDATE ' . SPBC_TBL_SCAN_FILES
                    . ' SET'
                    . ' checked_signatures = 1,'
                    . ' last_sent = null,'
                    . ' status =   \'' . $status . '\','
                    . ' severity = ' . QueueHelper::prepareParamForSQLQuery($severity) . ','
                    . ' weak_spots = ' . QueueHelper::prepareParamForSQLQuery($weak_spots) . ','
                    . ' error_msg = ' . $error_msg
                    . ' WHERE fast_hash = \'' . $file['fast_hash'] . '\';'
                );

                // Adding to log
                ScanningLogFacade::writeToLog(
                    $file['path'] . ': ' . $stage_data_obj::getTitle() . ' - ' . $status
                );

                $result_db !== null ? $scanned++ : $scanned;
            }
        }

        $spbc->data['scanner']['scanned_total'] += $scanned;
        $spbc->save('data');

        $out = array(
            'found'     => count($files_to_check),
            'processed' => (int)$scanned,
            'end'       => (int)$scanned < $amount && !$size_breaking_flag,
        );

        $stage_data_obj->increase('count_files_to_check', count($files_to_check));
        $stage_data_obj->increase('scanned_count_files', $scanned);
        $stage_data_obj->merge('statuses', $statuses->getStatuses());

        // Adding data for user log
        $out['processed_items'] = $processed_items;

        if ( isset($total) ) {
            $out['total'] = $total;
        }

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $log_description = $stage_data_obj->getDescription();
        if (isset($spbc->errors['scanner_update_signatures_bad_signatures']) && $offset === 0) {
            $log_description .= ' ' . __('Some signatures were not recorded in the database: ', 'security-malware-firewall')
                                . $spbc->errors['scanner_update_signatures_bad_signatures']['error'];
        }
        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $log_description
        );

        return $out;
    }

    /**
     * Iterative function
     * Scan files from the DB via heuristic analysis
     *
     * @param string $status
     * @param int $offset
     * @param int $amount
     *
     * @return array
     */
    public function heuristic_analysis($status = 'UNKNOWN,MODIFIED,OK,INFECTED,ERROR', $offset = null, $amount = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;
        $status_raw = isset($status) ? $status : stripslashes(Request::get('status'));
        if ( ! preg_match('#^[A-Z,_]+$#', $status_raw) ) {
            return array('error' => 'BAD_PARAMS');
        }
        $offset = isset($offset) ? $offset : $this->offset;
        $amount = isset($amount) ? $amount : $this->amount;
        $status = is_string($status_raw) ? explode(',', $status_raw) : $status_raw;
        $status = '"' . implode('","', $status) . '"';
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(HeuristicAnalysis::class);

        // Count total files if offset is 0
        if ( $offset === 0 ) {
            $total = $this->countFilesByStatusAndChecked($status_raw, 'HEURISTIC_ANALYSIS');
            if ( ! isset($total['total']) ) {
                error_log('countFilesByStatusAndChecked() ERROR: ' . $total['error'] . ' ' . $total['comment']);
            }
            $total = $total['total'];
            $stage_data_obj->set('total_count_files_for_analysis', $total);
        }

        // Get files to check for this iteration
        $files = $this->db->fetchAll(
            'SELECT path, source_type, source, version, status, checked_heuristic, checked_signatures, fast_hash, real_full_hash, full_hash, weak_spots, difference, severity, size, error_msg'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . " WHERE checked_heuristic = 0 AND status IN ($status)"
            . " LIMIT 1000"
        );

        $aggregated_size = 0;
        $files_to_check  = array();
        $size_breaking_flag = false;
        foreach ( $files as $file ) {
            if ( $aggregated_size < static::$max_queue_files_aggregated_size__heuristic ) {
                //even if a single file over limit to load, it will be added to files for checking anyway
                $aggregated_size  += $file['size'];
                $files_to_check[] = $file;
            } else {
                $size_breaking_flag = true;
                break;
            }
        }

        // Preparing data for log
        $processed_items = array();
        foreach ( $files_to_check as $file ) {
            $processed_items[$file['fast_hash']] = array(
                'path'   => $file['path'],
                'module' => $stage_data_obj::getTitle(),
                'status' => 0,
            );
        }

        $scanned = 0;
        $statuses = new ScannerFileStatuses();

        if ( count($files_to_check) ) {
            $root_path  = spbc_get_root_path();

            $heuristic_scanner = new \CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller();

            foreach ( $files_to_check as $file ) {
                $file_to_check = new FileInfoExtended($file);

                $result = $heuristic_scanner->scanFile($file_to_check, $root_path);

                // Add log data
                $processed_items[$file['fast_hash']]['status'] = $file['status'] === 'MODIFIED'
                    ? 'MODIFIED'
                    : $result->status;

                // Insert found bad includes in table
                foreach ( $result->includes as $include ) {
                    if ( $include['status'] === false && $include['exists'] && $include['path'] ) {
                        unset($include['include']);

                        // Cutting file's path, leave path from CMS ROOT to file
                        $real_path = $include['path'];
                        $path      = str_replace($this->root, '', $real_path);
                        $path      = $spbc->is_windows ? str_replace('/', '\\', $path) : $path;
                        $mtime     = @filemtime($real_path);
                        if ( empty($mtime) ) {
                            clearstatcache($real_path);
                            $mtime = @filemtime($real_path);
                            if ( empty($mtime) ) {
                                clearstatcache($real_path);
                                $mtime = @filemtime($path);
                                if ( empty($mtime) ) {
                                    $mtime = @filectime($real_path);
                                    if ( empty($mtime) ) {
                                        $mtime = time();
                                    }
                                }
                            }
                        }
                        $size      = filesize($real_path);
                        $perms     = substr(decoct(fileperms($real_path)), 3);
                        $fast_hash = md5($path);
                        $full_hash = is_readable($real_path)
                            ? md5_file($real_path)
                            : 'unknown';

                        $this->db->prepare(
                            'INSERT INTO ' . SPBC_TBL_SCAN_FILES
                            . ' (`path`, `size`, `perms`, `mtime`,`status`,`fast_hash`, `full_hash`, `detected_at`) VALUES'
                            . "(%s, %d, %d, %d, 'UNKNOWN', %s, %s, %d)"
                            . 'ON DUPLICATE KEY UPDATE
                                size = VALUES(`size`)',
                            //should be offset to use in date()
                            array($path, $size, $perms, $mtime, $fast_hash, $full_hash, current_time('timestamp'))
                        )
                                 ->execute();

                        // Make 'processed' counter big enough to make an another iteration with new files
                        $scanned = 5;
                    }
                }

                $current_error_msg = self::handleErrorMsg($file['error_msg'], $result->error_msg, 'heuristic_analysis');

                $error_msg = !empty($current_error_msg)
                    ? '\'' . $current_error_msg . '\''
                    : 'NULL';

                $result_db = $this->db->execute(
                    'UPDATE ' . SPBC_TBL_SCAN_FILES
                    . ' SET '
                    . ' checked_heuristic = 1,'
                    . ' status = \'' . ($file['status'] === 'MODIFIED' ? 'MODIFIED' : $result->status) . '\','
                    . ' severity = ' . ($file['severity'] ? '\'' . $file['severity'] . '\'' : ($result->severity ? '\'' . $result->severity . '\'' : 'NULL')) . ','
                    . ' weak_spots = ' . ($result->weak_spots
                        ? QueueHelper::prepareParamForSQLQuery(json_encode($result->weak_spots))
                        : 'NULL')
                    . ','
                    . ' error_msg = ' . $error_msg
                    . ' WHERE fast_hash = \'' . $file['fast_hash'] . '\';'
                );

                $statuses->addStatus($file['status'] === 'MODIFIED' ? 'MODIFIED' : $result->status);

                // Adding to log
                ScanningLogFacade::writeToLog(
                    $file['path'] . ': ' . $stage_data_obj::getTitle() . ' - ' . ($file['status'] === 'MODIFIED' ? 'MODIFIED' : $result->status)
                );

                $result_db !== null ? $scanned++ : $scanned;
            }
        }

        $out = array(
            'found'     => count($files_to_check),
            'processed' => (int)$scanned,
            'end'       => (int)$scanned < $amount && !$size_breaking_flag,
        );

        // Adding data for user log
        if ( $processed_items ) {
            $out['processed_items'] = $processed_items;
        }

        if ( isset($total) ) {
            $out['total'] = $total;
        }

        $stage_data_obj->increase('count_files_to_check', count($files_to_check));
        $stage_data_obj->increase('scanned_count_files', $scanned);
        $stage_data_obj->merge('statuses', $statuses->getStatuses());

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $out;
    }

    /**
     * Schedule files to send for analysis during scan process via cron job.
     * @return array
     */
    public function schedule_send_heuristic_suspicious_files() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        // Init logging
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(ScheduleSendHeuristicSuspiciousFiles::class);

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        // Update records with pscan_pending_queue = 1, this will be checked by cron and file will be sent if so.
        $result_db = $this->db->execute(
            'UPDATE ' . SPBC_TBL_SCAN_FILES
            . ' SET '
            . ' pscan_pending_queue = 1 '
            . ' WHERE severity = "SUSPICIOUS" '
            . ' AND last_sent is NULL '
            . ' AND checked_heuristic = 1 '
            . ' AND weak_spots NOT LIKE "%SIGNATURES%" '
            . ' AND status NOT IN ("APPROVED_BY_USER", "APPROVED_BY_CT", "APPROVED_BY_CLOUD")'
            . ' AND (pscan_pending_queue IS NULL OR pscan_pending_queue = 0); '
        );

        $count = (int)$result_db;
        // Add cron job, ignore rescanning to reduce site load
        if ($count !== 0) {
            \CleantalkSP\SpbctWP\Cron::updateTask(
                'scanner_resend_pscan_files',
                'spbc_scanner_resend_pscan_files',
                SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD,
                time() + SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD,
                array('do_rescan' => false)
            );
            \CleantalkSP\SpbctWP\Cron::updateTask(
                'scanner_update_pscan_files_status',
                'spbc_scanner_update_pscan_files_status',
                SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD,
                time() + (SPBC_PSCAN_UPDATE_FILES_STATUS_PERIOD * 2)
            );
        }

        $stage_data_obj->increase('count_scheduled', $count);
        // Save logging
        $scanning_stages_storage->saveToDb();

        return array(
                'processed' => $stage_data_obj->getData()['count_scheduled'],
                'scheduled'     => $stage_data_obj->getData()['count_scheduled'],
                'end'       => true,
                'message'   => __(
                    'Files sending scheduled',
                    'security-malware-firewall'
                ),
                'stage_data_for_logging' => array(
                    'title' => $stage_data_obj::getTitle(),
                    'description' => $stage_data_obj->getDescription()
                )
            );
    }

    public function auto_cure_backup() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        return spbc_backup__files_with_signatures(true);
    }

    /**
     * @param int $offset
     * @param int $amount
     * @return \CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\Verdict|string[]|array
     * @psalm-suppress UnusedVariable
     */
    public function auto_cure($offset = 0, $amount = 1) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $offset = isset($offset) ? $offset : $this->offset;
        $amount = isset($amount) ? $amount : $this->amount;

        global $spbc;

        $files = $this->db->fetchAll(
            'SELECT * '
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE weak_spots LIKE "%\"SIGNATURES\":%";'
        );

        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(AutoCure::class);

        $processed = 0;
        $cured = array();

        if ( $files !== null && count($files)) {
            $stage_data_obj->increase('count_files', count($files));

            //get root path to rescan
            $root_path  = spbc_get_root_path();

            // init heuristic module to rescan
            $heuristic_scanner = new \CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller();

            foreach ( $files as $file ) {
                //init cure log item
                $cure_log_record = new CureLogRecord(array(
                    'fast_hash' => isset($file['fast_hash']) ? $file['fast_hash'] : '',
                    'real_path' => isset($file['path']) ? $file['path'] : '',
                    'cured' => 0,
                    'has_backup' => 0,
                    'cci_cured' => null,
                    'fail_reason' => '',
                    'last_cure_date' => time(),
                    'scanner_start_local_date' => $spbc->data['scanner']['scanner_start_local_date'],
                ));
                // get array of weakspots from JSON of table row
                $weak_spots = json_decode($file['weak_spots'], true);
                //init empty string of signatures
                $signatures_in_file = '';
                if ( ! empty($weak_spots['SIGNATURES']) ) {
                    $signatures_in_file = array();
                    foreach ( $weak_spots['SIGNATURES'] as $signatures_in_string ) {
                        $signatures_in_file = array_merge(
                            $signatures_in_file,
                            array_diff($signatures_in_string, $signatures_in_file)
                        );
                    }
                    $signatures_in_file = implode(',', $signatures_in_file);
                }

                //check if siganture can be cured - has instructions
                $signatures_with_cci = ! empty($signatures_in_file)
                    ? $this->db->fetchAll(
                        'SELECT * '
                        . ' FROM ' . SPBC_TBL_SCAN_SIGNATURES
                        . ' WHERE id IN (' . $signatures_in_file . ') AND cci IS NOT NULL AND cci <> \'\''
                    )
                    : null;

                //init cure log
                $cure_log = new CureLog();

                if ( ! empty($signatures_with_cci) ) {
                    //skip files with no backup
                    if (!spbc_file_has_backup($file['path'])) {
                        $cure_log_record->fail_reason = 'File has no backup.';
                        $cure_log->logCureResult($cure_log_record);
                        $processed++;
                        continue;
                    }

                    //process Cure
                    $cure = new Cure($file);

                    if ( ! empty($cure->result['error']) ) {
                        //if Cure process errored keep the reason
                        $cure_log_record->fail_reason = $cure->result['error'];
                    } else {
                        //old log way
                        $cured[$file['path']] = 'CURED';

                        //new log way
                        $cure_log_record->cured = 1;
                        $cure_log_record->cci_cured = count($weak_spots['SIGNATURES']);

                        //file is cured, remove signatures weakspots
                        unset($weak_spots['SIGNATURES']);

                        //process any other weakspots to save them
                        if ( empty($weak_spots) ) {
                            $weak_spots       = 'NULL';
                            $severity = 'NULL';
                            $status   = 'OK';
                        } else {
                            $weak_spots       = QueueHelper::prepareParamForSQLQuery(json_encode($weak_spots));
                            $severity = $file['severity'];
                            $status   = $file['status'];
                        }

                        //update scan results table
                        $this->db->execute(
                            'UPDATE ' . SPBC_TBL_SCAN_FILES
                            . ' SET '
                            . 'weak_spots = ' . $weak_spots . ','
                            . 'severity = "' . $severity . '",'
                            . 'status = "' . $status . '"'
                            . ' WHERE fast_hash = "' . $file['fast_hash'] . '";'
                        );

                        // Scanning file with heuristic after the cure
                        $file_to_check_with_heuristic = $this->db->fetchAll(
                            'SELECT * '
                            . ' FROM ' . SPBC_TBL_SCAN_FILES
                            . ' WHERE fast_hash = "' . $file['fast_hash'] . '";'
                        );
                        $file_to_check_with_heuristic = $file_to_check_with_heuristic[0];

                        $file_to_check = new FileInfoExtended($file);
                        $result = $heuristic_scanner->scanFile($file_to_check, $root_path);
                        if ( is_object($result) ) {
                            $this->db->execute(
                                'UPDATE ' . SPBC_TBL_SCAN_FILES
                                . ' SET'
                                . " checked_heuristic = 1,"
                                . ' status = \'' . $result->status . '\','
                                . ' severity = ' . ($result->severity ? '\'' . $result->severity . '\'' : 'NULL') . ','
                                . ' weak_spots = ' . ($result->weak_spots ? QueueHelper::prepareParamForSQLQuery(
                                    json_encode($result->weak_spots)
                                ) : 'NULL')
                                . ' WHERE fast_hash = \'' . $file_to_check_with_heuristic['fast_hash'] . '\';'
                            );
                        } else {
                            $out = $result;
                        }
                    }
                    //record log on any Cure result
                    $cure_log->logCureResult($cure_log_record);
                } else {
                    //can not be cured, log this
                    $cure_log_record->cured = 0;
                    $cure_log_record->fail_reason = 'No CCI found.';
                    $cure_log->logCureResult($cure_log_record);
                }
                //inc processed count
                $processed++;
            }
            //this stuff is used to send cure logs
            $spbc->data['scanner']['cured'] = $cured;
            $spbc->save('data');
        }

        // prepare output
        $out = ! empty($out)
            //this fires only if heuristic rescan fails
            ? $out
            : array(
                'processed' => $processed,
                'cured'     => count($cured),
                'end'       => $processed >= count($files),
                'message'   => __(
                    'We recommend changing your secret authentication keys and salts when curing is done.',
                    'security-malware-firewall'
                )
            );

        $stage_data_obj->increase('count_cured', count($cured));

        // Counting files to cure if offset is 0
        if ( $offset === 0 ) {
            $result_db = $this->db->fetch(
                'SELECT COUNT(*) AS cnt FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE weak_spots LIKE "%SIGNATURES%";',
                OBJECT
            );
            if ( $result_db !== null ) {
                $out = $result_db !== null
                    ? array_merge($out, array('total' => $result_db->cnt,))
                    : array_merge(
                        $out,
                        array(
                            'error'   => __FUNCTION__ . ' DataBase write error while counting files.',
                            'comment' => substr($this->db->getLastError(), 0, 1000),
                        )
                    );
            }
        }

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $out;
    }

    /**
     * @param null $offset
     * @param null $amount
     *
     * @return array
     * @global  State $spbc
     *
     */
    public function outbound_links($offset = null, $amount = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $offset = isset($offset) ? $offset : $this->offset;
        $amount = isset($amount) ? $amount : $this->amount;
        $output = [];
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(OutboundLinks::class);

        // Count total links
        if ( $offset === 0 ) {
            $links_scanner   = new Links(array('count' => true));
            $output['total'] = $links_scanner->posts_total;
            $stage_data_obj->set('total', $output['total']);
        }

        $scanner = new Links(
            array(
                'amount'        => $amount,
                'check_default' => false,
                'mirrors'       => ! empty($spbc->settings['scanner__outbound_links_mirrors']) ? $spbc->settings['scanner__outbound_links_mirrors'] : '',
            )
        );

        if ( ! empty($scanner->links) ) {
            // Getting only new links
            $prev_scanned_links = $this->db->fetchAll(
                'SELECT link FROM ' . SPBC_TBL_SCAN_LINKS,
                OBJECT_K
            );
            $new_links          = array_diff_key($scanner->links, $prev_scanned_links);

            //Getting current scan_id
            $scan_id = $this->db->fetch('SELECT MAX(scan_id) AS scan_num FROM ' . SPBC_TBL_SCAN_LINKS . ';');
            $scan_id = $scan_id->scan_num + 1;

            // Preparing request
            $sql_hat =
                'INSERT INTO ' . SPBC_TBL_SCAN_LINKS
                . ' (`scan_id`, `link`, `domain`, `link_text`, `page_url`)'
                . ' VALUES ';

            // Preparing data
            $new_links = QueueHelper::prepareParamForSQLQuery($new_links);
            $sql_values = array();
            foreach ( $new_links as $link => $param ) {
                $link         = QueueHelper::prepareParamForSQLQuery($link);
                $sql_values[] = "($scan_id, $link, {$param['domain']}, {$param['link_text']}, {$param['page_url']})";
            }
            $sql_values = implode(',', $sql_values);

            // Adding results to storage table
            $this->db->execute($sql_hat . $sql_values);
        }

        $output['found']     = $scanner->links_found;
        $output['processed'] = $scanner->posts_checked;
        $output['end']       = $scanner->posts_checked < $amount;

        $stage_data_obj->increase('founded', $output['found']);

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $output['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $output;
    }

    public function frontend_analysis($offset = null, $amount = null) // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        $offset    = isset($offset) ? $offset : $this->offset;
        $amount    = isset($amount) ? $amount : $this->amount;
        $output    = [];
        $last_scan = date('Y-m-d H:i:s');
        if (isset($spbc->data['scanner']['last_scan__front_end'])) {
            $last_scan = date('Y-m-d H:i:s', $spbc->data['scanner']['last_scan__front_end']);
        } else {
            $spbc->data['scanner']['last_scan__front_end'] = time();
            $spbc->data['scanner']['first_scan__front_end'] = 1;
            $spbc->save('data');
        }

        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(FrontendAnalysis::class);

        // Count total
        if ( $offset === 0 ) {
            $output['total']                             = Frontend::countUncheckedPages($last_scan);
            $spbc->data['scanner']['scanned_site_pages'] = 0;
            $spbc->data['scanner']['total_site_pages']   = Frontend::getTotalPages();
            $stage_data_obj->set('total', $output['total']);
            $stage_data_obj->set('total_site_pages', $spbc->data['scanner']['total_site_pages']);
        }

        // Skip scan if the \DOMDocument not exists
        if ( ! class_exists('\DOMDocument') ) {
            return array('end' => true,);
        }

        $front_scanner = new Frontend(
            array(
                'amount'             => $amount,
                'last_scan'          => $last_scan,
                'signatures'         => $this->db->fetchAll('SELECT * FROM ' . SPBC_TBL_SCAN_SIGNATURES),
                'domains_exceptions' => CSV::parseNSV(
                    $spbc->settings['scanner__frontend_analysis__domains_exclusions']
                ),
                'csrf_check'         => $spbc->settings['scanner__frontend_analysis__csrf'],
            )
        );

        $sql_hat =
            'INSERT INTO ' . SPBC_TBL_SCAN_FRONTEND
            . ' (`page_id`, `url`, `dbd_found`, `redirect_found`, `signature`, `csrf`, `bad_code`, `weak_spots`)'
            . ' VALUES ';

        foreach ( $front_scanner->pages as $page ) {
            if ( $page['bad'] ) {
                $guid       = QueueHelper::prepareParamForSQLQuery($page['guid']);
                $id         = QueueHelper::prepareParamForSQLQuery($page['ID']);
                $weak_spots = $page['found']['weak_spots'] ? QueueHelper::prepareParamForSQLQuery(
                    $page['found']['weak_spots']
                ) : 'NULL';

                // Preparing data
                $sql_values[] = "({$id}, {$guid}, {$page['found']['dbd']}, {$page['found']['redirects']}, {$page['found']['signatures']}, {$page['found']['csrf']}, NULL, {$weak_spots})";
            }
        }

        $sql_suffix =
            ' ON DUPLICATE KEY'
            . ' UPDATE'
            . ' url            = VALUES(url),'
            . ' dbd_found      = VALUES(dbd_found),'
            . ' redirect_found = VALUES(redirect_found),'
            . ' signature      = NULL,'
            . ' bad_code       = NULL,'
            . ' weak_spots	   = VALUES(weak_spots);';

        // Adding results to storage table
        $success = isset($sql_values)
            ? $this->db->execute($sql_hat . implode(',', $sql_values) . $sql_suffix)
            : true;

        /**
         * Switching the status of the first scan
         */
        if ($front_scanner->posts_count < $amount) {
            $spbc->data['scanner']['first_scan__front_end'] = 0;
        }
        $output['success']                           = $success;
        $output['processed']                         = $front_scanner->posts_count;
        $output['end']                               = $front_scanner->posts_count < $amount;
        $spbc->data['scanner']['scanned_site_pages'] += $output['processed'];
        $spbc->save('data');

        $stage_data_obj->increase('success', $output['success']);
        $stage_data_obj->increase('processed', $output['processed']);

        $scanning_stages_storage->saveToDb();

        // Adding to log
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $output['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        return $output;
    }

    public function important_files_listing() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $out = array(
            'processed'          => 0,
            'accessible_urls'    => array(),
            'accessible_listing' => array(),
        );

        $addresses_to_check_accessibility = array(
            '/wp-content/debug.log',
            '/.svn/entries',
            '/.git/config',
        );

        $addresses_to_check_listing = array(
            '/.svn',
            '/.git',
        );

        foreach ( $addresses_to_check_accessibility as $address ) {
            $url_to_check = get_option('home') . $address;
            if ( HTTP::getResponseCode($url_to_check) === 200 ) {
                $out['accessible_urls'][] = array('url' => $address, 'type' => 'accessible');
            }
        }

        foreach ( $addresses_to_check_listing as $address ) {
            $url_to_check = get_option('home') . $address;
            $page = HTTP::getContentFromURL($url_to_check);
            if (
                empty($page['error']) &&
                is_string($page) &&
                strpos($page, 'Index of ' . $address) !== false
            ) {
                $out['accessible_urls'][] = array('url' => $address, 'type' => 'listing');
            }
        }

        $out['processed'] = count($addresses_to_check_accessibility) + count($addresses_to_check_listing);
        $out['end']       = 1;

        // Saving the result
        global $spbc;

        /** Fixed for PHP 8.1: PHP Deprecated:  Automatic conversion of false to array is deprecated */
        if ( ! is_array($spbc->scanner_listing) ) {
            $spbc->scanner_listing = array(
                'accessible_urls' => $out['accessible_urls']
            );
        } else {
            $spbc->scanner_listing['accessible_urls'] = $out['accessible_urls'];
        }

        $spbc->save('scanner_listing', true, false);

        return $out;
    }

    /**
     * @psalm-suppress UnusedVariable
     * @psalm-suppress RedundantCondition
     */
    public function send_results() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc, $wpdb;

        // Getting modified files
        $sql_result__critical = $this->db->fetchAll(
            'SELECT full_hash, mtime, size, source_type, source, source_status, path, status, severity'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE'
            . ' severity = "CRITICAL" AND'
            . ' status <> "QUARANTINED" AND'
            . ' status <> "APPROVED_BY_USER" AND'
            . ' status <> "APPROVED_BY_CLOUD" AND'
            . ' status <> "APPROVED_BY_CT"'
        );

        $sql_result__suspicious = $this->db->fetchAll(
            'SELECT full_hash, mtime, size, source_type, source, source_status, path, status, severity'
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE'
            . ' severity = "SUSPICIOUS" AND'
            . ' status <> "QUARANTINED" AND'
            . ' status <> "APPROVED_BY_USER" AND'
            . ' status <> "APPROVED_BY_CLOUD" AND'
            . ' status <> "APPROVED_BY_CT"'
        );

        // Getting modified files
        $critical_files_found = array();
        if ( count($sql_result__critical) ) {
            foreach ( $sql_result__critical as $row ) {
                $path = $spbc->is_windows ? str_replace('\\', '/', $row['path']) : $row['path'];
                unset($row['path'], $row['status'], $row['severity']);
                $row['mtime'] = $row['mtime'] + $spbc->data['site_utc_offset_in_seconds'];
                $critical_files_found[$path] = array_values($row);
            }
        }

        // Getting modified files
        $suspicious_files_found = array();
        if ( count($sql_result__suspicious) ) {
            foreach ( $sql_result__suspicious as $row ) {
                $path = $spbc->is_windows ? str_replace('\\', '/', $row['path']) : $row['path'];
                unset($row['path'], $row['status'], $row['severity']);
                $row['mtime'] = $row['mtime'] + $spbc->data['site_utc_offset_in_seconds'];
                $suspicious_files_found[$path] = array_values($row);
            }
        }

        // Getting unknown files
        $unknown_files_found = array();
        if ( $spbc->settings['scanner__list_unknown'] ) {
            // Getting unknown files (without source)
            $sql_result__unknown = $this->db->fetchAll(
                'SELECT full_hash, mtime, size, path, source, severity, detected_at'
                . ' FROM ' . SPBC_TBL_SCAN_FILES
                . ' WHERE source IS NULL AND'
                . ' status <> "APPROVED_BY_USER" AND'
                . ' status <> "APPROVED_BY_CT" AND'
                . ' status <> "APPROVED_BY_CLOUD" AND'
                . ' detected_at >= ' . (time() - $spbc->settings['scanner__list_unknown__older_than'] * 86400) . ' AND'
                . ' path NOT LIKE "%wp-content%themes%" AND'
                . ' path NOT LIKE "%wp-content%plugins%" AND'
                . ' path NOT LIKE "%wp-content%cache%" AND'
                . ' (severity NOT IN ("CRITICAL","SUSPICIOUS") OR severity IS NULL)'
            );

            foreach ( $sql_result__unknown as $row ) {
                $path = $spbc->is_windows ? str_replace('\\', '/', $row['path']) : $row['path'];
                unset($row['path'], $row['severity'], $row['source'], $row['detected_at ']);
                $row['mtime'] = $row['mtime'] + $spbc->data['site_utc_offset_in_seconds'];
                $unknown_files_found[$path] = array_values($row);
            }
        }

        $error = '';

        /**
         * Getting parameters for security_mscan_logs()
         */
        $key                  = $spbc->settings['spbc_key'];
        $list_unknown         = (int)$spbc->settings['scanner__list_unknown'];
        $service_id           = $spbc->service_id;
        $scanner_start_local_date = isset($spbc->data['scanner']['scanner_start_local_date'])
            ? $spbc->data['scanner']['scanner_start_local_date']
            : current_time('Y-m-d H:i:s');
        $scan_result          = !empty($critical_files_found) || !empty($suspicious_files_found) ? 'warning' : 'passed';
        $total_site_files     = $spbc->data['scanner']['files_total'] = $this->countFileSystem()['total'];
        $scan_type            = RemoteCalls::check() ? 'auto' : 'manual';
        $checksums_count_ct   = isset($spbc->data['scanner']['checksums_count_ct']) ? $spbc->data['scanner']['checksums_count_ct'] : null;
        $checksums_count_user = (int)$wpdb->get_var(
            'SELECT COUNT(*) from ' . SPBC_TBL_SCAN_FILES . ' WHERE status = "APPROVED_BY_USER"'
        );
        $signatures_count     = isset($spbc->data['scanner']['signature_count']) ? $spbc->data['scanner']['signature_count'] : null;
        $scanned_total        = isset($spbc->data['scanner']['scanned_total']) ? $spbc->data['scanner']['scanned_total'] : null;
        $total_site_pages     = isset($spbc->data['scanner']['total_site_pages']) ? $spbc->data['scanner']['total_site_pages'] : 0;
        $scanned_site_pages   = isset($spbc->data['scanner']['scanned_site_pages']) ? $spbc->data['scanner']['scanned_site_pages'] : 0;
        $total_core_files = (int)$wpdb->get_var(
            'SELECT COUNT(*) FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE source_type = "CORE" AND source = "wordpress"'
        );
        $total_core_files = $total_core_files ?: 0;
        $signatures_found = isset($spbc->data['scanner']['signatures_found']) ? $spbc->data['scanner']['signatures_found'] : [];
        $signatures_found = json_encode($signatures_found);

        if ( is_null($signatures_count) && is_string($signatures_found) ) {
            $signatures_count = count(json_decode($signatures_found, true));
        }

        // API. Sending files scan result
        $result = API::method__security_mscan_logs(
            $key,
            $list_unknown,
            $service_id,
            $scanner_start_local_date,
            $scan_result,
            $total_core_files,
            $total_site_files,
            $critical_files_found,
            $suspicious_files_found,
            $unknown_files_found,
            $scan_type,
            $checksums_count_ct,
            $checksums_count_user,
            $signatures_count,
            $scanned_total,
            $total_site_pages,
            $scanned_site_pages,
            $signatures_found
        );

        if ( ! empty($result['error']) ) {
            $error = 'Common result send: ' . $result['error'];
        } else {
            $spbc->data['scanner']['last_sent']        = current_time('timestamp');
            $spbc->data['scanner']['last_scan']        = current_time('timestamp');
            $spbc->data['scanner']['scan_finish_timestamp'] = time();
            $spbc->data['scanner']['last_scan_amount'] = Request::get('total_scanned') ?: $scanned_total;
            $spbc->data['scanner']['signatures_found'] = []; // Clearing ids of the signatures found
        }

        // Sending links scan result
        if ( $spbc->settings['scanner__outbound_links'] ) {
            $links         = $this->db->fetchAll(
                'SELECT `link`, `link_text`, `page_url`'
                . ' FROM ' . SPBC_TBL_SCAN_LINKS
                . ' WHERE scan_id = (SELECT MAX(scan_id) FROM ' . SPBC_TBL_SCAN_LINKS . ');',
                OBJECT
            );
            $links_to_send = array();
            foreach ( $links as $link ) {
                $links_to_send[$link->link] = array(
                    'link_text'   => $link->link_text,
                    'page_url'    => $link->page_url,
                );
            }
            $links_count   = sizeof($links_to_send);
            $links_to_send = json_encode($links_to_send);

            $result_links = API::method__security_linksscan_logs(
                $spbc->settings['spbc_key'],
                $scanner_start_local_date,
                $links_count ? 'failed' : 'passed',
                $links_count,
                $links_to_send
            );
            if ( ! empty($result_links['error']) ) {
                $error .= ' Links result send: ' . $result_links['error'];
            } else {
                $spbc->data['scanner']['last_scan_links_amount'] = $links_count;
            }
        }

        // Sending info about backup
        if ( $spbc->settings['scanner__auto_cure'] && ! empty($spbc->data['scanner']['cured']) ) {
            //todo This stuff should be refactored on cloud to use CureLog instance, at the moment this does not send failed files
            $result_repairs = API::method__security_mscan_repairs(
                $spbc->settings['spbc_key'],            // API key
                'SUCCESS',                    // Repair result
                'ALL_DONE',                // Repair comment
                (array)$spbc->data['scanner']['cured'], // Files
                count($spbc->data['scanner']['cured']), // Links found for last scan
                $spbc->data['scanner']['last_backup'],  // Last backup num
                $scanner_start_local_date               // Scanner start local date
            );
            if ( ! empty($result_repairs['error']) ) {
                $error .= ' Repairs result send: ' . $result_repairs['error'];
            }
        }

        // Frontend analysis
        if ( isset($spbc->settings['scanner__frontend_analysis']) && $spbc->settings['scanner__frontend_analysis'] ) {
            try {
                Frontend::sendFmsLogs();
            } catch (\Exception $exception) {
                $error .= $exception->getMessage();
            }
        }

        $spbc->error_toggle((bool)$error, 'scanner_result_send', $error);

        if ( $spbc->settings['scanner__auto_start'] && empty($spbc->errors['configuration']) ) {
            $scanner_launch_data = spbc_get_custom_scanner_launch_data();
            Cron::updateTask(
                'scanner__launch',
                'spbc_scanner__launch',
                $scanner_launch_data['period'],
                $scanner_launch_data['start_time']
            );
        }

        $spbc->save('data');

        // Adding to log
        $duration_of_scanning = isset($spbc->data['scanner']['scan_start_timestamp'], $spbc->data['scanner']['scan_finish_timestamp'])
            ? '<b>' . sprintf(__('Scan duration %s seconds.', 'security-malware-firewall') . '</b>', $spbc->data['scanner']['scan_finish_timestamp'] - $spbc->data['scanner']['scan_start_timestamp'])
            : __('The duration of the scan is not known', 'security-malware-firewall');
        ScanningLogFacade::writeToLog($duration_of_scanning);

        $out = array(
            'end' => 1,
            'stage_data_for_logging' => array(
                'title' => $duration_of_scanning,
                'description' => ''
            )
        );
        if ( (bool)$error ) {
            $out['error'] = $error;
        }

        $this->end_of_scan = true;

        return $out;
    }

    public function file_monitoring() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $file_monitoring = new FileMonitoringEntry();

        return $file_monitoring->handle()->getResults();
    }

    /**
     * Delete files which paths are included to the scanner exclusions directories.
     * @param string $scanner__dir_exclusions
     * @return bool|int
     * @psalm-suppress PossiblyUnusedReturnValue
     */
    public function deleteFilesOfExclusionDirs($scanner__dir_exclusions)
    {
        $deleted_count = 0;
        foreach ( spbc__get_exists_directories(explode("\n", $scanner__dir_exclusions)) as $exclusion ) {
            if ( $exclusion ) {
                $result = $this->db->prepare(
                    'DELETE FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE LOWER(path) LIKE LOWER(%s)',
                    ['%' . $this->db->escapeLike($exclusion) . '%']
                )->execute();
                $deleted_count = !empty($result) ? $deleted_count + (int)$result : $deleted_count;
            }
        }
        return $deleted_count;
    }

    /**
     * @param $file_record_error - current record error
     * @param $new_error_msg - new error from scan stage
     * @param $type - type of error source
     * @return string - JSON encoded string
     */
    private static function handleErrorMsg($file_record_error, $new_error_msg, $type)
    {
        if (!in_array($type, ['signature_analysis', 'heuristic_analysis'])) {
            return '';
        }
        if (is_null($file_record_error)) {
            return '';
        }
        $current_error_msg = json_decode($file_record_error, true);

        if (!empty($current_error_msg)) {
            if (!empty($new_error_msg)) {
                $current_error_msg[$type] = $new_error_msg;
            } else {
                unset($current_error_msg[$type]);
            }
        } else {
            if (!empty($new_error_msg)) {
                $current_error_msg[$type] = $new_error_msg;
            }
        }

        $current_error_msg = json_encode($current_error_msg);

        if (!empty($current_error_msg)) {
            return $current_error_msg;
        }

        return '';
    }
}
