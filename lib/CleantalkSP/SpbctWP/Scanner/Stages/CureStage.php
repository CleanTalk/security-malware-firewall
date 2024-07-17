<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages;

use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\Verdict;
use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Helpers\Helper as QueueHelper;
use CleantalkSP\SpbctWP\Scanner\Cure;
use CleantalkSP\SpbctWP\Scanner\CureLog\CureLog;
use CleantalkSP\SpbctWP\Scanner\CureLog\CureLogRecord;
use CleantalkSP\SpbctWP\Scanner\FileInfoExtended;
use CleantalkSP\SpbctWP\Scanner\ScanningLog\ScanningLogFacade;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\ScanningStagesStorage;
use CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages\AutoCure;

class CureStage
{
    /**
     * @var DB
     */
    private $db;
    /**
     * @var array
     */
    private $stage_result;
    /**
     * @var null|int
     */
    private $total_files_to_cure_at_first_run = null;

    /**
     * Constructor for the CureStage class.
     *
     * @param DB $db An instance of the DB class. This is used for database operations within the CureStage class.
     */
    public function __construct($db)
    {
        $this->db = $db;
    }

    public function runStage($offset, $amount)
    {
        global $spbc;

        //prepare facade log
        $scanning_stages_storage = new ScanningStagesStorage();
        $scanning_stages_storage->converter->loadCollection();
        $stage_data_obj = $scanning_stages_storage->getStage(AutoCure::class);

        //init common vars
        $processed = 0;
        $cured = array();

        //init cure log
        $cure_log = new CureLog();

        //count first offset counter for total file
        //todo fix this (int) cast, if false - this is error
        if ( $offset === 0 ) {
            $this->total_files_to_cure_at_first_run = (int)$this->getCountOfFilesWereNotTriedToCure();
            //to facade log
            $stage_data_obj->increase('count_files', $this->total_files_to_cure_at_first_run);
        }

        //get files with signatures weak spots
        $files = $this->getFilesToCure($amount);

        if ( count($files) ) {
            //main cure process
            foreach ( $files as $file ) {
                $cure_result = $this->processCure($file);
                $cure_log->logCureResult($cure_result);
                if ( $cure_result->cured ) {
                    //for logs sending way
                    $cured[$file['path']] = 'CURED';
                }
                //inc processed count anyway
                $processed++;
            }
            //this stuff is used to send cure logs
            $spbc->data['scanner']['cured'] = $cured;
            $spbc->save('data');
        }

        // Adding to facade log
        $stage_data_obj->increase('count_cured', count($cured));
        $scanning_stages_storage->saveToDb();
        ScanningLogFacade::writeToLog(
            '<b>' . $stage_data_obj::getTitle() . '</b> ' . $stage_data_obj->getDescription()
        );

        $this->stage_result = $this->prepareAjaxOutput($processed, count($cured), $stage_data_obj);
    }

    /**
     * This method is used to retrieve files that need to be cured.
     *
     * @param int $limit The maximum number of files to retrieve.
     * @return array An array of files that need to be cured. Each file is represented as an associative array.
     */
    private function getFilesToCure($limit)
    {
        $result = $this->db->fetchAll(
            'SELECT * '
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE weak_spots LIKE "%\"SIGNATURES\":%"'
            . ' LIMIT ' . $limit . ';'
        );

        if (is_null($result) || is_object($result)) {
            $result = array();
        }
        return $result;
    }

    public function processCure($file)
    {
        global $spbc;

        $weak_spots_decoded = json_decode($file['weak_spots'], true);

        //init cure log item, this item is DTO, used during all the process
        $cure_log_record = new CureLogRecord(array(
            'fast_hash' => isset($file['fast_hash']) ? $file['fast_hash'] : '',
            'real_path' => isset($file['path']) ? $file['path'] : '',
            'cured' => 0,
            'has_backup' => 0,
            'cci_cured' => null,
            'fail_reason' => '',
            'last_cure_date' => time(),
            'heuristic_rescan_result' => null,
            'scanner_start_local_date' => $spbc->data['scanner']['scanner_start_local_date'],
        ));

        $cure_log_record = $this->preCheckFile($file, $cure_log_record, $weak_spots_decoded);

        if ( $cure_log_record->fail_reason ) {
            return $cure_log_record;
        }

        //process Cure
        $cure_file_result = $this->doCureFile($file);
        //update table
        $cure_log_record = $this->updateScanResultsTableOnAfterCure(
            $cure_file_result,
            $file,
            $cure_log_record,
            $weak_spots_decoded
        );

        //if cured, rescan file with heuristic
        if ( empty($cure_log_record->fail_reason) ) {
            $recheck_result = $this->rescanFileHeuristic($file);
            $cure_log_record->heuristic_rescan_result = json_encode($recheck_result);
            //if rescanned, update results table
            if ( empty($recheck_result->error_msg) ) {
                $this->updateScanResultsTableOnHeuristicReCheck($file, $recheck_result);
            }
        }

        return $cure_log_record;
    }

    /**
     * This method is used to perform preliminary checks on the file before attempting to cure it.
     *
     * @param array $file An associative array representing the file to be checked.
     * @param CureLogRecord $cure_log_record An instance of the CureLogRecord class. This is used to log the results of the cure process.
     * @param array $weak_spots_decoded An associative array representing the JSON decoded weak spots in the file.
     *
     * @return CureLogRecord The updated CureLogRecord instance. This may contain a failure reason if the file cannot be cured.
     */
    private function preCheckFile($file, $cure_log_record, $weak_spots_decoded)
    {

        //check if even one of file signatures is curable
        if ( !$this->fileHasCurableSignatures($weak_spots_decoded) ) {
            //can not be cured, log this and return cure_log_record
            $cure_log_record->cured = 0;
            $cure_log_record->fail_reason = 'No CCI found.';
            return $cure_log_record;
        }

        //check if file has backup
        if ( !$this->fileHasBackup($file) ) {
            //cure is not safe without backups, log this and return cure_log_record
            $cure_log_record->fail_reason = 'File has no backup.';
            return $cure_log_record;
        } else {
            $cure_log_record->has_backup = 1;
        }

        return $cure_log_record;
    }

    /**
     * This method checks if the file has curable signatures.
     *
     * @param array $weak_spots_on_file An associative array representing the weak spots in the file.
     *
     * @return bool Returns true if the file has curable signatures, false otherwise.
     */
    public function fileHasCurableSignatures($weak_spots_on_file)
    {
        //init empty string of signatures
        $signatures_in_file = '';
        if ( !empty($weak_spots_on_file['SIGNATURES']) ) {
            $signatures_in_file = array();
            foreach ( $weak_spots_on_file['SIGNATURES'] as $signatures_in_string ) {
                $signatures_in_file = array_merge(
                    $signatures_in_file,
                    array_diff($signatures_in_string, $signatures_in_file)
                );
            }
            $signatures_in_file = implode(',', $signatures_in_file);
        }

        //check if signature can be cured - has instructions
        $signatures_with_cci = !empty($signatures_in_file)
            ? $this->db->fetchAll(
                'SELECT * '
                . ' FROM ' . SPBC_TBL_SCAN_SIGNATURES
                . ' WHERE id IN (' . $signatures_in_file . ') AND cci IS NOT NULL AND cci <> \'\''
                . ' LIMIT 1'
            )
            : false;
        return is_array($signatures_with_cci) && !empty($signatures_with_cci);
    }

    /**
     * This method checks if the file has a backup.
     *
     * @param array $file An associative array representing the file to be checked.
     *
     * @return bool Returns true if the file has a backup, false otherwise.
     */
    private function fileHasBackup($file)
    {
        return spbc_file_has_backup($file['path']);
    }

    /**
     * This method is used to perform the cure operation on the file.
     *
     * @param array $file An associative array representing the file to be cured.
     *
     * @return Cure Returns an instance of the Cure class.
     */
    private function doCureFile($file)
    {
        return new Cure($file);
    }

    /**
     * This method updates the scan results table after the cure process.
     *
     * @param Cure $cure_result The result of the cure process. This is an instance of the Cure class.
     * @param array $file An associative array representing the file that was cured.
     * @param CureLogRecord $cure_log_record An instance of the CureLogRecord class. This is used to log the results of the cure process.
     * @param array $weak_spots_decoded An associative array representing the JSON decoded weak spots in the file.
     *
     * @return CureLogRecord The updated CureLogRecord instance. This may contain a failure reason if the file cannot be cured.
     */
    private function updateScanResultsTableOnAfterCure($cure_result, $file, $cure_log_record, $weak_spots_decoded)
    {
        if ( !empty($cure_result->result['error']) ) {
            //if Cure process errored keep the reason
            $cure_log_record->fail_reason = $cure_result->result['error'];
        } else {
            //new log way
            $cure_log_record->cured = 1;
            $cure_log_record->cci_cured = count($weak_spots_decoded['SIGNATURES']);

            //file is cured, remove signatures weakspots
            unset($weak_spots_decoded['SIGNATURES']);

            //process any other weakspots to save them
            if ( empty($weak_spots_decoded) ) {
                $weak_spots_encoded = 'NULL';
                $severity = 'NULL';
                $status = 'OK';
            } else {
                $weak_spots_encoded = QueueHelper::prepareParamForSQLQuery(json_encode($weak_spots_decoded));
                $severity = $file['severity'];
                $status = $file['status'];
            }

            //update scan results table
            $this->db->execute(
                'UPDATE ' . SPBC_TBL_SCAN_FILES
                . ' SET '
                . 'weak_spots = ' . $weak_spots_encoded . ','
                . 'severity = "' . $severity . '",'
                . 'status = "' . $status . '"'
                . ' WHERE fast_hash = "' . $file['fast_hash'] . '";'
            );
        }

        return $cure_log_record;
    }

    /**
     * This method is used to rescan a file using heuristic analysis.
     *
     * @param array $file An associative array representing the file to be rescanned.
     *
     * @return Verdict Returns the result of the heuristic scan. The type and content of this result can vary depending on the heuristic scanner.
     */
    private function rescanFileHeuristic($file)
    {
        //get root path to rescan
        $root_path = spbc_get_root_path();

        // Get file form DB - not from thread - important!
        $file_to_check_with_heuristic = $this->db->fetchAll(
            'SELECT * '
            . ' FROM ' . SPBC_TBL_SCAN_FILES
            . ' WHERE fast_hash = "' . $file['fast_hash'] . '";'
        );
        $file_to_check_with_heuristic = $file_to_check_with_heuristic[0];

        $file_to_check = new FileInfoExtended($file_to_check_with_heuristic);

        // init heuristic module to rescan
        $heuristic_scanner = new \CleantalkSP\Common\Scanner\HeuristicAnalyser\Controller();

        return $heuristic_scanner->scanFile($file_to_check, $root_path);
    }

    /**
     * This method updates the scan results table after a heuristic recheck.
     *
     * @param array $file An associative array representing the file that was rescanned.
     * @param Verdict $result The result of the heuristic recheck. This is an instance of the Verdict class.
     *
     * The method updates the following fields in the scan results table:
     * - checked_heuristic: Set to 1 to indicate that a heuristic recheck has been performed.
     * - status: The status of the file after the heuristic recheck.
     * - severity: The severity of the file after the heuristic recheck. If the severity is null, it is set to 'NULL'.
     * - weak_spots: The weak spots in the file after the heuristic recheck. If there are no weak spots, it is set to 'NULL'.
     */
    private function updateScanResultsTableOnHeuristicReCheck($file, $result)
    {
        //update table
        $this->db->execute(
            'UPDATE ' . SPBC_TBL_SCAN_FILES
            . ' SET'
            . " checked_heuristic = 1,"
            . ' status = \'' . $result->status . '\','
            . ' severity = ' . ($result->severity ? '\'' . $result->severity . '\'' : 'NULL') . ','
            . ' weak_spots = ' . ($result->weak_spots ? QueueHelper::prepareParamForSQLQuery(
                json_encode($result->weak_spots)
            ) : 'NULL')
            . ' WHERE fast_hash = \'' . $file['fast_hash'] . '\';'
        );
    }

    /**
     * This method retrieves the count of files that have not been attempted to be cured.
     *
     * The method performs a SQL query to count the number of files in the scan files table that have signatures as weak spots
     * and are not present in the cure log table with a cured status of 0.
     *
     * @return int|bool Returns the count of files that have not been attempted to be cured. If there is a database read error, it returns false.
     */
    private function getCountOfFilesWereNotTriedToCure()
    {
        $query = '
                SELECT
                    COUNT(*) AS cnt FROM ' . SPBC_TBL_SCAN_FILES . '
                    WHERE weak_spots LIKE "%SIGNATURES%"
                    AND fast_hash NOT IN 
                        (SELECT fast_hash FROM ' . SPBC_TBL_CURE_LOG . ' WHERE cured = 0);
            ';
        $result = $this->db->fetch($query, OBJECT);
        if ( $result !== null && isset($result->cnt) ) {
            return (int)$result->cnt;
        }

        return false;
    }

    /**
     * This method prepares the AJAX output for the cure stage.
     *
     * @param int $processed The number of files that have been processed in the current run of the cure stage.
     * @param int $cured_count The number of files that have been cured in the current run of the cure stage.
     * @param ScanningStagesStorage $stage_data_obj An instance of the ScanningStagesStorage class. This is used to get the title and description of the cure stage.
     *
     * @return array The AJAX output for the cure stage. This includes the following fields:
     * - processed: The number of files that have been processed in the current run of the cure stage.
     * - cured: The number of files that have been cured in the current run of the cure stage.
     * - end: A boolean indicating whether all files have been attempted to be cured. This is true if there are no more files to cure, and false otherwise.
     * - message: A message recommending the user to change their secret authentication keys and salts when the curing is done.
     * - stage_data_for_logging: An associative array containing the title and description of the cure stage.
     * - error: An error message if there is a database read error while counting the files that have not been attempted to be cured. This field is only present if there is a database read error.
     * - comment: A comment containing the last database error. This field is only present if there is a database read error.
     * - total: The total number of files that were to be cured at the start of the first run of the cure stage. This field is only present in the output of the first run of the cure stage.
     * @psalm-suppress UndefinedMethod - this suppress is used because the ScanningStagesStorage class does not have a static method getTitle().
     */
    private function prepareAjaxOutput($processed, $cured_count, $stage_data_obj)
    {
        $uncured = $this->getCountOfFilesWereNotTriedToCure();

        //prepare AJAX output
        $out = array(
            'processed' => $processed,
            'cured' => $cured_count,
            'end' => (int)$uncured === 0,
            'message' => __(
                'We recommend changing your secret authentication keys and salts when curing is done.',
                'security-malware-firewall'
            )
        );

        $out['stage_data_for_logging'] = array(
            'title' => $stage_data_obj::getTitle(),
            'description' => $stage_data_obj->getDescription()
        );

        if ( false === $uncured ) {
            return array_merge(
                $out,
                array(
                    'error' => __FUNCTION__ . ' DataBase read error while counting files.',
                    'comment' => substr($this->db->getLastError(), 0, 1000),
                )
            );
        }

        //provide this value just once, if provide more - there will cause unexpected percentage counter
        if ( isset($this->total_files_to_cure_at_first_run) ) {
            $out = array_merge($out, array('total' => $this->total_files_to_cure_at_first_run));
        }

        return $out;
    }

    /**
     * This method is used to get the result of the stage.
     *
     * @return array The result of the stage. The type and content of this result can vary depending on the stage.
     */
    public function getStageResult()
    {
        return $this->stage_result;
    }
}
