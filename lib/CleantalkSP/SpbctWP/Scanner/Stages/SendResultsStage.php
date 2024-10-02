<?php

namespace CleantalkSP\SpbctWP\Scanner\Stages;

use CleantalkSP\SpbctWP\API;
use CleantalkSP\SpbctWP\Cron;
use CleantalkSP\SpbctWP\RemoteCalls;
use CleantalkSP\SpbctWP\Scanner\Frontend;
use CleantalkSP\SpbctWP\Scanner\ScanningLog\ScanningLogFacade;
use CleantalkSP\SpbctWP\Scanner\Stages\DTO\SendBackupDTO;
use CleantalkSP\SpbctWP\Scanner\Stages\DTO\SendFilesDTO;
use CleantalkSP\Variables\Request;
use CleantalkSP\SpbctWP\Scanner\Stages\Repositories\CriticalRepository;
use CleantalkSP\SpbctWP\Scanner\Stages\Repositories\LinksRepository;
use CleantalkSP\SpbctWP\Scanner\Stages\Repositories\SuspiciousRepository;
use CleantalkSP\SpbctWP\Scanner\Stages\Repositories\UnknownRepository;
use CleantalkSP\SpbctWP\Scanner\Surface;

class SendResultsStage
{
    /**
     * Execute send result stage
     *
     * @return array
     */
    public function execute()
    {
        global $spbc;

        $error = '';

        $error = $this->sendFiles($error);

        $links = new LinksRepository();
        $error = $links->handle($error);

        $error = $this->sendBackup($error);

        $error = $this->sendFrontend($error);

        $spbc->error_toggle((bool)$error, 'scanner_result_send', $error);

        $this->updateAutoStart();

        $spbc->save('data');

        $duration_of_scanning = $this->updateLog();

        $out = array(
            'end' => 1,
            'stage_data_for_logging' => array(
                'title' => $duration_of_scanning,
                'description' => ''
            )
        );

        if ((bool)$error) {
            $out['error'] = $error;
        }

        return $out;
    }

    /**
     * Send files to the cloud
     *
     * @param string $error
     *
     * @return array<array-key, mixed>|bool|mixed
     */
    private function sendFiles($error)
    {
        global $spbc;

        $params = [
            'api_key' => $spbc->settings['spbc_key'],
            'service_id' => $spbc->service_id,
            'list_unknown' => (int)$spbc->settings['scanner__list_unknown'],
        ];

        $dto = new SendFilesDTO($params);

        try {
            $this->gatherFileData($dto);
            $this->gatherScanData($dto);
            $this->gatherCountData($dto);
            $this->gatherSignatureData($dto);
        } catch (\Exception $e) {
            $error .= $e->getMessage();
            return $error;
        }

        $result = API::method__security_mscan_logs($dto);

        if ( ! empty($result['error']) ) {
            $error = 'Common result send: ' . $result['error'];
        } else {
            $spbc->data['scanner']['last_sent'] = current_time('timestamp');
            $spbc->data['scanner']['last_scan'] = current_time('timestamp');
            $spbc->data['scanner']['scan_finish_timestamp'] = time();
            $spbc->data['scanner']['last_scan_amount'] = Request::get('total_scanned') ?: $dto->total_scan_files;
            $spbc->data['scanner']['signatures_found'] = []; // Clearing ids of the signatures found
        }

        return $error;
    }

    /**
     * Gather scan data
     *
     * @param $dto
     */
    private function gatherFileData($dto)
    {
        global $spbc;

        $critical = new CriticalRepository();
        $dto->critical = $critical->getResultData();

        $suspicious = new SuspiciousRepository();
        $dto->suspicious = $suspicious->getResultData();

        $unknown = new UnknownRepository();
        $dto->unknown = $unknown->getResultData();

        if ( ! empty($dto->critical)) {
            $dto->failed_files      = json_encode($dto->critical);
            $dto->failed_files_rows = count($dto->critical);
        }
        if ( ! empty($dto->suspicious)) {
            $dto->suspicious_files      = json_encode($dto->suspicious);
            $dto->suspicious_files_rows = count($dto->suspicious);
        }
    }

    /**
     * Gather scan data
     *
     * @param $dto
     */
    private function gatherScanData($dto)
    {
        global $spbc;

        $dto->scanner_last_start_local_date = isset($spbc->data['scanner']['scanner_start_local_date'])
            ? $spbc->data['scanner']['scanner_start_local_date']
            : current_time('Y-m-d H:i:s');
        $dto->scan_type = RemoteCalls::check() ? 'auto' : 'manual';
        $dto->scanner_result = !empty($dto->critical) || !empty($dto->suspicious) ? 'warning' : 'passed';
    }

    /**
     * Gather count data
     *
     * @param $dto
     * @throws \Exception
     */
    private function gatherCountData($dto)
    {
        global $spbc, $wpdb;

        $total_core_files = (int)$wpdb->get_var(
            'SELECT COUNT(*) FROM ' . SPBC_TBL_SCAN_FILES . ' WHERE source_type = "CORE" AND source = "wordpress"'
        );
        $dto->total_core_files   = $total_core_files ?: 0;
        $dto->total_site_files   = $spbc->data['scanner']['files_total'] = $this->countFileSystem()['total'];
        $dto->total_scan_files   = isset($spbc->data['scanner']['scanned_total']) ? $spbc->data['scanner']['scanned_total'] : null;
        $dto->total_site_pages   = isset($spbc->data['scanner']['total_site_pages']) ? $spbc->data['scanner']['total_site_pages'] : 0;
        $dto->scanned_site_pages = isset($spbc->data['scanner']['scanned_site_pages']) ? $spbc->data['scanner']['scanned_site_pages'] : 0;

        $dto->checksum_count_ct   = isset($spbc->data['scanner']['checksums_count_ct']) ? $spbc->data['scanner']['checksums_count_ct'] : null;
        $dto->checksum_count_user = (int)$wpdb->get_var(
            'SELECT COUNT(*) from ' . SPBC_TBL_SCAN_FILES . ' WHERE status = "APPROVED_BY_USER"'
        );
    }

    /**
     * Gather signature data
     *
     * @param $dto
     */
    private function gatherSignatureData($dto)
    {
        global $spbc;

        $dto->signatures_count     = isset($spbc->data['scanner']['signature_count']) ? $spbc->data['scanner']['signature_count'] : null;
        $signatures_found = isset($spbc->data['scanner']['signatures_found']) ? $spbc->data['scanner']['signatures_found'] : [];
        $dto->signatures_found = json_encode($signatures_found);

        if ( is_null($dto->signatures_count) && is_string($signatures_found) ) {
            $$dto->signatures_count = count(json_decode($signatures_found, true));
        }
    }

    /**
     * Send backup
     *
     * @param string $error
     *
     * @return string
     */
    private function sendBackup($error)
    {
        global $spbc;

        $cured = isset($spbc->data['scanner']['cured']) ? (array)$spbc->data['scanner']['cured'] : [];

        $params = [
            'api_key' => $spbc->settings['spbc_key'],
            'repair_result' => 'SUCCESS',
            'repair_comment' => 'ALL_DONE',
            'repaired_processed_files' => $cured,
            'repaired_total_files_processed' => count($cured),
            'backup_id' => isset($spbc->data['scanner']['last_backup']) ? $spbc->data['scanner']['last_backup'] : 0,
        ];

        $dto = new SendBackupDTO($params);

        $dto->scanner_last_start_local_date = isset($spbc->data['scanner']['scanner_start_local_date'])
            ? $spbc->data['scanner']['scanner_start_local_date']
            : current_time('Y-m-d H:i:s');

        if ( $spbc->settings['scanner__auto_cure'] && ! empty($spbc->data['scanner']['cured']) ) {
            //@todo This stuff should be refactored on cloud to use CureLog instance, at the moment this does not send failed files
            $result_repairs = API::method__security_mscan_repairs($dto);
            if ( ! empty($result_repairs['error']) ) {
                $error .= ' Repairs result send: ' . $result_repairs['error'];
            }
        }

        return $error;
    }

    /**
     * Send frontend
     *
     * @param string $error
     *
     * @return string
     */
    private function sendFrontend($error)
    {
        global $spbc;

        if ( isset($spbc->settings['scanner__frontend_analysis']) && $spbc->settings['scanner__frontend_analysis'] ) {
            try {
                Frontend::sendFmsLogs();
            } catch (\Exception $exception) {
                $error .= $exception->getMessage();
            }
        }

        return $error;
    }

    /**
     * Update auto start
     */
    private function updateAutoStart()
    {
        global $spbc;

        if ( $spbc->settings['scanner__auto_start'] && empty($spbc->errors['configuration']) ) {
            $scanner_launch_data = spbc_get_custom_scanner_launch_data();
            Cron::updateTask(
                'scanner__launch',
                'spbc_scanner__launch',
                $scanner_launch_data['period'],
                $scanner_launch_data['start_time']
            );
        }
    }

    /**
     * Update log
     *
     * @return string
     */
    private function updateLog()
    {
        global $spbc;

        $duration_of_scanning = __('The duration of the scan is not known', 'security-malware-firewall');
        if (isset($spbc->data['scanner']['scan_start_timestamp'], $spbc->data['scanner']['scan_finish_timestamp'])) {
            $duration_of_scanning = '<b>'
                . sprintf(__('Scan duration %s seconds.', 'security-malware-firewall')
                . '</b>', $spbc->data['scanner']['scan_finish_timestamp'] - $spbc->data['scanner']['scan_start_timestamp']) ;
        }

        ScanningLogFacade::writeToLog($duration_of_scanning);

        return $duration_of_scanning;
    }

    /**
     * @param string $path_to_scan
     *
     * @return array
     * @throws \Exception
     */
    public function countFileSystem($path_to_scan = ABSPATH)
    {
        global $spbc;

        ini_set('max_execution_time', '120');

        $path_to_scan = realpath($path_to_scan);
        $init_params  = array(
            'count'           => true,
            'file_exceptions' => 'wp-config.php',
            'extensions'      => 'php, html, htm, php2, php3, php4, php5, php6, php7, phtml, shtml, phar, odf, [ot.]',
            'files_mandatory' => array(),
            'dir_exceptions'  => array(SPBC_PLUGIN_DIR . 'quarantine')
        );

        if ( ! empty($spbc->settings['scanner__dir_exclusions']) ) {
            $init_params['dir_exceptions'] = array_merge(
                $init_params['dir_exceptions'],
                spbc__get_exists_directories(explode("\n", $spbc->settings['scanner__dir_exclusions']))
            );
        }

        $scanner = new Surface($path_to_scan, realpath(ABSPATH), $init_params);
        if ($scanner->has_errors) {
            throw new \Exception('Count system files error on sending result');
        }

        return array(
            'total' => $scanner->output_files_count,
            'end'   => 1,
        );
    }
}
