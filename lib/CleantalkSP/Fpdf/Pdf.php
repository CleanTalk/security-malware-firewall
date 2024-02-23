<?php

namespace CleantalkSP\Fpdf;

use CleantalkSP\SpbctWP\DB;
use CleantalkSP\SpbctWP\Scanner\CureLog\CureLog;

class Pdf extends Fpdf
{
    /**
     * @var array
     */
    private $doc_text_headers = array();

    /**
     * Generate doc header. Replace parent method Header
     */
    public function Header() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        $this->SetTextColor(150, 150, 150);
        $this->setDocTextHeaders();
        // Logo
        $this->Image(__DIR__ . DIRECTORY_SEPARATOR . 'img' . DIRECTORY_SEPARATOR . 'logo.png', 10, 6, 15);

        $this->SetFont('Times', 'B', 15);

        // Move to the right
        $this->Cell(80);

        // Title
        $this->Cell(30, 10, $this->getDocTextHeader('main_title'), 0, 0, 'C');

        // Line break
        $this->Ln(15);

        $this->SetFont('Times', 'B', 12);
        $this->Cell(0, 0, $this->getDocTextHeader('brand_title'), 0, 1, 'L');

        $this->Ln(5);
    }

    /**
     * Generate doc footer. Replace parent method Footer
     */
    public function Footer() // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        // Position at 1.5 cm from bottom
        $this->SetY(-15);

        $this->SetFont('Times', '', 8);

        // Page number
        $this->Cell(0, 10, 'Page ' . $this->PageNo() . '/{nb}', 0, 0, 'L');
        $this->Cell(0, 10, $spbc->data["wl_mode_enabled"] ? $spbc->data["wl_support_url"] : 'https://cleantalk.org/wordpress-security-malware-firewall', 0, 0, 'R');
    }

    /**
     * Set escaped text headers for document.
     */
    private function setDocTextHeaders()
    {
        global $spbc;

        $this->doc_text_headers = array(
            'heuristic_results' => esc_html__('Heuristic analysis', 'security-malware-firewall'),
            'signature_results' => esc_html__('Signature analysis', 'security-malware-firewall'),
            'critical_files' => esc_html__('Critical files list', 'security-malware-firewall'),
            'suspicious_files' => esc_html__('Suspicious files list', 'security-malware-firewall'),
            'main_title' => esc_html__('Malware Scanner logs', 'security-malware-firewall'),
            'brand_title' => $spbc->data["wl_brandname"],
            'cure_log' => esc_html__('Automatic cure log', 'security-malware-firewall'),
            'common_stats' => esc_html__('Scanner stats', 'security-malware-firewall'),
        );
    }
    /**
     * Get text of document header
     * @param string $type Type of header listed in $this->doc_text_headers
     * @return string
     */
    private function getDocTextHeader($type)
    {
        return isset($this->doc_text_headers[$type]) ? $this->doc_text_headers[$type] : 'Empty header';
    }

    /**
     * Data loading handler
     * @param string $type Type of data to handle
     * @return array|object
     */
    private function LoadData($type = '') // phpcs:ignore PSR1.Methods.CamelCapsMethodName.NotCamelCaps
    {
        global $spbc;

        switch ( $type ) {
            case 'common_stats':
                $timezone = get_option('gmt_offset');
                if ( $timezone < 0 ) {
                    $timezone = '-' . $timezone;
                } else {
                    $timezone = '+' . $timezone;
                }

                $data = array(
                    "Date and time (GMT" . $timezone . ")" => date('M d Y H:i:s', $spbc->data['scanner']['last_scan']),
                    "Site URL" => site_url(),
                    "Duration of scanning" => $spbc->data['scanner']['scan_finish_timestamp'] - $spbc->data['scanner']['scan_start_timestamp'] . ' sec',
                    "Total files" => isset($spbc->data['scanner']['files_total'])
                        ? $spbc->data['scanner']['files_total']
                        : $spbc->data['scanner']['last_scan_amount'],
                );
                break;

            case 'heuristic_results':
                $query_result = DB::getInstance()->fetchAll(
                    'SELECT id, content FROM ' . SPBC_TBL_SCAN_RESULTS_LOG
                    . ' WHERE content LIKE "%Heuristic analysis%"'
                    . ' ORDER BY id DESC'
                    . ' LIMIT 1'
                );
                $data = isset($query_result[0]) && is_array($query_result[0])
                    ? $query_result[0]
                    : array('content' => '');
                break;

            case 'signature_results':
                $query_result = DB::getInstance()->fetchAll(
                    'SELECT id, content FROM ' . SPBC_TBL_SCAN_RESULTS_LOG
                    . ' WHERE content LIKE "%Signature analysis%"'
                    . ' ORDER BY id DESC'
                    . ' LIMIT 1'
                );
                $data = isset($query_result[0]) && is_array($query_result[0])
                    ? $query_result[0]
                    : array('content' => '');
                break;

            case 'critical_files':
                $query_result = DB::getInstance()->fetchAll(
                    "SELECT `path` FROM " . SPBC_TBL_SCAN_FILES
                    . " WHERE severity = 'CRITICAL'"
                );
                $data = !empty($query_result) ? $query_result : array();
                break;

            case 'suspicious_files':
                $query_result = DB::getInstance()->fetchAll(
                    "SELECT `path` FROM " . SPBC_TBL_SCAN_FILES
                    . " WHERE severity = 'SUSPICIOUS'"
                );
                $data = !empty($query_result) ? $query_result : array();
                break;

            case 'cure_log':
                $cure_log = new CureLog();
                $data = $cure_log->getDataToPDF();
                break;

            default:
                $data = array();
        }

        return $data;
    }

    /**
     * Run common stats table rendering
     */
    public function drawScanCommonStatsTable()
    {
        $data = $this->loadData('common_stats');

        //header
        $this->SetFont('Times', 'B', 12);

        $this->Cell(80);
        $this->Cell(40, 8, $this->getDocTextHeader('common_stats'), 'B', 0, 'C');

        $this->Ln(5);
        $this->Ln(5);

        $this->SetFont('Times', 'B', 10);

        // table headers
        $this->Cell(70, 8, 'Description', 1);
        $this->Cell(120, 8, 'Details', 1);

        $this->Ln();

        $this->SetFont('Times', '', 10);

        // table data
        foreach ( $data as $key => $value ) {
            $this->Cell(70, 7, $key, 1);
            $this->Cell(120, 7, $value, 1);
            $this->Ln();
        }
    }

    /**
     * Run scan results stats table rendering by type of scan
     * @param string $type 'signature_results','heuristic_results'
     */
    public function drawScanResultsOfScanType($type)
    {

        if ( !empty($type) ) {
            $data = $this->loadData($type);

            $lines = explode(';', strip_tags($data['content']));

            $this->SetFont('Times', 'B', 12);

            $this->Cell(80);
            $this->Cell(40, 8, $this->getDocTextHeader($type), 'B', 0, 'C');

            $this->Ln();

            $this->SetFont('Times', '', 10);

            foreach ( array_values($lines) as $value ) {
                $this->MultiCell(200, 5, $this->prettier($value), 0);
            }
        }
    }

    /**
     * Run files list rendering by type of files
     * @param string $type 'critical_files'
     */
    public function drawFilesListByType($type)
    {
        if ( !empty($type) ) {
            $data = $this->loadData($type);
            if ( !empty($data) ) {
                $this->SetFont('Times', 'B', 12);

                $this->Cell(80);
                $this->Cell(40, 8, $this->getDocTextHeader($type) . ' (' . count($data) . ')', 'B', 0, 'C');

                $this->Ln();
                $this->Ln();

                $this->SetFont('Times', '', 10);

                switch ($type) {
                    case 'critical_files':
                    case 'suspicious_files':
                        foreach ( array_values($data) as $value ) {
                            $this->MultiCell(195, 7, '../' . $value['path']);
                        }
                        break;
                    case 'cure_log':
                        $headers = array('Path', 'Status', 'Last try date', 'Threats cured');
                        $headers_count = count($headers);
                        // Column widths
                        $widths = array('100', 20, 50, 22);
                        // Header
                        for ($i = 0; $i < $headers_count; $i++) {
                            $this->Cell($widths[$i], 7, $headers[$i], 1, 0, 'C');
                        }
                        $this->Ln();
                        // Data
                        foreach ($data as $row) {
                            $this->Cell($widths[0], 6, '..' . substr($row['real_path'], $widths[0] * -1), 1);
                            $this->Cell($widths[1], 6, $row['cured'], '1', 0, 'C');
                            $this->Cell($widths[2], 6, $row['last_cure_date'], '1', 0, 'R');
                            $this->Cell($widths[3], 6, $row['cci_cured'], '1', 0, 'C');
                            $this->Ln();
                        }
                        // Closing line
                        $this->Cell(array_sum($widths), 0, '', 'T');
                        break;
                }
            }
        }
    }

    /**
     * Text transformations for data strings
     * @param $string
     * @return array|mixed|string|string[]
     */
    private function prettier($string)
    {
        $headers = array('Heuristic analysis' => 'heuristic', 'Signature analysis' => 'signature');
        $headers_replaced = false;
        foreach ( $headers as $key => $value ) {
            if ( strpos($string, $key) !== false ) {
                $string = str_replace($key, '', $string);
                $string = str_replace('Total files for analysis', 'Total files for ' . $value . ' analysis:', $string);
                $headers_replaced = true;
            }
        }
        if ( !$headers_replaced ) {
            $string = preg_replace('[\_|\.|\:]', ' ', $string);
            $string = ' - ' . $string;
        }
        return $string;
    }
}
