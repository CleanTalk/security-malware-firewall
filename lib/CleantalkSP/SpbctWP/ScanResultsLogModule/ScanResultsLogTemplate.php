<?php

namespace CleantalkSP\SpbctWP\ScanResultsLogModule;

class ScanResultsLogTemplate
{
    public function render()
    {
        echo $this->template();
    }

    public function template()
    {
        $scan_results_log_repository = new ScanResultsLogRepository();
        $rows = $scan_results_log_repository->getScanResultsLogRows();
        $template = '';

        if (count($rows) > 0) {
            $template = '<div id="spbcscan-results-log-module">';
            $template .= '<div class="panel-body">';

            foreach ($rows as $row) {
                $template .= '<p class="spbc_log-line">'
                             . gmdate('M d Y H:i:s', $row['checked_at'])
                             . ' - ' .$row['path'] .
                             '<b>: ' . $row['status_of_check'] . '</b>' .
                             '<i>: ' . strtolower($row['check_type']) . '</i>' .
                             '</p>';
            }

            $template .= '</div>';
            $template .= '</div>';
        }

        return $template;
    }

    public function getLogByParams()
    {
        $scan_results_log_repository = new ScanResultsLogRepository();
        $rows = $scan_results_log_repository->getScanResultsLogRows();
        $template = '';

        if (count($rows) > 0) {
            foreach ($rows as $row) {
                $template .= '<p class="spbc_log-line">'
                             . gmdate('Y-m-d H:i:s', $row['checked_at'])
                             . ' - ' .$row['path'] .
                             '<b>: ' . $row['status_of_check'] . '</b>' .
                             '<i>: ' . strtolower($row['check_type']) . '</i>' .
                             '</p>';
            }
        }

        return $template;
    }
}