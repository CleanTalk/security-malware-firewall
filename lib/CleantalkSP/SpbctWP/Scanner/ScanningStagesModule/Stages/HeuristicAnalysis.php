<?php

namespace CleantalkSP\SpbctWP\Scanner\ScanningStagesModule\Stages;

use CleantalkSP\SpbctWP\DB\ObjectForOptionsInterface;

class HeuristicAnalysis extends ScanningStageAbstract implements ObjectForOptionsInterface
{
    public $total_count_files_for_analysis = 0;
    public $count_files_to_check = 0;
    public $scanned_count_files = 0;
    public $statuses = array();

    /** @psalm-suppress PossiblyUnusedMethod */
    public static function getTitle()
    {
        return __('Heuristic analysis', 'security-malware-firewall');
    }

    /** @psalm-suppress PossiblyUnusedMethod */
    public function getDescription()
    {
        return __('Total files for analysis ', 'security-malware-firewall')
               . $this->total_count_files_for_analysis
               . '; '
               . __('Files to check ', 'security-malware-firewall')
               . $this->count_files_to_check
               . '; '
               . __('Scanned files ', 'security-malware-firewall')
               . $this->scanned_count_files
               . '; '
               . __('Statuses ', 'security-malware-firewall')
               . $this->getStatusesWithTitle();
    }

    public function getStatusesWithTitle()
    {
        $description_array = array();
        foreach ($this->statuses as $status => $count) {
            $description_array[] = $status . ': ' . $count;
        }
        return $description_array ? implode('; ', $description_array) . '.' : '';
    }

    public function getName()
    {
        return __CLASS__;
    }

    public function getData()
    {
        return array(
            'total_count_files_for_analysis' => $this->total_count_files_for_analysis,
            'count_files_to_check' => $this->count_files_to_check,
            'scanned_count_files' => $this->scanned_count_files,
            'statuses' => $this->statuses
        );
    }
}
