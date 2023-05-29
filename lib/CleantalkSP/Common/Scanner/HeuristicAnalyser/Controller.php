<?php

namespace CleantalkSP\Common\Scanner\HeuristicAnalyser;

use CleantalkSP\Common\Helpers\Arr;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Exceptions\HeuristicScannerException;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Model\Model;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\FileInfo;
use CleantalkSP\Common\Scanner\HeuristicAnalyser\Structures\Verdict;

class Controller
{
    const FILE_MAX_SIZE = 524288; // 512 KB

    /**
     * @var Model
     */
    private $model;
    public $final_code;

    public function __construct(Model $model)
    {
        $this->model = $model;
    }

    public function scanFile(FileInfo $file_info, $root_path = null)
    {
        $root_path  = $root_path ?: $this->getRootPath();


        // 1) Get content or path based heuristic object
        // 2) Run preparing process
        // 3) processContent

        try {
            $output = $this->scanFileForHeuristic($file_info, $root_path);
        } catch (HeuristicScannerException $e) {
            $output = array('error' => $e->getMessage());
        }

        return $output;
    }

    /**
     * Scan file against the heuristic
     *
     * @param FileInfo $file_info Array with files data (path, real_full_hash, source_type, source, version), other is optional
     * @param string $root_path Path to CMS's root folder
     *
     * @return Verdict False or Array of found bad constructs sorted by severity
     */
    private function scanFileForHeuristic(FileInfo $file_info, $root_path = '')
    {
        $root_path = $root_path ?: $this->getRootPath();

        $scanner = new HeuristicAnalyser(array('path' => $root_path . $file_info->path));

        $output = new Verdict();

        if ( ! empty($scanner->error) ) {
            $output->weak_spots = null;
            $output->severity   = null;
            $output->status     = 'OK';
            $output->includes   = array();
            return $output;
        }
        $scanner->processContent();

        // Saving only signatures from the previous result
        $file_info->weak_spots = ! empty($file_info->weak_spots) ? json_decode(
            $file_info->weak_spots,
            true
        ) : array();
        $file_info->weak_spots = isset($file_info->weak_spots['SIGNATURES'])
            ? array('SIGNATURES' => $file_info->weak_spots['SIGNATURES'])
            : array();

        $verdict = Arr::mergeWithSavingNumericKeysRecursive($file_info->weak_spots, $scanner->verdict);

        $output->includes = $scanner->getIncludes();

        // Processing results
        if ( ! empty($verdict) ) {
            $output->weak_spots = $verdict;
            $output->severity   = array_key_exists('CRITICAL', $verdict) ? 'CRITICAL' : (array_key_exists(
                'DANGER',
                $verdict
            ) ? 'DANGER' : 'SUSPICIOUS');
            $output->status     = array_key_exists('CRITICAL', $verdict) ? 'INFECTED' : 'OK';
        } else {
            $output->weak_spots = null;
            $output->severity   = null;
            $output->status     = 'OK';
        }

        $this->final_code = $scanner->deobfuscated_code;
        return $output;
    }

    private function getRootPath()
    {
        return $this->model->getRootPath();
    }
}
